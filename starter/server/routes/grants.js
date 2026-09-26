// Grants routes: create and revoke permission grants.
// D9: no self-grants. assertMayGrant: no privilege laundering.
// D19: unknown permission string is rejected (by DB FK, surfaced as 400).

import { send, badRequest, forbidden, notFound, conflict } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan, assertMayGrant } from '../permissions.js';
import { audit } from '../audit.js';
import { normalizeTs } from '../http.js';

export function registerGrantRoutes(router, { db }) {
  // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/grants  — list active grants in this org
  // Requires user:read (sufficient for read-only view per the UI tests)
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/grants', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');

    const grants = db.prepare(
      `SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at,
              g.created_by, g.revoked_at, g.created_at,
              u.name AS user_name, u.email AS user_email
         FROM grants g
         JOIN users u ON u.id = g.user_id
        WHERE g.org_id = ?
        ORDER BY g.created_at DESC`
    ).all(ctx.orgId);

    // Attach the permission list to each grant.
    const result = grants.map((g) => {
      const permissions = db.prepare(
        'SELECT permission FROM grant_permissions WHERE grant_id = ?'
      ).all(g.id).map((r) => r.permission);
      return { ...g, permissions };
    });

    send(res, 200, { grants: result });
  });

  // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/grants  — create a grant
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/grants', async (ctx, params, res) => {
    assertCan(db, ctx, 'grant:create');

    const { userId, deviceId = null, effect, permissions, startsAt, expiresAt } = ctx.body;
    if (!userId) throw badRequest('userId is required');
    if (!effect || !['allow', 'deny'].includes(effect)) throw badRequest('effect must be allow or deny');
    if (!Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('permissions must be a non-empty array');
    }

    // D9: no self-grants.
    if (userId === ctx.userId) {
      throw forbidden('you cannot grant to yourself', 'self_grant');
    }

    // Target user must be an active member of this org.
    const targetMem = db.prepare(
      `SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(ctx.orgId, userId);
    if (!targetMem) throw notFound('target user is not an active member of this org');

    // Device must belong to this org if specified.
    if (deviceId) {
      const dev = db.prepare(
        `SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
      ).get(deviceId, ctx.orgId);
      if (!dev) throw notFound('device not found in this org');
    }

    // Validate: every permission pattern must exist in permission_patterns.
    // The DB FK will catch it at INSERT too, but we surface a friendlier error first.
    const validPatterns = new Set(
      db.prepare('SELECT pattern FROM permission_patterns').all().map((r) => r.pattern)
    );
    for (const p of permissions) {
      if (!validPatterns.has(p)) {
        throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
      }
    }

    // No privilege laundering: caller must hold every permission being granted
    // at the scope of the grant.
    assertMayGrant(db, ctx, permissions, deviceId ?? null);

    const startsAtNorm  = normalizeTs(startsAt,  'startsAt');
    const expiresAtNorm = normalizeTs(expiresAt, 'expiresAt');

    const grantId = newId('grt');
    db.prepare(
      `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(grantId, ctx.orgId, userId, deviceId ?? null, effect, startsAtNorm, expiresAtNorm, ctx.userId);

    for (const p of permissions) {
      db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)').run(grantId, p);
    }

    // Bump perm_version so the grantee's next request gets the new permissions.
    bumpPermVersion(db, { orgId: ctx.orgId, userId });

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'grant.create',
      targetType: 'grant',
      targetId:   grantId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 201, { id: grantId, userId, deviceId, effect, permissions });
  });

  // -------------------------------------------------------------------------
  // DELETE /v1/orgs/:orgId/grants/:grantId  — revoke a grant
  // -------------------------------------------------------------------------
  router.delete('/v1/orgs/:orgId/grants/:grantId', async (ctx, params, res) => {
    assertCan(db, ctx, 'grant:revoke');

    const grant = db.prepare(
      `SELECT id, user_id, revoked_at FROM grants WHERE id = ? AND org_id = ?`
    ).get(params.grantId, ctx.orgId);
    if (!grant) throw notFound('grant not found');
    if (grant.revoked_at) throw conflict('grant is already revoked', 'CONFLICT');

    db.prepare(`UPDATE grants SET revoked_at = ? WHERE id = ?`)
      .run(nowIso(), grant.id);

    // Bump perm_version for the grantee.
    bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'grant.revoke',
      targetType: 'grant',
      targetId:   grant.id,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 200, { id: grant.id, revokedAt: nowIso() });
  });
}
