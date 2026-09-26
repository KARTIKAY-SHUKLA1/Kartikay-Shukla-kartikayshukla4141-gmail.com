// Org routes: create org, device list (with resolved permissions), members,
// role changes, suspend/reinstate, leave, audit log.

import { send, badRequest, forbidden, notFound, conflict, selfRoleChange } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan, resolveDevices } from '../permissions.js';
import { assertCanModify, assertNotLastOwner, endActiveSessions } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';

export function registerOrgRoutes(router, { db }) {
  // -------------------------------------------------------------------------
  // POST /v1/orgs  — create a new org, making the caller its sole owner
  // -------------------------------------------------------------------------
  router.post('/v1/orgs', async (ctx, params, res) => {
    const { name } = ctx.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      throw badRequest('name is required');
    }

    const orgId = newId('org');
    const memId = newId('mem');
    const theme = 'cobalt'; // default theme; org:update can change it later

    db.prepare(
      `INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)`
    ).run(orgId, name.trim(), theme);

    db.prepare(
      `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at)
       VALUES (?, ?, ?, 'owner', 'active', ?)`
    ).run(memId, orgId, ctx.userId, nowIso());

    audit(db, {
      orgId,
      actorId:    ctx.userId,
      action:     'org.create',
      targetType: 'org',
      targetId:   orgId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 201, { id: orgId, name: name.trim(), theme, role: 'owner' });
  });

  // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/devices
  // Returns device rows with resolved permissions per device (batched).
  // device:list gates the endpoint; device:view gates row inclusion.
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/devices', async (ctx, params, res) => {
    assertCan(db, ctx, 'device:list');

    const devices = db.prepare(
      `SELECT id, name, kind, online FROM devices
        WHERE org_id = ? AND deleted_at IS NULL
        ORDER BY name`
    ).all(ctx.orgId);

    const deviceIds = devices.map((d) => d.id);
    const { byDevice } = resolveDevices(db, {
      userId:    ctx.userId,
      orgId:     ctx.orgId,
      deviceIds,
    });

    // Filter to only rows where device:view is allowed.
    const visible = devices
      .filter((d) => byDevice[d.id]?.['device:view']?.effect === 'allow')
      .map((d) => ({
        id:          d.id,
        name:        d.name,
        kind:        d.kind,
        online:      Boolean(d.online),
        permissions: byDevice[d.id],
      }));

    send(res, 200, { devices: visible });
  });

  // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/members
  // Requires user:read
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/members', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');

    const members = db.prepare(
      `SELECT m.id, m.user_id, m.role, m.status, m.joined_at, u.email, u.name
         FROM memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status IN ('active','suspended')
        ORDER BY u.name`
    ).all(ctx.orgId);

    send(res, 200, {
      members: members.map((m) => ({
        id:        m.id,
        userId:    m.user_id,
        email:     m.email,
        name:      m.name,
        role:      m.role,
        status:    m.status,
        joinedAt:  m.joined_at,
      })),
    });
  });

  // -------------------------------------------------------------------------
  // PATCH /v1/orgs/:orgId/members/:userId  — change role
  // D8: caller rank must exceed target rank. No self-role-change.
  // -------------------------------------------------------------------------
  router.patch('/v1/orgs/:orgId/members/:userId', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:role:update');

    const targetUserId = params.userId;
    const { role: newRole } = ctx.body;
    if (!newRole) throw badRequest('role is required');

    if (targetUserId === ctx.userId) throw selfRoleChange();

    const targetMem = db.prepare(
      `SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(ctx.orgId, targetUserId);
    if (!targetMem) throw notFound('member not found');

    // Caller must outrank BOTH the current role and the new role.
    assertCanModify(db, ctx.role, targetMem.role);
    assertCanModify(db, ctx.role, newRole);

    // Last-owner guard: can't demote the last owner away from owner.
    if (targetMem.role === 'owner' && newRole !== 'owner') {
      assertNotLastOwner(db, ctx.orgId, targetUserId);
    }

    db.prepare(
      `UPDATE memberships SET role = ?, perm_version = perm_version + 1
        WHERE org_id = ? AND user_id = ?`
    ).run(newRole, ctx.orgId, targetUserId);

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'member.role.update',
      targetType: 'user',
      targetId:   targetUserId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 200, { userId: targetUserId, role: newRole });
  });

  // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/members/:userId/suspend
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/members/:userId/suspend', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;
    const targetMem = db.prepare(
      `SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(ctx.orgId, targetUserId);
    if (!targetMem) throw notFound('member not found');

    assertCanModify(db, ctx.role, targetMem.role);

    db.prepare(
      `UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1
        WHERE org_id = ? AND user_id = ?`
    ).run(ctx.orgId, targetUserId);

    // Tenancy event: end active sessions.
    endActiveSessions(db, { orgId: ctx.orgId, userId: targetUserId, reason: 'user_suspended' });

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'member.suspend',
      targetType: 'user',
      targetId:   targetUserId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 200, { userId: targetUserId, status: 'suspended' });
  });

  // -------------------------------------------------------------------------
  // DELETE /v1/orgs/:orgId/members/:userId/suspend  — reinstate
  // -------------------------------------------------------------------------
  router.delete('/v1/orgs/:orgId/members/:userId/suspend', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');

    const targetUserId = params.userId;
    const targetMem = db.prepare(
      `SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'suspended'`
    ).get(ctx.orgId, targetUserId);
    if (!targetMem) throw notFound('member not found or not suspended');

    assertCanModify(db, ctx.role, targetMem.role);

    db.prepare(
      `UPDATE memberships SET status = 'active', perm_version = perm_version + 1
        WHERE org_id = ? AND user_id = ?`
    ).run(ctx.orgId, targetUserId);

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'member.reinstate',
      targetType: 'user',
      targetId:   targetUserId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 200, { userId: targetUserId, status: 'active' });
  });

  // -------------------------------------------------------------------------
  // DELETE /v1/orgs/:orgId/members/me  — leave org
  // -------------------------------------------------------------------------
  router.delete('/v1/orgs/:orgId/members/me', async (ctx, params, res) => {
    assertNotLastOwner(db, ctx.orgId, ctx.userId);

    db.prepare(
      `UPDATE memberships SET status = 'removed', perm_version = perm_version + 1
        WHERE org_id = ? AND user_id = ?`
    ).run(ctx.orgId, ctx.userId);

    endActiveSessions(db, { orgId: ctx.orgId, userId: ctx.userId, reason: 'membership_removed' });

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'member.leave',
      targetType: 'user',
      targetId:   ctx.userId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 200, {});
  });

  // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/audit
  // Requires audit:read. Supports limit (1–100) and offset query params.
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/audit', async (ctx, params, res) => {
    assertCan(db, ctx, 'audit:read');

    const limitRaw  = ctx.query.get('limit')  ?? '50';
    const offsetRaw = ctx.query.get('offset') ?? '0';
    const limit  = Number(limitRaw);
    const offset = Number(offsetRaw);

    if (!Number.isInteger(limit)  || limit  < 1 || limit  > 9999) throw badRequest('limit must be between 1 and 9999');
    if (!Number.isInteger(offset) || offset < 0) throw badRequest('offset must be >= 0');

    const events = db.prepare(
      `SELECT id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
         FROM audit_events
        WHERE org_id = ?
        ORDER BY at DESC
        LIMIT ? OFFSET ?`
    ).all(ctx.orgId, limit, offset);

    send(res, 200, { events });
  });
}
