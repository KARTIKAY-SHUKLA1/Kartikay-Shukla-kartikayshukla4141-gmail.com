// Invite routes: create, public peek, accept.
// Invite tokens are returned in the response (not emailed) but ONLY stored hashed.
// One live invite per email enforced by DB partial unique index.

import { send, badRequest, notFound, conflict, gone } from '../http.js';
import { newId, nowIso } from '../db.js';
import { assertCan } from '../permissions.js';
import { newInviteToken, hashInviteToken, hashPassword } from '../auth.js';
import { audit } from '../audit.js';

const INVITE_TTL_HOURS = 72;

export function registerInviteRoutes(router, { db }) {
  // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/invites  — create an invite (authenticated)
  // Requires user:invite
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/invites', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');

    const { email, role } = ctx.body;
    if (!email || typeof email !== 'string') throw badRequest('email is required');
    if (!role) throw badRequest('role is required');

    const normalEmail = email.trim().toLowerCase();

    // Role must exist.
    const validRole = db.prepare('SELECT 1 FROM roles WHERE key = ?').get(role);
    if (!validRole) throw badRequest(`unknown role: ${role}`);

    // User is already a member — no invite needed.
    const existing = db.prepare(
      `SELECT 1 FROM memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? COLLATE NOCASE AND m.status IN ('active','suspended')`
    ).get(ctx.orgId, normalEmail);
    if (existing) throw conflict('user is already a member of this org', 'CONFLICT');

    const rawToken  = newInviteToken();
    const tokenHash = hashInviteToken(rawToken);
    const expiresAt = new Date(Date.now() + INVITE_TTL_HOURS * 60 * 60 * 1000).toISOString();
    const inviteId  = newId('inv');

    db.prepare(
      `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(inviteId, ctx.orgId, normalEmail, role, tokenHash, ctx.userId, expiresAt);

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'invite.create',
      targetType: 'invite',
      targetId:   inviteId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    // Return the raw token ONCE. After this it is only stored hashed.
    send(res, 201, { id: inviteId, email: normalEmail, role, expiresAt, inviteToken: rawToken });
  });

  // -------------------------------------------------------------------------
  // GET /v1/invites/:token  — public peek (no auth required)
  // Must NOT leak org id, devices, or any confidential data — only org name + role.
  // -------------------------------------------------------------------------
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const hash   = hashInviteToken(params.token);
    const invite = db.prepare(
      `SELECT i.id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at,
              o.name AS org_name
         FROM invites i
         JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = ?`
    ).get(hash);

    if (!invite || invite.accepted_at || invite.revoked_at || invite.expires_at < nowIso()) {
      throw notFound('invite not found or no longer valid');
    }

    // Deliberately minimal: no org id, no device data.
    send(res, 200, {
      email:   invite.email,
      role:    invite.role,
      orgName: invite.org_name,
    });
  });

  // -------------------------------------------------------------------------
  // POST /v1/invites/:token/accept  — public (no auth required)
  // Creates the user if needed, creates the membership, marks invite accepted.
  // -------------------------------------------------------------------------
  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const { name, password } = ctx.body;
    if (!name || !password) throw badRequest('name and password are required');
    if (password.length < 8) throw badRequest('password must be at least 8 characters');

    const hash   = hashInviteToken(params.token);
    const invite = db.prepare(
      `SELECT i.id, i.org_id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at
         FROM invites i WHERE i.token_hash = ?`
    ).get(hash);

    if (!invite) throw notFound('invite not found');
    if (invite.accepted_at || invite.revoked_at) {
      throw conflict('invite already used', 'CONFLICT');
    }
    if (invite.expires_at < nowIso()) throw gone('invite has expired');

    // Find or create the user.
    let user = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(invite.email);
    if (!user) {
      const userId = newId('usr');
      db.prepare(
        `INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)`
      ).run(userId, invite.email.toLowerCase(), name.trim(), hashPassword(password));
      user = { id: userId };
    }

    // Create the membership (or reactivate if previously removed).
    const memExisting = db.prepare(
      `SELECT id, status FROM memberships WHERE org_id = ? AND user_id = ?`
    ).get(invite.org_id, user.id);

    if (memExisting) {
      db.prepare(
        `UPDATE memberships SET status = 'active', role = ?, joined_at = ?, perm_version = perm_version + 1
          WHERE id = ?`
      ).run(invite.role, nowIso(), memExisting.id);
    } else {
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
         VALUES (?, ?, ?, ?, 'active', ?, ?)`
      ).run(newId('mem'), invite.org_id, user.id, invite.role, null, nowIso());
    }

    // Mark the invite accepted (DB triggers prevent double-acceptance via the unique index).
    db.prepare(
      `UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?`
    ).run(nowIso(), user.id, invite.id);

    send(res, 200, { email: invite.email, role: invite.role });
  });
}
