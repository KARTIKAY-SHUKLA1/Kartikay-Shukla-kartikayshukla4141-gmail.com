// Auth routes: login, refresh, org-switch (token).
// These are the only routes on PUBLIC_ROUTES in server/index.js (except invites).

import { send, badRequest, unauthenticated, notFound } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import {
  verifyPassword,
  hashPassword,
  issueAccessToken,
  newRefreshToken,
  hashRefreshToken,
  verifyAccessToken,
  assertFresh,
} from '../auth.js';
import { authenticate } from '../context.js';

export function registerAuthRoutes(router, { db, secret }) {
  // -------------------------------------------------------------------------
  // POST /v1/auth/login
  // Public. Returns access token + orgs list. Picks the highest-rank org by
  // default (or the one requested). Issues a refresh token in an HttpOnly cookie.
  // -------------------------------------------------------------------------
  router.post('/v1/auth/login', async (ctx, params, res) => {
    const { email, password, orgId } = ctx.body;
    if (!email || !password) throw badRequest('email and password are required');

    // User lookup — same error for wrong email and wrong password (no enumeration).
    const user = db.prepare(
      `SELECT id, email, password_hash FROM users WHERE email = ? COLLATE NOCASE`
    ).get(String(email).toLowerCase());

    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid credentials');
    }

    // All active memberships for this user.
    const memberships = db.prepare(
      `SELECT m.org_id, m.role, m.perm_version, o.name, o.theme
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(user.id);

    if (!memberships.length) throw unauthenticated('no active membership found');

    // Pick the target org: requested orgId, or the one with the highest rank.
    let target;
    if (orgId) {
      target = memberships.find((m) => m.org_id === orgId);
      if (!target) throw notFound('org not found or not a member');
    } else {
      // Default to the org where the user has the highest-rank role.
      const ranks = db.prepare('SELECT key, rank FROM roles').all();
      const rankMap = Object.fromEntries(ranks.map((r) => [r.key, r.rank]));
      target = memberships.slice().sort((a, b) => (rankMap[b.role] ?? 0) - (rankMap[a.role] ?? 0))[0];
    }

    const accessToken = issueAccessToken(
      { userId: user.id, orgId: target.org_id, role: target.role, permVersion: target.perm_version },
      secret
    );

    // Issue a rotating refresh token.
    const raw = newRefreshToken();
    const familyId = newId('fam');
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      newId('rt'),
      user.id,
      hashRefreshToken(raw),
      familyId,
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    );

    // HttpOnly refresh cookie — must be set BEFORE send() which calls res.end().
    res.setHeader('set-cookie', `rt=${raw}; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh`);
    send(res, 200, {
      token: accessToken,
      role: target.role,
      orgs: memberships.map((m) => ({ id: m.org_id, name: m.name, theme: m.theme })),
    });
  });

  // -------------------------------------------------------------------------
  // POST /v1/auth/refresh
  // Public. Rotates the refresh token and issues a new access token.
  // Reuse of an old (rotated) token kills the entire family (D12).
  // -------------------------------------------------------------------------
  router.post('/v1/auth/refresh', async (ctx, params, res) => {
    // The refresh token comes from the HttpOnly cookie OR from the body (for
    // check-api.js which cannot set cookies directly in some environments).
    const cookieHeader = ctx.req.headers['cookie'] ?? '';
    const fromCookie = cookieHeader.match(/(?:^|;\s*)rt=([^;]+)/)?.[1];
    const raw = fromCookie || ctx.body?.refreshToken;
    if (!raw) throw unauthenticated('missing refresh token');

    const hash = hashRefreshToken(raw);
    const stored = db.prepare(
      `SELECT id, user_id, family_id, revoked_at, expires_at
         FROM refresh_tokens WHERE token_hash = ?`
    ).get(hash);

    if (!stored) throw unauthenticated('invalid refresh token');

    // If the token has been revoked (family reuse attack), kill the whole family.
    if (stored.revoked_at || stored.expires_at < nowIso()) {
      db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ?`)
        .run(nowIso(), stored.family_id);
      throw unauthenticated('refresh token reused or expired');
    }

    // Revoke the used token and issue a new one (rotation).
    db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`)
      .run(nowIso(), stored.id);

    const newRaw = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      newId('rt'),
      stored.user_id,
      hashRefreshToken(newRaw),
      stored.family_id,
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    );

    // Re-issue access token in the user's current highest-rank org.
    const memberships = db.prepare(
      `SELECT m.org_id, m.role, m.perm_version
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(stored.user_id);
    if (!memberships.length) throw unauthenticated('no active membership');

    const ranks = db.prepare('SELECT key, rank FROM roles').all();
    const rankMap = Object.fromEntries(ranks.map((r) => [r.key, r.rank]));
    const target = memberships.slice().sort((a, b) => (rankMap[b.role] ?? 0) - (rankMap[a.role] ?? 0))[0];

    const accessToken = issueAccessToken(
      { userId: stored.user_id, orgId: target.org_id, role: target.role, permVersion: target.perm_version },
      secret
    );

    res.setHeader('set-cookie', `rt=${newRaw}; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh`);
    send(res, 200, { token: accessToken });
  });

  // -------------------------------------------------------------------------
  // POST /v1/auth/token  (authenticated)
  // Org-switch: exchange current token for a token scoped to a different org
  // that the same user also belongs to.
  // -------------------------------------------------------------------------
  router.post('/v1/auth/token', async (ctx, params, res) => {
    // Manually call authenticate (this route is NOT on PUBLIC_ROUTES but also
    // doesn't enforce the orgId isolation — user can switch to ANY org they belong to).
    const authHeader = ctx.req.headers['authorization'] ?? '';
    const [, token] = authHeader.split(' ');
    const claims = verifyAccessToken(token, secret);
    const { sub: userId } = claims;

    const { orgId: targetOrgId } = ctx.body;
    if (!targetOrgId) throw badRequest('orgId is required');

    const membership = db.prepare(
      `SELECT m.role, m.perm_version FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.org_id = ? AND m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).get(targetOrgId, userId);
    if (!membership) throw notFound('org not found or not a member');

    const accessToken = issueAccessToken(
      { userId, orgId: targetOrgId, role: membership.role, permVersion: membership.perm_version },
      secret
    );

    send(res, 200, { token: accessToken, role: membership.role });
  });
}
