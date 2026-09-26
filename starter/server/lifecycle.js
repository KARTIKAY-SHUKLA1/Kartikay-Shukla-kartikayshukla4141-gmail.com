// Shared domain rules: role ranks, last-owner protection, ending sessions,
// session expiry, and the authority snapshot written at session start.
//
// Rules centralised here so "what ends a session" has exactly one implementation.
// Sources: PERMISSIONS.md §7.2 and D8.
//
// Two invariants worth noting:
//   - roles.rank is MODIFICATION AUTHORITY ONLY. It answers "can A demote B",
//     never "can A do X". operator and auditor are unordered by permission.
//   - Permission changes do NOT end sessions in flight (grandfathering).
//     Suspension, membership removal, and device transfer DO (tenancy events).

import { forbidden, notFound, lastOwner } from './http.js';

// ---------------------------------------------------------------------------
// roleRanks(): return a Map<roleKey, rank> built from the live roles table.
// Used by assertCanModify so it never hardcodes the rank matrix.
// ---------------------------------------------------------------------------
export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  return new Map(rows.map((r) => [r.key, r.rank]));
}

// ---------------------------------------------------------------------------
// assertRoleExists(): throw 400 if the role key is not in the roles table.
// ---------------------------------------------------------------------------
export function assertRoleExists(db, role) {
  const exists = db.prepare('SELECT 1 FROM roles WHERE key = ?').get(role);
  if (!exists) throw Object.assign(new Error(`unknown role: ${role}`), { status: 400, code: 'VALIDATION', reason: null });
}

// ---------------------------------------------------------------------------
// assertCanModify(): enforce D8 — modification authority via rank.
// A caller may only demote/remove a target whose rank is strictly below their own.
// An equal-rank target is protected (you cannot demote a peer owner, only a lower role).
// ---------------------------------------------------------------------------
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  const callerRank = ranks.get(callerRole) ?? 0;
  const targetRank = ranks.get(targetRole) ?? 0;
  if (callerRank < targetRank) {
    throw forbidden(
      `your role (${callerRole}) does not outrank the target role (${targetRole})`,
      'insufficient_rank'
    );
  }
}

// ---------------------------------------------------------------------------
// assertNotLastOwner(): enforce D17 — an org must always have at least one owner.
// Throws LAST_OWNER (409) if removing/demoting this user would leave zero owners.
// userId is the user being removed or demoted.
// ---------------------------------------------------------------------------
export function assertNotLastOwner(db, orgId, userId) {
  // Count active owners in this org excluding the user in question.
  const { n } = db.prepare(
    `SELECT COUNT(*) AS n FROM memberships
      WHERE org_id = ? AND role = 'owner' AND status = 'active' AND user_id != ?`
  ).get(orgId, userId);

  if (n === 0) throw lastOwner();
}

// ---------------------------------------------------------------------------
// endActiveSessions(): end all active exclusive (control/terminal) sessions that
// match the given criteria. Tenancy events (suspend, remove, device transfer)
// use this; permission changes do NOT (grandfathering).
//
// Options:
//   orgId          — required
//   userId         — end sessions for this user (suspend / remove)
//   deviceId       — end sessions on this device (device transfer)
//   reason         — one of the valid end_reason values
//   exceptSessionId — skip this session (used when superseding)
// ---------------------------------------------------------------------------
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const nowIso = new Date().toISOString();

  let query = `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
                WHERE org_id = ? AND state = 'active'`;
  const params = [reason, nowIso, orgId];

  if (userId) {
    query += ' AND user_id = ?';
    params.push(userId);
  }
  if (deviceId) {
    query += ' AND device_id = ?';
    params.push(deviceId);
  }
  if (exceptSessionId) {
    query += ' AND id != ?';
    params.push(exceptSessionId);
  }

  db.prepare(query).run(...params);
}

// ---------------------------------------------------------------------------
// snapshotAuthority(): build the authorized_by JSON stored in sessions.id.
// This snapshot is the authority for the life of the session (PERMISSIONS.md §7.1).
// It captures the role and the grant IDs that contributed to the session permission,
// so the audit log can explain why a session was allowed.
// ---------------------------------------------------------------------------
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db.prepare(
    `SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).get(orgId, userId);

  const role = membership?.role ?? null;

  // Collect the IDs of grants that are currently active and relevant.
  const nowIso = new Date().toISOString();
  const grantIds = db.prepare(
    `SELECT g.id FROM grants g
     WHERE g.user_id = ?
       AND g.org_id  = ?
       AND g.revoked_at IS NULL
       AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
       AND (g.expires_at IS NULL OR g.expires_at  > ?)
       AND (g.device_id IS NULL OR g.device_id = ?)`
  ).all(userId, orgId, nowIso, nowIso, deviceId).map((r) => r.id);

  return JSON.stringify({
    role,
    grantIds,
    snapshotAt: nowIso,
  });
}

// ---------------------------------------------------------------------------
// sessionExpiry(): return the ISO timestamp when a new session in this org expires.
// org.max_session_minutes is the upper bound on grandfathering (PERMISSIONS.md §7.3).
// ---------------------------------------------------------------------------
export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  if (!org) throw notFound('org not found');
  const expiresAt = new Date(Date.now() + org.max_session_minutes * 60 * 1000);
  return expiresAt.toISOString();
}
