// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// Rule summary (from check-permissions.js vectors):
//
//   1. No membership (or org doesn't exist): all deny, reason=not_a_member
//   2. membership.status = 'suspended': all deny, reason=suspended
//   3. Role baseline (role_permissions table) sets initial allow/deny per permission.
//      A permission absent from the baseline is implicitly denied.
//   4. Active grants (non-revoked, time-window current) are applied as deltas:
//      - wildcards ('device:*', '*') expand against the live permissions table
//      - DENY ALWAYS WINS at any scope. An org-wide deny cannot be carved out by a
//        device-scoped allow (D1, vector 7).
//      - org-wide grants (device_id IS NULL) apply to every device
//      - device-scoped grants apply only to the named device
//   5. Reason codes: 'not_a_member', 'suspended', 'explicit_deny', 'implicit'
//   6. source: 'role:<role>' for baseline, 'grant:<grantId>' for grant-driven result
//
// NOTE: Never hardcode the permission catalogue. Read `permissions` from the DB.
// The personalised database adds at least one extra role + permission not in the prose.

import { forbidden } from './http.js';

export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal',
};

// ---------------------------------------------------------------------------
// Expand permission patterns against the live catalogue.
// 'device:*' → all permissions where resource = 'device'
// '*'        → every permission
// A concrete key → just that key (validated by DB FK on insert)
// ---------------------------------------------------------------------------
function expandPatterns(db, patterns) {
  const all = db.prepare('SELECT key, resource FROM permissions').all();
  const result = new Set();
  for (const pat of patterns) {
    if (pat === '*') {
      all.forEach((p) => result.add(p.key));
    } else if (pat.endsWith(':*')) {
      const resource = pat.slice(0, -2);
      all.filter((p) => p.resource === resource).forEach((p) => result.add(p.key));
    } else {
      if (all.some((p) => p.key === pat)) result.add(pat);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Fetch all active (non-revoked, time-window current) grants for a user+org.
// Returns [{ id, device_id, effect, permissions: Set<string> }]
// ---------------------------------------------------------------------------
function activeGrants(db, { userId, orgId, now }) {
  const nowIso = now.toISOString();

  const grants = db.prepare(
    `SELECT g.id, g.device_id, g.effect
       FROM grants g
      WHERE g.user_id = ?
        AND g.org_id  = ?
        AND g.revoked_at IS NULL
        AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
        AND (g.expires_at IS NULL OR g.expires_at  > ?)`
  ).all(userId, orgId, nowIso, nowIso);

  return grants.map((g) => {
    const patterns = db
      .prepare('SELECT permission FROM grant_permissions WHERE grant_id = ?')
      .all(g.id)
      .map((r) => r.permission);

    return {
      id: g.id,
      device_id: g.device_id,
      effect: g.effect,
      permissions: expandPatterns(db, patterns),
    };
  });
}

// ---------------------------------------------------------------------------
// resolve(): resolve one user's full permission set in one org.
//
//   deviceId === null  →  org-level view (org-wide grants only)
//   deviceId !== null  →  per-device check (org-wide + device-scoped grants)
//
// Returns:
//   {
//     role: string | null,
//     permissions: {
//       [permKey]: { effect: 'allow'|'deny', reason: string, source: string }
//     }
//   }
// ---------------------------------------------------------------------------
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const allPerms = db.prepare('SELECT key FROM permissions').all().map((r) => r.key);

  // --- No-membership fast path --------------------------------------------
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
  ).get(orgId, userId);

  if (!membership) {
    const deny = Object.fromEntries(
      allPerms.map((k) => [k, { effect: 'deny', reason: 'not_a_member', source: null }])
    );
    return { role: null, permissions: deny };
  }

  // --- Suspended membership -----------------------------------------------
  if (membership.status === 'suspended') {
    const deny = Object.fromEntries(
      allPerms.map((k) => [
        k,
        { effect: 'deny', reason: 'suspended', source: `role:${membership.role}` },
      ])
    );
    return { role: membership.role, permissions: deny };
  }

  const role = membership.role;

  // --- Role baseline -------------------------------------------------------
  const baseline = new Set(
    db
      .prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(role)
      .map((r) => r.permission)
  );

  const result = {};
  for (const key of allPerms) {
    result[key] = baseline.has(key)
      ? { effect: 'allow', reason: 'implicit', source: `role:${role}` }
      : { effect: 'deny',  reason: 'implicit', source: `role:${role}` };
  }

  // --- Grant deltas --------------------------------------------------------
  // Collect grants relevant to this call: org-wide + device-scoped (if deviceId given).
  const grants = activeGrants(db, { userId, orgId, now });
  const relevant = grants.filter(
    (g) => g.device_id === null || g.device_id === deviceId
  );

  // DENY ALWAYS WINS: collect all explicit denies across every relevant scope first.
  // An org-wide deny cannot be carved out by any device-scoped allow (vector 7 test).
  const explicitDeny = new Set();
  for (const g of relevant) {
    if (g.effect === 'deny') {
      g.permissions.forEach((p) => explicitDeny.add(p));
    }
  }

  // Collect allows, preferring device-scoped provenance for the source field.
  // Sort: device-scoped first so their grant id wins over org-wide for source.
  const allowSource = {}; // permKey → grantId
  const allowsDeviceFirst = [
    ...relevant.filter((g) => g.device_id !== null && g.effect === 'allow'),
    ...relevant.filter((g) => g.device_id === null  && g.effect === 'allow'),
  ];
  for (const g of allowsDeviceFirst) {
    for (const p of g.permissions) {
      if (!allowSource[p]) allowSource[p] = g.id;
    }
  }

  // Apply explicit denies (highest precedence — overwrites any baseline allow).
  for (const p of explicitDeny) {
    if (result[p]) {
      result[p] = { effect: 'deny', reason: 'explicit_deny', source: 'grant:explicit_deny' };
    }
  }

  // Apply allows only where no deny exists.
  for (const [p, grantId] of Object.entries(allowSource)) {
    if (result[p] && !explicitDeny.has(p) && result[p].effect !== 'allow') {
      result[p] = { effect: 'allow', reason: 'grant', source: `grant:${grantId}` };
    }
  }

  return { role, permissions: result };
}

// ---------------------------------------------------------------------------
// resolveDevices(): batched form for list endpoints.
// Resolves permissions for multiple devices in a single pass so device-list
// routes don't do one full resolution per row.
//
// Returns: { role, byDevice: { [deviceId]: permissions } }
// ---------------------------------------------------------------------------
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const allPerms = db.prepare('SELECT key FROM permissions').all().map((r) => r.key);

  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
  ).get(orgId, userId);

  if (!membership) {
    const deny = Object.fromEntries(
      allPerms.map((k) => [k, { effect: 'deny', reason: 'not_a_member', source: null }])
    );
    return { role: null, byDevice: Object.fromEntries(deviceIds.map((id) => [id, deny])) };
  }

  if (membership.status === 'suspended') {
    const deny = Object.fromEntries(
      allPerms.map((k) => [
        k,
        { effect: 'deny', reason: 'suspended', source: `role:${membership.role}` },
      ])
    );
    return {
      role: membership.role,
      byDevice: Object.fromEntries(deviceIds.map((id) => [id, deny])),
    };
  }

  const role = membership.role;
  const baseline = new Set(
    db
      .prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(role)
      .map((r) => r.permission)
  );

  // Fetch all active grants once (org-wide + all device-scoped for this user).
  const grants = activeGrants(db, { userId, orgId, now });
  const orgWide = grants.filter((g) => g.device_id === null);

  // Build the org-level base (baseline + org-wide grants) once.
  const orgBase = {};
  for (const key of allPerms) {
    orgBase[key] = baseline.has(key)
      ? { effect: 'allow', reason: 'implicit', source: `role:${role}` }
      : { effect: 'deny',  reason: 'implicit', source: `role:${role}` };
  }

  // Org-wide denies.
  const orgDeny = new Set();
  for (const g of orgWide) {
    if (g.effect === 'deny') g.permissions.forEach((p) => orgDeny.add(p));
  }
  for (const p of orgDeny) {
    if (orgBase[p]) {
      orgBase[p] = { effect: 'deny', reason: 'explicit_deny', source: 'grant:explicit_deny' };
    }
  }

  // Org-wide allows (only where no org-wide deny).
  const orgAllowSource = {};
  for (const g of orgWide.filter((g) => g.effect === 'allow')) {
    for (const p of g.permissions) {
      if (!orgAllowSource[p]) orgAllowSource[p] = g.id;
    }
  }
  for (const [p, grantId] of Object.entries(orgAllowSource)) {
    if (orgBase[p] && !orgDeny.has(p) && orgBase[p].effect !== 'allow') {
      orgBase[p] = { effect: 'allow', reason: 'grant', source: `grant:${grantId}` };
    }
  }

  // Per-device: start from orgBase, overlay device-scoped grants.
  const byDevice = {};
  for (const deviceId of deviceIds) {
    const devGrants = grants.filter((g) => g.device_id === deviceId);

    if (devGrants.length === 0) {
      byDevice[deviceId] = { ...orgBase };
      continue;
    }

    const perms = {};
    for (const [k, v] of Object.entries(orgBase)) perms[k] = { ...v };

    // Device-scoped denies.
    const devDeny = new Set();
    for (const g of devGrants) {
      if (g.effect === 'deny') g.permissions.forEach((p) => devDeny.add(p));
    }
    for (const p of devDeny) {
      if (perms[p]) {
        perms[p] = { effect: 'deny', reason: 'explicit_deny', source: 'grant:explicit_deny' };
      }
    }

    // Device-scoped allows: only where neither org-wide nor device-scoped deny.
    for (const g of devGrants.filter((g) => g.effect === 'allow')) {
      for (const p of g.permissions) {
        if (perms[p] && !orgDeny.has(p) && !devDeny.has(p) && perms[p].effect !== 'allow') {
          perms[p] = { effect: 'allow', reason: 'grant', source: `grant:${g.id}` };
        }
      }
    }

    byDevice[deviceId] = perms;
  }

  return { role, byDevice };
}

// ---------------------------------------------------------------------------
// can(): returns true if the caller holds the permission, false otherwise.
// ---------------------------------------------------------------------------
export function can(db, ctx, permission, deviceId = null) {
  const { permissions } = resolve(db, {
    userId: ctx.userId,
    orgId:  ctx.orgId,
    deviceId,
  });
  return permissions[permission]?.effect === 'allow';
}

// ---------------------------------------------------------------------------
// assertCan(): throws 403 with the reason code if the caller lacks the permission.
// ---------------------------------------------------------------------------
export function assertCan(db, ctx, permission, deviceId = null) {
  const { permissions } = resolve(db, {
    userId: ctx.userId,
    orgId:  ctx.orgId,
    deviceId,
  });
  const entry = permissions[permission];
  if (!entry || entry.effect !== 'allow') {
    const reason = entry?.reason ?? 'missing_permission';
    throw forbidden(`permission denied: ${permission}`, reason);
  }
}

// ---------------------------------------------------------------------------
// assertMayGrant(): no privilege laundering.
// You may only grant permissions you hold at the scope being granted.
// patterns: the permission patterns the new grant will carry (may include wildcards).
// deviceId: null = org-wide grant, non-null = device-scoped grant.
// ---------------------------------------------------------------------------
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const concrete = expandPatterns(db, patterns);
  for (const perm of concrete) {
    if (!can(db, ctx, perm, deviceId)) {
      throw forbidden(
        `cannot grant permission you do not hold: ${perm}`,
        'missing_permission'
      );
    }
  }
}

// ---------------------------------------------------------------------------
// assertCanStartSession(): compound check — requires BOTH:
//   1. session:start (checked at device scope, since grants can be device-scoped)
//   2. The mode-specific device permission (device:view / device:control / device:terminal)
//
// Both checks use the device-scoped resolution so that a device-scoped grant that
// includes session:start (like the viewer's grant on lab-mac-01) is recognized.
//
// The two failures produce DIFFERENT reason codes:
//   missing_permission        → lacks session:start
//   missing_device_permission → has session:start, lacks the mode permission
// ---------------------------------------------------------------------------
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePerm = MODE_PERMISSION[mode];
  if (!modePerm) throw forbidden(`unknown session mode: ${mode}`, 'missing_permission');

  // Resolve once at device scope — covers both org-wide and device-scoped grants.
  const { permissions: devPerms } = resolve(db, {
    userId: ctx.userId,
    orgId:  ctx.orgId,
    deviceId,
  });

  if (devPerms['session:start']?.effect !== 'allow') {
    const err = forbidden('missing session:start permission', 'missing_permission');
    err.reason = 'missing_permission';
    throw err;
  }

  if (devPerms[modePerm]?.effect !== 'allow') {
    const err = forbidden(`missing ${modePerm}`, 'missing_device_permission');
    err.reason = 'missing_device_permission';
    throw err;
  }
}
