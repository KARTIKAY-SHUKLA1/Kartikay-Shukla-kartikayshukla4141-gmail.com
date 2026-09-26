// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers so this module only ever
// INSERTs — the schema prevents anything else.
//
// Two invariants from PERMISSIONS.md §8 / BRIEF.md §4:
//   - DENIED attempts are recorded, not just successes.
//   - A single action produces a single row, written inside the same transaction
//     as the change it describes.

import { newId } from './db.js';
import { forbidden } from './http.js';

// ---------------------------------------------------------------------------
// audit(): write one audit event row.
// All fields except org_id and result are optional (nullable in schema).
// ---------------------------------------------------------------------------
export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode, requestId }) {
  db.prepare(
    `INSERT INTO audit_events
       (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    newId('aud'),
    orgId,
    actorId  ?? null,
    action,
    targetType ?? null,
    targetId   ?? null,
    result,
    reasonCode ?? null,
    requestId  ?? null,
  );
}

// ---------------------------------------------------------------------------
// auditDenials(): run fn(); if it throws a 403 FORBIDDEN, record the denial
// in the audit log and rethrow. All other errors propagate unchanged.
//
// Usage:
//   auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId }, () => {
//     assertCanStartSession(db, ctx, mode, deviceId);
//   });
// ---------------------------------------------------------------------------
export function auditDenials(db, ctx, { action, targetType, targetId }, fn) {
  try {
    return fn();
  } catch (err) {
    if (err?.status === 403) {
      audit(db, {
        orgId:      ctx.orgId,
        actorId:    ctx.userId,
        action,
        targetType: targetType ?? null,
        targetId:   targetId   ?? null,
        result:     'deny',
        reasonCode: err.reason ?? null,
        requestId:  ctx.requestId ?? null,
      });
    }
    throw err;
  }
}
