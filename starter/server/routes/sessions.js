// Sessions routes: start, list, get one.

import { send, badRequest, conflict, notFound, deviceBusy } from '../http.js';
import { newId, nowIso } from '../db.js';
import { assertCanStartSession, MODE_PERMISSION } from '../permissions.js';
import { endActiveSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';

export function registerSessionRoutes(router, { db }) {
  // -------------------------------------------------------------------------
  // POST /v1/orgs/:orgId/sessions  — start a session
  // -------------------------------------------------------------------------
  router.post('/v1/orgs/:orgId/sessions', async (ctx, params, res) => {
    const { deviceId, mode } = ctx.body;
    if (!deviceId) throw badRequest('deviceId is required');
    if (!mode || !MODE_PERMISSION[mode]) throw badRequest('mode must be view, control, or terminal');

    // Device must belong to this org.
    const device = db.prepare(
      `SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`
    ).get(deviceId, ctx.orgId);
    if (!device) throw notFound('device not found');

    // Compound permission check (audited on denial).
    auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId }, () => {
      assertCanStartSession(db, ctx, mode, deviceId);
    });

    // D10: one exclusive session per device (enforced by DB partial unique index,
    // but we surface the conflict as DEVICE_BUSY before the DB raises it).
    if (mode !== 'view') {
      const existing = db.prepare(
        `SELECT id FROM sessions
          WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')`
      ).get(deviceId);
      if (existing) throw deviceBusy();
    }

    const sessionId    = newId('ses');
    const expiresAt    = sessionExpiry(db, ctx.orgId);
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

    db.prepare(
      `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
    ).run(sessionId, ctx.orgId, ctx.userId, deviceId, mode, authorizedBy, expiresAt);

    audit(db, {
      orgId:      ctx.orgId,
      actorId:    ctx.userId,
      action:     'session.start',
      targetType: 'device',
      targetId:   deviceId,
      result:     'allow',
      requestId:  ctx.requestId,
    });

    send(res, 201, { id: sessionId, mode, state: 'active', expiresAt });
  });

  // -------------------------------------------------------------------------
  // GET /v1/orgs/:orgId/sessions  — list sessions in this org
  // -------------------------------------------------------------------------
  router.get('/v1/orgs/:orgId/sessions', async (ctx, params, res) => {
    const sessions = db.prepare(
      `SELECT id, device_id, user_id, mode, state, end_reason, started_at, expires_at, ended_at
         FROM sessions
        WHERE org_id = ?
        ORDER BY started_at DESC`
    ).all(ctx.orgId);

    send(res, 200, { sessions });
  });

  // -------------------------------------------------------------------------
  // GET /v1/sessions/:sessionId  — get a single session (cross-org aware)
  // The token's orgId gates visibility: you only see sessions in your org.
  // -------------------------------------------------------------------------
  router.get('/v1/sessions/:sessionId', async (ctx, params, res) => {
    const session = db.prepare(
      `SELECT id, org_id, device_id, user_id, mode, state, end_reason,
              started_at, expires_at, ended_at, authorized_by
         FROM sessions WHERE id = ?`
    ).get(params.sessionId);

    // Invisible if not found or belongs to a different org (structural isolation).
    if (!session || session.org_id !== ctx.orgId) throw notFound('session not found');

    send(res, 200, session);
  });
}
