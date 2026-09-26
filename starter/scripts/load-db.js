// Loads db/schema.sql, db/reference.sql, then seed/orgs.json.
// Idempotent: drops and recreates app.db.  Run: npm run db:reset

import { readFileSync, rmSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { openDatabase, newId } from '../server/db.js';
import { hashPassword } from '../server/auth.js';
import { readNonce, buildOverlay, applyOverlay, describeOverlay } from './personalise.js';

const DB_FILE = process.env.DATABASE_FILE ?? 'app.db';
const here = (p) => fileURLToPath(new URL(p, import.meta.url));

for (const suffix of ['', '-wal', '-shm']) {
  if (existsSync(DB_FILE + suffix)) rmSync(DB_FILE + suffix);
}

const db = openDatabase(DB_FILE);
db.exec(readFileSync(here('../db/schema.sql'), 'utf8'));
db.exec(readFileSync(here('../db/reference.sql'), 'utf8'));

const seed = JSON.parse(readFileSync(here('../seed/orgs.json'), 'utf8'));

// Timestamps in the fixture are RELATIVE ('-2h', '+7d', 'now') so the fixture never
// goes stale and seeded grants never silently expire.
function resolveTime(value) {
  if (value === null || value === undefined) return null;
  const m = /^([+-])(\d+)([dhm])$/.exec(value);
  if (!m) return value; // already absolute ISO-8601
  const unit = { d: 864e5, h: 36e5, m: 6e4 }[m[3]];
  return new Date(Date.now() + (m[1] === '-' ? -1 : 1) * Number(m[2]) * unit).toISOString();
}

// The fixture stores the password in plaintext on purpose. Hash it HERE — never copy
// seedPassword into password_hash.
const passwordHash = hashPassword(seed.seedPassword);

const load = db.transaction(() => {
  for (const o of seed.organizations) {
    db.prepare('INSERT INTO organizations (id,name,theme,max_session_minutes) VALUES (?,?,?,?)')
      .run(o.id, o.name, o.theme, o.maxSessionMinutes ?? 60);
  }

  for (const u of seed.users) {
    db.prepare('INSERT INTO users (id,email,name,password_hash) VALUES (?,?,?,?)')
      .run(u.id, u.email.toLowerCase(), u.name, passwordHash);
  }

  for (const m of seed.memberships) {
    db.prepare(
      `INSERT INTO memberships (id,org_id,user_id,role,status,joined_at) VALUES (?,?,?,?,?,?)`
    ).run(newId('mem'), m.orgId, m.userId, m.role, m.status ?? 'active', resolveTime(m.joinedAt));
  }

  for (const d of seed.devices) {
    db.prepare('INSERT INTO devices (id,org_id,name,kind,online) VALUES (?,?,?,?,?)')
      .run(d.id, d.orgId, d.name, d.kind, d.online ? 1 : 0);
  }

  for (const g of seed.grants) {
    db.prepare(
      `INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,expires_at,created_by)
       VALUES (?,?,?,?,?,?,?,?)`
    ).run(g.id, g.orgId, g.userId, g.deviceId ?? null, g.effect,
          resolveTime(g.startsAt), resolveTime(g.expiresAt), g.createdBy);

    for (const p of g.permissions) {
      db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run(g.id, p);
    }
  }

  for (const s of seed.sessions) {
    db.prepare(
      `INSERT INTO sessions (id,org_id,user_id,device_id,mode,state,end_reason,authorized_by,started_at,expires_at,ended_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    ).run(s.id, s.orgId, s.userId, s.deviceId, s.mode, s.state, s.endReason ?? null,
          JSON.stringify(s.authorizedBy), resolveTime(s.startedAt), resolveTime(s.expiresAt), resolveTime(s.endedAt));
  }

  for (const e of seed.auditEvents) {
    db.prepare(
      `INSERT INTO audit_events (id,org_id,actor_id,action,target_type,target_id,result,reason_code,at)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).run(e.id, e.orgId, e.actorId, e.action, e.targetType ?? null, e.targetId ?? null,
          e.result, e.reasonCode ?? null, resolveTime(e.at));
  }
});
load();

// --- per-candidate overlay ---------------------------------------------
// ADDITIVE: it adds one organization and never touches the documented two, so the
// shipped public suites stay calibrated with or without it. No nonce -> no overlay,
// which reproduces the documented fixture exactly.
const overlay = buildOverlay(readNonce());
if (overlay) applyOverlay(db, overlay, { passwordHash: hashPassword });

const counts = ['organizations', 'users', 'memberships', 'devices', 'grants', 'sessions', 'audit_events']
  .map((t) => `${t}=${db.prepare(`SELECT count(*) AS n FROM ${t}`).get().n}`)
  .join('  ');

console.log(`seeded ${DB_FILE}\n  ${counts}`);
console.log(`  permissions=${db.prepare('SELECT count(*) AS n FROM permissions').get().n}  patterns=${db.prepare('SELECT count(*) AS n FROM permission_patterns').get().n}`);
console.log(`\n  login as dana@example.test / ${seed.seedPassword}  (owner in Acme, viewer in Globex)`);
console.log(`  login as sam@example.test  / ${seed.seedPassword}  (operator in Acme, auditor in Globex)`);

if (overlay) console.log(describeOverlay(overlay));

db.close();
