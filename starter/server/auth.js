// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is done for you;
// `verifyAccessToken` below is a stub you have to implement. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and restated in the TODO comment.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue an access token. Note what is NOT in here: the resolved permission set.
// The token carries the authorization INPUTS (org, role, pv); the server resolves
// the permissions. See AUTH-DATA-MODEL.md §1 (D11).
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// ---------------------------------------------------------------------------
// Verify an access token and return its claims, or throw `unauthenticated(...)`.
//
// It rejects ALL of the following, each with a 401 UNAUTHENTICATED:
//   1. a token that is not three dot-separated segments
//   2. a header or payload that is not valid base64url-encoded JSON, or not an object
//   3. a header whose `alg` is anything other than 'HS256', or whose `typ` is not 'JWT'
//      -- the alg: none and algorithm-substitution defence. We read the header but
//         NEVER trust it to choose the algorithm — we always enforce ALG ourselves.
//   4. a signature that does not match, compared in constant time
//   5. an `exp` that is missing, not a number, or <= now (half-open: exp==now is expired)
//   6. an `iss` or `aud` that does not match our constants
//   7. a missing or empty `jti`
//
// AUTH-DATA-MODEL.md §10 lists the failure modes; §2 defines the claim set.
// `node scripts/check-jwt.js` is the public test suite for this function.
// ---------------------------------------------------------------------------
export function verifyAccessToken(token, secret) {
  // --- Failure mode 1: must be exactly three dot-separated segments -----------
  // String(token) guards against null/undefined without throwing before we can
  // produce the right error type.
  const parts = String(token ?? '').split('.');
  if (parts.length !== 3) throw unauthenticated('malformed token: expected three segments');

  const [rawHeader, rawPayload, rawSig] = parts;

  // --- Failure mode 2: header and payload must be valid base64url JSON objects -
  let header, claims;
  try {
    const h = JSON.parse(unb64(rawHeader).toString('utf8'));
    if (h === null || typeof h !== 'object' || Array.isArray(h)) throw new Error();
    header = h;
  } catch {
    throw unauthenticated('malformed token: header is not a JSON object');
  }
  try {
    const p = JSON.parse(unb64(rawPayload).toString('utf8'));
    if (p === null || typeof p !== 'object' || Array.isArray(p)) throw new Error();
    claims = p;
  } catch {
    throw unauthenticated('malformed token: payload is not a JSON object');
  }

  // --- Failure mode 3: algorithm and type lock --------------------------------
  // We decide the algorithm (HS256). We read header.alg only to REJECT anything
  // that isn't ours. Trusting header.alg to choose the verifier is the classic
  // alg:none / RS256-confusion attack.
  if (header.alg !== ALG || header.typ !== 'JWT') {
    throw unauthenticated('malformed token: unsupported alg or typ');
  }

  // --- Failure mode 4: signature verification in constant time ----------------
  // Re-derive what the MAC should be for this header+payload and compare with
  // timingSafeEqual so an attacker cannot learn the secret from timing differences.
  // An empty segment ('') produces a zero-length buffer; timingSafeEqual requires
  // equal lengths, so we handle length mismatch explicitly before calling it.
  const expectedSig = createHmac('sha256', secret)
    .update(`${rawHeader}.${rawPayload}`)
    .digest();
  const actualSig = unb64(rawSig);
  if (
    actualSig.length !== expectedSig.length ||
    !timingSafeEqual(actualSig, expectedSig)
  ) {
    throw unauthenticated('token signature does not match');
  }

  // --- Failure mode 5: expiry (half-open: exp <= now is already expired) ------
  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || claims.exp <= nowSec) {
    throw unauthenticated('token is expired or missing exp');
  }

  // --- Failure mode 6: issuer and audience ------------------------------------
  if (claims.iss !== ISS || claims.aud !== AUD) {
    throw unauthenticated('token iss or aud does not match');
  }

  // --- Failure mode 7: jti must be a non-empty string -------------------------
  if (!claims.jti || typeof claims.jti !== 'string') {
    throw unauthenticated('token is missing a jti');
  }

  return claims;
}


// The freshness check (AUTH-DATA-MODEL.md §3). Compares the token's pv against the
// membership's current perm_version. Note `!==`, not `<`: a token from the future is
// as suspect as a stale one.
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// --- opaque credentials: refresh tokens and invite tokens -------------------
//
// Both are bearer credentials that live in a database, so both are stored hashed —
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file — which defeats the
// point of hashing a high-entropy token.

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// --- passwords --------------------------------------------------------------

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
