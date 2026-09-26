// Per-request context: turn a bearer token into an authenticated caller.
//
// What it does:
//   1. Extracts the Bearer token from the Authorization header.
//   2. Verifies the token cryptographically (delegates to verifyAccessToken).
//   3. STRUCTURAL ORG ISOLATION: if the request addresses an org different from
//      the token's `org` claim, return 404 — never 403. The caller must not be
//      able to infer that another org exists at all. (PERMISSIONS.md §6)
//   4. Looks up the active membership for (userId, orgId). No membership → 401.
//   5. Checks perm_version freshness: if the token's `pv` != membership.perm_version,
//      the caller's role or grants have changed since the token was issued. Force a
//      refresh now — 401 TOKEN_STALE — so the change takes effect on the next request,
//      not at token expiry. (AUTH-DATA-MODEL.md §3)
//   6. Returns { userId, orgId, role, membership, claims } for use by route handlers.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // --- Step 1: extract the Bearer token from Authorization header -----------
    const authHeader = req.headers['authorization'] ?? '';
    const [scheme, token] = authHeader.split(' ');
    if (scheme !== 'Bearer' || !token) {
      throw unauthenticated('missing or malformed Authorization header');
    }

    // --- Step 2: cryptographic verification ----------------------------------
    // verifyAccessToken throws unauthenticated() on any failure — we let it
    // propagate unchanged. On success we get the decoded claims.
    const claims = verifyAccessToken(token, secret);
    const { sub: userId, org: orgId } = claims;

    // --- Step 3: structural org isolation ------------------------------------
    // `params` is the URL path parameters object built by the router.
    // If the route has an :orgId segment, it must match the token's org claim
    // exactly. A mismatch is 404, not 403: the resource is INVISIBLE to this
    // caller, not merely forbidden. This is not a filter — the check happens
    // before we touch the database for that org at all.
    if (params.orgId && params.orgId !== orgId) {
      throw notFound();
    }

    // --- Step 4: membership lookup -------------------------------------------
    // We only accept 'active' memberships. 'invited', 'suspended', and 'removed'
    // all mean the caller has no authority in this org right now.
    const membership = db.prepare(
      `SELECT id, org_id, user_id, role, status, perm_version
         FROM memberships
        WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(orgId, userId);

    if (!membership) {
      throw unauthenticated('not a member of this org');
    }

    // --- Step 5: perm_version freshness check --------------------------------
    // assertFresh compares claims.pv against membership.perm_version and throws
    // tokenStale() (401 TOKEN_STALE) if they differ. Using !== not <: a token
    // from the future is as suspect as a stale one. (AUTH-DATA-MODEL.md §3)
    assertFresh(claims, membership);

    // --- Step 6: return the caller context -----------------------------------
    return {
      userId,
      orgId,
      role: membership.role,
      membership,
      claims,
    };
  };
}
