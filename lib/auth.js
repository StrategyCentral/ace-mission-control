/**
 * ACE Mission Control — SSO auth bridge
 * --------------------------------------
 * Mission Control has no user database of its own. Access is granted purely
 * on the strength of a short-lived JWT handed over by the ACE Customer Hub
 * (dashboard.acetradingbots.com) via /api/sso/launch?to=mission-control.
 *
 * Flow:
 *   Hub (authenticated, staff role) -> mints HS256 JWT (issuer "ace-hub",
 *   signed with the shared JWT_SECRET, includes { email, role, hub_user_id })
 *   -> redirects to /sso/consume?token=...  on this app.
 *   We verify it, check the role is allowed, then set our own signed
 *   `mc_session` cookie (issuer "ace-mc") so the SPA can be used normally.
 *
 * ENV:
 *   JWT_SECRET        — REQUIRED to enforce auth. Shared with the Hub.
 *                       If absent, the app FAILS OPEN (stays public, as it is
 *                       today) so a missing var can never lock everyone out.
 *   MC_ALLOWED_ROLES  — comma list of Hub roles allowed in. Default
 *                       "admin,super_admin".
 */
const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const HUB_ISSUER = 'ace-hub';
const MC_ISSUER = 'ace-mc';
const SESSION_COOKIE = 'mc_session';
const SESSION_TTL = 60 * 60 * 12; // 12 hours

const ALLOWED_ROLES = (process.env.MC_ALLOWED_ROLES || 'admin,super_admin')
  .split(',').map((r) => r.trim().toLowerCase()).filter(Boolean);

function secret() { return process.env.JWT_SECRET || ''; }
function hasSecret() { return secret().length > 0; }

function verifyHubToken(token) {
  if (!token || !hasSecret()) return null;
  try {
    return jwt.verify(token, secret(), { issuer: HUB_ISSUER, algorithms: ['HS256'] });
  } catch (_e) {
    return null;
  }
}

function isAllowed(payload) {
  if (!payload || !payload.role) return false;
  return ALLOWED_ROLES.includes(String(payload.role).toLowerCase());
}

function issueSession(res, payload) {
  const token = jwt.sign(
    { email: payload.email, role: payload.role, hub_user_id: payload.hub_user_id },
    secret(),
    { issuer: MC_ISSUER, algorithm: 'HS256', expiresIn: SESSION_TTL }
  );
  res.setHeader('Set-Cookie', cookie.serialize(SESSION_COOKIE, token, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: SESSION_TTL,
  }));
}

function readSession(req) {
  if (!hasSecret()) return null;
  const cookies = cookie.parse(req.headers.cookie || '');
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  try {
    return jwt.verify(token, secret(), { issuer: MC_ISSUER, algorithms: ['HS256'] });
  } catch (_e) {
    return null;
  }
}

function clearSession(res) {
  res.setHeader('Set-Cookie', cookie.serialize(SESSION_COOKIE, '', {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0,
  }));
}

module.exports = {
  verifyHubToken, isAllowed, issueSession, readSession, clearSession,
  hasSecret, ALLOWED_ROLES, SESSION_COOKIE,
};
