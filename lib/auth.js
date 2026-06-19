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

// ── Supabase auto-login (mint a magic-link OTP for the SSO'd email) ───────────
const MC_SUPABASE_URL = (process.env.MC_SUPABASE_URL || '').replace(/\/$/, '');
const MC_SERVICE_KEY = process.env.MC_SUPABASE_SERVICE_KEY || '';
function ssoLoginConfigured() { return !!(MC_SUPABASE_URL && MC_SERVICE_KEY); }

async function sbAdmin(pathname, body) {
  const r = await fetch(MC_SUPABASE_URL + pathname, {
    method: 'POST',
    headers: { apikey: MC_SERVICE_KEY, Authorization: 'Bearer ' + MC_SERVICE_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await r.json(); } catch (_e) {}
  return { ok: r.ok, status: r.status, data };
}

// Returns a magic-link token_hash the browser can redeem with supabase.auth.verifyOtp,
// or null on any failure (caller then falls back to MC's own login screen).
async function mintLoginOtp(email) {
  if (!ssoLoginConfigured() || !email) return null;
  try {
    let res = await sbAdmin('/auth/v1/admin/generate_link', { type: 'magiclink', email });
    if (!res.ok) {
      await sbAdmin('/auth/v1/admin/users', { email, email_confirm: true });
      res = await sbAdmin('/auth/v1/admin/generate_link', { type: 'magiclink', email });
    }
    if (!res.ok) { console.error('generate_link failed', res.status, JSON.stringify(res.data).slice(0,200)); return null; }
    const d = res.data || {};
    return d.hashed_token || (d.properties && d.properties.hashed_token) || null;
  } catch (e) {
    console.error('mintLoginOtp error', e && e.message);
    return null;
  }
}

module.exports = {
  verifyHubToken, isAllowed, issueSession, readSession, clearSession,
  hasSecret, ALLOWED_ROLES, SESSION_COOKIE,
  mintLoginOtp, ssoLoginConfigured,
};
