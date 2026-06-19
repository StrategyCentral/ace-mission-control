const express = require('express');
const path = require('path');
const auth = require('./lib/auth');

const app = express();
const PORT = process.env.PORT || 3000;

const HUB_ORIGIN = process.env.HUB_ORIGIN || 'https://dashboard.acetradingbots.com';
const HUB_LAUNCH_URL = `${HUB_ORIGIN}/api/sso/launch?to=mission-control`;

app.disable('x-powered-by');

// ── Health check (always open) ───────────────────────────────────────────────
app.get('/healthz', (req, res) =>
  res.json({ ok: true, ssoEnforced: auth.hasSecret(), roles: auth.ALLOWED_ROLES }));

// ── SSO consume: the Hub redirects here with ?token=<jwt> ─────────────────────
app.get('/sso/consume', (req, res) => {
  // No secret configured yet -> fail open (app is still public, as before).
  if (!auth.hasSecret()) return res.redirect('/');

  const payload = auth.verifyHubToken(req.query.token);
  if (!payload) {
    return res.status(401).send(denyPage(
      'Sign-in link invalid or expired',
      'Head back to the ACE Hub and launch Mission Control again.',
      HUB_LAUNCH_URL, 'Launch via ACE Hub'));
  }
  if (!auth.isAllowed(payload)) {
    return res.status(403).send(denyPage(
      'Staff access only',
      `Signed in as ${escapeHtml(payload.email || 'unknown')} — role "${escapeHtml(payload.role || 'none')}" is not permitted in Mission Control.`,
      `${HUB_ORIGIN}/dashboard`, 'Back to Hub'));
  }

  auth.issueSession(res, payload);
  const next = typeof req.query.next === 'string' && req.query.next.startsWith('/')
    ? req.query.next : '/';
  return res.redirect(next);
});

// ── Logout ───────────────────────────────────────────────────────────────────
app.get('/logout', (req, res) => {
  auth.clearSession(res);
  return res.redirect(`${HUB_ORIGIN}/dashboard`);
});

// ── Auth gate for everything else ────────────────────────────────────────────
app.use((req, res, next) => {
  if (!auth.hasSecret()) return next();           // fail open until configured
  const session = auth.readSession(req);
  if (session) { req.user = session; return next(); }
  return res.redirect(HUB_LAUNCH_URL);            // hand off to Hub login + SSO
});

// ── The app (only reached when authenticated, or fail-open) ───────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`ACE Mission Control on :${PORT} — SSO ${auth.hasSecret() ? 'ENFORCED' : 'OPEN (set JWT_SECRET to lock down)'}; roles=${auth.ALLOWED_ROLES.join('/')}`);
});

// ── Helpers ──────────────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function denyPage(title, sub, href, cta) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ACE // Mission Control</title>
<style>
  html,body{height:100%;margin:0;background:#0b0918;color:#e8dff5;
    font-family:'Space Grotesk',system-ui,sans-serif;display:flex;align-items:center;justify-content:center}
  .card{max-width:440px;padding:40px;text-align:center;border:1px solid rgba(25,159,216,.25);
    border-radius:14px;background:rgba(18,10,40,.78);box-shadow:0 0 60px rgba(25,159,216,.12)}
  h1{font-size:13px;letter-spacing:3px;color:#199FD8;text-transform:uppercase;margin:0 0 18px}
  h2{font-size:22px;margin:0 0 10px;color:#f0eaff}
  p{color:rgba(210,195,235,.6);font-size:14px;line-height:1.5;margin:0 0 26px}
  a{display:inline-block;padding:11px 22px;border-radius:8px;background:#199FD8;color:#04121f;
    font-weight:600;text-decoration:none;font-size:14px}
</style></head><body><div class="card">
  <h1>// ACE Mission Control</h1>
  <h2>${escapeHtml(title)}</h2>
  <p>${sub}</p>
  <a href="${href}">${escapeHtml(cta)}</a>
</div></body></html>`;
}
