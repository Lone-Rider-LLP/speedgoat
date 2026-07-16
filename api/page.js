/**
 * GET /api/page?p=<page-name>
 * Checks the session cookie and serves the requested HTML file.
 * Called via vercel.json rewrites — the browser URL stays as /index.html etc.
 * If not authenticated, redirects to Auth0 login.
 */
const { createHmac } = require('crypto');
const path = require('path');
const fs = require('fs');

const PAGES = [
  'index',
  'product-catalog',
  'bundle-mapping',
  'transportation-costs',
  'shipping-estimator',
];

function parseCookies(cookieHeader) {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [key, ...val] = c.trim().split('=');
      return [key.trim(), val.join('=').trim()];
    })
  );
}

function verifySession(cookieValue, secret) {
  const dotIndex = cookieValue.lastIndexOf('.');
  if (dotIndex === -1) return false;

  const payloadB64 = cookieValue.slice(0, dotIndex);
  const sigHex    = cookieValue.slice(dotIndex + 1);

  const expected = createHmac('sha256', secret).update(payloadB64).digest('hex');
  if (sigHex !== expected) return false;

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    return payload.exp > Date.now();
  } catch {
    return false;
  }
}

module.exports = function handler(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  const session = cookies.lr_session;
  const secret  = process.env.SESSION_SECRET;

  // Sanitise and validate page name
  const rawPage = (req.query.p || 'index').replace(/[^a-z0-9-]/g, '');
  const page    = PAGES.includes(rawPage) ? rawPage : 'index';
  const returnTo = page === 'index' ? '/' : `/${page}.html`;

  // Auth check
  if (!session || !verifySession(session, secret)) {
    return res.redirect(302,
      `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`
    );
  }

  // Read and serve the HTML
  const htmlPath = path.join(process.cwd(), 'warehouse-kpi-dashboard', `${page}.html`);

  if (!fs.existsSync(htmlPath)) {
    return res.status(404).send('Page not found.');
  }

  const html = fs.readFileSync(htmlPath, 'utf8');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(html);
};
