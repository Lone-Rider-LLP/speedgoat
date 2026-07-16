const { createHmac } = require('crypto');

/**
 * Parse cookies from the Cookie header (Vercel doesn't auto-parse them).
 */
function parseCookies(cookieHeader) {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [key, ...val] = c.trim().split('=');
      return [key.trim(), val.join('=').trim()];
    })
  );
}

/**
 * Create a signed session cookie value.
 * Format: base64url(JSON payload) + "." + hex(HMAC-SHA256)
 * Expiry is embedded in the payload (8 hours).
 */
function createSessionToken(email, secret) {
  const payload = {
    email,
    exp: Date.now() + 8 * 60 * 60 * 1000, // 8 hours
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', secret).update(payloadB64).digest('hex');
  return `${payloadB64}.${sig}`;
}

/**
 * GET /api/auth/callback?code=…&state=…
 * - Validates CSRF state
 * - Exchanges code for tokens with Auth0
 * - Decodes the ID token to get the user's email
 * - Rejects anyone not on @lonerider.com
 * - Sets a signed session cookie and redirects back to the dashboard
 */
module.exports = async function handler(req, res) {
  const host = req.headers['x-forwarded-host'] || req.headers.host || '';
  if (host.endsWith('.vercel.app')) {
    return res.status(403).send('This URL is no longer active. Use speedgoat.lonerider.ai');
  }

  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(
      `<p>Auth0 error: <strong>${error}</strong> — ${error_description || ''}</p>` +
      `<p><a href="/api/auth/login">Try again</a></p>`
    );
  }

  if (!code || !state) {
    return res.status(400).send('Missing code or state parameter.');
  }

  // --- Parse state ---
  let returnTo = '/';
  let csrf;
  try {
    const stateData = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
    returnTo = stateData.returnTo || '/';
    csrf = stateData.csrf;
  } catch {
    return res.status(400).send('Invalid state parameter.');
  }

  // --- CSRF validation ---
  const cookies = parseCookies(req.headers.cookie);
  if (!csrf || !cookies.lr_state || cookies.lr_state !== csrf) {
    return res.status(400).send('CSRF validation failed. Please try logging in again.');
  }

  const domain = process.env.AUTH0_DOMAIN;
  const clientId = process.env.AUTH0_CLIENT_ID;
  const clientSecret = process.env.AUTH0_CLIENT_SECRET;
  const baseUrl = process.env.AUTH0_BASE_URL;
  const sessionSecret = process.env.SESSION_SECRET;

  // --- Exchange authorization code for tokens ---
  let idToken;
  try {
    const tokenResp = await fetch(`https://${domain}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: `${baseUrl}/api/auth/callback`,
      }),
    });

    const tokenData = await tokenResp.json();

    if (!tokenResp.ok) {
      throw new Error(tokenData.error_description || tokenData.error || 'Token exchange failed');
    }

    idToken = tokenData.id_token;
  } catch (err) {
    console.error('Token exchange error:', err.message);
    return res.status(500).send('Authentication failed. Please try again.');
  }

  // --- Extract email from ID token (JWT payload is base64url-encoded JSON) ---
  let email;
  try {
    const payloadB64 = idToken.split('.')[1];
    const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    email = claims.email;
  } catch (err) {
    console.error('ID token decode error:', err.message);
    return res.status(500).send('Could not read user information from token.');
  }

  // --- Domain restriction: @lonerider.com only ---
  if (!email || !email.toLowerCase().endsWith('@lonerider.com')) {
    return res.status(403).send(
      `<p>Access denied.</p>` +
      `<p>Only <strong>@lonerider.com</strong> accounts are permitted.</p>` +
      `<p>You signed in as: <code>${email || 'unknown'}</code></p>` +
      `<p><a href="/api/auth/logout">Sign out</a></p>`
    );
  }

  // --- Create signed session cookie ---
  const sessionToken = createSessionToken(email, sessionSecret);

  res.setHeader('Set-Cookie', [
    // Clear the CSRF state cookie
    `lr_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
    // Set the session cookie (8 hours, HttpOnly, Secure)
    `lr_session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`,
  ]);

  // Redirect to original page (or root if returnTo is not a valid relative path)
  res.redirect(302, returnTo.startsWith('/') ? returnTo : '/');
};
