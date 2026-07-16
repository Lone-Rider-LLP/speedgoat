const { randomBytes } = require('crypto');

/**
 * GET /api/auth/login?returnTo=/some/path
 * Generates a CSRF state token and redirects to Auth0 Universal Login.
 */
module.exports = function handler(req, res) {
  const { returnTo = '/' } = req.query;

  const domain = process.env.AUTH0_DOMAIN;
  const clientId = process.env.AUTH0_CLIENT_ID;
  const baseUrl = process.env.AUTH0_BASE_URL;

  if (!domain || !clientId || !baseUrl) {
    return res.status(500).send('Auth0 environment variables are not configured.');
  }

  // Generate random CSRF token; embed returnTo in the state so we can
  // redirect back to the original page after login.
  const csrf = randomBytes(16).toString('hex');
  const statePayload = JSON.stringify({ csrf, returnTo: returnTo.startsWith('/') ? returnTo : '/' });
  const state = Buffer.from(statePayload).toString('base64url');

  // Short-lived cookie to validate the state on callback
  res.setHeader('Set-Cookie',
    `lr_state=${csrf}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  );

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: `${baseUrl}/api/auth/callback`,
    scope: 'openid email profile',
    state,
  });

  res.redirect(302, `https://${domain}/authorize?${params}`);
};
