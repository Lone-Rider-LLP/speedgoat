/**
 * GET /api/auth/logout
 * Clears the session cookie and redirects to Auth0's logout endpoint,
 * which then redirects back to the dashboard root.
 */
module.exports = function handler(req, res) {
  const host = req.headers.host || '';
  if (host.endsWith('.vercel.app')) {
    return res.status(403).send('This URL is no longer active. Use speedgoat.lonerider.ai');
  }

  const domain = process.env.AUTH0_DOMAIN;
  const clientId = process.env.AUTH0_CLIENT_ID;
  const baseUrl = process.env.AUTH0_BASE_URL;

  // Expire the session cookie immediately
  res.setHeader('Set-Cookie',
    `lr_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  );

  const params = new URLSearchParams({
    client_id: clientId,
    returnTo: baseUrl,
  });

  res.redirect(302, `https://${domain}/v2/logout?${params}`);
};
