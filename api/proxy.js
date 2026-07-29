/**
 * GET/POST /api/proxy?supapath=rest/v1/table&...
 * Called via vercel.json rewrite from /api/supabase/* — avoids the [...]
 * catch-all routing issue. Checks session cookie, forwards to Supabase
 * using the service role key.
 */
const { createHmac } = require('crypto');

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
  const expected  = createHmac('sha256', secret).update(payloadB64).digest('hex');
  if (sigHex !== expected) return false;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    return payload.exp > Date.now();
  } catch {
    return false;
  }
}

module.exports = async function handler(req, res) {
  // ── Auth check ──────────────────────────────────────────────────────────
  const cookies = parseCookies(req.headers.cookie);
  const session = cookies.lr_session;
  if (!session || !verifySession(session, process.env.SESSION_SECRET)) {
    return res.status(401).json({ error: 'Unauthorised' });
  }

  // ── Build Supabase URL ───────────────────────────────────────────────────
  // supapath comes from the rewrite: /api/supabase/rest/v1/foo → supapath=rest/v1/foo
  const { supapath = '', path: _ignoredPath, ...queryParams } = req.query;
  const queryString = new URLSearchParams(queryParams).toString();
  const supabaseUrl = `${process.env.SUPABASE_URL}/${supapath}${queryString ? '?' + queryString : ''}`;
  console.log('[proxy] req.query:', JSON.stringify(req.query));
  console.log('[proxy] supabaseUrl:', supabaseUrl);

  // ── Forward request ──────────────────────────────────────────────────────
  const forwardHeaders = {
    'apikey':        process.env.SUPABASE_SERVICE_KEY,
    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
    'Content-Type':  'application/json',
  };
  if (req.headers['prefer']) forwardHeaders['Prefer'] = req.headers['prefer'];
  if (req.headers['range'])  forwardHeaders['Range']  = req.headers['range'];

  const fetchOptions = { method: req.method, headers: forwardHeaders };
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.body) {
    fetchOptions.body = JSON.stringify(req.body);
  }

  try {
    const upstream = await fetch(supabaseUrl, fetchOptions);
    res.status(upstream.status);
    const contentRange = upstream.headers.get('content-range');
    if (contentRange) res.setHeader('Content-Range', contentRange);
    const text = await upstream.text();
    res.setHeader('Content-Type', 'application/json');
    res.send(text);
  } catch (err) {
    console.error('Supabase proxy error:', err.message);
    res.status(502).json({ error: 'Upstream request failed' });
  }
};
