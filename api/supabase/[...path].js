/**
 * Supabase proxy — catches all /api/supabase/* requests.
 * Checks the session cookie, then forwards to Supabase using the
 * service role key (server-side only, never exposed to the browser).
 *
 * Required env vars (set in Vercel Project Settings):
 *   SUPABASE_URL          e.g. https://prcbzlnwqmtvqqpxwmgg.supabase.co
 *   SUPABASE_SERVICE_KEY  service_role key from Supabase → Settings → API
 *   SESSION_SECRET        same value used by api/auth/*
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
  // req.query.path = ['rest','v1','table_name'] from the catch-all segment
  const { path: pathArr = [], ...queryParams } = req.query;
  const supaPath    = pathArr.join('/');
  const queryString = new URLSearchParams(queryParams).toString();
  const supabaseUrl = `${process.env.SUPABASE_URL}/${supaPath}${queryString ? '?' + queryString : ''}`;

  // ── Forward request ──────────────────────────────────────────────────────
  const forwardHeaders = {
    'apikey':        process.env.SUPABASE_SERVICE_KEY,
    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
    'Content-Type':  'application/json',
  };
  // Pass through PostgREST control headers if present
  if (req.headers['prefer']) forwardHeaders['Prefer'] = req.headers['prefer'];
  if (req.headers['range'])  forwardHeaders['Range']  = req.headers['range'];

  const fetchOptions = { method: req.method, headers: forwardHeaders };
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.body) {
    fetchOptions.body = JSON.stringify(req.body);
  }

  try {
    const upstream = await fetch(supabaseUrl, fetchOptions);

    // Forward status and any PostgREST headers the client needs
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
