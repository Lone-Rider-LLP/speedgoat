/**
 * Edge Middleware – runs before every request.
 * Skips /api/auth/* routes (login / callback / logout).
 * All other routes require a valid lr_session cookie.
 * No external imports — uses Web Crypto API only (built into Edge runtime).
 */
export const config = {
  // Exclude auth endpoints, static assets, and _vercel internals.
  // Note: .html is intentionally NOT excluded — those pages must be protected.
  matcher: '/((?!api/auth|_vercel|favicon\\.ico|.*\\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$).*)',
};

const SECRET = process.env.SESSION_SECRET;

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function verifySession(cookieValue) {
  if (!SECRET) return false;

  const dotIndex = cookieValue.lastIndexOf('.');
  if (dotIndex === -1) return false;

  const payloadB64 = cookieValue.slice(0, dotIndex);
  const sigHex = cookieValue.slice(dotIndex + 1);

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      hexToBytes(sigHex),
      new TextEncoder().encode(payloadB64)
    );

    if (!valid) return false;

    // Decode base64url payload
    const json = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'));
    const payload = JSON.parse(json);

    // Check expiry
    if (!payload.exp || payload.exp < Date.now()) return false;

    return true;
  } catch {
    return false;
  }
}

export default async function middleware(request) {
  const session = request.cookies.get('lr_session')?.value;

  if (session && (await verifySession(session))) {
    return; // Authenticated — pass through to origin (serve static file)
  }

  // Not authenticated — redirect to login, preserving the original URL
  const url = new URL(request.url);
  const loginUrl = new URL('/api/auth/login', request.url);
  loginUrl.searchParams.set('returnTo', url.pathname + url.search);

  return Response.redirect(loginUrl.toString(), 302);
}
