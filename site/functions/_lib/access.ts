/**
 * Cloudflare Access (Zero Trust) auth for the /dash* routes.
 *
 * Access sits in front of cilock.dev/dash (see infra/cloudflare/) and forwards a
 * signed JWT in Cf-Access-Jwt-Assertion — NOT the Cf-Access-Authenticated-User-Email
 * convenience header — while stripping any client-supplied Cf-Access-* headers at the
 * edge. We verify that JWT (RS256 vs the team JWKS + aud/iss/exp) and require an
 * @testifysec.com email claim, so every /dash route fails closed on its own even if the
 * Access policy were misconfigured or removed.
 */

const ACCESS_TEAM = 'https://testifysec.cloudflareaccess.com';
const ACCESS_AUD = '34a55b01efb1a9dc3b67c17bbbe10e13c0f5ca93417a0af0e0b42440b1702408';
const ALLOWED_DOMAIN = '@testifysec.com';

function b64urlToBytes(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const b64urlToJson = (s: string) => JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));

export async function verifyAccessEmail(token: string): Promise<string | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  let header: Record<string, unknown>, payload: Record<string, unknown>;
  try { header = b64urlToJson(parts[0]); payload = b64urlToJson(parts[1]); } catch { return null; }
  if (payload.iss !== ACCESS_TEAM) return null;
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(ACCESS_AUD)) return null;
  if (typeof payload.exp === 'number' && Date.now() / 1000 > payload.exp) return null;
  try {
    const jwks = await fetch(`${ACCESS_TEAM}/cdn-cgi/access/certs`).then((r) => r.json()) as { keys?: (JsonWebKey & { kid?: string })[] };
    const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    if (!ok) return null;
  } catch { return null; }
  return String(payload.email || '').toLowerCase();
}

/** Verified @testifysec.com email for a /dash request, or null if not authorised. */
export async function authedEmail(request: Request): Promise<string | null> {
  const token = request.headers.get('Cf-Access-Jwt-Assertion') || '';
  const email = token ? await verifyAccessEmail(token) : null;
  return email && email.endsWith(ALLOWED_DOMAIN) ? email : null;
}
