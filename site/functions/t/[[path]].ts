/**
 * Factors.ai First-Party Proxy (Cloudflare Pages Function)
 *
 * Mirrors the testifysec.com setup so cilock.dev rides the same Factors path.
 *   /t/f.js     -> fetch app.factors.ai/assets/factors.js, rewrite API URLs to first-party
 *   /t/api/*    -> proxy to api.factors.ai/* (forwards client IP for reverse-IP matching)
 *
 * First-party serving bypasses ad blockers and Safari ITP cookie capping.
 */

interface Env {
  // no bindings needed for the proxy
}

const FACTORS_SCRIPT_URL = 'https://app.factors.ai/assets/factors.js';
const FACTORS_API_HOST = 'https://api.factors.ai';
const SCRIPT_CACHE_TTL = 3600;

export const onRequest: PagesFunction<Env> = async (context) => {
  const url = new URL(context.request.url);
  const path = url.pathname;

  if (path === '/t/f.js') return handleScriptRequest(context);
  if (path.startsWith('/t/api/')) return handleApiRequest(context);
  return new Response('Not Found', { status: 404 });
};

async function handleScriptRequest(context: EventContext<Env, string, unknown>): Promise<Response> {
  try {
    const response = await fetch(FACTORS_SCRIPT_URL, {
      headers: {
        'User-Agent': context.request.headers.get('User-Agent') || 'Mozilla/5.0',
        Accept: 'application/javascript, text/javascript, */*',
      },
    });
    if (!response.ok) {
      return new Response('// Failed to load Factors.ai', {
        status: 502,
        headers: { 'Content-Type': 'application/javascript' },
      });
    }
    let scriptContent = await response.text();
    const origin = new URL(context.request.url).origin;
    scriptContent = scriptContent.replace(/https?:\/\/api\.factors\.ai/g, `${origin}/t/api`);
    scriptContent = scriptContent.replace(/https?:\/\/app\.factors\.ai/g, origin);
    return new Response(scriptContent, {
      status: 200,
      headers: {
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': `public, max-age=${SCRIPT_CACHE_TTL}`,
        'Access-Control-Allow-Origin': '*',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch {
    return new Response('// Error loading Factors.ai', {
      status: 500,
      headers: { 'Content-Type': 'application/javascript' },
    });
  }
}

async function handleApiRequest(context: EventContext<Env, string, unknown>): Promise<Response> {
  const url = new URL(context.request.url);
  const apiPath = url.pathname.replace('/t/api/', '');
  const targetUrl = new URL(`${FACTORS_API_HOST}/${apiPath}`);
  url.searchParams.forEach((value, key) => targetUrl.searchParams.set(key, value));

  const headers = new Headers(context.request.headers);
  headers.delete('host');
  headers.delete('cf-connecting-ip');
  headers.delete('cf-ray');
  headers.delete('cf-visitor');
  headers.delete('cf-ipcountry');
  headers.set('Host', 'api.factors.ai');

  // Preserve the real client IP so Factors' reverse-IP matching works.
  const clientIP =
    context.request.headers.get('cf-connecting-ip') || context.request.headers.get('x-forwarded-for');
  if (clientIP) {
    headers.set('X-Forwarded-For', clientIP);
    headers.set('X-Real-IP', clientIP);
  }

  try {
    const response = await fetch(targetUrl.toString(), {
      method: context.request.method,
      headers,
      body:
        context.request.method !== 'GET' && context.request.method !== 'HEAD'
          ? context.request.body
          : undefined,
    });
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (context.request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: responseHeaders });
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  } catch {
    return new Response(JSON.stringify({ error: 'Proxy error' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
}
