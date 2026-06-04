/**
 * GET /manifest.json — the release manifest (versions index + "latest" pointer),
 * served from R2. This is a root-level alias for /dl/manifest.json; both serve the
 * same object so tooling can fetch whichever it prefers.
 *
 * Shape: see Manifest in functions/_lib/dist.ts. Short cache (publishing rewrites it).
 */

import { type Env, loadManifest } from './_lib/dist';

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
  }
  const manifest = await loadManifest(env);
  if (!manifest) return new Response('Not Found', { status: 404 });
  const body = request.method === 'HEAD' ? null : JSON.stringify(manifest);
  return new Response(body, {
    status: 200,
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=60' },
  });
};
