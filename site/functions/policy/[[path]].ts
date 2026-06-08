/**
 * GET /policy/<file> — verification policy files, served from R2 (application/json).
 *
 *   /policy/release-policy.json   -> policy/release-policy.json
 *
 * install.sh and `cilock verify` reference cilock.dev/policy/release-policy.json as
 * the trust anchor for release artifacts. This root key is the current signed
 * policy (overwritten each release with the same prod-signed policy); an
 * immutable per-version copy ships at /dl/<version>/release-policy.json.
 *
 * Path traversal is rejected: only a single flat segment under /policy/ is allowed.
 */

import { type Env, serveRootObject } from '../_lib/dist';

export const onRequest: PagesFunction<Env> = (context) => {
  const url = new URL(context.request.url);
  const file = url.pathname.replace(/^\/policy\//, '').replace(/^\/+/, '');
  // No nested paths, no traversal, no directory listings.
  if (!file || file.includes('/') || file.includes('..')) {
    return new Response('Not Found', { status: 404 });
  }
  return serveRootObject(context.env, context.request.method, `policy/${file}`, {
    cacheControl: 'public, max-age=31536000, immutable',
  });
};
