/**
 * GET /policy/<file> — verification policy files, served from R2 (application/json).
 *
 *   /policy/release-v1.policy.json   -> policy/release-v1.policy.json
 *
 * install.sh and `cilock verify` reference cilock.dev/policy/release-v1.policy.json as
 * the trust anchor for release artifacts. Policies are versioned by file name
 * (release-v1, release-v2, ...), so each name is immutable once published.
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
