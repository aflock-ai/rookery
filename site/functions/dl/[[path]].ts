/**
 * Release artifact download: GET /dl/<version>/<file>  (and /dl/latest/<file>)
 *
 * Streams the requested object from the private R2 bucket bound as DIST and logs a
 * download event to D1 (binding DB, type='dl'). The bucket is never public — this
 * function is the only read path.
 *
 *   /dl/v1.2.0/cilock-v1.2.0-linux-amd64.tar.gz   -> v1.2.0/cilock-v1.2.0-linux-amd64.tar.gz
 *   /dl/latest/cilock-...-linux-amd64.tar.gz       -> <manifest.latest>/cilock-...-linux-amd64.tar.gz
 *   /dl/manifest.json                               -> manifest.json (served, no dl event)
 *
 * Behaviour:
 *   - 404 if the object is absent (or "latest" requested with no manifest pointer).
 *   - Correct Content-Type per artifact; Content-Disposition: attachment for tarballs/zips.
 *   - Immutable Cache-Control for versioned paths; short cache for latest/ and the manifest.
 *   - GET/HEAD only; everything else is 405.
 */

import {
  type Env,
  contentTypeFor,
  loadManifest,
  logDownload,
  r2Response,
  resolveKey,
  versionFromKey,
} from '../_lib/dist';

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
  }
  if (!env.DIST) return new Response('Distribution not configured', { status: 503 });

  const url = new URL(request.url);
  // Everything after "/dl/". params.path is the [[path]] catch-all segments.
  const tail = url.pathname.replace(/^\/dl\//, '').replace(/^\/+/, '');
  if (!tail || tail.endsWith('/')) return new Response('Not Found', { status: 404 });

  // The manifest is served here too, but it isn't a "download" — no D1 event.
  if (tail === 'manifest.json') {
    const manifest = await loadManifest(env);
    if (!manifest) return new Response('Not Found', { status: 404 });
    return new Response(JSON.stringify(manifest), {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=60' },
    });
  }

  const isLatest = tail.startsWith('latest/');
  const key = await resolveKey(env, tail);
  if (!key) return new Response('Not Found', { status: 404 }); // latest/ with no manifest pointer

  const obj = request.method === 'HEAD' ? await env.DIST.head(key) : await env.DIST.get(key);
  if (!obj) return new Response('Not Found', { status: 404 });

  const name = key.split('/').pop() || key;
  const version = versionFromKey(key);

  if (request.method === 'HEAD') {
    const headers = new Headers();
    (obj as R2Object).writeHttpMetadata(headers);
    if (!headers.has('content-type')) headers.set('content-type', contentTypeFor(name));
    headers.set('etag', (obj as R2Object).httpEtag);
    if (typeof (obj as R2Object).size === 'number') headers.set('content-length', String((obj as R2Object).size));
    // latest/ resolves to a moving target, so it must not be cached immutably.
    headers.set('cache-control', isLatest ? 'public, max-age=300' : 'public, max-age=31536000, immutable');
    return new Response(null, { status: 200, headers });
  }

  // Log the download (best-effort, non-blocking). `path` is the request path so the
  // dashboard can group by what users actually hit (latest/... vs the concrete version).
  logDownload(context, { path: url.pathname, asset: key, version });

  return r2Response(obj as R2ObjectBody, name, { immutable: !isLatest });
};
