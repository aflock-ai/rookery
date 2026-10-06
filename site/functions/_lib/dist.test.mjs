// jade:ring local
// node --test: the release manifest is readable cross-origin (judge#6005).
//
// The platform's "Download cilock" page fetches /dl/manifest.json from another
// origin. Without Access-Control-Allow-Origin the browser blocks the read and
// the page always reported the manifest unreachable.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Node 22.18+ strips TypeScript types on import; dist.ts has no relative imports.
import { manifestResponse } from './dist.ts';

const manifest = { schema: 1, latest: 'v1.2.0', versions: [{ version: 'v1.2.0', files: [] }] };

test('the manifest response is cross-origin readable', async () => {
  const res = manifestResponse(manifest, 'GET');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  assert.equal(res.headers.get('content-type'), 'application/json');
  assert.equal(res.headers.get('cache-control'), 'public, max-age=60');
  assert.deepEqual(await res.json(), manifest);
});

test('HEAD carries the same headers and no body', async () => {
  const res = manifestResponse(manifest, 'HEAD');
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  assert.equal(await res.text(), '');
});

// Both manifest routes must build their response through manifestResponse, so
// a route that re-spells the headers by hand cannot drop the CORS header again.
// The routes import '../_lib/dist' without an extension (the Pages bundler
// resolves it), so they are checked by source rather than imported.
test('both manifest routes serve through manifestResponse', () => {
  for (const route of ['../manifest.json.ts', '../dl/[[path]].ts']) {
    const src = readFileSync(new URL(route, import.meta.url), 'utf8');
    assert.match(src, /return manifestResponse\(manifest, request\.method\);/, `${route} does not serve the manifest through manifestResponse`);
    assert.doesNotMatch(src, /JSON\.stringify\(manifest\)/, `${route} renders the manifest by hand`);
  }
});
