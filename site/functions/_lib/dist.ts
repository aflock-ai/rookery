/**
 * Shared helpers for the release-distribution functions (functions/dl, install.sh,
 * functions/policy). All of these read from the private R2 bucket bound as DIST and
 * log a download event to D1 (binding DB), reusing the cl/e.ts write pattern.
 *
 * The bucket layout is flat-by-version, with a manifest object at the root:
 *
 *   manifest.json                                   <- versions index + "latest" pointer
 *   install.sh, install.sh.sig, install.sh.cert     <- bootstrap installer (version-agnostic)
 *   policy/release-v1.policy.json                    <- verification policy referenced by cilock verify
 *   <version>/cilock-<version>-<os>-<arch>.tar.gz    <- binary tarballs (+ .sig / .pem)
 *   <version>/checksums-sha256.txt(.sig/.pem)
 *   <version>/release-<version>.policy.json
 *   <version>/*-sbom.spdx.json, *.attestation.json, *.vsa.json
 *
 * "/dl/latest/<file>" resolves <file> against manifest.latest's version, so callers
 * never have to know the current version number.
 */

export interface Env {
  DIST?: R2Bucket;
  // Override for the canonical cross-property analytics hub ingest endpoint that
  // logDownload() POSTs download events to. Defaults to ANALYTICS_HUB_DEFAULT.
  CILOCK_ANALYTICS_HUB?: string;
}

/** Canonical cross-property analytics hub ingest endpoint (see logDownload). */
const ANALYTICS_HUB_DEFAULT = 'https://analytics.testifysec.com/ingest/web';
/**
 * Anti-noise write key the hub expects on /ingest/web (low-security, not a secret —
 * it just keeps casual junk out; real abuse protection is edge rate-limiting). Must
 * match the hub's INGEST_WRITE_KEY.
 */
const ANALYTICS_HUB_KEY = 'clk-web-ingest-pub-2026';

/** One published file inside a version, as recorded in the manifest. */
export interface ManifestFile {
  name: string; // file name only, e.g. cilock-v1.2.0-linux-amd64.tar.gz
  sha256: string; // lowercase hex sha256 of the object bytes
  size?: number; // bytes, optional
  os?: string; // linux|darwin|windows (binary tarballs only)
  arch?: string; // amd64|arm64 (binary tarballs only)
}

export interface ManifestVersion {
  version: string; // e.g. v1.2.0
  released?: string; // ISO-8601 publish timestamp
  files: ManifestFile[];
}

export interface Manifest {
  schema: 1; // manifest schema version
  latest: string; // version string that "latest" resolves to, e.g. v1.2.0
  versions: ManifestVersion[]; // newest-first by convention
  updated?: string; // ISO-8601 of the last manifest write
}

export const MANIFEST_KEY = 'manifest.json';

/**
 * Content-Type for an artifact, keyed off its file name. Defaults to
 * application/octet-stream so unknown artifacts still download safely.
 */
export function contentTypeFor(name: string): string {
  const n = name.toLowerCase();
  if (n.endsWith('.tar.gz') || n.endsWith('.tgz')) return 'application/gzip';
  if (n.endsWith('.zip')) return 'application/zip';
  if (n.endsWith('.json')) return 'application/json';
  if (n.endsWith('.txt') || n.endsWith('.sig') || n.endsWith('.pem') || n.endsWith('.cert'))
    return 'text/plain; charset=utf-8';
  if (n.endsWith('.sh')) return 'text/x-shellscript; charset=utf-8';
  return 'application/octet-stream';
}

/** True for artifacts that should download with a Content-Disposition: attachment. */
export function isAttachment(name: string): boolean {
  const n = name.toLowerCase();
  return n.endsWith('.tar.gz') || n.endsWith('.tgz') || n.endsWith('.zip');
}

/** Pull a "vX.Y.Z" (or "X.Y.Z") version token out of an R2 key, or null. */
export function versionFromKey(key: string): string | null {
  const seg = key.split('/')[0];
  return /^v?\d+\.\d+/.test(seg) ? seg : null;
}

let manifestCache: { at: number; manifest: Manifest } | null = null;
const MANIFEST_TTL_MS = 30_000;

/** Load + parse the manifest from R2, with a short in-isolate cache. */
export async function loadManifest(env: Env): Promise<Manifest | null> {
  if (!env.DIST) return null;
  const now = Date.now();
  if (manifestCache && now - manifestCache.at < MANIFEST_TTL_MS) return manifestCache.manifest;
  const obj = await env.DIST.get(MANIFEST_KEY);
  if (!obj) return null;
  try {
    const manifest = (await obj.json()) as Manifest;
    manifestCache = { at: now, manifest };
    return manifest;
  } catch {
    return null;
  }
}

/**
 * Resolve a request path's tail into a concrete R2 key.
 *   resolveKey("v1.2.0/cilock-...tar.gz")  -> "v1.2.0/cilock-...tar.gz"
 *   resolveKey("latest/cilock-...tar.gz")  -> "<manifest.latest>/cilock-...tar.gz"
 * Returns null when "latest" is requested but no manifest/latest pointer exists.
 */
export async function resolveKey(env: Env, tail: string): Promise<string | null> {
  if (!tail.startsWith('latest/')) return tail;
  const manifest = await loadManifest(env);
  if (!manifest?.latest) return null;
  return `${manifest.latest}/${tail.slice('latest/'.length)}`;
}

/**
 * Log a download event to the canonical cross-property analytics hub
 * (analytics.testifysec.com/ingest/web), best-effort and non-blocking. Downloads no
 * longer go to a local D1 table; the hub is the single source of truth for
 * cross-property analytics.
 *
 * A download is an AGGREGATE functional count — we send NO visitor PII (no cookies, no
 * visitor_id/session_id). The hub treats type='dl' as a consent-exempt aggregate, derives
 * country from request.cf of this POST, and parses the asset filename
 * (cilock-<version>-<os>-<arch>.tar.gz) for version/os/arch display. Failures are
 * swallowed (logged) so a hub outage never breaks a download.
 */
export function logDownload(
  context: { env: Env; waitUntil: (p: Promise<unknown>) => void; request: Request },
  rec: { path: string; asset: string; version: string | null },
): void {
  const endpoint = context.env.CILOCK_ANALYTICS_HUB || ANALYTICS_HUB_DEFAULT;
  // `query` carries the asset key/filename; the hub parses os/arch/version from it.
  const asset = (rec.asset.split('/').pop() || rec.asset).slice(0, 256);
  const body = JSON.stringify({
    source: 'cilock.dev',
    kind: 'event',
    type: 'dl',
    key: ANALYTICS_HUB_KEY,
    path: rec.path.slice(0, 256),
    query: asset,
  });

  console.log(`DOWNLOAD ${JSON.stringify({ asset, version: rec.version, endpoint })}`);

  context.waitUntil(
    fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    })
      .then(() => undefined)
      .catch((e) => console.log(`DOWNLOAD_HUB_ERR ${String(e)}`)),
  );
}

/**
 * Serve a single, version-agnostic file straight from the R2 root (no manifest
 * resolution, no download event). Used by the /install.sh{,.sig,.cert} routes and
 * the /policy/* routes. 404 when the object is absent.
 */
export async function serveRootObject(
  env: Env,
  method: string,
  key: string,
  opts: { cacheControl: string },
): Promise<Response> {
  if (!env.DIST) return new Response('Distribution not configured', { status: 503 });
  if (method !== 'GET' && method !== 'HEAD') {
    return new Response('Method Not Allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
  }
  const obj = method === 'HEAD' ? await env.DIST.head(key) : await env.DIST.get(key);
  if (!obj) return new Response('Not Found', { status: 404 });

  const name = key.split('/').pop() || key;
  const headers = new Headers();
  (obj as R2Object).writeHttpMetadata(headers);
  if (!headers.has('content-type')) headers.set('content-type', contentTypeFor(name));
  headers.set('etag', (obj as R2Object).httpEtag);
  if (typeof (obj as R2Object).size === 'number') headers.set('content-length', String((obj as R2Object).size));
  headers.set('cache-control', opts.cacheControl);
  headers.set('x-content-type-options', 'nosniff');

  if (method === 'HEAD') return new Response(null, { status: 200, headers });
  return new Response((obj as R2ObjectBody).body, { status: 200, headers });
}

/**
 * Stream an R2 object as an HTTP response with correct headers. Used by all three
 * distribution functions. `immutable` enables long-lived caching for versioned paths.
 */
export function r2Response(obj: R2ObjectBody, name: string, opts: { immutable: boolean }): Response {
  const headers = new Headers();
  obj.writeHttpMetadata(headers); // carries any stored content-type/encoding
  if (!headers.has('content-type')) headers.set('content-type', contentTypeFor(name));
  headers.set('etag', obj.httpEtag);
  if (typeof obj.size === 'number') headers.set('content-length', String(obj.size));
  if (isAttachment(name)) {
    const base = name.split('/').pop() || name;
    headers.set('content-disposition', `attachment; filename="${base}"`);
  }
  headers.set(
    'cache-control',
    opts.immutable ? 'public, max-age=31536000, immutable' : 'public, max-age=300',
  );
  headers.set('x-content-type-options', 'nosniff');
  return new Response(obj.body, { status: 200, headers });
}
