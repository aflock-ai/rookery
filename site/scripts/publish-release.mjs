#!/usr/bin/env node
/**
 * publish-release.mjs — UPLOAD a cilock.dev release to Cloudflare R2.
 *
 * Given a local directory of release artifacts and a version, this script:
 *   1. Uploads the artifacts to the R2 bucket (default cilock-dist) under
 *      <version>/<file>, via the S3 API (rclone) or wrangler.
 *   2. Promotes version-agnostic files (install.sh{,.sig,.cert}, the release
 *      policy) to canonical root keys, and writes/updates manifest.json with the
 *      new version + a "latest" pointer.
 *   3. Writes a per-version `verification` block into manifest.json indexing the
 *      OFFLINE-verification material the release publishes alongside the binaries
 *      (the signed policy, the Fulcio CA + Root CA `fulcio-roots.pem`, the TSA
 *      `tsa-chain.pem`, and each binary's per-step DSSE envelopes and required
 *      inventory companions with sha256s). This lets a PUBLIC downloader run
 *      `cilock verify --platform-url ""` with no platform/tenant/Archivista access.
 *
 * VERIFICATION (the publish gate) is still the CALLER's responsibility. In the
 * release fan-out (.github/workflows/release-fanout.yml) the `verify` job verifies
 * every binary ONLINE against the platform-trust policy (`cilock verify
 * --platform-url --enable-archivista`, attestations pulled from Archivista by
 * subject digest) and BLOCKS publish on any failure — this script runs only after
 * that gate. The `verification` block this script writes is the material for a
 * DOWNLOADER's later offline re-verify, NOT a gate on this upload.
 *
 * Usage:
 *   node scripts/publish-release.mjs --dir ./dist/v1.2.0 --version v1.2.0 [options]
 *   npm run publish:release -- --dir ./dist/v1.2.0 --version v1.2.0
 *
 * Options:
 *   --dir <path>        Directory of release artifacts (required).
 *   --version <vX.Y.Z>  Release version (required).
 *   --bucket <name>     R2 bucket (default: cilock-dist).
 *   --policy <file>     Release policy file in --dir to publish (default:
 *                       release-policy.json). Uploaded to policy/<file>.
 *   --latest            Mark this version "latest" (default: true for a higher
 *                       semver; --no-latest to skip; pre-releases default to no).
 *   --dry-run           Plan only; perform no R2 writes.
 *   --remote / --local  wrangler r2 target (default: --remote).
 *
 * R2 credentials (env): R2_S3_ACCESS_KEY_ID / R2_S3_SECRET_ACCESS_KEY /
 *   R2_S3_ENDPOINT (preferred, rclone S3), or CLOUDFLARE_ACCOUNT_ID /
 *   CLOUDFLARE_API_TOKEN (wrangler fallback).
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const MANIFEST_KEY = 'manifest.json';

function parseArgs(argv) {
  const out = { bucket: 'cilock-dist', policy: 'release-policy.json', target: '--remote', latest: undefined, dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--dir': out.dir = argv[++i]; break;
      case '--version': out.version = argv[++i]; break;
      case '--bucket': out.bucket = argv[++i]; break;
      case '--policy': out.policy = argv[++i]; break;
      case '--latest': out.latest = true; break;
      case '--no-latest': out.latest = false; break;
      case '--dry-run': out.dryRun = true; break;
      case '--remote': out.target = '--remote'; break;
      case '--local': out.target = '--local'; break;
      default: die(`unknown argument: ${a}`);
    }
  }
  return out;
}

function die(msg) {
  console.error(`publish-release: ERROR: ${msg}`);
  process.exit(1);
}

function run(cmd, args, opts = {}) {
  console.log(`+ ${cmd} ${args.join(' ')}`);
  const r = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  if (r.error) die(`failed to run ${cmd}: ${r.error.message}`);
  return r.status ?? 1;
}

function sha256Hex(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function inventoryStatement(payload) {
  // Native parsing validates grammar first. Scan byte offsets, not a reserialized
  // object: internal whitespace, escapes and UTF-8 are part of the commitment.
  const statement = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload));
  if (!statement || Array.isArray(statement) || typeof statement !== 'object') throw new Error('expected statement object');
  let i = 0;
  let predicateBytes;
  const whitespace = () => {
    while ([0x20, 0x09, 0x0a, 0x0d].includes(payload[i])) i++;
  };
  const string = () => {
    const start = i++;
    while (payload[i] !== 0x22) {
      if (payload[i] === 0x5c) i++;
      i++;
    }
    const value = JSON.parse(payload.subarray(start, ++i).toString('utf8'));
    for (const char of value) {
      const code = char.codePointAt(0);
      if (code >= 0xd800 && code <= 0xdfff) throw new Error('unpaired Unicode surrogate');
    }
    return value;
  };
  const value = (depth) => {
    if (depth > 128) throw new Error('JSON nesting exceeds 128');
    whitespace();
    const token = payload[i];
    if (token === 0x22) { string(); return; }
    if (token === 0x7b || token === 0x5b) {
      const object = token === 0x7b;
      const end = object ? 0x7d : 0x5d;
      const keys = new Set();
      i++;
      whitespace();
      while (payload[i] !== end) {
        let key;
        if (object) {
          key = string();
          if (keys.has(key)) throw new Error('duplicate JSON key');
          keys.add(key);
          whitespace();
          i++; // Colon; grammar has already been checked by JSON.parse.
          whitespace();
        }
        const start = i;
        value(depth + 1);
        if (depth === 0 && key === 'predicate') predicateBytes = payload.subarray(start, i);
        whitespace();
        if (payload[i] === end) break;
        i++; // Comma.
        whitespace();
      }
      i++;
      return;
    }
    while (i < payload.length && ![0x20, 0x09, 0x0a, 0x0d, 0x2c, 0x7d, 0x5d].includes(payload[i])) i++;
  };
  value(0);
  if (!predicateBytes || !statement.predicate || Array.isArray(statement.predicate) || typeof statement.predicate !== 'object') {
    throw new Error('expected inventory predicate object');
  }
  return { statement, predicateBytes };
}

// Tools published through this lane (release-fanout.yml builds + verifies both).
// The download UIs and install.sh stay cilock-only by design — they filter by
// the cilock- name prefix; jctl's front door is the platform /tools page.
const TOOLS = ['cilock', 'jctl'];
const TOOL_ALT = TOOLS.join('|');

/** tool/os/arch parsed from <tool>-<version>-<os>-<arch>.tar.gz; nulls for non-binaries. */
function parseBinaryName(name) {
  const m = new RegExp(`^(${TOOL_ALT})-[^-]+(?:-[^-]+)*?-(\\w+)-(\\w+)\\.(?:tar\\.gz|tgz|zip)$`).exec(name);
  return m ? { tool: m[1], os: m[2], arch: m[3] } : { tool: null, os: null, arch: null };
}

function isBinaryTarball(name) {
  const { os } = parseBinaryName(name);
  return os !== null;
}

/** A simple "is a pre-release" check: any version with a hyphen (e.g. -rc1, -beta). */
function isPrerelease(version) {
  return version.includes('-');
}

// buildVerification assembles the per-version `verification` block that lets a
// downloader run `cilock verify --platform-url ""` FULLY OFFLINE — no platform,
// tenant, or Archivista access. It references the published trust material and
// the per-binary DSSE attestation envelopes (BOTH the source-git and build
// envelopes are required for the verify to pass), each with its sha256.
//
//   policy      — canonical root key for the signed release policy.
//   fulcioRoots — <version>/fulcio-roots.pem (Fulcio CA + platform Root CA).
//   tsaChain    — <version>/tsa-chain.pem (RFC3161 TSA cert chain).
//   attestations[] — one entry per binary, with source-git + build, optional sign,
//                    and all required inventory envelopes + sha256s.
//
// Required envelopes and detached companions fail closed before any upload.
// This checks transport completeness, not signatures or policy: those remain
// the caller's verification gate. A local file is never proof of Archivista upload.
function buildVerification(dir, allFiles, version, policyName) {
  const v = {};
  if (allFiles.includes(policyName)) v.policy = `policy/${policyName}`;
  if (allFiles.includes('fulcio-roots.pem')) v.fulcioRoots = `${version}/fulcio-roots.pem`;
  if (allFiles.includes('tsa-chain.pem')) v.tsaChain = `${version}/tsa-chain.pem`;

  const binaries = allFiles.filter(isBinaryTarball);
  const attestations = [];
  for (const tarball of binaries) {
    const { os, arch } = parseBinaryName(tarball);
    const prefix = tarball.replace(/\.(tar\.gz|tgz|zip)$/, '');
    const envelopes = [];
    const steps = ['source-git', 'build'];
    if (allFiles.includes(`${prefix}.sign.att.json`)) steps.push('sign');
    for (const step of steps) {
      const name = `${prefix}.${step}.att.json`;
      if (!allFiles.includes(name)) die(`${tarball}: missing required envelope ${name}`);
      envelopes.push({ step, file: `${version}/${name}`, sha256: sha256Hex(join(dir, name)) });
      const parent = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(dir, name), 'utf8')).payload, 'base64').toString('utf8'));
      for (const kind of ['material', 'product']) {
        const att = parent.predicate?.attestations?.find((a) => a.type === `https://aflock.ai/attestations/${kind}/v0.3`);
        const ref = att?.attestation?.inventory;
        if (!ref) continue; // Inline or empty captured set.
        const inventoryType = 'https://aflock.ai/attestations/file-inventory/v0.1';
        if (ref.schema !== inventoryType || ref.kind !== kind || ref.state !== 'detached') {
          die(`${name}: invalid ${kind} inventory; release chain details must be retained`);
        }
        const companion = `${name}-${kind}-inventory.json`;
        if (!allFiles.includes(companion)) die(`${name}: missing required inventory ${companion}`);
        let statement, predicateBytes;
        try {
          ({ statement, predicateBytes } = inventoryStatement(Buffer.from(JSON.parse(readFileSync(join(dir, companion), 'utf8')).payload, 'base64')));
        } catch (error) {
          die(`${companion}: invalid inventory statement: ${error.message}`);
        }
        if (statement.predicateType !== inventoryType || statement.predicate?.schema !== inventoryType || statement.predicate?.kind !== kind ||
            !Number.isSafeInteger(ref.bytes) || ref.bytes < 1 || ref.bytes > 64 * 1024 * 1024 || predicateBytes.length !== ref.bytes ||
            createHash('sha256').update(predicateBytes).digest('hex') !== ref.digest ||
            !Number.isSafeInteger(ref.fileCount) || ref.fileCount < 1 || ref.fileCount > 1000000 ||
            !Array.isArray(statement.predicate.entries) || statement.predicate.entries.length !== ref.fileCount ||
            !statement.subject?.some((s) => s.name === `inventory:${kind}` && s.digest?.sha256 === ref.digest)) {
          die(`${companion}: inventory does not match its parent reference`);
        }
        // Existing download consumers fetch every envelopes[] entry. Keep the
        // companion here, not in an optional field that older consumers ignore.
        envelopes.push({ step, kind, predicateType: inventoryType, file: `${version}/${companion}`, sha256: sha256Hex(join(dir, companion)) });
      }
    }
    const entry = {
      binary: tarball,
      os,
      arch,
      envelopes,
    };
    attestations.push(entry);
  }
  if (attestations.length > 0) v.attestations = attestations;

  // Only emit the block when it carries something an offline verify can use.
  return Object.keys(v).length > 0 ? v : undefined;
}

// --- main -------------------------------------------------------------------

const opts = parseArgs(process.argv.slice(2));
if (!opts.dir) die('--dir is required');
if (!opts.version) die('--version is required');
if (!existsSync(opts.dir) || !statSync(opts.dir).isDirectory()) die(`--dir not a directory: ${opts.dir}`);
if (!/^v?\d+\.\d+/.test(opts.version)) die(`--version does not look like a version: ${opts.version}`);

const policyPath = join(opts.dir, opts.policy);
if (!existsSync(policyPath)) die(`release policy not found in --dir: ${policyPath}`);

const allFiles = readdirSync(opts.dir).filter((f) => statSync(join(opts.dir, f)).isFile());
const binaries = allFiles.filter(isBinaryTarball);
if (binaries.length === 0) die(`no binary tarballs ({${TOOLS.join(',')}}-*-<os>-<arch>.tar.gz) found in ${opts.dir}`);

// NOTE: no verification here. The release fan-out's `verify` job already verified
// every binary ONLINE against the platform-trust policy (fail-closed) before this
// script runs. The old offline attestation-sidecar verify-then-upload was an alpha
// pattern and has been removed — this is now strictly an uploader.
console.log(`\n== Publishing ${binaries.length} binaries (verified upstream) ==`);

// --- Stage 2: plan the upload + manifest -----------------------------------

console.log(`\n== Stage 2: PLAN upload to r2://${opts.bucket} ==`);

// Version-agnostic root promotions: name in --dir -> canonical root key.
const rootPromotions = {
  'install.sh': 'install.sh',
  'install.sh.sig': 'install.sh.sig',
  'install.sh.cert': 'install.sh.cert',
  [opts.policy]: `policy/${opts.policy}`,
};

// Versioned files: everything in --dir lands at <version>/<file>.
const manifestFiles = allFiles.map((name) => {
  const { os, arch } = parseBinaryName(name);
  const entry = { name, sha256: sha256Hex(join(opts.dir, name)), size: statSync(join(opts.dir, name)).size };
  if (os) entry.os = os;
  if (arch) entry.arch = arch;
  return entry;
});

const verification = buildVerification(opts.dir, allFiles, opts.version, opts.policy);
const newVersion = { version: opts.version, released: new Date().toISOString(), files: manifestFiles };
// Per-version offline-verification material (trust roots + per-binary envelopes).
// Backward-compatible: a consumer that doesn't know the field (install.sh reads
// only `latest` + per-file sha256) ignores it. Omitted entirely when absent.
if (verification) newVersion.verification = verification;

// Decide "latest": explicit flag wins; otherwise promote unless it's a pre-release.
const promoteLatest = opts.latest === undefined ? !isPrerelease(opts.version) : opts.latest;

const attestedBinaries = verification?.attestations?.length ?? 0;
console.log(`   version:       ${opts.version}`);
console.log(`   files:         ${allFiles.length} -> ${opts.version}/<file>`);
console.log(`   root promote:  ${Object.entries(rootPromotions).filter(([k]) => allFiles.includes(k)).map(([k, v]) => `${k}->${v}`).join(', ') || '(none present)'}`);
console.log(`   verification:  ${verification ? `policy=${verification.policy ?? '-'} fulcioRoots=${verification.fulcioRoots ? 'yes' : 'no'} tsaChain=${verification.tsaChain ? 'yes' : 'no'} attestedBinaries=${attestedBinaries}` : '(none — no trust/envelopes in --dir)'}`);
console.log(`   latest:        ${promoteLatest ? `YES (manifest.latest=${opts.version})` : 'no (pre-release or --no-latest)'}`);

if (opts.dryRun) {
  console.log('\n--dry-run: stopping before any R2 write.');
  console.log('\nManifest entry that WOULD be written:');
  console.log(JSON.stringify(newVersion, null, 2));
  process.exit(0);
}

// --- Stage 3: upload --------------------------------------------------------

console.log(`\n== Stage 3: UPLOAD (${opts.target}) ==`);

// Upload backend. R2 "Object Read & Write" tokens are S3 credentials — they do
// NOT carry the "Workers R2 Storage" permission that `wrangler r2 object put`
// (Cloudflare REST API) requires, so wrangler 403s with them. When S3 creds are
// present we upload via the S3 API with rclone (--s3-no-check-bucket: the token
// can write objects but not create/inspect the bucket); otherwise fall back to
// wrangler for a Workers-R2-Storage Bearer token.
const s3 = {
  // .trim(): a secret set via an interactive `gh secret set` prompt can pick up
  // a trailing newline, which corrupts the SigV4 signature and yields an opaque
  // S3 "403 Forbidden" — so normalize defensively.
  keyId: (process.env.R2_S3_ACCESS_KEY_ID || '').trim(),
  secret: (process.env.R2_S3_SECRET_ACCESS_KEY || '').trim(),
  endpoint: (process.env.R2_S3_ENDPOINT || '').trim(),
};
const useS3 = Boolean(s3.keyId && s3.secret && s3.endpoint);
const rcloneEnv = useS3
  ? {
      ...process.env,
      RCLONE_CONFIG_R2_TYPE: 's3',
      RCLONE_CONFIG_R2_PROVIDER: 'Cloudflare',
      RCLONE_CONFIG_R2_ACCESS_KEY_ID: s3.keyId,
      RCLONE_CONFIG_R2_SECRET_ACCESS_KEY: s3.secret,
      RCLONE_CONFIG_R2_ENDPOINT: s3.endpoint,
    }
  : null;
console.log(`   upload backend: ${useS3 ? 'rclone (S3 API)' : 'wrangler (Cloudflare REST)'}`);

function r2Put(localPath, key) {
  const status = useS3
    ? run('rclone', ['copyto', '--s3-no-check-bucket', localPath, `R2:${opts.bucket}/${key}`], { env: rcloneEnv })
    : run('wrangler', ['r2', 'object', 'put', `${opts.bucket}/${key}`, '--file', localPath, opts.target]);
  if (status !== 0) die(`upload failed for ${key} (exit ${status}) — bucket may be partially updated; re-run to converge.`);
}

// r2Get downloads an object to localPath; returns the child exit code (non-zero
// when the object is absent — used to detect "no existing manifest").
function r2Get(key, localPath) {
  return useS3
    ? run('rclone', ['copyto', '--s3-no-check-bucket', `R2:${opts.bucket}/${key}`, localPath], { env: rcloneEnv })
    : run('wrangler', ['r2', 'object', 'get', `${opts.bucket}/${key}`, '--file', localPath, opts.target]);
}

// 3a. versioned objects
for (const name of allFiles) r2Put(join(opts.dir, name), `${opts.version}/${name}`);

// 3b. root promotions (installer + policy)
for (const [name, key] of Object.entries(rootPromotions)) {
  if (allFiles.includes(name)) r2Put(join(opts.dir, name), key);
}

// 3c. merge + write the manifest. Pull the existing one first so we don't lose history.
console.log('\n== Stage 4: MANIFEST ==');
const tmp = mkdtempSync(join(tmpdir(), 'cilock-pub-'));
const localManifest = join(tmp, MANIFEST_KEY);
let manifest = { schema: 1, latest: '', versions: [] };
const getStatus = r2Get(MANIFEST_KEY, localManifest);
if (getStatus === 0 && existsSync(localManifest)) {
  try { manifest = JSON.parse(readFileSync(localManifest, 'utf8')); } catch { console.log('   existing manifest unparseable; starting fresh'); }
} else {
  console.log('   no existing manifest; creating a new one');
}
if (manifest.schema !== 1) manifest.schema = 1;
if (!Array.isArray(manifest.versions)) manifest.versions = [];

// Replace any existing entry for this version, then put the new one at the front.
manifest.versions = manifest.versions.filter((v) => v.version !== opts.version);
manifest.versions.unshift(newVersion);
if (promoteLatest) manifest.latest = opts.version;
if (!manifest.latest) manifest.latest = opts.version; // first publish
manifest.updated = new Date().toISOString();

writeFileSync(localManifest, JSON.stringify(manifest, null, 2));
r2Put(localManifest, MANIFEST_KEY);

console.log(`\nDONE. Published ${opts.version} (${allFiles.length} files). manifest.latest=${manifest.latest}.`);
console.log(`Verify the live manifest:  curl -fsSL https://cilock.dev/manifest.json | jq .`);
