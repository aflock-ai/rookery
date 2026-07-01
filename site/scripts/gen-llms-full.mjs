#!/usr/bin/env node
// gen-llms-full.mjs — postbuild hook that assembles /llms-full.txt from the docs
// sources, following the llmstxt.org convention (title, summary, then the full
// content of each doc under a source header).
//
// Why postbuild and not static/: static/ is copied verbatim into build/ DURING
// `docusaurus build`, so a file written to static/ after the build has already
// been copied would be missed. Writing directly into build/ in the `postbuild`
// npm hook — the same contract strip-build-nul.mjs uses — guarantees the file
// lands at the site root (/llms-full.txt) on every regen, including the
// cilock.dev deploy. build/ is gitignored and regenerated, so this cannot drift.
//
// The short index (/llms.txt, hand-maintained in static/) is the curated map;
// /llms-full.txt is the full-text corpus an LLM can ingest in one fetch.
//
// Usage:  node scripts/gen-llms-full.mjs   (run automatically after build)

import {readdirSync, readFileSync, writeFileSync, statSync, existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join, relative, sep} from 'node:path';

const SITE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const DOCS_DIR = join(SITE_DIR, 'docs');
const BUILD_DIR = join(SITE_DIR, 'build');
const STATIC_LLMS = join(SITE_DIR, 'static', 'llms.txt');
const OUT_FILE = join(BUILD_DIR, 'llms-full.txt');

const SITE_URL = 'https://cilock.dev';

// Recursively collect .md/.mdx doc sources, sorted for deterministic output.
function walkDocs(dir, out) {
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      walkDocs(full, out);
    } else if (name.endsWith('.md') || name.endsWith('.mdx')) {
      out.push(full);
    }
  }
}

// Split leading YAML front-matter (--- ... ---) from the markdown body.
function splitFrontMatter(src) {
  if (!src.startsWith('---')) return {fm: {}, body: src};
  const end = src.indexOf('\n---', 3);
  if (end === -1) return {fm: {}, body: src};
  const raw = src.slice(3, end).trim();
  const body = src.slice(end + 4).replace(/^\n+/, '');
  const fm = {};
  for (const line of raw.split('\n')) {
    const m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (m) fm[m[1]] = m[2].replace(/^['"]|['"]$/g, '').trim();
  }
  return {fm, body};
}

// Canonical, trailing-slashed doc URL. docs routeBasePath is '/', so
// docs/intro.md -> /intro/ and docs/concepts/trust-model.md -> /concepts/trust-model/.
// Respects a front-matter `slug` override when present.
function docUrl(file, fm) {
  if (fm.slug) {
    const s = fm.slug.startsWith('/') ? fm.slug : '/' + fm.slug;
    return SITE_URL + (s.endsWith('/') ? s : s + '/');
  }
  let rel = relative(DOCS_DIR, file).split(sep).join('/');
  rel = rel.replace(/\.mdx?$/, '');
  if (rel.endsWith('/index')) rel = rel.slice(0, -'/index'.length);
  if (rel === 'index') rel = '';
  return SITE_URL + '/' + (rel ? rel + '/' : '');
}

// Reuse the hand-maintained llms.txt title + summary verbatim as the header.
function headerFromLlmsTxt() {
  if (!existsSync(STATIC_LLMS)) {
    return '# cilock — full docs corpus\n';
  }
  const lines = readFileSync(STATIC_LLMS, 'utf8').split('\n');
  const out = [];
  for (const line of lines) {
    // Keep the H1 title and the leading `>` summary block; stop at the first
    // section heading (## Docs, ## Concepts, ...) which is the curated index.
    if (line.startsWith('## ')) break;
    out.push(line);
  }
  return out.join('\n').trimEnd() + '\n';
}

function main() {
  if (!existsSync(BUILD_DIR)) {
    console.error(`[gen-llms-full] no build dir at ${BUILD_DIR}; run after \`docusaurus build\``);
    process.exit(1);
  }
  if (!existsSync(DOCS_DIR)) {
    console.error(`[gen-llms-full] no docs dir at ${DOCS_DIR}`);
    process.exit(1);
  }

  const files = [];
  walkDocs(DOCS_DIR, files);

  const parts = [];
  parts.push(headerFromLlmsTxt());
  parts.push(
    '\nThis file (/llms-full.txt) is the full-text corpus of the CI/lock docs, ' +
      'concatenated per the llmstxt.org convention. Each section below is one doc ' +
      'page, preceded by a source header with its canonical URL.\n',
  );

  let docCount = 0;
  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    const {fm, body} = splitFrontMatter(src);
    const url = docUrl(file, fm);
    const title = fm.title || fm.id || relative(DOCS_DIR, file);
    parts.push('\n---\n');
    parts.push(`# ${title}\n`);
    parts.push(`Source: ${url}\n`);
    parts.push('\n' + body.trimEnd() + '\n');
    docCount++;
  }

  const output = parts.join('');
  writeFileSync(OUT_FILE, output, 'utf8');
  console.log(
    `[gen-llms-full] wrote ${OUT_FILE} (${docCount} docs, ${output.length} bytes).`,
  );
}

main();
