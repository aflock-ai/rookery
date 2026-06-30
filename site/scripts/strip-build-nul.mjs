#!/usr/bin/env node
// strip-build-nul.mjs — postbuild guard that removes spurious NUL bytes from the
// built HTML.
//
// Root cause (confirmed empirically, not the catalog pipeline): Docusaurus
// 3.10.1's static-site render inserts one or more stray 0x00 bytes immediately
// BEFORE certain multi-byte UTF-8 sequences (em-dash U+2014, box-drawing chars
// U+2500.., zero-width-space U+200B) in the server-rendered HTML. The insertion
// survives both `SKIP_HTML_MINIFICATION` and terser `ascii_only:false`, so it is
// upstream of the minifiers. The real content is untouched — the NUL is purely
// inserted next to the multi-byte char — so deleting every 0x00 byte from the
// built HTML is lossless: it restores byte-for-byte-correct markup.
//
// This runs as a `postbuild` npm hook, so it re-applies on every `npm run build`
// (including the cilock.dev deploy). It is NOT a one-time strip of committed
// bytes (build/ is gitignored and regenerated) — it is wired into the build
// contract, so it cannot evaporate on the next regen.
//
// Usage:  node scripts/strip-build-nul.mjs   (run automatically after build)

import {readdirSync, readFileSync, writeFileSync, statSync, existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';

const SITE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const BUILD_DIR = join(SITE_DIR, 'build');

const NUL = 0x00;

function walkHtml(dir, out) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      walkHtml(full, out);
    } else if (name.endsWith('.html')) {
      out.push(full);
    }
  }
}

function main() {
  if (!existsSync(BUILD_DIR)) {
    console.error(`[strip-build-nul] no build dir at ${BUILD_DIR}; run after \`docusaurus build\``);
    process.exit(1);
  }

  const files = [];
  walkHtml(BUILD_DIR, files);

  let cleanedFiles = 0;
  let removedBytes = 0;
  for (const f of files) {
    const buf = readFileSync(f);
    const idx = buf.indexOf(NUL);
    if (idx === -1) continue;
    const filtered = buf.filter((b) => b !== NUL); // Buffer.filter -> Uint8Array
    removedBytes += buf.length - filtered.length;
    writeFileSync(f, Buffer.from(filtered));
    cleanedFiles++;
  }

  if (cleanedFiles) {
    console.log(
      `[strip-build-nul] removed ${removedBytes} stray NUL byte(s) from ${cleanedFiles} built HTML file(s).`,
    );
  } else {
    console.log(`[strip-build-nul] OK: no NUL bytes in ${files.length} built HTML file(s).`);
  }
}

main();
