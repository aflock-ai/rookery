// One-time: normalize the stale catalog "See also" links in existing
// tool/attestor pages (both generated .mdx and hand-written .md) in place.
import {readdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve, dirname} from 'node:path';
import {normalizeLinks} from './_links.mjs';

const DOCS = resolve('docs');
let changed = 0;
for (const area of ['tools', 'attestors']) {
  const dir = join(DOCS, area);
  for (const f of readdirSync(dir)) {
    if (!/\.(md|mdx)$/.test(f)) continue;
    const p = join(dir, f);
    const before = readFileSync(p, 'utf8');
    const after = normalizeLinks(before, dir);
    if (after !== before) {
      writeFileSync(p, after);
      changed++;
      console.log(`fixed links: ${area}/${f}`);
    }
  }
}
console.log(`\n${changed} files updated`);
