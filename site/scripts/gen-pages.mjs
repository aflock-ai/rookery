#!/usr/bin/env node
// Generate one tool/attestor page per catalog entry that has a doc.
//
// Reads _generated/catalog/<name>.json (produced by gen-catalog.mjs) and
// writes docs/{attestors,tools}/<name>.mdx — fully generated: frontmatter +
// metadata component + JSON-LD + the authored body sections + footer.
//
// Versioned attestors (a bare `<base>` plus `<base>-vX.Y` variants, e.g.
// product + product-v0.1 + product-v0.2) collapse into ONE page for the
// base: the latest version shows by default, a dropdown switches to older
// versions. Variant entries do NOT get their own page.
//
// Entries without a doc are skipped so we don't clobber un-migrated pages.
// URL area (attestors vs tools) is preserved from any existing page.
//
// Usage: node scripts/gen-pages.mjs   (after npm run gen:catalog)

import {existsSync, readdirSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {normalizeLinks} from './_links.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '..');
const CAT = join(REPO, '_generated', 'catalog');
const DOCS = join(REPO, 'docs');

function areaFor(name, entry) {
  for (const area of ['attestors', 'tools']) {
    if (existsSync(join(DOCS, area, `${name}.md`)) || existsSync(join(DOCS, area, `${name}.mdx`))) {
      return area;
    }
  }
  return entry.source === 'attestor-backed' && entry.predicateType ? 'attestors' : 'tools';
}

function yamlEscape(s) {
  // Escape the backslash FIRST, then the quote, so a literal backslash in the
  // input can't combine with a following quote to break the YAML string.
  return String(s || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// Version label for an entry: prefer the predicate type's trailing vX.Y,
// else the name's -vX.Y suffix, else "v0.1".
function versionLabel(entry) {
  let m = (entry.predicateType || '').match(/\/v(\d+\.\d+)$/);
  if (m) return `v${m[1]}`;
  m = entry.name.match(/-v(\d+\.\d+)$/);
  return m ? `v${m[1]}` : 'v0.1';
}

function importIdent(version) {
  return 'meta_' + version.replace(/[^a-z0-9]+/gi, '_');
}

function jsonLd(entry, area) {
  const ld = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: `${entry.title} — cilock ${area === 'attestors' ? 'attestor' : 'tool integration'}`,
    description: entry.description,
    url: `https://cilock.dev/${area}/${entry.name}`,
  };
  return `<script type="application/ld+json" dangerouslySetInnerHTML={{__html: ${JSON.stringify(
    JSON.stringify(ld),
  )}}} />`;
}

// Render one version's inner content: overview lead + metadata component +
// the rest of the sections. `metaVar` is the import identifier to feed the
// component.
function renderInner(entry, Comp, metaVar) {
  const overview = (entry.docSections || []).find((s) => s.slug === 'overview');
  const rest = (entry.docSections || []).filter((s) => s.slug !== 'overview');
  const out = [];
  if (overview) out.push(overview.markdown, '');
  out.push(`<${Comp} data={${metaVar}} />`, '');
  for (const s of rest) out.push(s.markdown, '');
  return out.join('\n');
}

function frontmatter(entry) {
  const fm = ['---', `title: ${JSON.stringify(entry.title)}`];
  if (entry.description) fm.push(`description: "${yamlEscape(entry.description)}"`);
  if (entry.sidebarPosition) fm.push(`sidebar_position: ${entry.sidebarPosition}`);
  fm.push('---');
  return fm.join('\n');
}

const GEN_NOTE = (name) =>
  `{/* GENERATED — do not edit. Source: rookery attestation/detection/docs/${name}.doc.md. Regenerate: npm run gen */}`;

// A single-version (non-versioned) page.
function renderSimple(entry) {
  const area = areaFor(entry.name, entry);
  const isAttestor = area === 'attestors';
  const Comp = isAttestor ? 'AttestorMeta' : 'ToolMeta';
  const lines = [
    frontmatter(entry),
    '',
    GEN_NOTE(entry.name),
    `import ${Comp} from '@site/src/components/Catalog/${Comp}';`,
    `import GeneratedFooter from '@site/src/components/Catalog/GeneratedFooter';`,
    `import meta from '@catalog/${entry.name}.json';`,
    '',
    `# \`${entry.name}\` ${isAttestor ? 'attestor' : 'integration'}`,
    '',
    renderInner(entry, Comp, 'meta'),
    jsonLd(entry, area),
    '',
    `<GeneratedFooter name="${entry.name}" />`,
    '',
  ];
  return {area, body: lines.join('\n')};
}

// A versioned page: base + variants, newest first, behind a dropdown.
function renderVersioned(base, group) {
  const latest = group.find((g) => g.isLatest) || group[0];
  const area = areaFor(base.name, base);
  const isAttestor = area === 'attestors';
  const Comp = isAttestor ? 'AttestorMeta' : 'ToolMeta';
  const ordered = [...group].sort((a, b) => (a.version < b.version ? 1 : -1)); // desc

  const imports = ordered.map(
    (g) => `import ${importIdent(g.version)} from '@catalog/${g.entry.name}.json';`,
  );
  const versionsArr = JSON.stringify(ordered.map((g) => g.version));

  const lines = [
    frontmatter(base),
    '',
    GEN_NOTE(base.name),
    `import ${Comp} from '@site/src/components/Catalog/${Comp}';`,
    `import GeneratedFooter from '@site/src/components/Catalog/GeneratedFooter';`,
    `import VersionedDoc, {VersionPane} from '@site/src/components/Catalog/VersionedDoc';`,
    ...imports,
    '',
    `# \`${base.name}\` ${isAttestor ? 'attestor' : 'integration'}`,
    '',
    `<VersionedDoc versions={${versionsArr}} latest="${latest.version}">`,
    '',
  ];
  for (const g of ordered) {
    lines.push(`<VersionPane version="${g.version}">`, '');
    lines.push(renderInner(g.entry, Comp, importIdent(g.version)));
    lines.push(`</VersionPane>`, '');
  }
  lines.push('</VersionedDoc>', '');
  lines.push(jsonLd(latest.entry, area), '');
  lines.push(`<GeneratedFooter name="${base.name}" />`, '');
  return {area, body: lines.join('\n')};
}

function main() {
  const files = readdirSync(CAT).filter((f) => f.endsWith('.json') && f !== 'index.json');
  const entries = {};
  for (const f of files) {
    const e = JSON.parse(readFileSync(join(CAT, f), 'utf8'));
    entries[e.name] = e;
  }

  // Build version groups: base -> [{version, name, entry, isLatest}].
  const groups = {};
  for (const name of Object.keys(entries)) {
    const m = name.match(/^(.*)-v(\d+\.\d+)$/);
    if (m && entries[m[1]]) {
      (groups[m[1]] ||= []).push({version: `v${m[2]}`, name, entry: entries[name], isLatest: false});
    }
  }
  for (const base of Object.keys(groups)) {
    const e = entries[base];
    groups[base].push({version: versionLabel(e), name: base, entry: e, isLatest: true});
  }
  const variantNames = new Set();
  for (const base of Object.keys(groups)) {
    for (const g of groups[base]) if (!g.isLatest) variantNames.add(g.name);
  }

  let written = 0;
  for (const name of Object.keys(entries)) {
    if (variantNames.has(name)) continue; // folded into its base page
    const entry = entries[name];
    let page;
    if (groups[name]) {
      if (!entry.hasDoc) continue; // base must have a doc to anchor the page
      page = renderVersioned(entry, groups[name]);
    } else {
      if (!entry.hasDoc) continue;
      page = renderSimple(entry);
    }
    const md = join(DOCS, page.area, `${name}.md`);
    if (existsSync(md)) rmSync(md);
    const body = normalizeLinks(page.body, join(DOCS, page.area));
    writeFileSync(join(DOCS, page.area, `${name}.mdx`), body);
    written++;
    console.log(`[gen-pages] ${page.area}/${name}.mdx${groups[name] ? ` (versions: ${groups[name].map((g) => g.version).join(', ')})` : ''}`);
  }
  console.log(`[gen-pages] generated ${written} page(s)`);
}

main();
