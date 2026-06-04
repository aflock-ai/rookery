#!/usr/bin/env node
// Generate the machine-readable catalog the docs render from.
//
// Single source of truth is the cilock binary's `tools show` surface — the
// SAME data `cilock tools show <name>` prints in the terminal, so the CLI
// and the website cannot drift:
//   - `cilock tools list --format json`        → the set of entries
//   - `cilock tools show <name> --format json` → metadata + predicate/lifecycle
//                                                 + the long-form doc (sections)
//   - `cilock tools test-plan --format json`   → detection command + setup/assert
//
// Output: _generated/catalog/<name>.json (one per tool/attestor) + index.json,
// committed so `npm run build` needs no cilock binary. CI regenerates + diffs
// to catch drift from the binary/catalog.
//
// Binary resolution: $CILOCK_BIN, else build the in-tree cilock at ../cilock.
//
// Usage: node scripts/gen-catalog.mjs   (or: npm run gen:catalog)

import {execFileSync} from 'node:child_process';
import {existsSync, mkdirSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {tmpdir} from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '..');
const OUT_DIR = join(REPO, '_generated', 'catalog');

function run(bin, args) {
  return execFileSync(bin, args, {encoding: 'utf8', maxBuffer: 64 * 1024 * 1024});
}

function resolveCilock() {
  if (process.env.CILOCK_BIN) {
    if (!existsSync(process.env.CILOCK_BIN)) {
      throw new Error(`CILOCK_BIN=${process.env.CILOCK_BIN} does not exist`);
    }
    return process.env.CILOCK_BIN;
  }
  // In-tree: this site lives at subtrees/rookery/site/, so cilock is one level
  // up at ../cilock (same rookery subtree). No sibling checkout / pinned SHA —
  // the catalog source of truth and the docs travel in the same commit.
  const inTree = resolve(REPO, '..', 'cilock', 'cmd', 'cilock');
  if (existsSync(inTree)) {
    const out = join(tmpdir(), 'cilock-catalog-gen');
    console.log(`[gen-catalog] building cilock from ${inTree} …`);
    run('go', ['build', '-o', out, inTree]);
    return out;
  }
  throw new Error('no cilock binary: set CILOCK_BIN, or run from within the monorepo (cilock at ../cilock)');
}

// Derive a copy-pasteable `cilock run` example from a pre-gate argv_prefix trigger.
function deriveRunExample(entry) {
  const argv = (entry.triggers || []).find((t) => t.gate === 'pre' && t.kind === 'argv_prefix');
  if (!argv) return null;
  const cmd = argv.value.replace(/^.*?:\s*/, '').trim();
  return cmd ? `cilock run -- ${cmd} .` : null;
}

function main() {
  const bin = resolveCilock();
  console.log(`[gen-catalog] using ${bin}`);

  const names = JSON.parse(run(bin, ['tools', 'list', '--format', 'json'])).map((t) => t.name);
  const plan = JSON.parse(run(bin, ['tools', 'test-plan', '--format', 'json']));
  const caseByName = {};
  for (const c of plan.cases || []) caseByName[c.detector] = c;

  // First pass: load every show record so we can build the emitted-format → tools map.
  const shows = {};
  for (const name of names) {
    shows[name] = JSON.parse(run(bin, ['tools', 'show', name, '--format', 'json']));
  }
  const emittedBy = {};
  for (const name of names) {
    for (const f of shows[name].emits_formats || []) (emittedBy[f] ||= []).push(name);
  }

  rmSync(OUT_DIR, {recursive: true, force: true});
  mkdirSync(OUT_DIR, {recursive: true});

  const index = [];
  for (const name of names) {
    const s = shows[name];
    const tc = caseByName[name];
    const doc = s.doc || null;
    const merged = {
      name,
      source: s.source,
      // doc.description is the SEO/summary; fall back to the structured one.
      description: (doc && doc.description) || s.description || '',
      title: (doc && doc.title) || name,
      sidebarPosition: (doc && doc.sidebar_position) || null,
      examplesRepo: (doc && doc.examples_repo) || null,
      categories: s.categories || [],
      primaryCategory: s.primary_category || (s.categories || [])[0] || null,
      upstream: s.upstream || null,
      gates: s.gates || [],
      recommendedTrace: s.recommended_trace || 'off',
      triggers: s.triggers || [],
      emitsFormats: s.emits_formats || [],
      emittedBy: emittedBy[name] || [], // tools whose output this (format) attestor consumes
      warnings: s.warnings || [],
      llmHints: s.llm_hints || {},
      predicateType: s.predicate_type || null,
      runType: s.run_type || null,
      defaultOn: !!s.default_on,
      runExample: deriveRunExample(s),
      detectionCommand: tc?.cilock_command || null,
      positiveSetup: tc?.positive_setup || null,
      negativeSetup: tc?.negative_setup || null,
      // doc body, split into addressable sections (empty until a doc.md exists)
      docSections: (doc && doc.sections) || [],
      hasDoc: !!doc,
    };
    writeFileSync(join(OUT_DIR, `${name}.json`), JSON.stringify(merged, null, 2) + '\n');
    index.push({
      name,
      source: merged.source,
      categories: merged.categories,
      primaryCategory: merged.primaryCategory,
      description: merged.description,
      emitsFormats: merged.emitsFormats,
      predicateType: merged.predicateType,
      runType: merged.runType,
      hasDoc: merged.hasDoc,
    });
  }

  index.sort((a, b) => a.name.localeCompare(b.name));
  writeFileSync(
    join(OUT_DIR, 'index.json'),
    JSON.stringify(
      {generatedFrom: 'cilock tools show --format json', count: index.length, withDoc: index.filter((e) => e.hasDoc).length, emittedBy, tools: index},
      null,
      2,
    ) + '\n',
  );

  console.log(`[gen-catalog] wrote ${index.length} entries (${index.filter((e) => e.hasDoc).length} with doc) to ${OUT_DIR}`);
  console.log(`[gen-catalog] (${readdirSync(OUT_DIR).length} files)`);
}

main();
