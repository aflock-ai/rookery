#!/usr/bin/env node
// check-cli-coverage.mjs — completeness gate for the hand-written CLI reference.
//
// The CLI reference (docs/reference/cli.md) is curated prose, not generated, so
// it can carry cross-links and nuance the binary's --help can't. The cost of
// hand-maintaining it is drift: a new command (or a renamed one) silently goes
// undocumented. This gate closes that gap WITHOUT flattening the prose — it walks
// the real command tree from the cilock binary and fails if any leaf command is
// missing a section/heading in cli.md.
//
// It checks COVERAGE (every command is documented), not flag-for-flag fidelity —
// the prose stays human, the completeness is machine-enforced.
//
// Usage:  CILOCK_BIN=/path/to/cilock node scripts/check-cli-coverage.mjs
//         (falls back to `cilock` on PATH). Exits 1 on any uncovered command.

import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';

const SITE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI_DOC = join(SITE_DIR, 'docs', 'reference', 'cli.md');
const CILOCK = process.env.CILOCK_BIN || 'cilock';

// Commands whose help is trivial/structural and intentionally not given their own
// reference section (they're covered by the top-level table or are shell plumbing).
const ALLOW_UNDOCUMENTED = new Set(['help', 'completion']);

function help(args) {
  try {
    return execFileSync(CILOCK, [...args, '--help'], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']});
  } catch (e) {
    // cobra writes help to stdout even on the help pseudo-exit; capture it.
    return (e.stdout || '').toString();
  }
}

// Parse the "Available Commands:" block of a cobra --help into command names.
function subcommands(text) {
  const out = [];
  const lines = text.split('\n');
  let inBlock = false;
  for (const line of lines) {
    if (/^[A-Za-z ]*Commands:\s*$/.test(line)) { inBlock = true; continue; }
    if (inBlock) {
      if (/^\S/.test(line) || line.trim() === '') { if (line.trim() === '') continue; else break; }
      const m = line.match(/^\s{2,}([a-z][a-z0-9-]*)\b/);
      if (m) out.push(m[1]);
    }
  }
  return out;
}

// Walk the tree to leaf command paths (e.g. ["policy","validate"], ["run"]).
function leafPaths(path = []) {
  const text = help(path);
  const subs = subcommands(text).filter((c) => !ALLOW_UNDOCUMENTED.has(c));
  if (subs.length === 0) return path.length ? [path] : [];
  return subs.flatMap((s) => leafPaths([...path, s]));
}

const doc = readFileSync(CLI_DOC, 'utf8');
const headings = doc.split('\n').filter((l) => /^#{1,4}\s/.test(l));

// Pre-extract the ORDERED command tokens of every backticked `cilock …` heading
// once. A command path is covered only if its FULL path appears as a contiguous
// token run in some heading — so `cilock keyid show` is matched by the keyid
// heading but NOT by `cilock tools show` (reused leaf names can't fail the gate
// open). Static regexes + token comparison only (no regex built from a command
// name) so there's nothing dynamic for a scanner to flag.
const HEADING_CMD = /`cilock\b([^`]*)`/; // static
const headingTokenLists = headings
  .map((h) => h.match(HEADING_CMD))
  .filter(Boolean)
  .map((m) => m[1].split(/[^a-z0-9-]+/i).filter(Boolean));

// True if `path` appears as a contiguous subsequence of `tokens`.
function containsPath(tokens, path) {
  for (let i = 0; i + path.length <= tokens.length; i++) {
    if (path.every((p, j) => tokens[i + j] === p)) return true;
  }
  return false;
}

function covered(path) {
  return headingTokenLists.some((tokens) => containsPath(tokens, path));
}

const leaves = leafPaths();
const missing = leaves.filter((p) => !covered(p));

if (leaves.length === 0) {
  console.error('check-cli-coverage: could not enumerate any commands from the cilock binary (is CILOCK_BIN set/built?)');
  process.exit(2);
}

if (missing.length) {
  console.error(`::error::CLI reference is missing ${missing.length} command(s) (drift). Add a section to docs/reference/cli.md for each:`);
  for (const p of missing) console.error('  - cilock ' + p.join(' '));
  console.error('\nThe CLI reference is hand-written but coverage-gated against the binary. Run a command\'s `--help` and add a `### `cilock <cmd>`` section with its flags + an example.');
  process.exit(1);
}

console.log(`check-cli-coverage: all ${leaves.length} cilock commands have a reference section. ✅`);
