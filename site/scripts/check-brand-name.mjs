#!/usr/bin/env node
// Brand-name lint + fixer.
//
// Convention:
//   - The product/brand in prose is **CI/lock**.
//   - The literal CLI / binary / package is **`cilock`** (inline code / backticks).
// So a bare `cilock` or `Cilock` in prose is a violation: it must be either
// backticked (CLI) or written `CI/lock` (brand).
//
// Exempt from scanning: fenced code blocks, inline code, <script> / JSON-LD
// blocks, link/image URLs, import/export lines, HTML/JSX tags.
// Allowed bare tokens: CILOCK_* env vars, cilock-action, cilock-docs,
// cilock.dev (domain), paths like cmd/cilock/.
//
// Usage:
//   node scripts/check-brand-name.mjs            # lint (report + nonzero exit)
//   node scripts/check-brand-name.mjs --fix      # auto-fix (backtick CLI / brand the rest)
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const FIX = process.argv.includes('--fix');

const files = execSync(
  "find docs src -type f \\( -name '*.md' -o -name '*.mdx' \\) 2>/dev/null",
  { encoding: 'utf8' }
).split('\n').filter(Boolean);

const SUBCMDS = '(run|verify|sign|attestors|tools|plan|init|build|keyid|bundle|attest|license|completion|version|help)';
// CLI context => the occurrence refers to the binary/command.
function isCLI(prose, idx, m) {
  const after = prose.slice(idx + m.length);
  const before = prose.slice(Math.max(0, idx - 14), idx).toLowerCase();
  if (new RegExp(`^\\s+(--|-[a-z]\\b)`).test(after)) return true;        // cilock --flag / -f
  if (new RegExp(`^\\s+${SUBCMDS}\\b`).test(after)) return true;          // cilock run ...
  if (/^\s+(binary|cli|command|config|executable)\b/i.test(after)) return true; // cilock binary/CLI
  if (/\b(the|a|stock|default|prebuilt|custom|built|run|via|invoke|invoking|running)\s$/.test(before)
      && /^\s+(binary|cli|command|is\s+built|is\s+installed)/i.test(after)) return true;
  return false;
}

// is this match inside an allowlisted token?
function allowed(prose, idx, m) {
  if (m === 'CI/lock') return true;
  const after = prose.slice(idx + m.length);
  const before = prose.slice(0, idx);
  if (/^_/.test(after)) return true;                  // CILOCK_FANOTIFY
  if (/^-/.test(after)) return true;                  // hyphenated compound: cilock-action, cilock-native, …
  if (/-$/.test(before)) return true;                 // inside a slug/identifier: verify-the-cilock-binary
  if (/^\.(aflock|dev|io|com)\b/i.test(after)) return true; // cilock.dev domain only
  if (/\//.test(before.slice(-1)) || /^\//.test(after)) return true; // path cmd/cilock/
  return false;
}

// Strip code/markup so the scanner only sees prose.
function strip(line) {
  return line
    .replace(/`[^`]*`/g, ' ')
    .replace(/\]\([^)]*\)/g, '] ')
    .replace(/<[^>]+>/g, ' ');
}

let total = 0;
const report = {};
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  const lines = src.split('\n');
  let inFence = false, inScript = false;
  const out = [];
  lines.forEach((raw, i) => {
    if (/^\s*```/.test(raw)) { inFence = !inFence; out.push(raw); return; }
    if (/<script[\s>]/i.test(raw)) inScript = true;
    const wasScript = inScript;
    if (/<\/script>/i.test(raw)) inScript = false;
    if (inFence || wasScript || /^\s*(import|export)\s/.test(raw)) { out.push(raw); return; }
    // A line with unbalanced backticks is part of a multi-line inline-code span;
    // skip it (can't reliably tell prose from code on it).
    if ((raw.match(/`/g) || []).length % 2 !== 0) { out.push(raw); return; }

    const prose = strip(raw);
    const re = /\bci\/?lock\b/gi;
    let mm;
    const hits = [];
    while ((mm = re.exec(prose)) !== null) {
      const m = mm[0];
      if (m === 'CI/lock' || allowed(prose, mm.index, m)) continue;
      hits.push({ idx: mm.index, m, cli: isCLI(prose, mm.index, m) });
    }
    if (hits.length) {
      total += hits.length;
      (report[f] ??= []).push({ line: i + 1, hits, snippet: raw.trim().slice(0, 90) });
    }
    if (FIX && hits.length) {
      // Replace on the RAW line, skipping inline-code spans, right-to-left by index.
      // Map prose hits back to raw by matching the same token sequence is fragile;
      // instead re-scan raw while honoring backtick spans.
      out.push(fixLine(raw));
    } else {
      out.push(raw);
    }
  });
  if (FIX) {
    const joined = out.join('\n');
    if (joined !== src) writeFileSync(f, joined);
  }
}

function fixLine(raw) {
  // Safety: skip lines with unbalanced backticks (a multi-line inline-code span
  // crosses this line) so we never inject backticks inside an open code span.
  if ((raw.match(/`/g) || []).length % 2 !== 0) return raw;
  // Split on inline-code spans; only transform non-code segments.
  const parts = raw.split(/(`[^`]*`)/);
  return parts.map(p => {
    if (p.startsWith('`')) return p;
    return p.replace(/\bci\/?lock\b/gi, (m, off, s) => {
      if (m === 'CI/lock') return m;
      if (allowed(s, off, m)) return m;
      return isCLI(s, off, m) ? '`cilock`' : 'CI/lock';
    });
  }).join('');
}

if (FIX) {
  console.log(`fixed ${total} occurrence(s) across ${Object.keys(report).length} file(s)`);
  process.exit(0);
}
if (total === 0) { console.log('✓ brand-name check passed'); process.exit(0); }
console.error(`✗ brand-name: ${total} bare "cilock"/"Cilock" in prose. Use \`cilock\` (backticks) for the CLI, or CI/lock for the product.\n`);
for (const [f, vs] of Object.entries(report)) {
  console.error(`  ${f}  (${vs.reduce((n,v)=>n+v.hits.length,0)})`);
  for (const v of vs.slice(0, 4)) console.error(`    ${v.line}: …${v.snippet}`);
  if (vs.length > 4) console.error(`    … +${vs.length - 4} more lines`);
}
process.exit(1);
