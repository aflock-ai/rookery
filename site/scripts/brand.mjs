#!/usr/bin/env node
/**
 * brand.mjs — enforce the "CI/lock" brand in PROSE while leaving commands and
 * identifiers as `cilock`.
 *
 * The CLI, the binary, the package/repo names, and the domain are literally
 * spelled `cilock`; the product brand in prose is `CI/lock`. This rebrands
 * prose occurrences and SKIPS anything that is a command or identifier:
 *
 *   - fenced code blocks (``` / ~~~) and indented code
 *   - inline code spans (`cilock run …`)
 *   - the domain (cilock.dev, cilock.aflock.ai …)
 *   - package/repo/path names (cilock-action, cilock-docs, aflock-ai/…, …/cilock)
 *   - YAML/JSON front-matter is left alone (between leading --- fences)
 *
 * Usage:
 *   node scripts/brand.mjs --check [globs…]   # exit 1 if any prose needs rebranding
 *   node scripts/brand.mjs --write [globs…]   # rewrite files in place
 *
 * Default target: docs markdown (md + mdx). Pass globs to override.
 * Edits are surgical (only the brand tokens change) so diffs stay minimal — the
 * file is NOT reformatted.
 */

import {readFileSync, writeFileSync} from 'node:fs';
import {globSync} from 'node:fs';

const args = process.argv.slice(2);
const write = args.includes('--write');
const check = args.includes('--check') || !write;
const globs = args.filter((a) => !a.startsWith('--'));
const targets = globs.length ? globs : ['docs/**/*.md', 'docs/**/*.mdx'];

// A prose "cilock" or "Cilock" token that is NOT part of an identifier/domain.
// \b gives word boundaries; we additionally reject when the char immediately
// after starts a domain/package/path or the char before is a path separator.
const TOKEN = /\b(cilock|Cilock)\b/g;
// Known cilock subcommands — `cilock <sub>` (or `cilock --flag`) is a COMMAND,
// kept verbatim even in prose. The brand `CI/lock` is for everything else.
// The subcommand must be a WHOLE word (\b) so prose verbs/nouns that merely start
// with one — "cilock signs", "cilock attestations", "cilock verifies" — are still
// rebranded, while real commands ("cilock verify <file>", "cilock run …") are not.
const SUBCOMMANDS =
  /^\s+((?:run|verify|sign|prove|attestors?|keygen|keyid|bundle|version|completion|help|attest|init|env)\b|--\S)/;
function isIdentifierContext(text, start, end, token) {
  const before = text[start - 1] ?? '';
  const after = text.slice(end, end + 16);
  if (before === '/' || before === '-' || before === '.') return true; // path/pkg/domain tail
  if (after.startsWith('-')) return true; // cilock-action, cilock-docs
  if (after.startsWith('/')) return true; // path
  if (/^\.[a-z]/.test(after)) return true; // cilock.dev, cilock.aflock.ai, cilock.json …
  // Command invocation: only the lowercase binary is a command (`Cilock run`
  // would be prose). Keep `cilock run`, `cilock verify`, `cilock --flag`, …
  if (token === 'cilock' && SUBCOMMANDS.test(after)) return true;
  return false;
}

// Replace prose tokens in a single non-code text segment.
function rebrandSegment(seg) {
  let out = '';
  let last = 0;
  for (const m of seg.matchAll(TOKEN)) {
    const start = m.index;
    const end = start + m[0].length;
    out += seg.slice(last, start);
    out += isIdentifierContext(seg, start, end, m[1]) ? m[0] : 'CI/lock';
    last = end;
  }
  return out + seg.slice(last);
}

// Process a line OUTSIDE fenced code: rebrand prose but skip inline-code spans.
function rebrandLine(line) {
  // Split on inline code spans (backtick runs). Even indices are prose; odd are code.
  const parts = line.split(/(`+[^`]*`+)/);
  return parts.map((p, i) => (i % 2 === 1 ? p : rebrandSegment(p))).join('');
}

function rebrandFile(src) {
  const lines = src.split('\n');
  let inFence = false;
  let fenceMarker = '';
  let inFrontMatter = false;
  let inScript = false;
  let changed = false;
  const out = lines.map((line, idx) => {
    // YAML front-matter at the very top (--- … ---): leave untouched.
    if (idx === 0 && line.trim() === '---') {
      inFrontMatter = true;
      return line;
    }
    if (inFrontMatter) {
      if (line.trim() === '---') inFrontMatter = false;
      return line;
    }
    // <script> / JSON-LD blocks: structured data + literal commands — skip.
    // Case-insensitive so an upper/mixed-case <SCRIPT> can't bypass the filter.
    if (!inScript && /<script[\s>]/i.test(line)) {
      if (!/<\/script>/i.test(line)) inScript = true; // multi-line script opens
      return line; // single-line <script>…</script> is skipped wholesale too
    }
    if (inScript) {
      if (/<\/script>/i.test(line)) inScript = false;
      return line;
    }
    const fence = line.match(/^\s*(```+|~~~+)/);
    if (fence) {
      if (!inFence) {
        inFence = true;
        fenceMarker = fence[1][0];
      } else if (fence[1][0] === fenceMarker) {
        inFence = false;
      }
      return line; // the fence line itself is code
    }
    if (inFence) return line;
    if (/^(\t| {4,})\S/.test(line)) return line; // indented code block
    const next = rebrandLine(line);
    if (next !== line) changed = true;
    return next;
  });
  return {text: out.join('\n'), changed};
}

// TSX/TS/JS path. Prose lives in JSX text, attribute strings (title, aria-label,
// description), and comments; commands and terminal output live in template
// literals (`…`) and <code>/<CodeBlock> spans. Splitting the whole file on
// backticks separates template-literal content (odd segments — skipped) from
// everything else (even — rebranded), which also protects multi-line command and
// terminal examples like the homepage demo. Inline <code>/<CodeBlock> spans are
// masked before rebranding so `<code>cilock verify</code>` stays a command. The
// markdown "indented = code block" rule does NOT apply here — all JSX is indented.
// (Escaped backticks inside template literals aren't handled — none exist here.)
function rebrandCode(src) {
  let changed = false;
  const CODE_SPAN = /<(code|CodeBlock)\b[^>]*>[\s\S]*?<\/\1>/g;
  const parts = src.split('`'); // even = outside template literal, odd = inside
  for (let i = 0; i < parts.length; i += 2) {
    const masks = [];
    const masked = parts[i].replace(CODE_SPAN, (m) => {
      masks.push(m);
      return `\x00${masks.length - 1}\x00`;
    });
    const rebranded = rebrandSegment(masked);
    if (rebranded !== masked) changed = true;
    parts[i] = rebranded.replace(/\x00(\d+)\x00/g, (_, n) => masks[Number(n)]);
  }
  return {text: parts.join('`'), changed};
}

const files = targets.flatMap((g) => {
  try {
    return globSync(g, {nodir: true});
  } catch {
    return [];
  }
});

let offenders = 0;
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  const {text, changed} = /\.mdx?$/.test(f) ? rebrandFile(src) : rebrandCode(src);
  if (!changed) continue;
  offenders++;
  if (write) {
    writeFileSync(f, text);
    console.log(`rebranded: ${f}`);
  } else {
    // Show the offending prose lines for a --check failure.
    const a = src.split('\n');
    const b = text.split('\n');
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) console.log(`${f}:${i + 1}: ${a[i].trim()}  ->  ${b[i].trim()}`);
    }
  }
}

if (check && offenders > 0) {
  console.error(
    `\n${offenders} file(s) have un-branded prose "cilock"/"Cilock". Run: node scripts/brand.mjs --write`,
  );
  process.exit(1);
}
console.log(write ? `\nDone. ${offenders} file(s) rebranded.` : `\nOK — no prose rebranding needed.`);
