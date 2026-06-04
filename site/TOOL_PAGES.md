# Tool page style guide

This is an internal contributing guide. New tool pages and updates to existing ones MUST follow this template. The verification scripts in `aflock-ai/attestor-compliance-examples` are the source of truth for every invocation shown on a tool page — drift between docs and examples gets caught at PR review time.

## Frontmatter

```yaml
---
title: <Tool Name>
description: <one declarative sentence, ~30 words: what the tool does + what cilock contributes. AI search engines (Perplexity, ChatGPT, Bing Copilot, Google AI Overviews) cite the description verbatim. Mention the tool name, the verb, the output format.>
sidebar_position: <int>
---
```

Required fields: `title`, `description`, `sidebar_position`. The `description` is what populates the card on `/tools/`; without it the card renders blank.

## Body structure (in order)

### 1. Hero paragraph
One declarative sentence on what the tool does, one on what cilock adds. Aim for a passage an LLM could quote verbatim as the answer to "How do I get a signed X scan with cilock?".

### 2. `## Validated invocation`
Heading name MUST be exactly **"Validated invocation"** (not "Run it", "Capture the scan", etc.).

A single ```` ```bash ```` code block containing the EXACT command that's validated end-to-end in [`aflock-ai/attestor-compliance-examples`](https://github.com/aflock-ai/attestor-compliance-examples). When the example uses `_validation/key.pem`, the docs page may use `key.pem` for brevity — that's the only acceptable cosmetic difference.

If the tool requires a flag like `-no-fail` / `-s` / `--soft-fail` to keep `command-run/v0.1` green, the flag MUST be in the canonical invocation, with the reason explained in the surrounding prose.

### 3. `## What gets captured`
Heading name MUST be exactly **"What gets captured"** (not "Captured predicate types", "Capture / predicate types", "What's in the envelope", etc.).

A bullet list or short table of the predicate types emitted. The complete list for a SARIF-emitting tool is:

- `https://aflock.ai/attestations/environment/v0.1`
- `https://aflock.ai/attestations/git/v0.1`
- `https://aflock.ai/attestations/material/v0.3`
- `https://aflock.ai/attestations/command-run/v0.1`
- `https://aflock.ai/attestations/product/v0.3`
- `https://aflock.ai/attestations/sarif/v0.1`

For SBOM tools the last entry is `https://cyclonedx.org/bom` (CycloneDX) or `https://spdx.dev/Document` (SPDX) — the `sbom` attestor switches its emitted predicate type to the SBOM's native URI after format detection. Mention this explicitly, because it's a common policy-authoring gotcha.

### 4. `## Why this shape`
Heading name MUST be exactly **"Why this shape"** (not "Why direct invocation", "Why no cp", etc.).

A 2–3 paragraph explanation or a contrast table comparing:
- Antipattern: `cilock run -- bash -c "cp tool-output.sarif tool-product.sarif"`
- Correct: `cilock run -- <tool> <args> -o <out-file>`

Three properties must be called out:
1. `command-run/v0.1.cmd` records the real tool argv (not `bash`/`cp`).
2. The ptrace spy traces the tool's syscalls because cilock is the tool's direct parent.
3. `product/v0.3` captures the file the tool actually wrote, not a copy of one written outside cilock's view.

For tools that genuinely need an `sh -c` wrapper (govulncheck and hadolint write SARIF to stdout, kubectl pipes manifests via redirect): explain that `sh -c '<tool> ... > out.sarif'` is a single-shell-redirect routing the tool's output to a file the product attestor can hash. The `command-run` attestor records the full `sh -c` argv — that's a tool-output limitation, NOT the cp antipattern. Document the upstream feature request if one exists.

### 5. `## Validate it locally`
Heading name MUST be exactly **"Validate it locally"** (not "Validate locally", "Verify the envelope", "Inspect the attestation", etc.).

Two `jq` blocks:

a) **Predicate types** — copy-paste the canonical jq command + the expected output as a JSON array. The array MUST list ALL the predicate types the user's envelope will contain (don't truncate to just the tool-specific one). Example for SARIF tools:

````markdown
```bash
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
```

Expected output:

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/sarif/v0.1"
]
```
````

b) **Captured argv** — the second jq selects `command-run/v0.1` and prints `attestation.cmd`. The expected output is the literal tool argv (proof the cp antipattern is gone).

### 6. `## Notes` (optional)
Tool-specific gotchas. Examples:
- Flag renames across versions (`osv-scanner`'s `--output` → `--output-file` in v2)
- Soft-fail flag rationale (gosec, hadolint, checkov)
- Stdout-only-output limitation (govulncheck, hadolint)
- Format support / framework selection (kubescape NSA/MITRE/ArmoBest, semgrep rulesets)

### 7. `## FAQ`
3–5 question/answer pairs sized for AI-search citation. Each answer is 1–3 declarative sentences. Cover at least:
- "Does cilock support X?"
- The most idiosyncratic flag the tool needs under cilock
- How this flow differs from upstream X (i.e., what cilock adds)

LLMs preferentially cite Q/A blocks that name the entity (the tool) AND the action verb in the answer's first sentence. Phrase accordingly.

### 8. `## See also`
Required cross-links:
- `../attestors/<attestor-name>` — the underlying attestor doc
- The validated example in the examples repo
- The upstream tool homepage

### 9. JSON-LD HowTo (INVISIBLE — no heading)

At the very end of the file, after `## See also`, embed a Schema.org `HowTo` as an invisible script tag:

```jsx
<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({
  "@context": "https://schema.org",
  "@type": "HowTo",
  "name": "<one-line action description>",
  "description": "<longer description, ~50 words>",
  "tool": [
    {"@type": "HowToTool", "name": "cilock"},
    {"@type": "HowToTool", "name": "<tool name>"},
    {"@type": "HowToTool", "name": "jq"}
  ],
  "step": [
    {"@type": "HowToStep", "name": "Install <tool>", "text": "..."},
    {"@type": "HowToStep", "name": "Generate a signing key", "text": "..."},
    {"@type": "HowToStep", "name": "Run under cilock", "text": "..."},
    {"@type": "HowToStep", "name": "Validate the envelope", "text": "..."}
  ]
})}} />
```

DO NOT put the JSON-LD inside a visible ```` ```json ```` fenced code block — that renders to humans as a wall of code they don't need to see. The script tag renders as zero-pixel markup in the static HTML body; crawlers and AI Overviews pick it up, humans don't see it.

## Quality bar — what gets a page rejected

- `cilock run ... -- bash -c "cp foo.X bar.X"` anywhere in a code block (the cp antipattern)
- Synthetic placeholder commands like `bash -c "echo scan-done"` or `bash -c "echo 'no secrets'"`
- Visible Schema.org HowTo headings (`## Schema.org HowTo`, `## Structured data`, etc.)
- Missing `description` frontmatter
- Documented predicate-type list that's a subset of what the binary actually emits
- Heading names that drift from the standard names in §2–§8
- Documented cilock command that doesn't match the validated example in attestor-compliance-examples (modulo the `_validation/key.pem` → `key.pem` cosmetic difference)
- Tools that exit non-zero on findings without documenting the soft-fail flag

## Verification

Before opening a PR, run the documented invocation end-to-end and capture the predicate types. The canonical jq command for that is in the **§5 Validate it locally** section of every page — if running it against your envelope doesn't produce the expected output your page documents, fix the page or fix the command.

Maintainer-side checks (run in CI; see `scripts/check-tool-pages.py`):
- All required headings present, with canonical names
- `description` frontmatter present, ≥ 20 words
- Invisible JSON-LD script tag present, no visible HowTo headings
- No `bash -c.*\bcp\b.*\.(sarif|json|spdx|cdx)` matches in code blocks
- No `--workingdir .` (redundant; cilock defaults to CWD)
- Documented cilock command's `-- <tool> ...` tail matches the corresponding tool's `tool-<name>-<ext>/README.md` in attestor-compliance-examples
