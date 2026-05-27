---
title: Semgrep
description: Run Semgrep SAST under cilock — the SARIF report becomes a signed v0.3 attestation parsed by the rookery sarif attestor; supports any of Semgrep's bundled rulesets or custom rules.
sidebar_position: 4
examples_repo: tool-semgrep-sarif
---

Semgrep is a multi-language static analysis engine — Python, Go, Java, JavaScript/TypeScript, Ruby, C#, PHP, Scala, Kotlin, Swift, Terraform, Dockerfile, generic, and more. It ships with curated rulesets (`p/security-audit`, `p/owasp-top-ten`, language-specific packs) and accepts user-authored YAML rules.

Cilock doesn't replace Semgrep. It runs the same `semgrep ... --sarif --output ...` command you already use and turns the SARIF report into a **signed v0.3 in-toto attestation** that records the exact argv, the materials Semgrep read, the SARIF file Semgrep produced, and the structured findings — all in one envelope that policy can evaluate later.

## Validated invocation

```bash
cilock run --step semgrep-scan \
  --signer-file-key-path _validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- semgrep --config p/security-audit --sarif --output semgrep.sarif fixture/
```

`--config p/security-audit` uses a bundled Semgrep Registry ruleset and runs without a Semgrep account or API key. `--config auto` works too but requires network access to the Semgrep Registry so it can resolve the project-appropriate ruleset.

The trailing `fixture/` is the path Semgrep scans — substitute the source directory you care about.

## What gets captured
A successful run emits a DSSE envelope with six predicate entries:

| Predicate | What it records |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | OS, hostname, user, env vars (filtered) |
| `https://aflock.ai/attestations/git/v0.1` | repo state — head SHA, branch, dirty bit |
| `https://aflock.ai/attestations/material/v0.3` | Merkle tree of files Semgrep read |
| `https://aflock.ai/attestations/command-run/v0.1` | the literal semgrep argv + exit code + stdout/stderr digests |
| `https://aflock.ai/attestations/product/v0.3` | Merkle tree of files Semgrep produced (the SARIF report) |
| `https://aflock.ai/attestations/sarif/v0.1` | parsed SARIF — driver name, version, ruleset, structured findings |

The `sarif` predicate is what your verify-time rego gate reads. The `command-run` predicate is what proves the ruleset wasn't tampered with after the fact.

## Why this shape

`cilock run -- <tool> <args>` invokes the tool directly. Earlier examples wrapped scanners in `bash -c "cp ..."`; that broke causality:

- `command-run` recorded `bash` plus a `-c` string, not the actual semgrep argv — so consumers couldn't see which ruleset ran.
- The spy / ptrace-based attestors traced `cp`, not `semgrep` — so material→product causality was wrong.
- `sarif` still had to scrape a file that `cilock` never observed being produced inside the traced process tree.

With the direct invocation:

- `command-run` records `["semgrep", "--config", "p/security-audit", "--sarif", "--output", "semgrep.sarif", "fixture/"]` verbatim.
- `product` captures `semgrep.sarif` as a real output of the traced process.
- `sarif` parses that same file — and the digest matches what `product` recorded.

## Validate it locally
```bash
# Confirm all six predicates are present
jq -r '.payload' attestation.json | base64 -d \
  | jq -r '.predicate.attestations[].type'

# Confirm command-run captured the real semgrep argv (not bash -c)
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'

# Inspect SARIF findings count + tool driver
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        | .attestation
        | {tool:     .report.runs[0].tool.driver.name,
           findings: ([.report.runs[].results[]] | length),
           report:   .reportFileName}'
```

Validated against cilock dev (v0.3 line) + Semgrep OSS 1.157.0 + ruleset `p/security-audit` — produces one finding on the bundled `fixture/vuln.py`.

## Semgrep rulesets

The `--config` flag accepts:

- **Bundled registry packs** — `p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`, `p/r2c-security-audit`, language packs like `p/golang`, `p/python`, `p/javascript`, `p/typescript`, `p/java`, `p/ruby`, `p/dockerfile`, `p/terraform`, `p/kubernetes`. Most run network-free once Semgrep has bootstrapped them.
- **`--config auto`** — Semgrep inspects the repo and picks the relevant packs. Requires network access to the Registry; no account needed.
- **Custom rule files** — `--config ./my-rules.yml` or `--config ./rules/` for repo-local YAML. The rule file itself shows up under the `material` predicate, so the attestation records both the code that was scanned **and** the rules it was scanned against.
- **Multiple configs** — pass `--config` more than once; Semgrep unions the rules.

For policy purposes, prefer pinning to a specific pack (or a vendored rule file) so the `command-run` predicate is reproducible across runs.

## FAQ

**Does cilock support Semgrep?**
Yes. Semgrep emits SARIF and the `sarif` attestor parses it; the validated invocation above is in [`attestor-compliance-examples/tool-semgrep-sarif`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-semgrep-sarif).

**Which Semgrep rulesets does the attestor work with?**
All of them. The attestor reads the SARIF emitted by Semgrep — it doesn't care which `--config` produced it. Bundled packs (`p/security-audit`, `p/owasp-top-ten`, language packs), `--config auto`, and custom YAML rules all flow through the same predicate.

**Do I need a Semgrep account or API key?**
No for `--config p/<pack>` and `--config ./rules.yml`. `--config auto` needs network access to the Semgrep Registry but still doesn't require auth. Semgrep AppSec Platform / Pro features (Pro engine, supply chain, secrets) are separate products and not required by cilock.

**Does cilock pin the ruleset version?**
Cilock records the **exact argv** in the `command-run` predicate and the **digests of every file Semgrep read** in the `material` predicate. If you `--config` a local rule file, that file's hash is captured. If you reference a remote pack like `p/security-audit`, the ruleset name is recorded but Semgrep itself fetches/caches the pack — pin Semgrep's version (and vendor the rules if you need byte-level reproducibility).

## See also

- [`sarif` attestor](../attestors/sarif) — the underlying ingestion path
- [How cilock policy works](../guides/policy) — using SARIF findings at the deploy gate
- [Attestation graph + back-refs](../concepts/attestation-graph) — how scans link to artifacts via subject digests
- [Tools index](./index)
