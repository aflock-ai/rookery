---
title: Grype
description: Scan images or directories for vulnerabilities with Grype under cilock — the SARIF report becomes a signed v0.3 attestation parsed by the rookery sarif attestor, byte-identical to what Grype produced.
sidebar_position: 3
examples_repo: tool-grype-sarif
---

Grype accepts container images, directories, archives, and pre-existing Syft SBOMs as scan targets. A native Grype attestor is in development (tracked in the [tools catalog](./)); today the supported route is the [`sarif`](../attestors/sarif) attestor.

## You already know how to run Grype. Here's what cilock adds.

[Grype](https://github.com/anchore/grype) is Anchore's vulnerability scanner. Point it at a container image, a directory tree, an archive, or an existing Syft SBOM and it returns the CVEs that match the packages it found. On its own, Grype writes a report file — a loose artifact that's easy to lose, easy to edit silently, and impossible to bind to "the image we actually shipped."

Cilock wraps the same `grype` command you already run and turns the SARIF report into a **signed, linked attestation**. The wrapper records the literal `grype` argv into a `command-run/v0.1` predicate, the file Grype emits is captured as a `product/v0.3` Merkle root, and the `sarif` attestor parses the report directly out of that product. Nothing is re-encoded; nothing is copied; the bytes the policy verifies are the bytes Grype produced.

## Validated invocation

This is the exact shape that ships in [`aflock-ai/attestor-compliance-examples/tool-grype-sarif`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-grype-sarif) — copy it verbatim. The local-dir target is the default because it doesn't depend on registry network access during validation.

```bash
# Prereqs: grype on PATH and an ed25519 key at ../_validation/key.pem
cilock run --step grype-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- grype dir:. -o sarif=grype.sarif
```

### Scanning a registry image instead of a directory

Swap the trailing argv for the image-target form. Everything else is identical:

```bash
cilock run --step grype-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- grype alpine:3.20 -o sarif=grype.sarif
```

Grype's other input forms (`sbom:./sbom.json`, `oci-archive:./image.tar`, `docker-archive:./image.tar`, `registry:registry.example.com/foo:bar`) all work the same way — cilock just executes whatever argv follows the `--`.

## What gets captured

Six attestations end up in the envelope's predicate:

| Attestation | Predicate type | What it carries |
|---|---|---|
| `environment` | `https://aflock.ai/attestations/environment/v0.1` | OS, arch, working dir, env vars |
| `git` | `https://aflock.ai/attestations/git/v0.1` | commit SHA, branch, remotes, tag |
| `material/v0.3` | `https://aflock.ai/attestations/material/v0.3` | Merkle root of pre-execution files |
| `command-run/v0.1` | `https://aflock.ai/attestations/command-run/v0.1` | literal grype argv + exit code + stdio digests |
| `product/v0.3` | `https://aflock.ai/attestations/product/v0.3` | Merkle root of files Grype created (the SARIF) |
| `sarif/v0.1` | `https://aflock.ai/attestations/sarif/v0.1` | the SARIF document, byte-identical, under `.report` |

The `sarif` attestor stores the report as `json.RawMessage`, so the bytes inside the envelope are the same bytes Grype wrote to disk — no re-encoding, no field reordering.

## Why this shape

| Antipattern (don't do this) | Correct shape (this page) |
|---|---|
| `cilock run … -- bash -c 'cp grype-output.sarif grype-product.sarif'` | `cilock run … -- grype dir:. -o sarif=grype.sarif` |
| `command-run.cmd` records `["bash","-c","cp …"]` — cilock is "running" `cp` | `command-run.cmd` records the literal grype argv |
| Product is a copy-of-a-copy; spy / ptrace can't trace Grype's syscalls because cilock isn't its parent | Product is Grype's real output; spy traces Grype directly |
| sarif attestor parses a file that's a copy of one Grype produced elsewhere | sarif attestor parses the file Grype just produced inside the wrapped step |

If you find an older tool page in this site still showing the `bash -c "cp …"` shape, treat it as out of date and follow the Grype shape instead.

## Validate it locally

After the cilock run, decode the DSSE payload and confirm the attestation set:

```bash
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
```

Expected:

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

Then confirm `command-run.cmd` is the literal Grype argv (proof the antipattern is gone):

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'
# ["grype","dir:.","-o","sarif=grype.sarif"]
```

## A note on Grype's MatchDetails

Grype's native JSON output carries a `matchDetails` field on every finding: the matcher type (`exact-direct-match`, `cpe-match`, `language-matcher`, …), the searched-by criteria, and which package-metadata fingerprint produced the hit. That detail is **lost when Grype emits SARIF** — SARIF 2.1.0 has no schema slot for per-match provenance, so the data simply doesn't survive serialization.

For most release-gate policies (severity threshold, fixed-version availability, CVE-ID allowlist) the SARIF view is enough. For policies that need to distinguish "matched by CPE" from "matched by language ecosystem" — for example, suppressing CPE-only false positives on Go binaries — the cilock catalog tracks a native Grype attestor in development that ingests Grype's canonical JSON directly and preserves `matchDetails`. Until that ships, the SARIF route documented here is the supported path.

## How a verifier consumes this

A Rego policy attached to the cilock verify step reads the SARIF predicate via `input.report.runs[*].results[*]` — note the `.report` wrapper the `sarif` attestor adds. SARIF runs are nested under `input.report.runs`, not at the top level. A representative deploy gate:

```rego
package grype

deny[msg] {
  result := input.report.runs[_].results[_]
  result.level == "error"
  msg := sprintf("Grype critical: %s", [result.ruleId])
}
```

See the [`sarif` attestor reference](../attestors/sarif) for the full predicate schema and additional Rego patterns.

## FAQ

**Does cilock support Grype?** Yes — today via the `sarif` attestor using the validated invocation above. A native Grype attestor is in development; the SARIF path is the supported production route in the meantime.

**What scan targets work?** Anything Grype's CLI accepts as a positional: `dir:./path`, `registry:image:tag` (the bare `alpine:3.20` shortcut form too), `sbom:./sbom.json`, `oci-archive:./image.tar`, `docker-archive:./image.tar`, `file:./binary`. Cilock executes whatever argv follows `--`; the wrapper doesn't care which target Grype picks.

**Does it need Docker?** No. For the `dir:`, `sbom:`, and archive targets, Grype runs entirely on the local filesystem. For the `registry:` and bare-image targets, Grype pulls via its own registry client (or honours `DOCKER_HOST` if you've set it) — but cilock itself never shells out to Docker.

**What's lost going through SARIF vs the native attestor?** Grype's `matchDetails` (matcher type, search criteria, match fingerprint) and a few Grype-specific fields (`vulnerability.fix.state`, `vulnerability.advisories[]`) have no SARIF representation and are dropped by Grype's own SARIF serializer. CVE ID, severity, package coordinates, and location all survive. If you need full fidelity, wait for the native attestor or run Grype in JSON mode and parse it yourself in a custom attestor.

## See also

- [`sarif` attestor reference](../attestors/sarif) — predicate schema, Rego patterns, the `.report` wrapper
- [`product/v0.3` attestor](../attestors/product-v0.3) — how Grype's SARIF gets captured as a real product
- [`command-run/v0.1` attestor](../attestors/command-run) — how the literal `grype` argv is recorded
- [Tools index](./) — full catalog of validated tool integrations
- [`tool-grype-sarif` validated example](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-grype-sarif) — the upstream example this page mirrors
