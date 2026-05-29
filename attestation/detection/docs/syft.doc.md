---
title: Syft
description: Generate signed CycloneDX or SPDX SBOMs with cilock — Anchore's Syft runs under `cilock run` so the SBOM is captured as a real v0.3 product, hashed into a Merkle tree, and parsed by the `sbom` attestor.
sidebar_position: 2
examples_repo: tool-syft-sbom
---

[Syft](https://github.com/anchore/syft) is Anchore's open-source CLI that scans a directory or container image and writes a Software Bill of Materials in CycloneDX or SPDX. Running it under `cilock run` turns that throwaway report file into a signed in-toto envelope: cilock records syft's literal argv as a `command-run/v0.1` attestation, hashes the SBOM file into the `product/v0.3` Merkle root, and the `sbom` attestor parses the document and re-emits it under its native standard URI so downstream policy engines key off `https://cyclonedx.org/bom` directly.

## Validated invocation

The exact command below is the one CI runs against `aflock-ai/attestor-compliance-examples/tool-syft-sbom`. Don't wrap syft in `bash -c cp …` — cilock invokes syft directly so the captured argv, ptrace trace, and product Merkle root all refer to the real scanner process.

```bash
# Prereqs: syft on PATH and an ed25519 key at ../_validation/key.pem
cilock run --step syft-scan \
  --signer-file-key-path ../_validation/key.pem \
  --outfile attestation.json \
  --attestations sbom,environment,git \
  --enable-archivista=false \
  -- syft dir:. -o cyclonedx-json=syft.cdx.json
```

The same shape works against a container image — substitute `syft alpine:3.20 -o cyclonedx-json=syft.cdx.json` for the `--`-args. The local-directory target is documented as the default because it doesn't depend on registry network access.

## What gets captured

The resulting `attestation.json` is a DSSE envelope whose payload is an in-toto Statement carrying a rookery Collection. The Collection's `attestations[].type` list — the load-bearing field for policy engines — looks like this:

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://cyclonedx.org/bom"
]
```

Key insight: the SBOM predicate URI in the envelope is `https://cyclonedx.org/bom`, **not** `https://aflock.ai/attestations/sbom/v0.1`. The aflock URI is the *registered* type that `--attestations sbom` resolves to inside cilock; once the attestor detects the SBOM format it switches its emitted predicate type to the SBOM's native URI (`https://cyclonedx.org/bom` for CycloneDX, `https://spdx.dev/Document` for SPDX). That way downstream SBOM consumers and policy engines can match on the standard schema URL they already key off.

## Why this shape

Direct invocation matters. If you wrap syft in `bash -c 'cp …'` the `command-run/v0.1` attestor records `["bash","-c","cp …"]` — cilock is "running" cp, not syft, so the recorded argv lies about what produced the SBOM. The ptrace-based command trace also can't follow syft's syscalls because cilock isn't its parent process. Invoking syft as the wrapped command (`-- syft dir:. -o cyclonedx-json=syft.cdx.json`) fixes all three properties at once: the recorded argv is the real syft argv, ptrace traces syft directly, and the `product/v0.3` Merkle leaf binds the actual file syft wrote inside the wrapped step.

| Antipattern (old) | Correct shape (this example) |
|---|---|
| `cilock run ... -- bash -c "cp …syft-output… syft-product.json"` | `cilock run ... -- syft dir:. -o cyclonedx-json=syft.cdx.json` |
| `command-run.cmd` records `["bash","-c","cp …"]` | `command-run.cmd` records the literal syft argv |
| Product is a copy of a copy; ptrace can't trace syft | Product is syft's real output; ptrace traces syft directly |
| sbom attestor parses a file that's a copy of one syft produced elsewhere | sbom attestor parses the file syft just produced inside the wrapped step |

## Validate it locally

List the predicate types emitted into the Collection:

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
  "https://cyclonedx.org/bom"
]
```

Then confirm `command-run.cmd` is the literal syft argv (proof the `cp` antipattern is gone):

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'
# ["syft","dir:.","-o","cyclonedx-json=syft.cdx.json"]
```

## FAQ

**Does cilock support Syft?**
Yes. Syft runs unmodified under `cilock run` and the resulting SBOM is captured as a real `product/v0.3` Merkle leaf, then parsed and re-emitted by the `sbom` attestor under its native CycloneDX or SPDX predicate URI.

**What SBOM formats does cilock capture?**
CycloneDX JSON (`https://cyclonedx.org/bom`) and SPDX JSON (`https://spdx.dev/Document`). The `sbom` attestor sniffs the file on disk and switches its emitted predicate type to whichever format Syft wrote — byte-equal to syft's output, no re-encoding.

**How is a cilock-signed SBOM different from a plain syft SBOM?**
A plain `syft -o cyclonedx-json` writes an unsigned report file. `cilock run -- syft …` wraps the same execution and produces a DSSE-signed in-toto Statement whose subjects link the SBOM to the artifact that was scanned, the git commit it came from, and the CI identity that ran it. Downstream policy can verify provenance before deploy.

**Can I use the resulting attestation in Sigstore Rekor / Archivista?**
Yes. The `attestation.json` produced above is a standard DSSE envelope wrapping an in-toto Statement; it uploads to Archivista via cilock's `--enable-archivista` flag and can be mirrored to Rekor as an in-toto attestation. The CycloneDX-native predicate URI is what makes it portable across SBOM-aware consumers.

## See also

- [`sbom` attestor](../attestors/sbom) — the underlying ingestion path, predicate-type switching, and SBOM format detection
- [`product/v0.3` attestor](../attestors/product) — how syft's output file lands in the Merkle tree as a real product
- [`command-run/v0.1` attestor](../attestors/command-run) — what records the literal syft argv
- [Validated example: tool-syft-sbom](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-syft-sbom) — the upstream README this page mirrors
- [Anchore Syft on GitHub](https://github.com/anchore/syft) — upstream project
- [Tools index](./index)
