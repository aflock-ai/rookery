---
title: Zarf
description: Run Zarf under cilock so `zarf package create` — the air-gap package build — is captured as a signed run where the package tarball becomes a real v0.3 product and the literal zarf argv is recorded in command-run/v0.2.
sidebar_position: 33
---

[Zarf](https://github.com/zarf-dev/zarf) is the air-gap-native package manager for Kubernetes. A `zarf.yaml` declares components — container images, Helm charts, manifests, and local files — and `zarf package create` assembles them into a single self-contained tarball (`zarf-package-<name>-<arch>-<version>.tar.zst`) that can be carried across an air gap and applied to a disconnected cluster with `zarf init` / `zarf package deploy`. Running `zarf package create` under `cilock run` turns that build into signed provenance: cilock records the literal zarf argv as a `command-run/v0.2` attestation, hashes the package tarball into the `product/v0.3` Merkle root, and snapshots `zarf.yaml` plus the component source files into `material/v0.3`.

This is a **detection-only** catalog entry: cilock recognizes zarf by argv (`zarf package` / `zarf init` / `zarf dev`) and captures the build with its always-on attestors — there is no dedicated zarf attestor. Its categories are `build` (primary — `zarf package create` produces the primary build artifact) and `deploy` (`zarf init` / `zarf package deploy` apply a release to a cluster).

## Validated invocation

The command below is validated end-to-end against a file-only package (no container images, no cluster, no network) so it runs anywhere. `--platform-url ""` runs fully offline (local key, no hosted Fulcio/TSA); drop it and pass `cilock login` credentials to sign keyless against the platform. Don't wrap zarf in `bash -c` — cilock invokes zarf directly so the captured argv, the product Merkle root, and the ptrace trace all refer to the real zarf process.

```bash
# zarf.yaml declares one file-only component:
#   kind: ZarfPackageConfig
#   metadata: { name: catalog-file-only, version: 0.0.1 }
#   components:
#     - name: local-file
#       required: true
#       files: [ { source: hello.txt, target: hello.txt } ]

cilock run --step build \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations environment \
  --platform-url "" \
  -- zarf package create . --confirm -o . --sbom-out sboms --no-color
```

`zarf package create .` reads `zarf.yaml` from the current directory, writes `zarf-package-catalog-file-only-<arch>-0.0.1.tar.zst` into `-o .` (the working dir cilock watches), and extracts the per-component SBOMs into `sboms/`. `--confirm` skips the interactive prompt; `--no-color` keeps the log clean (there is no `--no-progress` flag on zarf v0.81.0).

## What gets captured

The resulting `attestation.json` is a DSSE envelope wrapping an in-toto Statement carrying a cilock Collection. Its `attestations[].type` list:

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, kernel, env vars (sensitive values obfuscated) |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over `zarf.yaml` + component source files, snapshotted before zarf runs |
| `https://aflock.ai/attestations/command-run/v0.2` | the literal `zarf package create . --confirm -o . --sbom-out sboms --no-color` argv + exit code |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over the `zarf-package-*.tar.zst` tarball (and `sboms/`) zarf wrote into the working dir |

List them from the envelope:

```bash
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
```

Confirm `command-run.cmd` carries the literal zarf argv (proof zarf, not a shell, was the wrapped process):

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.2") | .attestation.cmd'
# ["zarf","package","create",".","--confirm","-o",".","--sbom-out","sboms","--no-color"]
```

## SBOMs

Zarf **does** generate SBOMs during `package create` (`--sbom-out sboms` extracts them next to the package), but it writes them in native **Syft JSON** (`descriptor.name: "zarf"`, Syft schema) — one `zarf-component-<name>.json` per component plus an HTML viewer. cilock's `sbom` attestor only ingests **CycloneDX** (`*.cdx.json`) or **SPDX** (`*.spdx.json`) documents; handed Syft JSON it reports *"no SBOM file found in product set"* and skips. So the SBOM files are captured only as opaque bytes inside `product/v0.3`, not parsed into an SBOM predicate — which is why the catalog entry sets `emits_formats: []` rather than claiming `sbom`. To get a cilock-parsed SBOM of a zarf package, run Syft (or another CycloneDX/SPDX generator) over the built tarball as a separate `cilock run -- syft …` step (see the [`syft`](./syft) page).

## Upstream & governance

Zarf is licensed **Apache-2.0** and is **not** a CNCF project. It is community-governed under the [`zarf-dev`](https://github.com/zarf-dev) GitHub organization by a Technical Steering Committee (originally created by Defense Unicorns); adoption is tracked toward the OpenSSF project lifecycle.

## See also

- [`command-run` attestor](../attestors/command-run) — records the literal zarf argv + exit code
- [`product` attestor](../attestors/product) — how the `zarf-package-*.tar.zst` tarball lands in the Merkle tree
- [`material` attestor](../attestors/material) — snapshots `zarf.yaml` + sources before the build
- [`syft` tool](./syft) — generate a cilock-parsed CycloneDX/SPDX SBOM of the built package
- [Zarf on GitHub](https://github.com/zarf-dev/zarf) — upstream project
- [Zarf documentation](https://docs.zarf.dev/) — package schema, `zarf package create` reference
- [Tools index](./)
