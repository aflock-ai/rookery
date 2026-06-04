---
title: Rookery
sidebar_position: 1
---

# CI/lock and rookery

**Rookery** is the modular attestation monorepo where CI/lock is built. It splits the attestation core, every individual attestor, every signer, and the binary builder into separate Go modules so each can be versioned and consumed independently.

## Layout

| Directory | What's there |
|---|---|
| `attestation/` | Core attestation library (minimal deps), DSSE handling, in-toto statement assembly, the attestor/signer interfaces, factory registration, Archivista client, type-alias registry. |
| `plugins/attestors/` | Each attestor as its own Go module (40 attestors today). |
| `plugins/signers/` | Each signer as its own Go module. Default binary ships `file`, `fulcio`; the remaining seven (`debug-signer`, `kms/{aws,azure,gcp}`, `spiffe`, `vault`, `vault-transit`) are opt-in via [`rookery-builder`](../guides/build-a-custom-cilock). |
| `presets/` | Convenience modules that blank-import curated plugin sets — `all`, `cicd`, `minimal`. |
| `builder/` | `rookery-builder` — generates a real `cilock` binary with a custom plugin set from a manifest or CLI flags. Output binary is a drop-in CI/lock with the full `run`/`verify`/`sign` surface. Also supports branded distribution via `--customer`/`--tenant` ldflag injection. See [Build a custom CI/lock](../guides/build-a-custom-cilock). |
| `cilock/` | The `cilock` CLI binary; `cmd/cilock/main.go` blank-imports the cilock-default plugin set (every attestor + `file` + `fulcio`). |
| `lockctl/` | A separate CLI binary (own `go.mod`) for control-plane operations, lives alongside CI/lock in the monorepo. |
| `compat/` | Compatibility shims (notably `compat/go-witness/`) so go-witness consumers can pin to rookery without re-importing every plugin path. |
| `deploy/` | Packaging recipes (melange / apko / similar) for producing release-shape binaries. |
| `docs/` and `docs-website/` | Markdown content and the Docusaurus-style site source for the CI/lock docs. |

The monorepo also hosts other CLIs that consume the same attestation core; this page focuses only on CI/lock.

## Versioning

Rookery uses standard Go path-prefixed multi-module tags:

```
attestation/v0.1.0
plugins/attestors/git/v0.1.0
plugins/signers/file/v0.1.0
```

Each module can be released independently, so a fix to the `git` attestor doesn't force a release of the whole tree.

## Why this matters for CI/lock

Because CI/lock is just `main.go` with a curated set of blank imports, you can build **your own `cilock` binary** with a different mix of attestors or signers — for example, adding `kms/aws` for an AWS-native pipeline, dropping cloud signers entirely for an air-gapped build, or adding `inspec`, `kube-bench`, `nessus`, `oscap`, or `prowler` for compliance-heavy environments. The [`rookery-builder`](../guides/build-a-custom-cilock) generates a real CI/lock with your chosen plugins; the [release pipeline](https://github.com/aflock-ai/rookery/blob/main/.github/workflows/release.yml) is the template for a full multi-arch signed release build.

The **default `cilock` binary** ships every attestor and two signers (`file`, `fulcio`). The remaining seven signers (`debug-signer`, `kms/aws`, `kms/gcp`, `kms/azure`, `spiffe`, `vault`, `vault-transit`) are opt-in via `rookery-builder --with <signer-module>`. This keeps the prebuilt binary's transitive dependency tree about 600 Go packages smaller.

## Presets

The `presets/` modules are the easiest way to grab a curated set without writing imports yourself:

- `presets/all` — every attestor and signer in rookery
- `presets/cicd` — the CI/CD-relevant subset (attestors + `file` signer)
- `presets/minimal` — `commandrun`, `environment`, `git`, `material`, `product` + `file` signer

The builder accepts a preset name (`--preset cicd`) and then layers `--with <module>` flags on top, so the typical "I need cicd plus KMS" build is one command.

## Licensing

CI/lock uses an open-core split:

- **The stock `cilock` CLI is Apache 2.0** — fully open source, no strings attached. `cilock license` on a stock binary prints the Apache 2.0 text.
- **The rookery builder, its derivative works, and the binaries it produces are licensed under the [Business Source License 1.1](https://github.com/aflock-ai/rookery/blob/main/builder/LICENSE)** (BUSL). BUSL is source-available: each release **converts to GPL 2.0 four years after publication**, and production use is granted free while you hold a valid [TestifySec platform](./testifysec-platform) license. A builder-produced binary's `cilock license` reports BUSL.

So you can read, build, and self-use the builder source; commercial production use of builder-composed binaries is covered by a TestifySec platform license until the Change Date.

## Contributing

Both CI/lock and witness changes land here. See the [rookery CONTRIBUTING guide](https://github.com/aflock-ai/rookery/blob/main/CONTRIBUTING.md) for the workflow.
