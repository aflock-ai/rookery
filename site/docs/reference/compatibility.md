---
title: Compatibility
sidebar_position: 7
---

# Compatibility

What CI/lock is built for, tested against, and known to interoperate with.

> Sources: [`rookery/cilock/go.mod`](https://github.com/aflock-ai/rookery/blob/main/cilock/go.mod), [`rookery/.github/workflows/release.yml`](https://github.com/aflock-ai/rookery/blob/main/.github/workflows/release.yml), [`rookery/cilock/cmd/cilock/main.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/cmd/cilock/main.go).

## Toolchain

| | Version |
|---|---|
| Go (build) | **1.26.0+** (per `go.mod`) |
| Build flags | `CGO_ENABLED=0`, `GOWORK=off`, `-trimpath` |
| FIPS mode | On by default (`//go:debug fips140=on` in `main.go`) |

## Released platforms

The official rookery release pipeline produces static binaries for:

| OS | Architectures | Notes |
|---|---|---|
| Linux | amd64, arm64 | Full feature set including `--trace` (ptrace) |
| macOS (Darwin) | amd64, arm64 | All attestors except `--trace` (ptrace is Linux-only) |
| Windows | (not shipped) | **Not shipped:** the `omnitrail` attestor has linux/darwin-only build constraints (per `release.yml` comment). |

To build a Windows binary anyway, fork `cilock/cmd/cilock/main.go` and remove the `omnitrail` import.

## Container image

| | |
|---|---|
| Registry | `ghcr.io/aflock-ai/cilock` |
| Tags | `<version>` (current: `v1.1.0`) and `latest` |
| Built with | Chainguard [`melange`](https://github.com/chainguard-dev/melange) + [`apko`](https://github.com/chainguard-dev/apko) |
| Architectures | x86_64, aarch64 |
| Signed by | [cosign](https://github.com/sigstore/cosign) (keyless OIDC) |

## CI platforms

Tested integrations from the cilock-action ecosystem:

| Platform | Integration | Source |
|---|---|---|
| GitHub Actions | `aflock-ai/cilock-action@v1.0.1` (also `@v1`) | [cilock-action](https://github.com/aflock-ai/cilock-action) |
| GitLab CI | Reusable template at `cilock-action/gitlab/cilock.gitlab-ci.yml` | Same repo |
| Jenkins | Via the `jenkins` attestor + raw `cilock` binary | `rookery/plugins/attestors/jenkins` |
| AWS CodeBuild | Via the `aws-codebuild` attestor | `rookery/plugins/attestors/aws-codebuild` |

## Signers

The default `cilock` binary blank-imports two signer providers — `file` and `fulcio` (verified from `cilock/cmd/cilock/main.go`):

| Signer | Module | In default binary? |
|---|---|---|
| Sigstore Fulcio | `plugins/signers/fulcio` | ✅ default |
| File (PEM) | `plugins/signers/file` | ✅ default |
| KMS (`--signer-kms-ref`: `awskms://`, `gcpkms://`, `azurekms://`, `hashivault://`) | `plugins/signers/kms/{aws,gcp,azure}` | ⚙️ flag present, provider opt-in |
| debug-signer | `plugins/signers/debug-signer` | builder opt-in |
| SPIFFE/SPIRE | `plugins/signers/spiffe` | builder opt-in |
| HashiCorp Vault | `plugins/signers/vault`, `vault-transit` | builder opt-in |

The `--signer-kms-ref` **flag** is present in the default binary, but no KMS **provider** is compiled in — passing it errors with `no kms provider found` until you build a variant that imports `plugins/signers/kms/{aws,gcp,azure}`. The other "builder opt-in" signers likewise exist as Go modules in rookery but aren't blank-imported by default. Add the import to `cilock/cmd/cilock/main.go` (or use `rookery-builder --with …`) and rebuild — see [build a custom CI/lock](../guides/build-a-custom-cilock).

## Timestamp authorities

[RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161) compatible TSAs. Tested against:

- **Sigstore TSA** (Sigstore-operated public TSA, the cilock-action default)
- Self-hosted TSAs reachable over HTTPS

URL pattern: TSAs are passed via `--timestamp-servers <url>` (repeatable) or under `run.timestamp-servers` in the config file.

## Evidence storage

| Sink | Notes |
|---|---|
| File output | Default; via `--outfile`. |
| OCI registry | Via the `oci` attestor + downstream `cosign`/`oras` push. |
| Archivista | Tested against the [in-toto/archivista](https://github.com/in-toto/archivista) reference server. URL pattern `<platform-url>/archivista`; auth via static `--archivista-headers` or OIDC (`--archivista-oidc` + `--archivista-audience`). |

## Witness compatibility

CI/lock shares witness's DSSE + in-toto envelope format, but interop is **asymmetric — witness → CI/lock, not fully the reverse**:

- CI/lock attestation type URLs use the `https://aflock.ai/attestations/<name>/v0.1` namespace.
- Legacy witness URLs (`https://witness.dev/attestations/<name>/v0.1`) are accepted via aliases registered in [`attestation/legacy.go`](https://github.com/aflock-ai/rookery/blob/main/attestation/legacy.go), called from `main.go` at startup via `attestation.RegisterLegacyAliases()`.
- Witness-signed policies (DSSE payload type `https://witness.testifysec.com/policy/v0.1`) work with `cilock verify`.
- **Witness-produced attestations verify under `cilock verify`.**
- The reverse holds **only for the shared base attestors**. CI/lock's v0.3 Merkle-tree `product`/`material` attestations (`tree:products` root + inline leaves), standalone inclusion proofs, and trace records use predicates and verification logic witness doesn't implement, so **`witness verify` cannot validate most CI/lock attestations**.

## Predicate types in scope

| Predicate | Notes |
|---|---|
| in-toto Statement v1 (with versioned predicate URLs) | Native format for all CI/lock attestations. |
| DSSE envelope | Wraps every signed attestation. |
| SLSA Provenance v1 | Emitted by the `slsa` attestor. |
| CycloneDX, SPDX | Embedded by the `sbom` attestor when found in products. |
| SARIF | Embedded by the `sarif` attestor when found in products. |
| VEX | Emitted by the `vex` attestor. |

## Version pinning recommendations

| Dependency | Pin to |
|---|---|
| `aflock-ai/cilock-action` in workflows | A commit SHA (not a floating tag like `@v1`), see the [defending-against-supply-chain-attacks](../tutorials/defending-against-supply-chain-attacks) tutorial for why. |
| `cilock` binary | A specific release version, not `:latest`, in any production-bound workflow. |
| Custom binaries built via the rookery builder | Pin every plugin module to a path-prefixed tag. |

## What's not covered

- **Real-time network egress monitoring.** CI/lock observes file/syscall activity, not network traffic. Pair with [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) for that gap.
- **Developer laptop or production server protection.** CI/lock operates in CI/CD only.
- **Windows attestor coverage.** Until the `omnitrail` build constraint is relaxed or made conditional, Windows requires a custom build.
