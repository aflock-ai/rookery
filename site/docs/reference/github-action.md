---
title: GitHub Action reference
sidebar_position: 2
---

# `aflock-ai/cilock-action` reference

> Source of truth: [`cilock-action/action.yml`](https://github.com/aflock-ai/cilock-action/blob/main/action.yml).

The CI/lock GitHub Action wraps a command (or another GitHub Action) and produces signed attestations. It downloads its own variant of the `cilock` binary at runtime from the cilock-action releases.

```yaml
- uses: aflock-ai/cilock-action@v1.0.4   # pin to an exact tag or commit SHA
  with:
    step: build
    command: "go build -o myapp ./cmd/myapp"
```

**Latest release:** [`v1.0.4`](https://github.com/aflock-ai/cilock-action/releases/tag/v1.0.4) — bundles a CI/lock built from rookery `main` with `govulncheck`, `inclusion-proof`, `secretscan`, `slsa`, and the [PR #153 atomic-rename trace fix](https://github.com/aflock-ai/rookery/pull/153). Pin to the exact tag (or commit SHA) — never a moving major-version ref.

## Multi-step chain via `step` names

CI/lock's policy language lets you declare relationships between attested steps. By giving each `cilock-action` invocation a distinct `step:` name and declaring `artifactsFrom` in the verification policy, the verifier enforces that step N's materials match step N-1's products byte-for-byte. This is how CI/lock's own release pipeline chains `vendor-cilock-deps` → `release-build` — see [Verify the `cilock` binary](../getting-started/verify-the-cilock-binary).

```yaml
# Step 1 — vendor
- uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: vendor-deps        # ← policy declares this step
    command: go mod vendor
    outfile: dist/vendor.attestation.json

# Step 2 — build, references step 1 via artifactsFrom in your policy
- uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: app-build
    command: go build -mod=vendor -o app ./cmd/app
    outfile: dist/build.attestation.json
    trace: "true"            # ← required for the hermetic / network-egress Rego
```

## Required permissions

For keyless Sigstore signing (the default), the workflow needs:

```yaml
permissions:
  id-token: write   # for OIDC token to Fulcio
  contents: read    # standard checkout
```

Add `packages: write` if you push container images, etc.

## Inputs

### Core

One of `command` or `action-ref` is required.

| Input | Default | Description |
|---|---|---|
| `step` | (required) | Step name for the attestation. |
| `command` | (none) | Shell command to run. |
| `action-ref` | (none) | GitHub Action to wrap (`owner/repo@ref` or `docker://image`). |
| `action-inputs` | (none) | JSON map of inputs to pass to the wrapped action. |
| `action-env` | (none) | Additional env vars for the wrapped action (`KEY=VALUE` per line). |

### Binary

| Input | Default | Description |
|---|---|---|
| `version` | matches action tag | cilock-action release version to download. |
| `cilock-binary-url` | (none) | Custom URL for a pre-built `cilock` binary. |
| `cilock-args` | (none) | Additional raw args passed through to CI/lock. |

### Attestation

| Input | Default | Description |
|---|---|---|
| `attestations` | `environment git github` | Space-separated attestor list (the shim translates to the comma-separated form the `cilock` CLI expects). |
| `outfile` | (none) | Output file for signed envelope. |
| `workingdir` | (none) | Working directory. |
| `trace` | `false` | Enable command tracing. |
| `hashes` | `sha256` | Hash algorithms. |

### TestifySec platform

| Input | Default | Description |
|---|---|---|
| `platform-url` | `https://platform.testifysec.com` | All service URLs are derived from this. Self-hosted customers override. |

### Archivista

Derived from `platform-url` if not explicitly set.

| Input | Default | Description |
|---|---|---|
| `enable-archivista` | `true` | Store attestations in Archivista. |
| `archivista-server` | derived from `platform-url` | Archivista server URL. |

### Sigstore / Fulcio

Derived from `platform-url` if not explicitly set.

| Input | Default | Description |
|---|---|---|
| `enable-sigstore` | `true` | Enable Sigstore/Fulcio signing. |
| `fulcio-url` | derived from `platform-url` | Fulcio server URL. |
| `fulcio-oidc-client-id` | `sigstore` | Fulcio OIDC client ID. |
| `fulcio-oidc-issuer` | `https://token.actions.githubusercontent.com` | Fulcio OIDC issuer URL. |
| `fulcio-use-http` | `true` | Use HTTP/REST API for Fulcio (works behind any reverse proxy). |

### File signer

| Input | Default | Description |
|---|---|---|
| `key` | (none) | Path to signing key. |
| `certificate` | (none) | Path to signing certificate. |
| `intermediates` | (none) | Comma-separated paths to intermediate certificates. |

### KMS

| Input | Default | Description |
|---|---|---|
| `kms-aws-profile` | (none) | AWS profile for KMS signing. |
| `kms-gcp-credentials-file` | (none) | GCP credentials file for KMS signing. |
| `kms-ref` | (none) | KMS key reference URI (`awskms://...`, `gcpkms://...`, `azurekms://...`, `hashivault://...`). |

### Vault

| Input | Default | Description |
|---|---|---|
| `vault-url` | (none) | HashiCorp Vault URL. |
| `vault-token` | (none) | HashiCorp Vault token. |

### Timestamps

| Input | Default | Description |
|---|---|---|
| `timestamp-servers` | derived from `platform-url` | Space-separated TSA URLs. |

### Environment filtering

| Input | Default | Description |
|---|---|---|
| `env-add-sensitive-key` | (none) | Comma-separated additional sensitive env var keys. |
| `env-filter-sensitive-vars` | `false` | Filter (remove) sensitive vars instead of obfuscating. |

### Material / Product

| Input | Default | Description |
|---|---|---|
| `product-include-glob` | `*` | Glob for product file inclusion. |
| `product-exclude-glob` | (none) | Glob for product file exclusion. |

### Attestor exports

| Input | Default | Description |
|---|---|---|
| `attestor-sbom-export` | `false` | Export SBOM as a separate attestation. |
| `attestor-slsa-export` | `false` | Export SLSA provenance as a separate attestation. |

### Builder

| Input | Default | Description |
|---|---|---|
| `builder-manifest` | (none) | Path to a [rookery-builder](../ecosystem/rookery) manifest for a custom binary. |
| `builder-preset` | (none) | Builder preset: `minimal`, `cicd`, `all`. |

## Outputs

| Output | Description |
|---|---|
| `git_oid` | GitOID of the stored attestation. |
| `attestation_file` | Path to the attestation output. |

## Runtime

```yaml
runs:
  using: "node20"
  main: "shim/index.js"
```

The `shim/index.js` Node entry point downloads the variant binary from `https://github.com/aflock-ai/cilock-action/releases/{latest/download | download/<tag>}` and invokes it with the constructed args.

## SLSA Build L3: the provenance workflow

When cilock runs inside your build job, the provenance it signs can reach SLSA Build L2 at most. The job's own steps could forge it. For L3, add a second job. It calls the reusable `provenance.yml` workflow, runs none of your code, and signs SLSA v1 provenance with its own Fulcio identity:

```yaml
  provenance:
    needs: build
    permissions: { id-token: write }
    uses: aflock-ai/cilock-action/.github/workflows/provenance.yml@<40-hex commit>
    with: { subjects: "${{ needs.build.outputs.subjects }}" }
```

- **Pin by commit, never by tag.** The verifier requires the certificate's Build Signer URI to name the pinned commit, so a tag pin is refused.
- **`subjects`** is one `<name>=sha256:<hex>` per line. Your build job outputs it, for example with `echo "subjects=app=sha256:$(sha256sum dist/app | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"`. The build job must also run cilock in the same workflow run: a subject is accepted only if that run's build collection carries it.
- **Triggers:** the workflow signs only for `push`, `release` and `workflow_dispatch`. Any other event, fork pull requests and `pull_request_target` included, fails the job.
- **Signer:** the platform's Fulcio and timestamp authority by default (`platform-url`). Set `public-sigstore: true` to use public Sigstore instead.

Verify with the built-in L3 policy. There is no `-p`:

```bash
cilock verify ./dist/app --slsa-level 3 \
  --slsa-builder-digest <the same commit> --slsa-source-repo <owner>/<repo> \
  -a provenance.json -a build.json --vsa-outfile vsa.json
```

`--slsa-level 3` exits 0 only if all of these hold:

- the provenance's signing certificate names `provenance.yml` at that commit, a GitHub-hosted runner, a writer-only trigger, and your repository;
- builder.id, repository, commit and run in the statement equal that certificate's extensions;
- `buildType` and `externalParameters` are what `provenance.yml` writes;
- the artifact is among the subjects, and a build collection from the same run, repository and commit carries it.

`--format json` lists each requirement that failed. The VSA states `SLSA_BUILD_LEVEL_3` only on a pass. Add `--slsa-roots public-sigstore` with `--slsa-public-sigstore-ca-roots` and `--slsa-public-sigstore-timestamp-servers` to accept public Sigstore signatures.

Status: this needs a cilock-action commit that contains `provenance.yml` and a cilock release that has `--slsa-level`. Neither is published yet.

## Worked examples

The action ships example workflows in [`examples/github/`](https://github.com/aflock-ai/cilock-action/tree/main/examples/github):

- Wrapping another GitHub Action (e.g. `docker/build-push-action`)
- Wrapping a shell command
- Multi-step pipeline with downstream verification

The full end-to-end walkthrough lives in the [GitHub Actions tutorial](../tutorials/github-actions-pipeline).
