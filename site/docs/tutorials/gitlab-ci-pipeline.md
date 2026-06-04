---
title: GitLab CI end-to-end
sidebar_position: 3
---

# GitLab CI: from build to verified release

This tutorial wires CI/lock into a GitLab pipeline using the reusable template at `aflock-ai/cilock-action/gitlab/cilock.gitlab-ci.yml`. The shape mirrors the [GitHub Actions tutorial](./github-actions-pipeline), same five-step pattern, same attestation outputs, with `CILOCK_*` variables instead of action `with:` inputs.

## What you'll build

A GitLab pipeline where each stage is wrapped by CI/lock and produces a signed in-toto attestation. The template produces a `cilock.env` dotenv artifact so downstream stages can read the GitOID of the attestation produced by an earlier stage.

## Prerequisites

- A GitLab project (the example is Go, but any language works)
- For OIDC keyless signing: GitLab's JWT (`CI_JOB_JWT_V2`) or `id_tokens:` config
- Optional: an Archivista instance reachable from the runner

## Step 1: Include the template

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/aflock-ai/cilock-action/v1/gitlab/cilock.gitlab-ci.yml'
```

This pulls in the `.cilock` job template that downstream jobs `extends:`.

## Step 2: A multi-stage attested pipeline

Adapted from `cilock-action/examples/gitlab/pipeline.gitlab-ci.yml` and the GitLab template README:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/aflock-ai/cilock-action/v1/gitlab/cilock.gitlab-ci.yml'

stages:
  - lint
  - test
  - build
  - publish
  - verify

variables:
  # File-signer setup (replace with KMS or Sigstore for production)
  CILOCK_KEY: "${CI_PROJECT_DIR}/signing-key.pem"

# 1. Lint + secret scan
lint:
  stage: lint
  extends: .cilock
  variables:
    CILOCK_STEP: lint
    CILOCK_COMMAND: "golangci-lint run ./..."
    CILOCK_ATTESTATIONS: "environment git gitlab secretscan"
    CILOCK_OUTFILE: attestation-lint
  artifacts:
    paths:
      - attestation-lint*.json
    reports:
      dotenv: cilock.env

# 2. Tests
test:
  stage: test
  extends: .cilock
  needs: [lint]
  variables:
    CILOCK_STEP: test
    CILOCK_COMMAND: "go test -count=1 -v ./..."
    CILOCK_OUTFILE: attestation-test
  artifacts:
    paths:
      - attestation-test*.json
    reports:
      dotenv: cilock.env

# 3. Build the binary — cilock observes go's exact argv via command-run;
#    bin/myapp lands in product/v0.3 as a Merkle leaf.
build:
  stage: build
  extends: .cilock
  needs: [test]
  variables:
    CILOCK_STEP: build
    CILOCK_COMMAND: "go build -o bin/myapp ./cmd/myapp"
    CILOCK_ATTESTATIONS: "environment git gitlab"
    CILOCK_OUTFILE: attestation-build
    CGO_ENABLED: "0"
  artifacts:
    paths:
      - bin/
      - attestation-build*.json
    reports:
      dotenv: cilock.env

# 3b. SBOM the build's output — separate cilock step so syft's argv is
#     its own command-run, the build artifact is recorded as material/v0.3,
#     and the SBOM lands in product/v0.3. Release-gate Rego in step 5 then
#     verifies the SBOM was generated against the build's product.
sbom:
  stage: build
  extends: .cilock
  needs: [build]
  variables:
    CILOCK_STEP: sbom
    CILOCK_COMMAND: "syft bin/myapp -o cyclonedx-json=bin/bom.cdx.json"
    CILOCK_ATTESTATIONS: "environment git gitlab sbom"
    CILOCK_OUTFILE: attestation-sbom
  artifacts:
    paths:
      - bin/
      - attestation-sbom*.json
    reports:
      dotenv: cilock.env

# 4. Container build
publish:
  stage: publish
  extends: .cilock
  needs: [build]
  variables:
    CILOCK_STEP: docker-build
    CILOCK_COMMAND: "docker buildx build --metadata-file docker-metadata.json -t myapp:test --load ."
    CILOCK_ATTESTATIONS: "environment git gitlab docker"
    CILOCK_OUTFILE: attestation-publish
  artifacts:
    paths:
      - attestation-publish*.json
      - docker-metadata.json
    reports:
      dotenv: cilock.env

# 5. Verify all attestations against a signed policy
verify:
  stage: verify
  needs: [publish]
  script:
    - |
      ATTESTATIONS=$(ls attestation-*.json | paste -sd,)
      cilock verify \
        --policy ./policy-signed.json \
        --publickey ./policy-pubkey.pem \
        --attestations "$ATTESTATIONS" \
        --subjects "sha1:$CI_COMMIT_SHA"
```

The `--attestations` flag takes a comma-separated list, so the snippet above globs every `attestation-*.json` artifact carried forward via `dependencies:`/`needs:` and joins them. You can equally pass `--attestations a.json,b.json,c.json` literally, or repeat `-a` per file.

The `--subjects "sha1:$CI_COMMIT_SHA"` flag tells CI/lock to match attestations whose subject list includes the git commit (every CI/lock attestation records the commit hash as a subject via the git attestor). Use that instead of `--artifactfile bin/myapp`: when multi-stage pipelines carry artifacts forward via `needs:`, the build's output binary often ends up in the build job's *materials* (because the prior stage's artifact made it visible to the material attestor before the build command ran) rather than its *products*, so `--artifactfile` won't find a matching subject. The git-commit subject is reliably present, end-to-end verified against the demo-cilock GitLab pipeline.

## Configurable `CILOCK_*` variables

Sourced from [`cilock-action/gitlab/README.md`](https://github.com/aflock-ai/cilock-action/blob/main/gitlab/README.md):

| Variable | Default | Notes |
|---|---|---|
| `CILOCK_STEP` | required | Step name; matches `policy.steps.<name>`. |
| `CILOCK_COMMAND` | required | Shell command to wrap. |
| `CILOCK_VERSION` | `v1` | cilock-action release version. |
| `CILOCK_ATTESTATIONS` | `environment git gitlab` | Space-separated attestor list. |
| `CILOCK_ENABLE_ARCHIVISTA` | `true` | Push to Archivista. |
| `CILOCK_ARCHIVISTA_SERVER` | `https://web.platform.testifysec.com` | Archivista URL. |
| `CILOCK_ENABLE_SIGSTORE` | `false` | Off by default, most GitLab teams use file or KMS signing. Set `true` to use Sigstore Fulcio. |
| `CILOCK_KEY` | (none) | Path to signing key (file signer). |
| `CILOCK_OUTFILE` | (none) | Output path prefix for the signed envelope. |
| `CILOCK_TRACE` | `false` | Enable Linux behavioral capture (eBPF where available, else ptrace+seccomp). |
| `CILOCK_HASHES` | `sha256` | Hash algorithms. |

For the full reference, see the [GitLab component reference](../reference/gitlab-component).

## Differences from the GitHub Actions pipeline

| | GitHub Action | GitLab template |
|---|---|---|
| Default attestations | `environment git github` | `environment git gitlab` |
| Default `enable-sigstore` | `true` | `false` |
| Wrapping another tool | `action-ref:` input | Not supported, call commands directly |
| OIDC | GH `id-token` permission | GitLab `id_tokens:` / `CI_JOB_JWT_V2` |
| Inter-step evidence | Action outputs (`git_oid`, `attestation_file`) | `cilock.env` dotenv artifact via `dependencies`/`needs` |

## Going further

- The defaults assume **file-based signing**. For Sigstore keyless signing in GitLab, set `CILOCK_ENABLE_SIGSTORE: "true"` and configure `id_tokens:` in your job.
- For policy enforcement, the verify stage above is what gates promotion. See [Verify in a release gate](../guides/verify-in-a-release-gate).
- For the threat-model walkthrough that motivates this whole shape, see [Defending against supply-chain attacks](./defending-against-supply-chain-attacks).
