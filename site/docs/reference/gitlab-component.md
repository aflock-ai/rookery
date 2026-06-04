---
title: GitLab component reference
sidebar_position: 3
---

# CI/lock GitLab CI template reference

> Source of truth: [`cilock-action/gitlab/cilock.gitlab-ci.yml`](https://github.com/aflock-ai/cilock-action/blob/main/gitlab/cilock.gitlab-ci.yml) and [`cilock-action/gitlab/README.md`](https://github.com/aflock-ai/cilock-action/blob/main/gitlab/README.md).

CI/lock for GitLab CI is shipped as a **reusable GitLab CI template** rather than a packaged component. Include the template and extend `.cilock`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/aflock-ai/cilock-action/v1/gitlab/cilock.gitlab-ci.yml'

build:
  extends: .cilock
  variables:
    CILOCK_STEP: build
    CILOCK_COMMAND: "go build -o myapp ./cmd/myapp"
```

All configuration is via `CILOCK_*` environment variables.

## Variables

Defaults below match `cilock-action/gitlab/cilock.gitlab-ci.yml`. Variables set as `.cilock` job-level defaults take precedence over workflow-level `variables:` blocks (GitLab CI precedence rule), so override them inside `.cilock-fixed` or per-job `variables:` rather than at the top of the file.

| Variable | Default | Description |
|---|---|---|
| `CILOCK_STEP` | (required) | Step name for the attestation. |
| `CILOCK_COMMAND` | (required) | Shell command to run. |
| `CILOCK_VERSION` | `v1` | cilock-action release version to download. **Known issue:** the floating `v1` tag does not exist as a real release; override to a pinned version like `v1.0.1`. See the [GitLab tutorial](../tutorials/gitlab-ci-pipeline) for the `.cilock-fixed` workaround. |
| `CILOCK_ATTESTATIONS` | `environment git gitlab` | Space-separated attestor list (the `cilock-action` shim translates this to the comma-separated form `cilock` expects). |
| `CILOCK_ENABLE_ARCHIVISTA` | `true` | Store attestations in Archivista. |
| `CILOCK_ARCHIVISTA_SERVER` | `https://web.platform.testifysec.com` | Archivista server URL. |
| `CILOCK_TIMESTAMP_SERVERS` | `https://tsa.platform.testifysec.com/api/v1/timestamp` | RFC 3161 timestamp authority URL. |
| `CILOCK_PRODUCT_INCLUDE_GLOB` | `*` | Glob for product file inclusion. |
| `CILOCK_HASHES` | `sha256` | Hash algorithms. |
| `CILOCK_ENABLE_SIGSTORE` | (unset; falls through to cilock-action default `true`) | Enable Sigstore/Fulcio signing. The GitLab template does not set this explicitly, so the cilock-action shim's default applies. Most GitLab setups override to `false` and use file or KMS signing because GitLab's OIDC audience flow differs from GitHub's. |
| `CILOCK_KEY` | (none) | Path to signing key (file signer). |
| `CILOCK_OUTFILE` | (none) | Output file for signed envelope. |
| `CILOCK_TRACE` | `false` | Enable command tracing. |

## Outputs

The template produces a `cilock.env` dotenv artifact that downstream stages can pick up via `dependencies` / `needs`.

```yaml
artifacts:
  reports:
    dotenv: cilock.env
```

This is how subsequent stages (e.g. a verify stage) can reference the GitOID or attestation file produced by an earlier step.

## Differences from the GitHub Action

| | GitHub Action | GitLab template |
|---|---|---|
| Default attestations | `environment git github` | `environment git gitlab` |
| Default `enable-sigstore` | `true` | `false` |
| Configuration | Action `with:` inputs | `CILOCK_*` variables |
| Wrapping another tool's UI | `action-ref:` input | Not applicable (call commands directly) |
| OIDC | GitHub `id-token` permission | GitLab JWT (`CI_JOB_JWT_V2`) |

## Example pipelines

The template ships worked examples in [`examples/gitlab/`](https://github.com/aflock-ai/cilock-action/tree/main/examples/gitlab):

- `basic.gitlab-ci.yml`, minimum two-stage build + test
- `pipeline.gitlab-ci.yml`, multi-step pipeline with file-based signing and a downstream verify stage

The full end-to-end walkthrough lives in the [GitLab CI tutorial](../tutorials/gitlab-ci-pipeline).
