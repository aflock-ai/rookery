---
title: CI quickstart
sidebar_position: 5
---

# CI quickstart

The fastest path from a vanilla GitHub Actions workflow to signed evidence. This page shows one copy-pasteable workflow that produces a signed attestation around a single build step, then points to the dropbox-clone reference for the fuller multi-step pattern.

If you want the local equivalent first (build, sign, write a policy, verify, all on your laptop), see [Getting Started](./first-attestation).

## Prerequisites

- A GitHub repository with a workflow file at `.github/workflows/`.
- Nothing else, no signing keys, no Sigstore account. The action defaults to keyless OIDC signing.

## The minimal workflow

This workflow wraps `go build` with [`cilock-action`](https://github.com/aflock-ai/cilock-action), produces a Sigstore-signed attestation via the workflow's GitHub OIDC token, and uploads the signed envelope as a workflow artifact you can download from the Actions run.

```yaml title=".github/workflows/build.yml"
name: Build with attestation

on:
  push:
    branches: [main]
  pull_request:

permissions:
  id-token: write   # required for keyless OIDC signing (Sigstore default)
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: aflock-ai/cilock-action@v1.0.4
        with:
          step: build
          command: "go build -o myapp ./"
          enable-archivista: false           # don't push to platform.testifysec.com (needs creds)
          outfile: build.attestation.json    # write the signed envelope to disk instead

      - name: Upload signed attestation
        uses: actions/upload-artifact@v4
        with:
          name: build-attestation
          path: build.attestation.json
          if-no-files-found: error
```

Adapted from [`cilock-action/examples/github/basic-command.yml`](https://github.com/aflock-ai/cilock-action/blob/main/examples/github/basic-command.yml). Pinning to an exact tag (`@v1.0.4`) is consistent with the SHA-pinning advice in [Layer 1 of the intro](../intro#layer-1-prevention-dont-run-untrusted-code), the floating-tag pattern is what the March 2026 Trivy attack exploited.

:::caution why `enable-archivista: false`
The action's default `enable-archivista: true` pushes attestations to `https://platform.testifysec.com/archivista`, which requires either a TestifySec API key or an OIDC token from an allowlisted org. Without those, the action exits with `archivista store returned 401: Invalid API credential`. The fix above keeps the attestation local, you can wire up a self-hosted Archivista or paid TestifySec credentials later, see [where to go next](#where-to-go-next).
:::

## What this produces

On each run, cilock-action wraps `go build` and records:

| Attestor | Captures |
|---|---|
| `material` (always) | SHA-256 digests of every file in the workspace before the step ran. |
| `command-run` (always) | argv, exit code, stdout/stderr digests, process info of `go build`. |
| `product` (always) | SHA-256 digests of every file added or changed (here: `myapp`). |
| `environment` (default) | os, hostname, username, env vars (sensitive ones filtered). |
| `git` (default) | commit SHA, tree hash, branch, snapshot of `git status`. |
| `github` (default) | GitHub Actions runner context: workflow ref, run id, event, actor, repo. |

The envelope is signed with a Sigstore Fulcio certificate issued from the workflow's GitHub OIDC token. With the above config it's written to `build.attestation.json` and uploaded as a workflow artifact named `build-attestation`, you can download it from the Actions run and inspect locally with the same `jq` commands from [Getting Started](./first-attestation#3-view-the-attestation).

By default, the cert chains to the **TestifySec Platform Fulcio CA** because the action's `platform-url` default is `https://platform.testifysec.com`, that's the Fulcio that issues the cert. Verifying its identity:

```bash
jq -r '.signatures[0].certificate' build.attestation.json | base64 -d \
  | openssl x509 -text -noout | grep -E "Issuer:|URI:"
#   Issuer: O=TestifySec, CN=TestifySec Platform Fulcio CA
#   URI:https://github.com/<owner>/<repo>/.github/workflows/build.yml@refs/heads/main
```

## Signing with the public Sigstore Fulcio (optional)

If you want the cert to chain to the **Sigstore public-good root** (so any standard cosign + Sigstore trust root can verify it without depending on TestifySec infrastructure), override the Fulcio + TSA endpoints:

```yaml
- uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: build
    command: "go build -o myapp ./"

    enable-archivista: false
    outfile: build.attestation.json

    enable-sigstore: true
    fulcio-url: https://fulcio.sigstore.dev
    fulcio-oidc-issuer: https://token.actions.githubusercontent.com
    fulcio-oidc-client-id: sigstore
    fulcio-use-http: "false"       # public Fulcio is gRPC, not HTTP/REST
    timestamp-servers: https://timestamp.sigstore.dev/api/v1/timestamp
```

The resulting cert's `Issuer` becomes `O=sigstore.dev, CN=sigstore-intermediate` instead of TestifySec, and the timestamp is signed by the public Sigstore TSA. Everything else (the in-toto payload, the GitHub OIDC subject URI binding the cert to your workflow file at a specific ref) is identical.

## Adding security attestors

To match the SHA-pinning + content-detection + behavioral-detection story from the [intro](../intro), add `secretscan` (content), `sbom` (provenance), or `sarif` (SAST output) per step:

```yaml
- uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: sast
    command: "gosec -fmt=sarif -out=gosec-results.sarif ./..."
    attestations: environment git github sarif
    cilock-args: --attestor-product-include-glob "*.sarif"
    enable-archivista: false
    outfile: sast.attestation.json

- uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: build
    command: "go build -o bin/myapp ./cmd/myapp"
    attestations: environment git github sbom
    enable-archivista: false
    outfile: build.attestation.json
```

The `attestations` input accepts a **space-separated list** (the action splits before passing to the `cilock` CLI). The direct CLI uses `-a name -a name2` or `-a name1,name2`, see [Getting Started](./first-attestation#what-gets-recorded).

## Multi-step pipeline

For a real five-step pipeline (lint, SAST, test, build+SBOM, docker build), the canonical reference is [`testifysec/dropbox-clone/.github/workflows/cilock-action-oidc.yaml`](https://github.com/testifysec/dropbox-clone/blob/main/.github/workflows/cilock-action-oidc.yaml). The cilock-action repo also ships [`examples/github/pipeline.yml`](https://github.com/aflock-ai/cilock-action/blob/main/examples/github/pipeline.yml) which demonstrates the build, test, publish, verify shape.

## Verifying in a release gate

This page only **produces** evidence. Turning that evidence into a deploy gate (verify against a signed policy before publishing) is one more step. See:

- [Getting Started](./first-attestation) for the local sign + verify loop with `cilock verify`.
- [Defending against supply-chain attacks](../tutorials/defending-against-supply-chain-attacks) for the OPA Rego policy pattern that catches the Trivy and LiteLLM playbooks.
- [Verify in a release gate](../guides/verify-in-a-release-gate) for the CI gate pattern (when written).

## Where to go next

- Full platform walkthroughs: [GitHub Actions end-to-end](../tutorials/github-actions-pipeline) and [GitLab CI end-to-end](../tutorials/gitlab-ci-pipeline).
- Pick a signer: [Choose a signer](../guides/choose-a-signer).
- Browse all cilock-action inputs: [GitHub Action reference](../reference/github-action).
