---
title: Generate & verify SLSA provenance in GitHub Actions
description: Wrap a GitHub Actions pipeline with CI/lock to produce signed, keyless (Fulcio + GitHub OIDC) in-toto attestations for every build step, timestamped with Sigstore TSA and uploaded to Archivista — SLSA-aligned CI/CD provenance end to end.
sidebar_position: 2
---

# GitHub Actions: from build to verified release

This tutorial walks through a full attested CI pipeline using `aflock-ai/cilock-action`, five steps (lint, SAST, test, build, docker-build) each producing signed in-toto attestations via OIDC. The pattern below is taken directly from Cole's reference implementation at [github.com/testifysec/dropbox-clone](https://github.com/testifysec/dropbox-clone).

## What you'll build

A pipeline where every step is wrapped by cilock-action and produces a signed attestation. All signing is keyless (Fulcio + GitHub OIDC), all attestations are timestamped (Sigstore TSA), and all evidence is uploaded to Archivista using OIDC for auth, no static API keys.

## Prerequisites

- A GitHub repo (this tutorial assumes a Go project, but any language works)
- Permission to add workflow files
- Optional: an Archivista instance + Fulcio reachable (the cilock-action defaults derive from `platform-url`)

## Step 1: Set the right permissions

Cilock-action needs `id-token: write` to request the OIDC token used by Fulcio (signing) and Archivista (upload). It needs `contents: read` for checkout. Nothing else.

```yaml
permissions:
  id-token: write
  contents: read
```

This is the same minimum set Cole uses in [`cilock-action-oidc.yaml`](https://github.com/testifysec/dropbox-clone/blob/main/.github/workflows/cilock-action-oidc.yaml).

## Step 2: The five-step attested pipeline

```yaml
name: cilock-action OIDC attestations

on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

env:
  STAGING_URL: https://platform.aws-sandbox-staging.testifysec.dev

jobs:
  attest:
    name: Attested CI Pipeline
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.24"

      - name: Install syft
        run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Install gosec
        run: go install github.com/securego/gosec/v2/cmd/gosec@latest

      # 1. Lint + secret scan
      - name: lint + secrets
        uses: aflock-ai/cilock-action@v1.0.4
        with:
          step: lint
          command: echo "lint passed"
          attestations: environment git github secretscan
          platform-url: ${{ env.STAGING_URL }}

      # 2. SAST: gosec writes SARIF, captured as a product. -no-fail keeps
      #    cilock's command-run attestor green when gosec reports findings;
      #    the policy gate is the Rego over the captured SARIF, not the
      #    tool's exit code.
      - name: sast
        uses: aflock-ai/cilock-action@v1.0.4
        with:
          step: sast
          command: gosec -no-fail -fmt=sarif -out=gosec-results.sarif ./...
          attestations: environment git github sarif
          platform-url: ${{ env.STAGING_URL }}
          cilock-args: --attestor-product-include-glob "*.sarif"

      # 3. Tests
      - name: test
        uses: aflock-ai/cilock-action@v1.0.4
        with:
          step: test
          command: go test -count=1 ./...
          attestations: environment git github
          platform-url: ${{ env.STAGING_URL }}

      # 4. Build the binary — cilock observes the compiler's exact argv
      #    via command-run; bin/myapp lands in product/v0.3 as a Merkle
      #    leaf. This is the artifact the SBOM step (next) will scan.
      - name: build
        uses: aflock-ai/cilock-action@v1.0.4
        env:
          CGO_ENABLED: "0"
        with:
          step: build
          command: go build -o bin/myapp ./cmd/myapp
          attestations: environment git github
          platform-url: ${{ env.STAGING_URL }}
          cilock-args: --attestor-product-include-glob "bin/*"

      # 5. SBOM the build's output — separate cilock step so syft's argv
      #    is its own command-run, the build artifact is recorded as
      #    material/v0.3 (because cilock hashes the working tree before
      #    syft runs), and the SBOM lands in product/v0.3. The release-
      #    gate Rego in step 7 verifies the SBOM's targeted file digest
      #    matches the build step's product.
      - name: sbom
        uses: aflock-ai/cilock-action@v1.0.4
        with:
          step: sbom
          command: syft bin/myapp -o cyclonedx-json=bin/bom.cdx.json
          attestations: environment git github sbom
          platform-url: ${{ env.STAGING_URL }}
          cilock-args: --attestor-product-include-glob "bin/*"

      # 5. Container build
      - name: docker-build
        uses: aflock-ai/cilock-action@v1.0.4
        with:
          step: docker-build
          command: docker buildx build --metadata-file docker-metadata.json -t myapp:test --load .
          attestations: environment git github docker
          platform-url: ${{ env.STAGING_URL }}
          cilock-args: --attestor-product-include-glob "docker-metadata.json"
```

## Why each step uses the attestor mix it does

| Step | Extra attestor | Why |
|---|---|---|
| `lint` | `secretscan` | Cheap to run on a no-op command, catches credentials accidentally echoed during real lint output. |
| `sast` | `sarif` | The output is a SARIF file; the SARIF attestor parses it into structured findings inside the attestation. |
| `test` | (none) | Test runs primarily need command-run + git + CI context. |
| `build` | `sbom` | Build produces the binary that's also the SBOM target, one CI/lock invocation captures both. |
| `docker-build` | `docker` | The docker attestor parses the buildx metadata file and records image digests. |

`environment`, `git`, and `github` are passed to every step, this gives you the source commit, runner identity, and CI context on every attestation, so verification policy can match identity claims per step.

## What gets produced

Each step produces a signed DSSE envelope containing an in-toto Collection. With `enable-archivista: true` (the cilock-action default), each envelope is also pushed to Archivista using a fresh OIDC token. The `attestation_file` and `git_oid` action outputs let downstream steps reference the evidence:

```yaml
- name: docker-build
  id: docker
  uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: docker-build
    # ...

- name: Print evidence GitOID
  run: echo "Evidence stored at ${{ steps.docker.outputs.git_oid }}"
```

## Adding a verification gate

To make this enforce policy (not just observe), add a separate job that runs `cilock verify` against a signed policy after all attested steps complete. See [Verify in a release gate](../guides/verify-in-a-release-gate) for the gate pattern.

## Going further

- **Need the raw CLI?** Cole's [`test-staging-cilock.yaml`](https://github.com/testifysec/dropbox-clone/blob/main/.github/workflows/test-staging-cilock.yaml) shows the same five-step pipeline using `cilock run` directly instead of the action, useful for understanding what the action does under the hood.
- **Two-pipeline architecture.** The repo also splits CI (`ci.yaml`, PR-triggered, `contents: read`) from CD (`deploy.yaml`, push-triggered, full AWS credentials via OIDC federation). This is the "two pipelines, two trust boundaries" pattern; CI/lock is the proof that the boundary holds.
- **Defending against real attacks.** See [Defending against supply-chain attacks](./defending-against-supply-chain-attacks) for how the layers above stop the Trivy and LiteLLM compromises.
