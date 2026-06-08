---
title: SBOM and SARIF evidence
sidebar_position: 5
---

# Capturing SBOM and SARIF as signed evidence

This tutorial wires two of the highest-value security attestors (`sbom` and `sarif`) into your CI pipeline. The goal isn't just to *generate* SBOMs and security findings, it's to make their existence **provable**, so a release-gate policy can enforce "this artifact must have a signed SBOM and SARIF attached, or it doesn't ship."

The patterns below are taken from Cole's reference implementation at [github.com/testifysec/dropbox-clone](https://github.com/testifysec/dropbox-clone).

## What each attestor does

| Attestor | What it captures | When to enable it |
|---|---|---|
| `sbom` | Parses any **CycloneDX or SPDX JSON file** in the captured products and embeds the document into the attestation. | Steps that produce an SBOM file, typically the `build` step, after running [syft](https://github.com/anchore/syft), [trivy sbom](https://github.com/aquasecurity/trivy), or another generator. |
| `sarif` | Parses any **SARIF result file** in the captured products. | Steps that run a SAST scanner, gosec, CodeQL, Semgrep, Trivy fs scan, etc. |

Both are post-product attestors, they run after the wrapped command finishes and inspect the products it produced. So **the trick is making sure the SBOM/SARIF file lands in the products glob.**

## Pattern 1: SBOM from a Go build with syft

Use two CI/lock steps — build then SBOM — so each tool's argv lands in its own `command-run/v0.1` attestation, and the SBOM step's `material/v0.3` Merkle root captures the build artifact as input to the SBOM:

```yaml
- name: build
  uses: aflock-ai/cilock-action@v1.0.4
  env:
    CGO_ENABLED: "0"
  with:
    step: build
    command: go build -o bin/myapp ./cmd/myapp
    attestations: environment git github
    cilock-args: --attestor-product-include-glob "bin/*"

- name: sbom
  uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: sbom
    command: syft bin/myapp -o cyclonedx-json=bin/bom.cdx.json
    attestations: environment git github sbom
    cilock-args: --attestor-product-include-glob "bin/*"
```

What happens:

1. **build step:** material attestor records source-file digests. `go build` runs as CI/lock's direct child — its argv is recorded by `command-run/v0.1`. `bin/myapp` lands in `product/v0.3` as a Merkle leaf.
2. **sbom step:** material attestor digests the working tree *after* build, so `bin/myapp` is captured as the SBOM step's input. `syft` runs as CI/lock's direct child. The CycloneDX SBOM lands in `product/v0.3`; the `sbom` attestor parses it and emits a `https://cyclonedx.org/bom` predicate.
3. A release-gate Rego policy can now verify that the SBOM was generated against the exact binary the build step produced — the SBOM step's `material/v0.3.merkleRoot` must contain the same digest as the build step's `product/v0.3.merkleRoot` for `bin/myapp`. See [verify-in-a-release-gate](../guides/verify-in-a-release-gate) for the worked policy.

Don't chain `go build && syft` inside a single `bash -c` — that collapses two tools into one `command-run` attestation, drops the build's product-vs-SBOM-material cross-step link, and breaks the supply-chain BackRef graph CI/lock is meant to produce.

## Pattern 2: SARIF from a SAST scanner

Same shape, different attestor. The trick is letting the SAST tool fail without failing the CI/lock step itself (you want the SARIF report regardless):

```yaml
- name: sast
  uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: sast
    command: gosec -no-fail -fmt=sarif -out=gosec-results.sarif ./...
    attestations: environment git github sarif
    cilock-args: --attestor-product-include-glob "*.sarif"
```

The `-no-fail` flag tells gosec to return 0 even when it finds issues — without it, CI/lock's `command-run/v0.1` attestor records a failed step and downstream attestors skip. The SARIF still carries the findings; the policy gate is the Rego over the captured SARIF, not the tool's exit code. (See [tools/gosec](../tools/gosec) for the full per-tool walkthrough.)

Adapting for other SAST tools — each has a comparable "don't fail on findings" flag so CI/lock's argv stays clean:

| Tool | Command (no shell wrapper) |
|---|---|
| **gosec** | `gosec -no-fail -fmt=sarif -out=results.sarif ./...` |
| **Semgrep** | `semgrep --config p/security-audit --sarif --output=results.sarif .` |
| **CodeQL** | Run `github/codeql-action/analyze` outside CI/lock first (it writes `results.sarif`); then a separate `cilock run --step codeql -- sh -c 'cat results.sarif > codeql.sarif'` captures the SARIF as a product. Yes the `sh -c` is a workaround — file [an action FR upstream](https://github.com/github/codeql-action) for native CI/lock support. |
| **Trivy fs** | `trivy fs --format sarif --output results.sarif .` |
| **Checkov** | `checkov -d . -s -o sarif --output-file-path .` (writes `results_sarif.sarif`; `-s` is the soft-fail flag) |

## Pattern 3: SBOM from a container image

For OCI images, generate the SBOM from the saved image tarball alongside the build:

```yaml
- name: docker-build
  uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: docker-build
    command: docker buildx build --metadata-file docker-metadata.json -t myapp:test -o type=docker,dest=image.tar .
    attestations: environment git github docker oci
    cilock-args: --attestor-product-include-glob "{docker-metadata.json,image.tar}"

- name: docker-sbom
  uses: aflock-ai/cilock-action@v1.0.4
  with:
    step: docker-sbom
    command: syft image.tar -o cyclonedx-json=image-bom.cdx.json
    attestations: environment git github sbom
    cilock-args: --attestor-product-include-glob "image-bom.cdx.json"
```

Each step gets its own signed attestation: `docker-build` carries the buildx metadata, the OCI image (via the `oci` attestor), and the image tarball as a product; `docker-sbom` carries the SBOM with the image tarball as material — so a release-gate policy can verify the SBOM was generated against the image that buildx actually produced.

## Verifying SBOM and SARIF presence in policy

The whole point is making absence a build-blocker. A policy fragment that requires both:

```json
{
  "steps": {
    "build": {
      "name": "build",
      "attestations": [
        { "type": "https://aflock.ai/attestations/material/v0.3" },
        { "type": "https://aflock.ai/attestations/command-run/v0.1" },
        { "type": "https://aflock.ai/attestations/product/v0.3" },
        { "type": "https://aflock.ai/attestations/sbom/v0.1" }
      ],
      "functionaries": [{ "type": "publickey", "publickeyid": "<your-key>" }]
    },
    "sast": {
      "name": "sast",
      "attestations": [
        { "type": "https://aflock.ai/attestations/command-run/v0.1" },
        { "type": "https://aflock.ai/attestations/sarif/v0.1" }
      ],
      "functionaries": [{ "type": "publickey", "publickeyid": "<your-key>" }]
    }
  }
}
```

If the build step ran but the SBOM file wasn't produced (or wasn't captured by the product glob), there's no `sbom` attestation in the collection and `cilock verify` fails the step.

## A subtle but important distinction

`sarif` proves a SAST tool **ran** and captures its findings. It does not prove the tool **passed** with zero findings. To enforce "no high-severity findings," combine the SARIF attestor with an OPA Rego rule:

```rego
package sast.results
import rego.v1

deny contains msg if {
    some run in input.report.runs
    some result in run.results
    result.level == "error"
    msg := sprintf("SARIF error-level finding: %s", [result.message.text])
}
```

Note the `input.report.runs` path: the SARIF attestor wraps the SARIF document under a `report` field alongside `reportFileName` and `reportDigestSet`, so the policy needs to traverse one extra level versus a bare SARIF file.

Embed the base64-encoded module under `regopolicies` for the `sarif` attestation in your policy. Same model for SBOM-based rules (e.g., "deny if the SBOM contains a known-bad component", traversing `input.components[]` on the CycloneDX BOM).

## See also

- [SBOM attestor schema upstream](https://github.com/in-toto/witness/blob/main/docs/attestors/sbom.md)
- [SARIF attestor schema upstream](https://github.com/in-toto/witness/blob/main/docs/attestors/sarif.md)
- [GitHub Actions tutorial](./github-actions-pipeline), full 5-step pipeline using these patterns
