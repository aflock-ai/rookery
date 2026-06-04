---
title: Tools
sidebar_label: Overview
sidebar_position: 0
description: CI/lock signs any CLI tool's output — SBOMs, SARIF, VEX, container metadata, IaC misconfigs. Wrap the tool with `cilock run` and the output becomes a signed v0.3 attestation parsed by the matching rookery attestor — no `cp` shims, no `bash -c` chains.
---

import DocCardList from '@theme/DocCardList';
import {useCurrentSidebarCategory} from '@docusaurus/theme-common';

# Tools

Wrap any CLI security or supply-chain tool with `cilock run` and the tool's structured output becomes a signed v0.3 attestation. The pattern is the same for every tool — CI/lock invokes the tool as its direct child, captures the output file as a real product in the v0.3 Merkle tree, and the matching rookery attestor parses that captured file. No `cp` shims, no `bash -c` shell wrappers.

## The pattern

```bash
cilock run --step <step-name> \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations <attestor>,environment,git \
  -- <tool> <args> -o <output-file>
```

What lands in the signed envelope:

| Predicate | Source |
|---|---|
| `command-run/v0.1` | The literal tool argv + exit code + opened-file traces via the ptrace spy |
| `material/v0.3` | Merkle root over the working tree before the tool runs |
| `product/v0.3` | Merkle root over files the tool produced (the SARIF, the SBOM, the metadata file) |
| Tool-specific | The matching attestor (`sarif`, `sbom`, `vex`, `docker`, `oci`, etc.) parses the captured output and emits its own predicate alongside |

Every tool below is **validated end-to-end** in [aflock-ai/attestor-compliance-examples](https://github.com/aflock-ai/attestor-compliance-examples) — the per-tool examples there are the source of truth for the invocations shown on each tool's page.

## Browse by category

Tools are grouped using the same ontology DevSecOps teams already use, expanded to cover the full lifecycle:

- **SAST** — CodeQL, Semgrep, gosec
- **SCA / Vulnerability** — Trivy, Grype, OSV-Scanner, govulncheck
- **IaC & Configuration** — Checkov, Hadolint
- **Container & Kubernetes** — Kubescape
- **SBOM Generation** — Syft
- **DAST** — OWASP ZAP, Nuclei
- **Cloud Security Posture (CSPM)** — Prowler, Steampipe
- **Compliance & Benchmark** — OpenSCAP, InSpec
- **TLS & Cryptographic Compliance** — testssl.sh
- **Service Mesh & Runtime** — Linkerd, Falco

The card grid below shows each supported tool with a one-line description, organized in the same order as the sidebar.

<DocCardList items={useCurrentSidebarCategory().items} />

### SAST — Static Application Security Testing

Source-code analysis. Pattern matching, dataflow, type inference; every finding lands as SARIF 2.1.0, parsed by the `sarif` attestor.

- [**CodeQL**](./codeql.mdx) — GitHub's static analysis engine (also powers GitHub Advanced Security). Python, Go, JS/TS, Java, Kotlin, C/C++, C#, Ruby, Swift.
- [**Semgrep**](./semgrep.mdx) — multi-language pattern + dataflow SAST with bundled and custom rulesets.
- [**gosec**](./gosec.mdx) — Go-focused SAST flagging the standard G-codes (weak crypto, insecure RNG, command injection, etc.).

### SCA — Software Composition Analysis

Match installed packages, lockfiles, or container layers against a vulnerability database. The `sarif` attestor captures SARIF 2.1.0 uniformly; tool-specific attestors are in development to preserve match metadata that flattens into SARIF.

- [**Trivy**](./trivy.mdx) — containers, IaC, secrets, licenses (multi-target). Also covers SCA via `trivy fs`.
- [**Grype**](./grype.mdx) — image or directory vulnerability matching against the Anchore feed; can consume a pre-built SBOM.
- [**OSV-Scanner**](./osv-scanner.mdx) — lockfile + container scanning against the OpenSSF [OSV.dev](https://osv.dev) database.
- [**govulncheck**](./govulncheck.mdx) — Go-specific scanner with call-graph reachability (flags only the vulns your code actually calls).

### IaC & Configuration

Lint Infrastructure-as-Code and container definitions before they're applied.

- [**Checkov**](./checkov.mdx) — Terraform, CloudFormation, Kubernetes, Helm, ARM, Bicep, Dockerfile, and more.
- [**Hadolint**](./hadolint.mdx) — Dockerfile linter with 100+ rules (pinned base images, package install hygiene, USER root).

### Container & Kubernetes

Image scanning + live-cluster posture against compliance frameworks (NSA/CISA, MITRE ATT&CK, ArmoBest).

- [**Kubescape**](./kubescape.mdx) — Kubernetes posture scanner. Supports static manifests + cluster-snapshot scans.

### SBOM Generation

Software Bill of Materials. The `sbom` attestor parses CycloneDX or SPDX JSON; the emitted predicate type is the SBOM's native URI (`https://cyclonedx.org/bom` or `https://spdx.dev/Document`), not an aflock namespace URI.

- [**Syft**](./syft.mdx) — multi-source SBOM generator (containers, directories, archives, OCI layouts). CycloneDX or SPDX output.

## Categorized by output format

| Output format | Tools | Attestor |
|---|---|---|
| **CycloneDX JSON / SPDX JSON** | Syft | `sbom` (emits `https://cyclonedx.org/bom` or `https://spdx.dev/Document`) |
| **SARIF 2.1.0** | Trivy, Grype, OSV-Scanner, govulncheck, Semgrep, gosec, Checkov, Hadolint, Kubescape | `sarif` |
| **OpenVEX** | (any VEX-emitting tool — `vexctl`, syft-vex, etc.) | `vex` |
| **BuildKit JSON metadata** | docker buildx | `docker` |
| **`docker save` tarball** | docker save | `oci` |
| **K8s manifest YAML** | `kubectl get` / `kubectl kustomize` | `k8smanifest` |

For the full per-attestor reference (predicate types, schema, JSON example) see the [attestor catalog](../reference/attestor-catalog.md).

## Adding a new tool

The criteria for inclusion:

1. **Stable machine-readable output flag.** Required. The tool must support a documented `--format` / `-o` / `--output-file` flag producing JSON, SARIF, XML, CycloneDX, or SPDX.
2. **Versioned schema.** The output's structure must be stable (a documented schema URL or a clear major-version commitment).
3. **Open source or free tier.** Commercial-only tools without a free tier are documented but not validated against.
4. **Not redundant with an existing attestor.** Avoid double-coverage — if a tool already flows through `sarif` or `sbom` cleanly, it's "supported-via-existing" and gets a tools page, not a new attestor.

See [`CANDIDATE-ATTESTORS.md`](https://github.com/aflock-ai/attestor-compliance-examples/blob/main/CANDIDATE-ATTESTORS.md) for the full evaluation matrix of 35 candidate tools.

## Frequently asked questions

### Does CI/lock support &lt;my tool&gt;?

If the tool emits SARIF 2.1.0, CycloneDX, SPDX, or OpenVEX — yes, today, via the matching attestor. If the tool emits a stable tool-specific JSON schema, file an issue against rookery to add a native attestor.

### Why must the tool be invoked directly by CI/lock?

So `command-run/v0.1` records the tool's real argv, the ptrace spy can trace the tool's syscalls, and `product/v0.3` captures the tool's real output file. A `bash -c "cp tool-output.sarif product.sarif"` shim records `bash` in `command-run`, hides the tool from the spy, and binds an indirect copy as the product — defeating the per-step provenance graph.

### What if the tool exits non-zero on findings?

Most security tools do (gosec, hadolint, trivy with `--exit-code`, checkov, etc.). Use the tool's native "soft-fail" flag (`-no-fail`, `-s`, `--exit-code 0`) so CI/lock's `command-run/v0.1` stays green. Enforce the finding-count gate in your policy's Rego over the captured SARIF, not at the tool exit code.

### What if the tool writes its output to stdout, not a file?

Wrap with a minimal `sh -c '<tool> ... > out.sarif'`. The `command-run` attestor records the full `sh -c` argv including the tool — that's not the `cp` antipattern, it's a single shell redirect routing the tool's output to a file the product attestor can hash. govulncheck, hadolint, and kubectl all need this.

### Can I use the same pattern in CI?

Yes — every tool page shows the raw CI/lock invocation; the [GitHub Actions](../tutorials/github-actions-pipeline.md) and [GitLab CI](../tutorials/gitlab-ci-pipeline.md) tutorials translate it to the cilock-action / cilock-runner shapes. Each scan/build step becomes its own discrete `cilock` run; the release-gate Rego ties them together via `attestationsFrom` + the v0.3 Merkle root binding.

## See also

- [Attestor catalog](../reference/attestor-catalog.md) — every attestor, its predicate type URI, and lifecycle phase
- [The spine of the graph](../concepts/the-spine-of-the-graph.md) — how subject digests link captures across steps
- [Verify a specific file](../guides/verify-a-specific-file.md) — consumer-side inclusion-proof flow
- [`aflock-ai/attestor-compliance-examples`](https://github.com/aflock-ai/attestor-compliance-examples) — every validated tool example, end-to-end

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({
  "@context": "https://schema.org",
  "@type": "ItemList",
  "name": "cilock supported tools",
  "description": "CLI security and supply-chain tools whose output can be captured under cilock as a signed v0.3 attestation.",
  "itemListElement": [
    {"@type": "SoftwareApplication", "name": "Syft", "url": "https://cilock.aflock.ai/tools/syft", "applicationCategory": "SBOM generator"},
    {"@type": "SoftwareApplication", "name": "Trivy", "url": "https://cilock.aflock.ai/tools/trivy", "applicationCategory": "Vulnerability scanner"},
    {"@type": "SoftwareApplication", "name": "Grype", "url": "https://cilock.aflock.ai/tools/grype", "applicationCategory": "Vulnerability scanner"},
    {"@type": "SoftwareApplication", "name": "OSV-Scanner", "url": "https://cilock.aflock.ai/tools/osv-scanner", "applicationCategory": "Vulnerability scanner"},
    {"@type": "SoftwareApplication", "name": "govulncheck", "url": "https://cilock.aflock.ai/tools/govulncheck", "applicationCategory": "Vulnerability scanner"},
    {"@type": "SoftwareApplication", "name": "CodeQL", "url": "https://cilock.aflock.ai/tools/codeql", "applicationCategory": "Static analysis"},
    {"@type": "SoftwareApplication", "name": "Semgrep", "url": "https://cilock.aflock.ai/tools/semgrep", "applicationCategory": "Static analysis"},
    {"@type": "SoftwareApplication", "name": "gosec", "url": "https://cilock.aflock.ai/tools/gosec", "applicationCategory": "Static analysis"},
    {"@type": "SoftwareApplication", "name": "Checkov", "url": "https://cilock.aflock.ai/tools/checkov", "applicationCategory": "IaC misconfig scanner"},
    {"@type": "SoftwareApplication", "name": "Hadolint", "url": "https://cilock.aflock.ai/tools/hadolint", "applicationCategory": "Dockerfile linter"},
    {"@type": "SoftwareApplication", "name": "Kubescape", "url": "https://cilock.aflock.ai/tools/kubescape", "applicationCategory": "Kubernetes posture scanner"}
  ]
})}} />
