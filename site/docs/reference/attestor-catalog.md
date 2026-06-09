---
title: Attestor catalog
sidebar_position: 4
---

# Attestor catalog

Every attestor compiled into the **default `cilock` binary** (verified against the released `cilock`'s `cilock attestors list` output), with its predicate type URL, lifecycle phase, and a one-line summary. Per-attestor JSON schemas live upstream in the witness docs (linked in the table); CI/lock and witness use compatible schemas, with CI/lock attestation types namespaced under `https://aflock.ai/attestations/<name>/v0.1` and witness types under `https://witness.dev/attestations/<name>/v0.1`. CI/lock accepts both via legacy aliases. Several attestors emit upstream-typed predicates (SLSA, OpenVEX, in-toto link, SLSA VSA) instead of an aflock-namespaced one; those exact types are shown in the table.

> Source of truth: [`rookery/cilock/cmd/cilock/main.go`](https://github.com/aflock-ai/rookery/blob/main/cilock/cmd/cilock/main.go) for the registered set; per-attestor source in [`rookery/plugins/attestors/<name>/`](https://github.com/aflock-ai/rookery/tree/main/plugins/attestors).

The current binary registers **45 attestors** (3 always-run, 2 default-on, the rest opt-in). The table below documents the most commonly used ones; run `cilock attestors list` for the authoritative, complete set for your exact binary.

## Inspecting your binary

```bash
# Full table of registered attestors with name, type URL, run type
cilock attestors list

# JSON Schema for a specific attestor's predicate
cilock attestors schema git
```

The `(always run)` and `(default)` markers in `cilock attestors list` show which attestors fire on every `cilock run` and which are enabled without being passed via `--attestations`.

## Source & build context

| Name | Predicate type | Lifecycle | What it captures | Upstream schema |
|---|---|---|---|---|
| `git` (default) | `https://aflock.ai/attestations/git/v0.1` | prematerial | Commit hash, branch, tags, author, committer, dirty status, refs, remotes, parents | [witness/git.md](https://github.com/in-toto/witness/blob/main/docs/attestors/git.md) |
| `command-run` (always run) | `https://aflock.ai/attestations/command-run/v0.1` | execute | argv, exit code, stdout/stderr digests, optional ptrace `openedfiles` and syscall records | [witness/command-run.md](https://github.com/in-toto/witness/blob/main/docs/attestors/command-run.md) |
| `material` (always run) | `https://aflock.ai/attestations/material/v0.3` | material | Merkle root over the digests of all files in the working directory before the command runs. The per-file `leaves` (path, fileDigest, leafHash) are inlined in the attestation by default, so the signed envelope is self-contained and every input file is directly verifiable from it. | [material (v0.3)](../attestors/material) |
| `product` (always run) | `https://aflock.ai/attestations/product/v0.3` | product | Merkle root over the digests of files changed/created during execute (filtered by `--attestor-product-include-glob` / `--attestor-product-exclude-glob`). Per-file `leaves` are inlined in the attestation, so every output file is directly verifiable from the signed envelope. | [product (v0.3)](../attestors/product) |
| `inclusion-proof` | `https://aflock.ai/attestations/inclusion-proof/v0.1` | postproduct | Signed RFC 6962 inclusion proof binding a single file's digest to a v0.3 product/material Merkle root. With v0.3 inline leaves, per-file verification flows directly from the product attestation; this attestor handles the standalone envelope path for separately-shipped proofs. | [inclusion-proof](../attestors/inclusion-proof) |
| `material-v0.1` (legacy, verify-only) | `https://aflock.ai/attestations/material/v0.1` | material | Verify-only decoder for the historical per-file `material` predicate body. `cilock verify` reads pre-cutover envelopes through this registration; not produced. | [material legacy](../attestors/material) |
| `product-v0.1` (legacy, verify-only) | `https://aflock.ai/attestations/product/v0.1` | product | Verify-only decoder for the historical per-file `product` predicate body. | [product legacy](../attestors/product) |
| `product-v0.2` (legacy, verify-only) | `https://aflock.ai/attestations/product/v0.2` | product | Verify-only decoder for v0.2 envelopes — same predicate body as v0.1 (the in-toto `Statement.Subject` is what differed). | [product legacy](../attestors/product) |
| `environment` (default) | `https://aflock.ai/attestations/environment/v0.1` | prematerial | OS, kernel, env vars (sensitive vars obfuscated or filtered) | [witness/environment.md](https://github.com/in-toto/witness/blob/main/docs/attestors/environment.md) |
| `configuration` | `https://aflock.ai/attestations/configuration/v0.1` | prematerial | Captures CI/lock's own runtime config for the step | (cilock-native) |
| `link` | `https://in-toto.io/attestation/link/v0.3` | postproduct | in-toto link statement format (legacy in-toto compat) | [witness/link.md](https://github.com/in-toto/witness/blob/main/docs/attestors/link.md) |
| `lockfiles` | `https://aflock.ai/attestations/lockfiles/v0.1` | prematerial | Hashes of detected lockfiles for package-manager integrity | [witness/lockfiles.md](https://github.com/in-toto/witness/blob/main/docs/attestors/lockfiles.md) |
| `go-build` | `https://aflock.ai/attestations/go-build/v0.1` | postproduct | Build provenance Go embeds in compiled binaries (`runtime/debug.BuildInfo`: module path, dependency versions, VCS commit, build settings), read from the step's product binaries. | (cilock-native) |

## CI platform identity

| Name | Predicate type | Lifecycle | What it captures | Upstream schema |
|---|---|---|---|---|
| `github-action` | `https://aflock.ai/attestations/github-action/v0.1` | execute | Workflow, job, run-id, actor, event, ref, SHA from `GITHUB_*` env | (cilock-native) |
| `github` | `https://aflock.ai/attestations/github/v0.1` | prematerial | GitHub OIDC token claims (audience, subject, repo, ref) | [witness/github.md](https://github.com/in-toto/witness/blob/main/docs/attestors/github.md) |
| `github-review` | `https://aflock.ai/attestations/github-review/v0.1` | prematerial | GitHub pull-request review state (reviewers, approval decisions) for the commit, fetched from the GitHub REST API. | (cilock-native) |
| `githubwebhook` | `https://aflock.ai/attestations/githubwebhook/v0.1` | postproduct | Inbound webhook payload digest for chain-of-custody | (cilock-native) |
| `gitlab` | `https://aflock.ai/attestations/gitlab/v0.1` | prematerial | GitLab CI JWT identity, pipeline, job, runner, ref | [witness/gitlab.md](https://github.com/in-toto/witness/blob/main/docs/attestors/gitlab.md) |
| `jenkins` | `https://aflock.ai/attestations/jenkins/v0.1` | prematerial | Jenkins build identity and job context | [witness/jenkins.md](https://github.com/in-toto/witness/blob/main/docs/attestors/jenkins.md) |
| `jwt` | `https://aflock.ai/attestations/jwt/v0.1` | prematerial | Generic JWT identity capture (used for non-built-in OIDC sources) | [witness/jwt.md](https://github.com/in-toto/witness/blob/main/docs/attestors/jwt.md) |

## Cloud identity & infrastructure

| Name | Predicate type | Lifecycle | What it captures | Upstream schema |
|---|---|---|---|---|
| `aws` | `https://aflock.ai/attestations/aws/v0.1` | prematerial | AWS EC2 instance identity document, cryptographically validated against the AWS public key | [witness/aws.md](https://github.com/in-toto/witness/blob/main/docs/attestors/aws.md) |
| `aws-codebuild` | `https://aflock.ai/attestations/aws-codebuild/v0.1` | prematerial | AWS CodeBuild project identity and build metadata | [witness/aws-codebuild.md](https://github.com/in-toto/witness/blob/main/docs/attestors/aws-codebuild.md) |
| `gcp-iit` | `https://aflock.ai/attestations/gcp-iit/v0.1` | prematerial | GCP Instance Identity Token, validated against GCP keys | [witness/gcp-iit.md](https://github.com/in-toto/witness/blob/main/docs/attestors/gcp-iit.md) |
| `docker` | `https://aflock.ai/attestations/docker/v0.1` | postproduct | Docker buildx metadata file digests, image tags | [witness/docker.md](https://github.com/in-toto/witness/blob/main/docs/attestors/docker.md) |
| `oci` | `https://aflock.ai/attestations/oci/v0.1` | postproduct | OCI image content from saved image tarball, layers, config, manifests | [witness/oci.md](https://github.com/in-toto/witness/blob/main/docs/attestors/oci.md) |
| `k8smanifest` | `https://aflock.ai/attestations/k8smanifest/v0.2` | postproduct | Kubernetes manifest digests for deploy artifacts | [witness/k8smanifest.md](https://github.com/in-toto/witness/blob/main/docs/attestors/k8smanifest.md) |

## Security & compliance evidence

| Name | Predicate type | Lifecycle | What it captures | Upstream schema |
|---|---|---|---|---|
| `sbom` | `https://aflock.ai/attestations/sbom/v0.1` | postproduct | Parses CycloneDX or SPDX JSON files in the products and embeds the SBOM document. (When a CycloneDX SBOM is emitted as a standalone attestation via `--attestor-sbom-export`, its inner predicateType becomes `https://cyclonedx.org/bom`.) | [witness/sbom.md](https://github.com/in-toto/witness/blob/main/docs/attestors/sbom.md) |
| `sarif` | `https://aflock.ai/attestations/sarif/v0.1` | postproduct | Parses SARIF result files (CodeQL, Semgrep, gosec, Trivy, etc.). Outer predicate wraps the SARIF report at `.report`, so Rego policies use `input.report.runs` not `input.runs`. | [witness/sarif.md](https://github.com/in-toto/witness/blob/main/docs/attestors/sarif.md) |
| `slsa` | `https://slsa.dev/provenance/v1.0` | postproduct | Emits SLSA Provenance v1 from the `cilock` run context. Uses the upstream SLSA predicate type directly. | [witness/slsa.md](https://github.com/in-toto/witness/blob/main/docs/attestors/slsa.md) |
| `slsa-provenance-v1` | `https://slsa.dev/provenance/v1` | verify | Typed SLSA Provenance v1, registered via the attestation factory. Distinct from the postproduct `slsa` attestor (which embeds provenance during a build). | (cilock-native) |
| `govulncheck` | `https://aflock.ai/attestations/govulncheck/v0.1` | postproduct | Parses `govulncheck` JSON — reports both imported and **reachable** Go vulnerabilities (call-graph based), not just dependency presence. | (cilock-native) |
| `test-results` | `https://aflock.ai/attestations/test-results/v0.1` | postproduct | Structured test-run results parsed from JUnit XML or CTRF JSON report files in the products (per-test pass/fail/skip). | (cilock-native) |
| `secretscan` | `https://aflock.ai/attestations/secretscan/v0.1` | postproduct | Gitleaks pattern scan with **recursive base64/hex/URL decode** (default `maxDecodeLayers=3`); `--attestor-secretscan-fail-on-detection` blocks the build on hits. See [concepts → secretscan](../concepts/attestors#secretscan-attestor). | [witness/secretscan.md](https://github.com/in-toto/witness/blob/main/docs/attestors/secretscan.md) |
| `vex` | `https://openvex.dev/ns` | postproduct | Vulnerability Exploit Exchange, explicit vulnerability disposition statements. Uses the upstream OpenVEX predicate type. | [witness/vex.md](https://github.com/in-toto/witness/blob/main/docs/attestors/vex.md) |
| `omnitrail` | `https://aflock.ai/attestations/omnitrail/v0.1` | prematerial | OmniTrail tooling trail (Linux/Darwin only; Windows builds excluded for this reason) | [witness/omnitrail.md](https://github.com/in-toto/witness/blob/main/docs/attestors/omnitrail.md) |
| `system-packages` | `https://aflock.ai/attestations/system-packages/v0.1` | prematerial | OS package inventory (deb/rpm/apk) | [witness/system-packages.md](https://github.com/in-toto/witness/blob/main/docs/attestors/system-packages.md) |
| `policyverify` | `https://slsa.dev/verification_summary/v1` | verify | Records a SLSA Verification Summary Attestation (VSA) for the verify result. **Verify-type attestor:** runs only inside `cilock verify`; cannot be combined with run-type attestors in `cilock run`. | (cilock-native; see [verify-in-a-release-gate](../guides/verify-in-a-release-gate)) |
| `maven` | `https://aflock.ai/attestations/maven/v0.1` | prematerial | Maven build context (POM path defaults to `pom.xml`) and dependency declarations | [witness/maven.md](https://github.com/in-toto/witness/blob/main/docs/attestors/maven.md) |

## Always-run and default sets

Verified from `rookery/cilock/internal/cmd/run.go` + the live `cilock attestors list`:

- **Always run** (cannot be omitted, run on every `cilock run`): `material`, `product`, and `command-run` (when args are provided).
- **Default attestation set** (when `--attestations` is not specified): `environment,git` (comma-separated, per cobra `StringSlice` semantics).

Pass additional attestors with `--attestations "<a>,<b>,<c>"` (comma-separated, not space). CI/lock also accepts the legacy witness URL aliases via `attestation.RegisterLegacyAliases()`, called from `cilock/cmd/cilock/main.go` at startup.

## Naming gotchas

The on-disk Go package name and the attestor's `Name()` aren't always identical. Use the `Name()` value when passing `--attestations`:

| Go package directory | Attestor `Name()` (use this in `--attestations`) |
|---|---|
| `plugins/attestors/commandrun/` | `command-run` |
| `plugins/attestors/githubaction/` | `github-action` |
| `plugins/attestors/aws-iid/` | `aws` |

## Available in rookery but not in the default `cilock` binary

These attestors live in [`rookery/plugins/attestors/`](https://github.com/aflock-ai/rookery/tree/main/plugins/attestors) but are not registered in the default `cilock` binary (some are imported but not registered, others aren't imported at all). To include them, add the blank-import to `cilock/cmd/cilock/main.go` and rebuild — see [Build from source](../getting-started/installation#4-build-from-source):

`asff`, `aws-config`, `docker-bench`, `nessus`, `sinkhole-flows`, `structured-data`, `vsa`

Confirm against your own binary with `cilock attestors list` — the registered set changes between releases, and several scanner attestors (`oscap`, `inspec`, `kube-bench`, `prowler`, `steampipe`, `pip-install`) that were previously opt-in are now registered by default.
