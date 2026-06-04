---
title: Attestors
sidebar_position: 2
---

# Attestors

An **attestor** is a plugin that asserts facts about a system and stores those facts in a versioned schema. Each attestor has a `Name`, `Type` (a versioned URL identifier like `https://aflock.ai/attestations/git/v0.1`), and a `RunType` that determines which lifecycle phase it runs in.

The versioned `Type` is what lets policy verification target a specific attestor's schema reliably.

## Attestor lifecycle

When CI/lock wraps a step, attestors run in a fixed five-phase lifecycle:

| Phase | What runs here |
|---|---|
| **Pre-material** | Environment-collection attestors that run before any other attestors (e.g. CI metadata, JWT identity, cloud IID). |
| **Material** | Attestors that capture state that may change after the command runs, primarily file digests of inputs. |
| **Execute** | Attestors that record information about the command or process being run. |
| **Product** | Attestors that record what changed during execute, typically file digests of outputs. |
| **Post-product** | Attestors that record additional information about specific products, such as OCI image data or SBOM contents from a saved image tarball. |

This ordering is what makes evidence cohesive: materials are captured before the build runs, products after, and the link between them is the verifiable record of what the step actually produced.

## Attestors in the `cilock` binary

The `cilock` binary registers **30+ attestors** by default. The exact set depends on the binary version; run `cilock attestors list` to see what's compiled into yours, or browse the [attestor catalog](../reference/attestor-catalog) for predicate types and lifecycle phases. They cover four broad categories — every attestor name below links to its dedicated reference page:

- **Source & build context:** [`git`](../attestors/git), [`command-run`](../attestors/command-run), [`material`](../attestors/material), [`product`](../attestors/product), [`environment`](../attestors/environment), [`configuration`](../attestors/configuration), [`link`](../attestors/link), [`lockfiles`](../attestors/lockfiles)
- **CI platform identity:** [`github-action`](../attestors/github-action), [`github`](../attestors/github), [`githubwebhook`](../attestors/githubwebhook), [`gitlab`](../attestors/gitlab), [`jenkins`](../attestors/jenkins), [`jwt`](../attestors/jwt)
- **Cloud identity & infrastructure:** [`aws`](../attestors/aws), [`aws-codebuild`](../attestors/aws-codebuild), [`gcp-iit`](../attestors/gcp-iit), [`docker`](../attestors/docker), [`oci`](../attestors/oci), [`k8smanifest`](../attestors/k8smanifest)
- **Security & compliance evidence:** [`sbom`](../attestors/sbom), [`sarif`](../attestors/sarif), [`slsa`](../attestors/slsa), [`secretscan`](../attestors/secretscan), [`vex`](../attestors/vex), [`omnitrail`](../attestors/omnitrail), [`system-packages`](../attestors/system-packages), [`policyverify`](../attestors/policyverify), [`maven`](../attestors/maven)

The `Name()` value (what you pass via `--attestations`) uses hyphens (`command-run`, `github-action`, `aws`) even when the Go package directory uses concatenated form (`commandrun/`, `githubaction/`, `aws-iid/`). The [attestor catalog](../reference/attestor-catalog#naming-gotchas) lists the package-vs-Name() mapping.

Per-attestor field schemas, flags, and gotchas are documented on each attestor's individual page (linked above) — those are the source-of-truth pages, generated from the actual Go struct definitions. The [attestor catalog](../reference/attestor-catalog) is the comparative overview.

The wider [rookery](../ecosystem/rookery) monorepo contains additional attestors that aren't enabled in the default `cilock` binary but can be included via a builder opt-in (see [Build from source](../guides/build-a-custom-cilock)): [`asff`](../attestors/asff), [`aws-config`](../attestors/aws-config), [`docker-bench`](../attestors/docker-bench), [`inspec`](../attestors/inspec), [`kube-bench`](../attestors/kube-bench), [`nessus`](../attestors/nessus), [`oscap`](../attestors/oscap), [`prowler`](../attestors/prowler), [`sinkhole-flows`](../attestors/sinkhole-flows), [`steampipe`](../attestors/steampipe), [`structured-data`](../attestors/structured-data), [`vsa`](../attestors/vsa).

## What to capture

You don't need to enable everything on day one. Most teams adopt evidence in three tiers.

### Foundation

The minimum useful set for any pipeline:

- Git context (`git`)
- CI platform context (`github-action`, `gitlab`, etc.)
- Command execution (`command-run`)
- Material inputs (`material`)
- Product outputs (`product`)

### Recommended next

Once the foundation is stable, add:

- SBOM generation (`sbom`)
- SARIF or security scan results (`sarif`)
- Container or OCI metadata (`oci`, `docker`)
- Timestamping (configured via signer, see [timestamping](./timestamping))

### When maturity grows

After evidence is reliably produced and stored:

- Secret scanning (`secretscan`) for credential exfiltration detection
- Process tracing (`command-run --trace`) for behavioral attack detection
- Policy verification summaries (`policyverify`)
- Release promotion rules (via `cilock verify` policies)
- Cross-system evidence search (via Archivista)
- Compliance report automation

## Attestor security model

Attestations are only as secure as the data that feeds them. Where possible, attestors validate cryptographic material from the environment and include evidence of that validation in the attestation itself for out-of-band verification. The cloud identity attestors (`aws`, `gcp-iit`, `gitlab`) are the canonical examples.

## `secretscan` attestor

The `secretscan` attestor is a `PostProductRunType` attestor that runs [Gitleaks](https://github.com/gitleaks/gitleaks) pattern detection over product files, prior attestations (which include stdout/stderr captured by `command-run`), and the values of sensitive environment variables. Because it runs post-product, it covers everything that finished before it but does not scan concurrent post-product attestors. It is one of the three layers in CI/lock's [defense model](./trust-model#the-three-layer-defense).

### Recursive multi-layer decoding

What makes `secretscan` more than a wrapper around Gitleaks is **recursive decoding**. Many real-world credential stealers hide payloads behind multiple layers of encoding, for example, the LiteLLM PyPI compromise of March 2026 used double-base64. `secretscan` recursively decodes through base64, hex, and URL-encoded content, running Gitleaks at every depth. The core loop, simplified from `rookery/plugins/attestors/secretscan/scanner.go`:

```go
// Simplified; the real condition also has special cases for double-encoded
// short values and padded base64. See scanner.go for the full version.
if currentDepth < a.maxDecodeLayers {
    for _, scanner := range defaultEncodingScanners { // base64, hex, url
        candidates := scanner.Finder(contentStr)
        for _, candidate := range candidates {
            decodedBytes, err := scanner.Decoder(candidate)
            if err == nil && len(decodedBytes) >= minSensitiveValueLength {
                recursiveFindings, _ := a.scanBytes(
                    decodedBytes, sourceIdentifier, detector,
                    processedInThisScan, currentDepth+1,
                )
                findings = append(findings, recursiveFindings...)
            }
        }
    }
}
```

The three encoding scanners are `base64`, `hex`, and `url`, defined in `encoding.go`. Default `maxDecodeLayers = 3` (`constants.go`); raise via `--attestor-secretscan-max-decode-layers <n>`. The upstream go-witness implementation is documented in detail at [go-witness/attestation/secretscan](https://github.com/in-toto/go-witness/tree/main/attestation/secretscan); CI/lock's rookery copy is functionally equivalent.

### Fail-closed mode

By default, `secretscan` records findings as evidence but does not fail the build (`defaultFailOnDetection = false`). Pass `--attestor-secretscan-fail-on-detection` to make any finding a build-blocker.

### Enabling it

```bash
cilock run --step build \
  --attestations "environment git github secretscan" \
  --attestor-secretscan-fail-on-detection \
  -- make build
```

## Process tracing (`--trace`)

Process tracing is the third layer of CI/lock's defense model. On Linux, it intercepts syscalls during the wrapped command's execution and records every file each process opens, plus suspicious syscalls (`ptrace`, `memfd_create`, `mount`, `clone`). The tracer backend is **eBPF where the kernel supports it, falling back to ptrace+seccomp otherwise** (see [How CI/lock captures files](./capture-modes) for backend selection).

### How it works

When `--trace` is set, the `command-run` attestor enables tracing on the wrapped command. The captured data lands in the attestation as `openedfiles` (a `map[string]DigestSet` per process) and as discrete syscall records:

```go
// commandrun.go
type ProcessInfo struct {
    OpenedFiles map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`
    // ...
}

type SyscallRecord struct {
    Syscall string `json:"syscall"` // "memfd_create", "ptrace", "mount", "clone"
    // ...
}
```

Tracing is **Linux-only**. On other platforms the flag is a no-op (`tracing_unsupported.go`).

### Behavioral OPA policies

The point of recording `openedfiles` is to let Rego policies match credential-harvesting filesystem fingerprints, without needing to see the credential content:

```rego
# policy-trace-behavioral.rego (adapted from 43-trivy-attack-detection)
package cilock.verify

import rego.v1

deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    startswith(file, "/tmp/runner_collected")
    msg := sprintf("Suspicious file access: process %s (PID %d) opened %s, matches credential harvesting pattern",
        [proc.program, proc.processid, file])
}

deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    file == "/proc/self/environ"
    msg := sprintf("Suspicious file access: process %s (PID %d) read /proc/self/environ, environment variable harvesting indicator",
        [proc.program, proc.processid])
}
```

These are the actual rules from [`43-trivy-attack-detection/policy-trace-behavioral.rego`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/43-trivy-attack-detection/policy-trace-behavioral.rego), tested in CI against a covert credential-harvesting attack.

### Performance

Trace overhead measured by Cole on an `npm install` workload: roughly **36% (5.1s → 6.9s)**. Significant enough that you'd enable trace selectively (e.g. on the build/install steps where third-party code runs), not on every step.

### Enabling it

```bash
cilock run --step build --trace \
  --attestations "environment git github" \
  -- npm install
```

## Custom attestors

When the built-in set doesn't cover what you need, you can write your own. See [Add a custom attestor](../guides/add-a-custom-attestor).
