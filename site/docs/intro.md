---
id: intro
title: What is CI/lock?
sidebar_position: 1
---

# What is CI/lock?

**CI/lock is a pipeline observer for CI/CD.** It wraps each pipeline step, records cryptographic evidence of what actually executed, and verifies that evidence against signed policy before any artifact ships.

CI/lock builds on [Witness](https://witness.dev) (originated at TestifySec, donated to the CNCF in-toto ecosystem) and verifies Witness-produced attestations directly — though CI/lock's own Merkle-tree, inclusion-proof, and tracing evidence goes beyond what Witness can validate ([details](./ecosystem/witness#interop-direction-precisely)). It implements the "pipeline observer" pattern recommended in the CNCF Software Supply Chain Best Practices v2 guide and the strategies in [NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final) (*Strategies for the Integration of Software Supply Chain Security in DevSecOps CI/CD Pipelines*; TestifySec contributed to this work).

## What it is

| | |
|---|---|
| **What it does** | Wraps a pipeline step and records evidence about the source, environment, command, inputs, outputs, and optional security analysis performed during that step. |
| **Why teams use it** | Logs tell you what the runner printed. CI/lock gives you signed evidence of what actually ran, plus policy enforcement to reject what shouldn't have. |
| **What it is not** | It is not your build tool, test framework, container builder, or deployment engine. It sits around those tools and records trustworthy facts about them. |

## What can you do with CI/lock?

- **Promote releases with confidence:** only ship artifacts when you can verify they came from the expected branch, workflow, build command, and signing identity. → [Release promotion gate](./tutorials/release-promotion-gate)
- **Prove security checks actually ran:** record signed evidence that tests, SAST, SBOM generation, or secret scanning were executed for a given release candidate. → [SBOM and SARIF evidence](./tutorials/sbom-and-sarif-evidence)
- **Reduce audit reconstruction work:** instead of collecting screenshots and CI logs by hand, present structured evidence tied to specific artifacts and releases. → [Store attestations in Archivista](./guides/store-attestations-in-archivista)
- **Make pipeline guardrails machine-checkable:** turn "our release process requires X, Y, and Z" into policy verification instead of relying on reviewers to remember every rule. → [Policy verification](./concepts/policy-verification)
- **Standardize provenance across CI systems:** capture similar evidence from GitHub Actions, GitLab CI, or other environments without redesigning your trust model each time. → [GitHub Actions](./tutorials/github-actions-pipeline) · [GitLab CI](./tutorials/gitlab-ci-pipeline)
- **Link artifacts back to source and pipeline context:** answer the operational question behind many incidents and audits. What exactly produced this binary, image, or package? → [Attestations](./concepts/attestations)
- **Capture runtime + cluster integrity, not just build evidence:** wrap [Falco](./tools/falco) for Kubernetes runtime detections, [Linkerd](./tools/linkerd) for service-mesh mTLS state, or [kube-bench](./attestors/kube-bench) for CIS benchmarks; the same DSSE + in-toto envelope shape that wraps a `go build` also wraps a live-cluster scan, so release-gate Rego works the same way at every stage.
- **Continuous compliance scans:** [Prowler](./tools/prowler) for multi-cloud CSPM, [OpenSCAP](./tools/oscap) / [InSpec](./tools/inspec) for STIG and benchmark compliance, [testssl.sh](./tools/testssl) for FIPS 140 TLS evidence — auditors verify signed envelopes instead of re-running anything.

## Why CI/lock exists

Two pressures push the same direction. Supply-chain attacks have moved past tag-pinning hygiene, and the regulatory environment now demands machine-readable evidence of every step — not just a passing CI badge.

### The attacks

Two supply-chain attacks in March 2026 made the case in five days:

- **March 19, 2026:** an attacker force-pushed 75 of 76 version tags in `aquasecurity/trivy-action`. Every pipeline referencing the action by tag silently ran malicious code on its next trigger. Credentials were scraped from `/proc/<pid>/environ`, encrypted with AES-256-CBC + RSA-4096, and exfiltrated to a typosquat domain.
- **March 24, 2026:** `litellm==1.82.7` and `1.82.8` shipped to PyPI with a credential stealer hidden in a `.pth` file. It executed on every Python interpreter startup (no `import litellm` required), sweeping SSH keys, cloud credentials, Kubernetes tokens, and shell history.

Both attacks used the same playbook: harvest, encrypt, exfiltrate to a typosquat. The shared root cause was structural: **the CI pipeline trusted code it shouldn't have, with credentials it shouldn't have had, and there was no signed record of what actually ran.** CI/lock addresses the structural problem.

### The regulatory environment

Highly regulated environments now require **machine-readable, key-based, continuous evidence** of how software is built and operated, replacing the quarterly-PDF model:

- **FedRAMP 20x** modernizes federal authorization toward continuous monitoring driven by signed, automated evidence — "key indicators" verified from telemetry, not human-curated control narratives. CI/lock's signed in-toto envelopes are exactly the wire format that fits.
- **EU Cyber Resilience Act (CRA)** requires manufacturers of products with digital elements to maintain SBOMs, document vulnerability handling, and prove secure development practices for the full product lifecycle. CI/lock's `sbom`, `vex`, and per-step attestors emit that proof as a byproduct of normal CI.
- **[NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final)** (DevSecOps Integration Strategies — TestifySec contributed) prescribes the "pipeline observer" pattern CI/lock implements: structured attestations across build, scan, and deploy that downstream verifiers can check without re-running.
- **SLSA**, **CMMC** levels 2 and 3, **NIST SSDF (SP 800-218)**, and the EU's **NIS2** directive all converge on the same primitive: signed, structured evidence of build, source, and runtime state. One pipeline observer, multiple compliance regimes.

Whether the trigger is an in-the-wild attack or a federal audit deadline, the answer is the same: **signed evidence at every checkpoint**, not log screenshots stitched together after the fact.

## Three layers of defense

SHA pinning alone isn't enough. The action you pinned to could itself be compromised by a maintainer, a stolen credential, or a typo-squat. CI/lock catches supply-chain attacks at three independent layers, so an attacker has to bypass all three to succeed.

### Layer 1: Prevention (don't run untrusted code)

Restrict actions to an approved catalog (internal forks, [Chainguard Actions](https://chainguard.dev/), GitHub's official `actions/*` namespace), then enforce it with policy. The cilock-action records whether each action ref is pinned to a 40-character commit SHA (`refpinned: true|false`) and emits a GitHub Actions annotation when it isn't. A signed Rego policy then decides whether to allow the build:

```rego
# policy-source-restrict.rego (verbatim from 43-trivy-attack-detection)
package cilock.verify

deny[msg] {
    ref := input.actionref
    not startswith(ref, "actions/")
    not startswith(ref, "chainguard-dev/")
    msg := sprintf("Action from untrusted source: %s", [ref])
}

deny[msg] {
    not input.refpinned
    msg := sprintf("Action ref not pinned to SHA: %s", [input.actionref])
}
```

### Layer 2: Content detection (catch credential leakage)

If prevention fails (a trusted source is compromised, a human overrides a check), CI/lock's [`secretscan`](./concepts/attestors#secretscan-attestor) attestor catches credential patterns in the command output. It runs Gitleaks pattern detection on stdout and **recursively decodes** base64, hex, and URL-encoded content through multiple layers. The default decode depth is **3 layers** (configurable via `--attestor-secretscan-max-decode-layers`).

![secretscan: Gitleaks patterns, recursive decode, env-var matching, encoded-secret detection. Each layer catches what the previous one missed](/img/layer2-content-detection.png)

`--attestor-secretscan-fail-on-detection` blocks the build when any finding fires.

### Layer 3: Behavioral detection (catch what the attacker does)

The `--trace` flag (Linux only) enables ptrace-based syscall capture. Every file each process opens is recorded as `openedfiles` in the `commandrun` attestation, along with suspicious syscalls (`ptrace`, `memfd_create`, `mount`, `clone`). OPA Rego policies match the credential-harvesting filesystem fingerprint:

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

These are the exact Rego rules used in the [`attestor-compliance-examples/43-trivy-attack-detection`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/43-trivy-attack-detection) repo to catch the covert variant of the TeamPCP credential stealer. Trace overhead measured on an `npm install` workload: roughly 36% (5.1s → 6.9s).

For a full walkthrough of how these layers stop the Trivy and LiteLLM attacks, see [Defending against supply-chain attacks](./tutorials/defending-against-supply-chain-attacks).

## Without CI/lock vs. with CI/lock

What the supply-chain attacks of 2026 looked like, with and without a pipeline observer in place:

![Without CI/lock: attacker pushes tag → CI executes blindly → secrets exfiltrated. With CI/lock: SHA pinned → secretscan detects payload → attestation signed and stored → policy blocks release](/img/without-and-with-cilock.png)

| Without CI/lock | With CI/lock |
|---|---|
| A compromised action or package enters the pipeline | Source policy blocks unapproved actions and packages before they run |
| CI executes blindly with no source or hash verification | SHA and hash pinning are enforced; tag rewrites and package swaps have no effect |
| Credentials are harvested at runtime (SSH keys, cloud creds, tokens, shell history) | Secretscan catches credential patterns in output, including payloads hidden under layered base64, hex, or URL encoding |
| Covert variants write to files instead of stdout, evading log inspection | Trace + OPA catches the credential-sweep filesystem access pattern |
| Encrypted bundle exfiltrated to an attacker-controlled domain | Signed attestation creates a tamper-evident record of what ran and what was accessed |
| No forensic trail of what executed, what was touched, or what was stolen | Policy enforcement blocks the release before any compromised artifact ships |

## Mental model: a notary for pipeline steps

If a normal pipeline says "trust me, I built version 1.2.3," CI/lock says "here is signed evidence of the exact commit, command, environment, inputs, outputs, and supporting scan artifacts behind that claim." CI/lock **collects trusted telemetry** from each step (what ran, where, on what inputs, producing what) and **signs the result as in-toto evidence**: structured, cryptographically verifiable, portable. The build provenance travels with the artifact instead of staying trapped in one CI tool, and the same envelope shape covers runtime + cluster telemetry (Falco events, Linkerd mesh state, kube-bench, Prowler) at decision time.

## Honest limitations

CI/lock is **forensic and policy-driven, not a runtime IPS**. It produces signed evidence and verifies it against policy at decision points — release time, audit time, deploy time — rather than enforcing inline in real time. We're explicit about the limits because trust costs more to recover than it costs to set:

- **Detection is post-execution.** If a step exfiltrates secrets during execution, the exfiltration has already happened. CI/lock blocks the *release* and provides forensic evidence; it cannot prevent the initial exfiltration.
- **Network egress is observed, not blocked.** The `trace` attestor captures every `connect`, `sendto`, and `bind` syscall — destination IP, port, address family, DNS lookups, and TLS SNI hostname extracted from the ClientHello — and policy can fail the build on a bad destination. It does not actively block in-flight traffic the way an inline egress proxy ([StepSecurity Harden-Runner](https://github.com/step-security/harden-runner), eBPF-based runtime agents) would.
- **`--trace` is Linux-only and opt-in.** Without it, behavioral detection at the syscall layer is off. Covert file-based attacks may evade content scanning alone.
- **Novel exfiltration techniques can evade pattern matching at the content layer.** Behavioral detection (filesystem + network patterns from ptrace) covers many of these; both layers together catch most known playbooks.
- **CI/lock is not a continuous runtime agent.** It produces signed *point-in-time captures* of production state via wrapped scans — [Falco](./tools/falco) event windows, [Linkerd](./tools/linkerd) mesh + mTLS snapshots, [Prowler](./tools/prowler) CSPM, [kube-bench](./attestors/kube-bench), [testssl.sh](./tools/testssl) — not real-time enforcement on developer laptops or production servers. Continuous runtime enforcement is the role of tools like Falco itself, eBPF agents, or service-mesh sidecars; CI/lock wraps *their* output into signed, policy-checkable evidence.

## How it works

1. **CI/lock wraps a step.** You run a build, test, scan, or packaging command through CI/lock, often in CI but sometimes locally. Each invocation is named via `--step` and represents one step in the supply-chain lifecycle.
2. **Attestors collect facts.** Plugins gather facts in five lifecycle phases (pre-material → material → execute → product → post-product): git state, CI metadata, environment details, file digests of inputs and outputs, SBOMs, SARIF, and more.
3. **Evidence is bundled and signed.** The run's attestations are bundled into a [Collection](./concepts/attestations) and wrapped in a DSSE envelope, then cryptographically signed.
4. **Evidence is stored or shipped.** The signed result can be saved as a file, pushed into [Archivista](./ecosystem/archivista), attached to an OCI image, or attached to downstream release workflows.
5. **Policies verify the release story.** A verifier checks the evidence against a signed policy that lists required attestations, trusted functionaries, and embedded OPA Rego rules.

## Media

More context on CI/lock and the supply-chain landscape it addresses:

- [75 Poisoned Tags and Nobody Noticed](https://testifysec.com/blog/cilock-action-supply-chain-attacks) by Cole Kennedy, March 2026. Trivy tag-rewrite attack walkthrough.
- [A .pth File, 34KB of Base64, and Every Secret You Have](https://testifysec.com/blog/cilock-litellm-supply-chain-attack) by Cole Kennedy, March 2026. LiteLLM PyPI attack walkthrough.
- [Preventing the Claude Code Leak with Attestation Policies](https://testifysec.com/blog/preventing-claude-code-leak-attestation-policies) by Cole Kennedy, April 2026. Attestation policies in action.

## Where to next

- Want the threat-model walkthrough? Read [Defending against supply-chain attacks](./tutorials/defending-against-supply-chain-attacks).
- Ready to try it? Jump to [Get Started → Installation](./getting-started/installation) or the [GitHub Actions tutorial](./tutorials/github-actions-pipeline).
- Coming from witness? See [ecosystem → Witness](./ecosystem/witness) for the interop story.
