---
title: Defending against supply-chain attacks
sidebar_position: 1
---

# Defending against supply-chain attacks

This tutorial walks through three real supply-chain compromises, `tj-actions/changed-files` (March 2025), `aquasecurity/trivy-action` (March 2026), and `litellm` on PyPI (March 2026), and shows how CI/lock's three-layer defense stops each one. The detection logic is the same across all three; only the delivery vector changes.

## The attacks share a playbook

| Attack | Vector | Encoding | Exfiltration |
|---|---|---|---|
| **tj-actions** (Mar 2025) | Mutable Git tag rewrite | base64 | HTTPS POST to attacker domain |
| **Trivy** (Mar 19, 2026) | 75 force-pushed Git tags | base64 (single layer) | HTTPS POST to typosquat domain |
| **LiteLLM** (Mar 24, 2026) | Compromised PyPI versions, `.pth` autoload | base64 (double layer) | HTTPS POST to typosquat domain |

All three followed the same four-stage kill chain: compromise the source, hide a payload, harvest credentials from the runner (env vars, SSH keys, cloud creds, k8s configs), encrypt with AES-256-CBC + RSA-4096, exfiltrate.

When the encryption scheme, exfiltration pattern, and credential targets are this similar across attacks, you're not looking at independent attackers, you're looking at a toolkit being reused.

## Layer 1: Prevention: don't run the compromised code

The `tj-actions` and Trivy attacks both worked because workflows referenced actions by mutable tag. When the attacker gained write access (via stolen maintainer credentials), they moved the tags to point at malicious commits. Every workflow using the tag immediately ran the compromised code on its next trigger.

**Fix:** require SHA pinning + an approved-source allowlist, enforced by Rego policy.

```yaml
# ❌ VULNERABLE: mutable tag can be moved to malicious code
- uses: actions/checkout@v4

# ✅ SAFE: immutable commit SHA, audited once
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v4
```

Cilock-action records `refpinned: true|false` and `actionref: <full ref>` in every attestation, and emits a GitHub Actions warning annotation when an action isn't pinned to a 40-character commit SHA. A signed Rego policy decides whether the build is allowed:

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

This is the actual policy used in [`attestor-compliance-examples/43-trivy-attack-detection`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/43-trivy-attack-detection/policy-source-restrict.rego), where the `verify-source-policy` job confirms it denies `actions/setup-node@v4` (allowed source, but unpinned tag).

### What to do instead of trivy-action

The cleanest defense against the trivy-action compromise isn't to "pin trivy-action better", it's to stop using trivy-action and wrap the trivy CLI itself with `cilock run`. This is exactly what trivy-action does internally, but with full attestation capture and no third-party action in the critical path:

```yaml
- name: Build image to scan
  run: docker build -t example-api:test .

- name: Install Trivy CLI
  run: |
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

- name: Trivy scan wrapped with cilock
  run: |
    cilock run \
      --step trivy-scan \
      --attestations secretscan \
      --attestations environment \
      --attestations git \
      --signer-fulcio-url https://fulcio.sigstore.dev \
      --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \
      --signer-fulcio-oidc-client-id sigstore \
      --timestamp-servers https://timestamp.sigstore.dev/api/v1/timestamp \
      --outfile trivy-attestation.json \
      -- trivy image --format sarif --output trivy-results.sarif \
            --severity CRITICAL,HIGH example-api:test
```

You get the same trivy scan, plus signed attestations of what trivy actually did, plus secretscan running over its output, and zero exposure to a future trivy-action tag rewrite. Pattern verified from the `wrap-real-trivy` job in [`43-trivy-attack-detection/.github/workflows/protected.yml`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/43-trivy-attack-detection/.github/workflows/protected.yml).

For PyPI/npm/maven dependencies, the equivalent is a hash-pinned lock file:

```rego
deny contains msg if {
    some step in input.steps
    step.command == "pip install"
    not step.flags["require-hashes"]
    msg := "pip install must use --require-hashes"
}
```

If the LiteLLM 1.82.8 wheel hash didn't match the lock file, the build stops before the `.pth` payload ever lands in `site-packages/`.

## Layer 2: Content detection: catch the encoded payload

Prevention isn't sufficient on its own. A trusted source can be compromised. A maintainer might re-pin to a malicious commit. A human override might let an unapproved action through.

When the malicious code does run, the LiteLLM attacker's playbook was to encode the credential stealer in **double base64**:

```python
# litellm_init.pth
import base64; exec(base64.b64decode(base64.b64decode(
    "VVZSS1IxUXlSWGhpUkZKb1VtMW9jMWxyWkZOT1..."  # 34KB
)))
```

A grep for `AWS_ACCESS_KEY` against the `.pth` file finds nothing. A grep against the first base64 decode also finds nothing, the inner content is *also* base64. The credential patterns only become visible at depth 2.

CI/lock's [`secretscan`](../concepts/attestors#secretscan-attestor) attestor recursively decodes through encoded content (default 3 layers, configurable via `--attestor-secretscan-max-decode-layers`) and runs Gitleaks pattern matching at every depth:

```go
// rookery/plugins/attestors/secretscan/scanner.go
if currentDepth < a.maxDecodeLayers {
    for _, scanner := range defaultEncodingScanners {
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

Add it to your pipeline by passing `secretscan` in `attestations` and the fail-closed flag:

```yaml
- uses: aflock-ai/cilock-action@v1.0.1
  with:
    step: install
    command: pip install -r requirements.txt
    attestations: environment git github secretscan
    cilock-args: --attestor-secretscan-fail-on-detection
```

When Cole's team reproduced the TeamPCP credential harvesting pattern in CI with `secretscan` enabled, the result was 4 findings (`github-pat` and `private-key` at depth 0, plus duplicates at depth 1 from the decoded stealer output) and the build was blocked.

## Layer 3: Behavioral detection: catch what the attacker does

The most sophisticated variant of the TeamPCP stealer was designed to be covert: credentials went directly to files, never to stdout. `secretscan` alone would miss it, there's nothing in the command output to match against.

This is what `--trace` is for. When enabled, CI/lock traces the wrapped command via eBPF where available (falling back to ptrace+seccomp otherwise) to record every file each process opens, plus suspicious syscalls (`ptrace`, `memfd_create`, `mount`, `clone`). The credential-harvesting filesystem fingerprint is what you policy against, no need to see the credential content:

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

These are the actual rules from [`43-trivy-attack-detection/policy-trace-behavioral.rego`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/43-trivy-attack-detection/policy-trace-behavioral.rego). The `verify-trace-behavioral` job in that repo's workflow confirms they fire against a covert attack that writes harvested credentials to `/tmp/runner_collected_<pid>.txt` and reads `/proc/self/environ`, exactly the TeamPCP fingerprint.

A legitimate `pip install` does not read `/.ssh/`, `/.aws/`, and `/.kube/config`. A legitimate test runner does not write to `/tmp/runner_collected_*`. The behavioral signature has essentially zero false-positive rate inside a typical CI step.

Enable it on the steps where third-party code actually runs:

```yaml
- uses: aflock-ai/cilock-action@v1.0.1
  with:
    step: install
    command: pip install -r requirements.txt
    attestations: environment git github
    cilock-args: --trace
```

Trace adds roughly **36% overhead** on an `npm install` workload (5.1s → 6.9s in Cole's measurements), so enable it selectively rather than universally.

## With and without CI/lock

| | Without CI/lock | With CI/lock |
|---|---|---|
| Compromised action runs | CI executes blindly | Layer 1 policy denies, unpinned/unapproved ref |
| Encoded credential stealer in stdout | Credentials exfiltrated; no record | Layer 2 `secretscan` recursive decoder catches the payload |
| Covert file-based harvest | Credentials exfiltrated; no record | Layer 3 trace + behavioral OPA catches the filesystem pattern |
| After the fact | No forensic trail; rotate everything | Signed attestation: which files were accessed by which process |

## A secretscan policy as an alternative to fail-on-detection

If you'd rather have the secretscan finding land in the attestation but reject the build at *verify* time (instead of at run time via `--attestor-secretscan-fail-on-detection`), use this Rego rule:

```rego
# policy-secretscan.rego (verbatim from 43-trivy-attack-detection)
package cilock.verify

import rego.v1

# Deny any step where secretscan found credentials
deny contains msg if {
    some step in input.predicate.attestations
    step.type == "https://aflock.ai/attestations/secretscan/v0.1"
    some finding in step.attestation.findings
    msg := sprintf("Secret detected: %s (%s)", [finding.ruleId, finding.location])
}
```

Useful when you want secretscan findings recorded as evidence on every build but only blocked at the release gate.

## Cryptographic verification: not just logging

Every CI/lock attestation is signed with a Fulcio short-lived certificate (tied to GitHub Actions OIDC identity), timestamped by Sigstore TSA (RFC 3161), and verified against a signed Rego policy. `cilock verify` validates the signature chain, checks the timestamp, and evaluates the policy. If anything fails, the release is blocked.

This is **not audit logging**. It's cryptographic proof of what ran, when it ran, what it produced, and whether it met policy, with a tamper-evident chain from the runner to the policy decision.

## What this doesn't cover

CI/lock is detection-and-policy, not real-time prevention. Read the [trust model](../concepts/trust-model#detection-vs-real-time-prevention) page for the honest version of what each layer can and can't catch. The headline limitations:

- **Detection is post-execution.** Exfiltration during a step has already happened by the time policy runs. CI/lock blocks the *release* of the affected artifact and produces forensic evidence, Layer 1 is what reduces the chance of the malicious step running at all.
- **Network egress is observed, not blocked.** `--trace` records every connection (destination IP, port, TLS SNI) as evidence and policy can fail the build on a bad destination, but CI/lock doesn't block traffic in flight — an inline egress proxy like [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) does.
- **`--trace` is Linux-only.**
- **CI/lock operates in CI/CD only:** not on developer laptops or production servers.

## Further reading

Cole's TestifySec blog posts on the underlying attacks:

- [The One Architecture Decision That Protects Your High-Value Secrets](https://testifysec.com/blog/ci-cd-isolation-protecting-secrets), CI/CD isolation, the two-pipeline pattern, and how CI/lock provides the proof layer.
- [75 Poisoned Tags and Nobody Noticed](https://testifysec.com/blog/cilock-action-supply-chain-attacks), the Trivy attack and the three-layer defense, with reproductions in a live GitHub Actions pipeline.
- [A `.pth` File, 34KB of Base64, and Every Secret You Have](https://testifysec.com/blog/cilock-litellm-supply-chain-attack), the LiteLLM attack and how the same three layers apply to a different vector.
