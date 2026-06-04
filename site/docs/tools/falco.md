---
title: Falco
description: Capture Falco runtime-security events under CI/lock — the native rookery falco attestor parses Falco's line-delimited JSON events into a signed v0.3 attestation with per-rule aggregation, priority counts, and Kubernetes cluster context.
sidebar_position: 19
---

# `Falco` integration

:::caution Not in the default binary
The `falco` attestor exists in [rookery](https://github.com/aflock-ai/rookery) but is **not compiled into the default `cilock` binary** — `cilock attestors list` won't show it. To use it, build a custom binary that includes the plugin with [rookery-builder](../guides/build-a-custom-cilock). The flows below assume such a build.
:::

[Falco](https://falco.org) is the de-facto open-source runtime-security engine for Kubernetes — it loads a kernel eBPF probe (or the legacy module driver) and fires structured events whenever a rule matches a syscall, container behavior, or Kubernetes audit event. Under CI/lock, the rookery **native `falco` attestor** ingests Falco's line-delimited JSON event output and produces a signed in-toto attestation linked to the host environment, the git commit, the literal capture argv, and per-rule + per-priority aggregations.

Unlike SARIF-shaped tools, Falco's output is a stream of events with a stable JSON schema (`time`, `rule`, `priority`, `output`, `output_fields`, K8s context). The native attestor parses every event, aggregates them per rule and per priority, and embeds both the raw events and the summary in the same envelope. A release-gate Rego policy can deny on `falco.summary.priorities.error > 0`, or on a specific rule firing more than zero times, without having to walk every event.

## Validated invocation

```bash
# Pre-reqs: Falco installed in your cluster (falcosecurity/falco Helm chart),
# kubeconfig pointed at it, ed25519 key at key.pem.

FALCO_CLUSTER_NAME=<your-cluster> cilock run --step falco-capture \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations falco,environment,git \
  --enable-archivista=false \
  -- sh -c 'kubectl logs daemonset/falco -n <falco-ns> --tail=500 \
            | grep "\"rule\"" > falco-events.jsonl'
```

This is the recipe exercised in [`tool-falco-events`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-falco-events) — validated against the [`dropbox-clone-dev`](https://github.com/testifysec/dropbox-clone) EKS cluster with a deterministic "Read sensitive file untrusted" rule firing (a test pod `cat`'s `/etc/shadow`).

The `sh -c` wrapper is necessary because `kubectl logs` writes to stdout — the shell redirect routes that stream to `falco-events.jsonl` so the `product/v0.3` Merkle tree can hash it. The `command-run/v0.1` predicate records the full `sh -c` argv; this is **not** the cp antipattern (you're not making a copy of a file written outside CI/lock's view, you're routing a streaming-only tool's stdout into a file). The grep filters out Falco's startup banner so only event lines are captured.

`FALCO_CLUSTER_NAME` is the only env var the falco attestor reads — it stamps the captured envelope's `falco.cluster` field so policies can branch on which cluster the events came from. If unset, the field is empty but the attestation still signs.

:::note Availability
The `falco` attestor is **available today via `rookery-builder --preset all`** ([guide](../guides/build-a-custom-cilock.md)). It will land in the canonical default `cilock` binary once [rookery#147](https://github.com/aflock-ai/rookery/pull/147) merges.
:::

## What gets captured

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, kernel, env vars (sensitive ones obfuscated) |
| `https://aflock.ai/attestations/git/v0.1` | commit hash, branch, dirty status |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over the working tree before the capture |
| `https://aflock.ai/attestations/command-run/v0.1` | literal `sh -c 'kubectl logs … > falco-events.jsonl'` argv + exit code |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over `falco-events.jsonl` as a real product file |
| `https://aflock.ai/attestations/falco/v0.1` | parsed events + per-rule aggregation + priority counts + cluster name |

The `falco/v0.1` predicate body has this shape:

```json
{
  "events": [ /* every Falco event verbatim: time, rule, priority, output, output_fields, K8s context */ ],
  "summary": {
    "total_events": 2,
    "priorities": { "warning": 2 },
    "rule_hits": [
      { "rule": "Read sensitive file untrusted", "count": 2, "highest_priority": "Warning" }
    ]
  },
  "cluster": "dropbox-clone-dev",
  "source_file": { "path": "falco-events.jsonl", "sha256": "..." }
}
```

## Why this shape

| Antipattern | Correct shape (this example) |
|---|---|
| `cilock run ... -- bash -c "kubectl logs ... > events.jsonl && cp events.jsonl falco-product.jsonl"` | `cilock run ... -- sh -c 'kubectl logs ... > falco-events.jsonl'` |
| `command-run.cmd` records the `bash -c "... && cp ..."` chain | `command-run.cmd` records the single `sh -c` with the kubectl + redirect; no cp |
| The product is a copy of a file written outside CI/lock's view | The product is `falco-events.jsonl` as the wrapped shell wrote it during the step |

Three properties matter under the falco attestor: (1) `command-run/v0.1.cmd` records the real `sh -c` argv including the kubectl invocation — not a chained shell with a separate cp. (2) The ptrace spy traces the shell + kubectl child processes because CI/lock is `sh`'s direct parent. (3) `product/v0.3` captures `falco-events.jsonl` as written via the single redirect inside the wrapped step, then the falco attestor parses the same file to produce `falco/v0.1`.

The single `sh -c` wrapper is the same pattern as [hadolint](./hadolint.mdx) and [govulncheck](./govulncheck.mdx) — tools (or in Falco's case, the `kubectl logs` consumer) that write structured output to stdout. The shell-redirect is the one-shot conversion from stdout to a file the product attestor can hash. The `command-run` predicate records the full argv; there's no copy of a file written outside CI/lock's view, so this is **not** the cp antipattern.

## Validate it locally

List the predicate types in the captured envelope:

```bash
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
```

Expected output:

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/falco/v0.1"
]
```

Confirm `command-run.cmd` carries the literal `sh -c` argv:

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'
# ["sh","-c","kubectl logs daemonset/falco -n <ns> --tail=500 | grep \"\\\"rule\\\"\" > falco-events.jsonl"]
```

Pull the Falco summary from the signed envelope:

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/falco/v0.1") | .attestation | {total: .summary.total_events, priorities: .summary.priorities, rules: .summary.rule_hits, cluster}'
# {
#   "total": 2,
#   "priorities": { "warning": 2 },
#   "rules": [ { "rule": "Read sensitive file untrusted", "count": 2, "highest_priority": "Warning" } ],
#   "cluster": "dropbox-clone-dev"
# }
```

## Notes

- **Falco install.** The validated example uses the [`falcosecurity/falco`](https://github.com/falcosecurity/charts) Helm chart with `driver.kind=modern-bpf`. JSON output is enabled via `--set json_output=true --set falco.json_output=true --set falco.json_include_output_property=true`. The full install + capture recipe is in [`tool-falco-events/reproduce.sh`](https://github.com/aflock-ai/attestor-compliance-examples/blob/main/tool-falco-events/reproduce.sh).
- **Why `--tail=500`.** A long-running Falco daemonset's log buffer can be huge. `--tail=500` keeps the capture deterministic for a single release-gate step; for forensic captures, run without `--tail` or stream via `kubectl logs -f` against a separate sidecar.
- **`FALCO_CLUSTER_NAME` env var.** The attestor reads this single env var to stamp the envelope's `falco.cluster` field. Set it in CI so policies can branch on cluster (`dropbox-clone-dev` vs `prod` vs `staging`). If unset, the field is empty but the attestation still signs.
- **Streaming vs windowed capture.** This page documents a windowed capture (`kubectl logs --tail=500`). For continuous streaming, run Falco's JSON output to a file via the [`json_output_file`](https://falco.org/docs/reference/daemon/configuration-options/#outputs) chart option, then `cilock run -- cat /var/log/falco.jsonl > events.jsonl` for the capture step. Either way the attestor parses the same line-delimited JSON.
- **Real-infra validation.** The captured envelope in [`tool-falco-events/raw/attestation.json`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-falco-events/raw) is from a real `dropbox-clone-dev` EKS cluster, not a synthetic fixture. The "Read sensitive file untrusted" rule firing is from a deliberate trigger pod (`kubectl run --image=alpine -- cat /etc/shadow`); the capture has no sensitive data because Falco redacts `output_fields` containing real file contents.

## FAQ

### Does CI/lock support Falco?

Yes. Wrap `sh -c 'kubectl logs daemonset/falco -n <ns> --tail=N | grep "\"rule\"" > falco-events.jsonl'` with `cilock run --attestations falco,environment,git`. The native `falco` attestor parses every event into a `https://aflock.ai/attestations/falco/v0.1` predicate with per-rule and per-priority summaries, alongside the standard collection (environment, git, material, command-run, product).

### Does this require the canonical `cilock` binary?

The `falco` attestor is on `presets/all` today — build via `rookery-builder --preset all` and the resulting binary has it. It will land in the canonical default `cilock` binary once [rookery#147](https://github.com/aflock-ai/rookery/pull/147) merges. The attestor itself is stable; only the canonical-main registration is pending.

### How do I gate a release on Falco priority counts?

Author a Rego policy on the `falco/v0.1` predicate's `summary.priorities` block. Example: deny if `priorities.error > 0` or if any of `priorities.alert + priorities.critical + priorities.emergency` is nonzero. A per-rule gate (e.g. deny on `Read sensitive file untrusted` firing more than zero times) uses `summary.rule_hits[]`. Examples in the [`policy/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-falco-events) directory once the example's policy bundle lands.

### Why parse Falco JSON into a custom predicate instead of SARIF?

Falco events have a richer schema than SARIF's locations-and-rules model — every event has K8s context (pod, namespace, container, image), syscall metadata, and free-form `output_fields`. A SARIF flattening would lose those; the `falco/v0.1` predicate preserves them verbatim and adds the per-rule + per-priority summaries policies care about most.

### How does this differ from running Falco standalone?

Standalone Falco emits a JSON event stream with no provenance — nothing binds it to a release, a cluster, a capture window, or a policy. CI/lock adds five predicates around the same events: `git/v0.1` (the commit), `environment/v0.1` (the host running the capture step), `material/v0.3` (the working tree), `command-run/v0.1` (the exact `sh -c` argv + exit code), and `product/v0.3` (the events file's content hash). The Falco events themselves are unchanged — same JSON, same downstream pipeline — but the surrounding evidence is now signed and policy-checkable.

## See also

- `falco` attestor — the underlying ingestion path
- [Validated example: tool-falco-events](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-falco-events) — real EKS-cluster capture + raw events + raw envelope + reproduce script
- [Falco project](https://falco.org) — upstream
- [rookery#147](https://github.com/aflock-ai/rookery/pull/147) — canonical-main registration PR
- [Tools index](./)

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({
  "@context": "https://schema.org",
  "@type": "HowTo",
  "name": "Capture Falco runtime-security events as a signed cilock attestation",
  "description": "Run a windowed kubectl logs capture of Falco JSON events under cilock and produce a signed v0.3 in-toto attestation with the native falco attestor — per-rule aggregation, priority counts, K8s cluster context, and command-run / material / product / environment / git predicates surrounding the event stream.",
  "tool": [
    {"@type": "HowToTool", "name": "cilock"},
    {"@type": "HowToTool", "name": "Falco"},
    {"@type": "HowToTool", "name": "kubectl"},
    {"@type": "HowToTool", "name": "jq"}
  ],
  "step": [
    {"@type": "HowToStep", "name": "Install Falco in your cluster", "text": "helm install falco falcosecurity/falco --set tty=true --set json_output=true --set falco.json_output=true --set falco.json_include_output_property=true --set driver.kind=modern-bpf"},
    {"@type": "HowToStep", "name": "Generate a signing key", "text": "openssl genpkey -algorithm ed25519 -out key.pem"},
    {"@type": "HowToStep", "name": "Build cilock with the falco attestor", "text": "rookery-builder --preset all (or wait for rookery#147 to merge into canonical main)"},
    {"@type": "HowToStep", "name": "Capture events under cilock", "text": "FALCO_CLUSTER_NAME=<your-cluster> cilock run --step falco-capture --signer-file-key-path key.pem --outfile attestation.json --attestations falco,environment,git --enable-archivista=false -- sh -c 'kubectl logs daemonset/falco -n <ns> --tail=500 | grep \"\\\"rule\\\"\" > falco-events.jsonl'"},
    {"@type": "HowToStep", "name": "Validate the envelope", "text": "jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)' — six predicate types including https://aflock.ai/attestations/falco/v0.1 should be present."}
  ]
})}} />
