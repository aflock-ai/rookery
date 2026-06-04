---
title: docker-bench
sidebar_position: 33
---

# `docker-bench` attestor

Captures CIS Docker Benchmark results produced by `docker-bench-security --json` and rolls them up into a signed attestation.

| | |
|---|---|
| Name | `docker-bench` |
| Predicate type | `https://aflock.ai/attestations/docker-bench/v0.1` |
| Lifecycle | `postproduct` |
| Default binary? | **No** — builder opt-in only |

## What it captures

The attestor scans the step's products for a JSON file whose top-level `desc` contains `CIS Docker Benchmark` and a non-empty `results` array, then records:

- `report_file` — the path of the docker-bench JSON output that was matched.
- `report_digest_set` — cryptographic digests of the report file, computed with the context's hash set.
- `benchmark_id` — the top-level `id` field from the report (for example `docker-bench-security`).
- `version` — derived from the report's `desc` by stripping the `CIS Docker Benchmark` prefix (for example `v1.6.0`). Omitted when the report does not embed a version.
- `container_ids` — 12-char hex prefixes pulled from the `details` string of each result; de-duplicated.
- `summary` — aggregated counts plus the list of non-passing checks:
  - `total_checks`, `total_pass`, `total_warn`, `total_info`, `total_note`
  - `failed_checks[]` with `id`, `desc`, `result` for every `WARN` result and any unknown status. `PASS`, `INFO`, and `NOTE` are not added to `failed_checks`.

### Subjects

Two kinds of in-toto subjects are emitted, each as a SHA-256 digest over a synthetic key:

- `benchmark:cis-docker-<version>` (falls back to `benchmark:cis-docker` when no version is parsed).
- `container:<12-char-id>` for every container ID extracted from failing-check details.

## When to use

Run as a post-product step on a Docker host (or in a privileged sidecar) after the build that produced your images, so the host-hardening posture is bound to the rest of the supply chain. Pair with [`kube-bench`](./kube-bench.mdx) for Kubernetes nodes.

## Flags

None. The attestor takes no CLI options — point your step at the `docker-bench-security --json` output via the step's product declaration and it will pick the file up automatically.

## Output shape

```json
{
  "report_file": "docker-bench.json",
  "report_digest_set": { "sha256": "..." },
  "benchmark_id": "docker-bench-security",
  "version": "v1.6.0",
  "container_ids": ["abcdef012345"],
  "summary": {
    "total_checks": 120,
    "total_pass": 95,
    "total_warn": 20,
    "total_info": 3,
    "total_note": 2,
    "failed_checks": [
      { "id": "2.1", "desc": "Restrict network traffic between containers", "result": "WARN" }
    ]
  }
}
```

## Gotchas

- **Strict product validation.** A candidate file is skipped unless its declared MIME type is `text/plain` or `application/json`, the on-disk digest matches the product digest in the attestation context, the `desc` contains `CIS Docker Benchmark`, and `results` is non-empty. If no product satisfies all four checks, `Attest` returns `no docker-bench report found in products`.
- **Only `WARN` (and unknown statuses) populate `failed_checks`.** `INFO` and `NOTE` results are counted but not enumerated, and the upstream `docker-bench-security` tool does not emit a `FAIL` status.
- **Container ID extraction is heuristic.** Any space-separated token in a result's `details` whose first 12 characters are hex is treated as a container ID, which can produce false positives on details strings that happen to contain hex-looking words.
- **Products only.** The attestor reads from the context's products, not materials, so the report must be declared as a product of the step.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/17-docker-bench](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/17-docker-bench). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog.md)
- [Build from source](../getting-started/installation.md#4-build-from-source)
- [`kube-bench`](./kube-bench.mdx)
