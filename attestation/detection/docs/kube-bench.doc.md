---
title: kube-bench
description: The cilock kube-bench attestor ingests an Aqua Security kube-bench CIS Kubernetes Benchmark JSON report from the step's products and signs a per-check pass/fail/warn summary into in-toto evidence.
sidebar_position: 32
examples_repo: 18-kube-bench
---

Captures Aqua Security `kube-bench` CIS Kubernetes Benchmark results by scanning the step's products for a JSON report and recording a per-check pass / fail / warn summary.

Enable in a custom build with `--with github.com/aflock-ai/rookery/plugins/attestors/kube-bench`.

## What it captures

The attestor does **not** execute `kube-bench` itself. It runs in the `postproduct` phase: you run `kube-bench --json > report.json` (or equivalent) earlier in the step so the file lands in the attestation context's products map, and this attestor picks it up.

Each product is filtered first by MIME type (only `text/plain` or `application/json` are considered), the file digest is recomputed and compared against the product's recorded digest, and the bytes are decoded into `KubeBenchReport`. The first file that decodes successfully **and** has a non-empty `Controls` array wins.

Top-level attestor fields:

- `report_file` — path of the kube-bench JSON file inside the attestation context.
- `report_digest_set` — digest of that file (taken from the product entry).
- `cluster_name` — populated from the `KUBE_BENCH_CLUSTER_NAME` environment variable at `New()` time.
- `version` — derived from the first control section's `ID` (e.g. section `"1"` → version `"1"`); this is the major section identifier, not a full CIS version string.
- `node_hostname` — captured from `os.Hostname()` when the attestor is constructed.
- `summary` — see below.

`summary` rolls up:

- `total_pass`, `total_fail`, `total_warn` — copied from the report's `Totals`.
- `failed_checks` — every result with `status == "FAIL"`, recorded as `{id, text}` from the result's `test_number` and `test_desc`.
- `warned_checks` — same shape, every result with `status == "WARN"`.

The full nested report (`Controls` → `Tests` → `Results` with `test_number`, `test_desc`, `status`, `scored`, `actual_value`, `expected_result`) is parsed during ingest but only the rolled-up summary is persisted in the attestation.

## Subjects

`Subjects()` emits up to three synthetic identity subjects so the report ties into the supply-chain graph:

- `benchmark:cis-kubernetes-<version>` (falls back to `benchmark:cis-kubernetes` if no version was derived).
- `cluster:<cluster_name>` — only when `KUBE_BENCH_CLUSTER_NAME` was set.
- `node:<node_hostname>` — only when the hostname was resolvable.

Each subject's digest is computed over the literal subject key string.

## When to use

Run as a dedicated step in a Kubernetes cluster hardening pipeline. Pair the actual `kube-bench` invocation with this attestor in `postproduct`, then verify the resulting attestation against a policy that gates on `summary.total_fail` or specific `failed_checks[*].id` values.

## Flags

None. Configuration is environment-driven: set `KUBE_BENCH_CLUSTER_NAME` before invoking `cilock` to label the run.

## Output shape

```json
{
  "report_file": "kube-bench.json",
  "report_digest_set": { "sha256": "..." },
  "cluster_name": "prod-eks",
  "version": "1",
  "node_hostname": "ip-10-0-1-23",
  "summary": {
    "total_pass": 42,
    "total_fail": 3,
    "total_warn": 5,
    "failed_checks": [
      { "id": "1.2.6", "text": "Ensure that the --kubelet-certificate-authority argument is set as appropriate" }
    ],
    "warned_checks": [
      { "id": "1.2.10", "text": "Ensure that the admission control plugin EventRateLimit is set" }
    ]
  }
}
```

## Gotchas

- **No exec.** If you forget to produce a `kube-bench` JSON file in the step, `Attest` returns `no kube-bench report found in products`.
- **Products must declare a compatible MIME type.** Files with a MIME type other than `text/plain` or `application/json` are skipped; products with an empty MIME type are still considered.
- **Digest must match.** If the file on disk no longer matches the product's recorded digest, the file is skipped silently (debug log only).
- **`version` is just the first section ID.** It is not a parsed CIS benchmark version — downstream policies should treat it as an opaque tag.
- **Node role is not captured.** Despite the CIS benchmark distinguishing master / node / etcd / controlplane profiles, this attestor does not record which profile was scanned; encode that into the `KUBE_BENCH_CLUSTER_NAME` value or a separate attestor if you need it.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/18-kube-bench](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/18-kube-bench). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog)
- [Build from source](../getting-started/installation#4-build-from-source)
- [`inspec`](./inspec)
- Upstream: [witness/kube-bench.md](https://github.com/in-toto/witness/blob/main/docs/attestors/kube-bench.md)
