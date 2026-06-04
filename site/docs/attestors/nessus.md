---
title: nessus
sidebar_position: 34
---

# `nessus` attestor

Ingests a Tenable Nessus `.nessus` XML report from the attestation products and emits a digest-pinned summary of hosts scanned, findings bucketed by severity, and CVEs referenced by critical/high findings.

| | |
|---|---|
| Name | `nessus` |
| Predicate type | `https://aflock.ai/attestations/nessus/v0.1` |
| Lifecycle | `postproduct` |
| Default binary? | **No** — builder opt-in only |

## What it captures

The attestor walks `ctx.Products()` looking for files whose path ends in `.nessus`, verifies the file digest matches the product digest already recorded by the attestation context, then XML-decodes the `NessusClientData_v2` document. The predicate records three top-level json-tagged fields:

- `reportFile` — path of the `.nessus` file that was ingested.
- `reportDigestSet` — the digest set carried by the matching product (used as the integrity anchor; the on-disk file is rejected if its digest does not match).
- `scanSummary` — a `Summary` object containing:
  - `totalHosts` — count of `<ReportHost>` elements across all `<Report>` elements.
  - `vulnerabilities` — a `SeverityCounts` object with integer fields `critical`, `high`, `medium`, `low`, `info` (mapped from Nessus numeric severity 4/3/2/1/0; anything outside 1-4 falls into `info`).
  - `topCVEs` — deduplicated list of CVE IDs that appeared on any finding with severity High or Critical.

Per-finding raw data (plugin ID, plugin name, full CVE list, per-host item lists) is parsed from the XML but is **not** preserved in the predicate — only the aggregated counts and the critical/high CVE set survive into the attestation.

## Subjects

The attestor implements `attestation.Subjecter` and emits SHA-256 digested subjects:

- `nessus:host:<host-name>` for every `<ReportHost name="...">` encountered.
- `cve:<CVE-ID>` for every CVE referenced by a finding whose severity is High (3) or Critical (4). Medium/Low/Info findings do not produce CVE subjects.

## When to use

Add this attestor to a custom `cilock` build when Nessus is your authoritative vulnerability scanner and you want a tamper-evident record of the scan summary attached to a release. The CVE subjects make the attestation joinable against `vex` statements and other CVE-keyed evidence.

## Flags

None. The attestor takes no configuration; it discovers the `.nessus` file by scanning the product set.

## Output shape

```json
{
  "reportFile": "out/scan-2026-05.nessus",
  "reportDigestSet": {
    "sha256": "..."
  },
  "scanSummary": {
    "totalHosts": 12,
    "vulnerabilities": {
      "critical": 2,
      "high": 7,
      "medium": 15,
      "low": 4,
      "info": 88
    },
    "topCVEs": [
      "CVE-2024-12345",
      "CVE-2024-67890"
    ]
  }
}
```

## Gotchas

- **`.nessus` XML only.** The source matches strictly on the `.nessus` suffix and `xml.Unmarshal`s a `NessusClientData_v2` document. JSON exports, `.csv`, and `.html` reports are ignored.
- **Must be a product.** The file has to be present in `ctx.Products()` — typically because an earlier step (or `--attestor-product-include-glob`) added it. If no `.nessus` file is in the product set the attestor returns `no .nessus file found in products` and fails the step.
- **Digest gate.** If the on-disk file's digest does not equal the product digest already recorded, that file is silently skipped (debug-logged) and the attestor falls through to the next candidate.
- **Lossy summary.** Plugin IDs, plugin names, and CVEs from Medium/Low/Info findings are parsed but discarded. If you need the full finding list, attach the raw `.nessus` file as a product as well — the digest in `reportDigestSet` lets verifiers fetch and re-parse it.
- **First match wins.** Iteration order over `ctx.Products()` is map order; if multiple `.nessus` files are present, only the first one whose digest matches is recorded.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/35-nessus](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/35-nessus). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog.md)
- [Build from source](../getting-started/installation.md#4-build-from-source)
- [`vex`](./vex.mdx)
- [`oscap`](./oscap.mdx), [`prowler`](./prowler.mdx)
