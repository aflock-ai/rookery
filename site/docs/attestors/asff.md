---
title: asff
sidebar_position: 37
---

# `asff` attestor

Reads an AWS Security Hub ASFF (AWS Security Finding Format) JSON report from the attestation products, validates it, and signs a condensed summary (counts, severity breakdown, failed findings) as the attestation predicate.

| | |
|---|---|
| Name | `asff` |
| Predicate type | `https://aflock.ai/attestations/asff/v0.1` |
| Lifecycle | `postproduct` |
| Default binary? | **No** — builder opt-in only |

## What it captures

The predicate is a `Summary` object with:

- `awsAccountId` — taken from the first finding that populates it.
- `totalFindings` — count of all findings in the report.
- `bySeverity` — map of uppercased severity label (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) to `{ count }`.
- `byComplianceStatus` — map of uppercased compliance status (`PASSED`, `FAILED`, `WARNING`, `NOT_AVAILABLE`) to a count.
- `failedFindings` — array of condensed records, one per finding whose `Compliance.Status == "FAILED"`. Each entry contains `findingArn`, `title`, `severity`, `productArn`, `awsAccountId`, and the list of `resources` (`type`, `id`). The full ASFF record is intentionally not embedded.
- `reportFile` — path of the JSON file consumed from products.
- `reportDigest` — `cryptoutil.DigestSet` of that file, matching the product digest recorded by the attestation context.

Subjects emitted for graph linking (SHA-256 of the identifier string):

- `aws:account:<id>` — the account ID from the summary.
- `aws:finding:<arn>` — the finding ARN for every `CRITICAL` or `HIGH` failed finding.
- `aws:arn:<arn>` — each unique resource ARN referenced by any failed finding.

## When to use

When running an AWS Security Hub `get-findings` query (or any pipeline that emits ASFF JSON) during or after a build and you want the security posture snapshot bound into the signed attestation graph. The summary lets policy gate on failed-finding counts, severity labels, or specific finding ARNs without carrying the full ASFF stream inline.

## Flags

None.

## Output shape

```json
{
  "summary": {
    "awsAccountId": "123456789012",
    "totalFindings": 412,
    "bySeverity": {
      "CRITICAL": { "count": 3 },
      "HIGH":     { "count": 14 },
      "MEDIUM":   { "count": 102 },
      "LOW":      { "count": 280 },
      "INFORMATIONAL": { "count": 13 }
    },
    "byComplianceStatus": {
      "PASSED": 360,
      "FAILED": 38,
      "WARNING": 6,
      "NOT_AVAILABLE": 8
    },
    "failedFindings": [
      {
        "findingArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.6/finding/abc",
        "title": "IAM.6 Hardware MFA should be enabled for the root user",
        "severity": "CRITICAL",
        "productArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "awsAccountId": "123456789012",
        "resources": [
          { "type": "AwsAccount", "id": "AWS::::Account:123456789012" }
        ]
      }
    ],
    "reportFile": "securityhub-findings.json",
    "reportDigest": { "sha256": "..." }
  }
}
```

## Gotchas

- The attestor consumes a **product**, not a free-form file path. The ASFF JSON report must be registered with the attestation context as a product with MIME type `text/plain` or `application/json` — other MIME types are skipped.
- The input must be the top-level envelope `{ "Findings": [ ... ] }` produced by `aws securityhub get-findings --output json`. Bare arrays are not accepted.
- Each candidate file is re-digested and compared against the product digest; mismatches are silently skipped and the next candidate is tried.
- Validation rejects empty `Findings` arrays and requires every record to have a non-empty `Id`, a `Severity.Label` in {`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`}, and a `Compliance.Status` in {`PASSED`, `FAILED`, `WARNING`, `NOT_AVAILABLE`}. Anything else falls through with "no ASFF JSON output file found in products".
- `awsAccountId` on the summary is taken from the first finding that has one. Multi-account exports collapse to that single account on the summary line (failed findings retain their own `awsAccountId` and resource IDs).
- Only `FAILED` findings are expanded into `failedFindings`. `WARNING` and `NOT_AVAILABLE` show up in counts only.
- `aws:finding:<arn>` subjects are emitted only for failed findings whose severity is `CRITICAL` or `HIGH`. Resource ARN subjects are emitted for every unique resource across all failed findings regardless of severity.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/34-asff](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/34-asff). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog.md)
- [Build from source](../getting-started/installation.md#4-build-from-source)
- [`prowler`](./prowler.mdx), [`aws-config`](./aws-config.md)
