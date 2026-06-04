---
title: aws-config
sidebar_position: 38
---

# `aws-config` attestor

Reads an AWS Config `get-compliance-details-by-config-rule` JSON report from the attestation products, aggregates rule-level compliance counts, and signs the summary as the attestation predicate.

| | |
|---|---|
| Name | `aws-config` |
| Predicate type | `https://aflock.ai/attestations/aws-config/v0.1` |
| Lifecycle | `postproduct` |
| Default binary? | **No** — builder opt-in only |

## What it captures

The predicate has three top-level fields:

- `reportFile` — path of the JSON file consumed from products.
- `reportDigestSet` — `cryptoutil.DigestSet` of that file. Must match the product digest the attestation context recorded; mismatched files are silently skipped.
- `summary` — a `ComplianceSummary` aggregating the report:
  - `totalRules` — count of distinct `ConfigRuleName` values seen in `EvaluationResults`.
  - `compliantCount` — number of evaluation results whose `ComplianceType` is `COMPLIANT`.
  - `nonCompliantCount` — number of evaluation results whose `ComplianceType` is `NON_COMPLIANT`.
  - `nonCompliantResources` — list of `<ResourceType>/<ResourceId>` strings for every non-compliant result (one entry per result, not deduplicated).

Subjects emitted for graph linking (SHA-256 of the identifier string):

- `aws-config:rule:<ConfigRuleName>` — one per distinct rule.
- `aws-config:resource:<ResourceType>/<ResourceId>` — one per evaluation result.
- `aws:account:<id>` — for every account ID extracted from a `ResourceId` that looks like an ARN (`arn:aws:<svc>:<region>:<account>:...`, position 4 in the `:`-split).

## When to use

In AWS pipelines where you already run `aws configservice get-compliance-details-by-config-rule` and want the continuous-compliance signal bound into the signed attestation graph alongside your build artifacts. The signed summary lets policy gate on `nonCompliantCount` or specific non-compliant `aws-config:rule:*` subjects without carrying the raw evaluation results inline.

## Flags

None.

## Output shape

```json
{
  "reportFile": "config-compliance.json",
  "reportDigestSet": { "sha256": "..." },
  "summary": {
    "totalRules": 12,
    "compliantCount": 47,
    "nonCompliantCount": 3,
    "nonCompliantResources": [
      "AWS::S3::Bucket/example-public-bucket",
      "AWS::IAM::User/legacy-svc",
      "AWS::EC2::SecurityGroup/sg-0a1b2c3d"
    ]
  }
}
```

## Gotchas

- Data source is a **file**, not a live SDK call. The attestor does not invoke the AWS Config service — you must produce the JSON yourself (e.g. `aws configservice get-compliance-details-by-config-rule --config-rule-name <name>`) and register it as a product. There is no AWS SDK dependency in this attestor.
- The attestor only considers products whose path ends in `.json`. Other files are skipped.
- Each candidate file is re-digested and compared against the product digest; mismatches are silently skipped and the next candidate is tried.
- The file must unmarshal into `{ "EvaluationResults": [...] }` and contain at least one result. Empty or non-matching JSON is skipped with "no aws config evaluation results JSON found in products".
- Only the **first** matching JSON file wins. If multiple `get-compliance-details-by-config-rule` outputs are registered as products, the rest are ignored — aggregate them yourself before attesting.
- `nonCompliantResources` is one entry per evaluation result. The same resource evaluated by multiple non-compliant rules appears multiple times.
- Account-ID extraction only fires when `ResourceId` itself is an ARN. Reports whose `ResourceId` is a bare name (e.g. `example-public-bucket`) emit no `aws:account:*` subject.
- `ComplianceType` values other than `COMPLIANT` / `NON_COMPLIANT` (e.g. `NOT_APPLICABLE`, `INSUFFICIENT_DATA`) are counted in `totalRules` but contribute to neither `compliantCount` nor `nonCompliantCount`.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/33-aws-config](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/33-aws-config). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog.md)
- [Build from source](../getting-started/installation.md#4-build-from-source)
- [`prowler`](./prowler.mdx), [`asff`](./asff.md)
