---
title: Prowler
description: Scan AWS, GCP, Azure, Kubernetes, and Microsoft 365 against CIS, NIST, ISO 27001, HIPAA, and PCI-DSS with Prowler under cilock — findings become a signed v0.3 attestation parsed by the native prowler attestor.
sidebar_position: 14
examples_repo: tool-prowler-ocsf
---

Prowler is the most popular open-source multi-cloud security posture (CSPM) scanner — it audits AWS, GCP, Azure, Kubernetes, and Microsoft 365 against CIS, NIST 800-53, ISO 27001, HIPAA, GDPR, PCI-DSS, and roughly twenty other compliance frameworks. Cilock wraps `prowler`, captures its real argv and exit code, hashes the report file it writes, and parses the findings into a structured `prowler/v0.1` predicate ready for Rego policy.

## Validated invocation

cilock invokes `prowler` **directly** as the wrapped command — no `bash -c "cp …"` shim. The real tool is what cilock executes, traces, and records. The validated invocation against AWS:

```bash
cilock run --step prowler-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations prowler,environment,git \
  --enable-archivista=false \
  -- prowler aws --services iam -M json -o output -F prowler-iam -z
```

This is the exact line validated end-to-end in [`tool-prowler-ocsf`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-prowler-ocsf) — don't paraphrase it.

Prowler exits with code `3` when failures are found. The `-z` / `--ignore-exit-code-3` flag keeps `command-run/v0.1.exitcode == 0` so the postproduct stage runs cleanly even when the scan finds problems — the findings themselves are still recorded inside the `prowler/v0.1` predicate, so downstream policy still sees them. Drop `-z` if you want the runner to abort on any non-zero from the scanner.

AWS authentication is read from the surrounding shell. For SSO-backed profiles run `aws sso login --profile <profile>` first; for keys export `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`; for instance roles nothing extra is needed.

## What gets captured

A single run with `--attestations prowler,environment,git` produces these predicate types in the signed envelope:

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, hostname, username, env vars (sensitive ones obfuscated) |
| `https://aflock.ai/attestations/git/v0.1` | commit hash, branch, tags, dirty status, parents |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over the working directory before prowler runs |
| `https://aflock.ai/attestations/command-run/v0.1` | literal `["prowler","aws",…]` argv, exit code, ptrace |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over `output/prowler-iam.json` as a real product file |
| `https://aflock.ai/attestations/prowler/v0.1` | the parsed Prowler report — account, provider, totalChecks/passCount/failCount, severity rollup, failedChecks list (checkId, severity, resourceArn, statusExtended), report digest |

The `prowler/v0.1` predicate is what distinguishes this flow from a generic `sarif` ingestion: Rego policy can branch on `summary.bySeverity.critical.fail` directly without re-parsing SARIF runs/results.

## Why this shape

| Antipattern (older docs, see [`28-prowler/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/28-prowler)) | Correct shape (this example) |
|---|---|
| `cilock run ... -- bash -c "cp prowler.json prowler-out.json"` after running prowler outside cilock | `cilock run ... -- prowler aws --services iam -M json -o output -F prowler-iam -z` |
| `command-run.cmd` records `["bash","-c","cp …"]` — cilock "ran" cp | `command-run.cmd` records `["prowler","aws",…]` — the literal scanner argv is in the envelope |
| The ptrace spy traces `cp`, not prowler | The ptrace spy traces prowler's syscalls because cilock is its direct parent |
| Product is a copy of a file prowler wrote elsewhere | Product is the file prowler wrote inside the wrapped step |

The older `28-prowler/` example needed the `cp` because earlier rookery versions couldn't trace a long-running scanner under ptrace reliably; the v0.3 ptrace spy doesn't have that limitation, so direct invocation is the right shape going forward.

## Validate it locally

After running the invocation above:

```bash
# All six predicate types should be present.
jq -r '.payload' attestation.json | base64 -d \
  | jq '[.predicate.attestations[].type] | sort'
```

Expected output:

```json
[
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/prowler/v0.1"
]
```

Confirm `command-run.cmd` carries the literal Prowler argv (proof the cp antipattern is gone):

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'
# ["prowler","aws","--services","iam","-M","json","-o","output","-F","prowler-iam","-z"]
```

Inspect the parsed Prowler summary that Rego policy will gate on:

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/prowler/v0.1") | .attestation.summary | {totalChecks, passCount, failCount, bySeverity}'
# {
#   "totalChecks": 93,
#   "passCount": 74,
#   "failCount": 19,
#   "bySeverity": { "critical": {"pass":5,"fail":2}, "high": {"pass":55,"fail":9}, "medium": {"pass":13,"fail":7}, "low": {"pass":1,"fail":1} }
# }
```

## How a verifier consumes this

The `prowler` attestor is a `postproduct` lifecycle attestor with predicate type `https://aflock.ai/attestations/prowler/v0.1`. It reads a Prowler JSON findings report from the attestation products, validates it, and signs a condensed `Summary` object as the predicate:

- `accountId` — AWS account ID taken from the first finding.
- `provider` — cloud provider string from the first finding (e.g. `aws`).
- `totalChecks` — count of all findings in the report.
- `passCount` / `failCount` — pass vs. non-pass tallies. `FAIL`, `MANUAL`, `NOT_AVAILABLE`, and `MUTED` are all counted as non-pass.
- `bySeverity` — map of lowercased severity → `{ pass, fail }` counts.
- `failedChecks` — array of condensed non-pass entries with `checkId`, `checkTitle`, `severity`, `serviceName`, `region`, `resourceId`, `resourceArn`, `statusExtended`. The full Prowler finding is intentionally not embedded.
- `reportFile` — path of the JSON file that was consumed from products.
- `reportDigest` — `cryptoutil.DigestSet` of that file, matching the product digest recorded by the attestation context.

Subjects emitted for graph linking (SHA-256 of the identifier string):

- `aws:account:<id>`
- `aws:arn:<arn>` for each unique failed-check `ResourceArn`
- `aws:service:<name>` for each unique failed-check `ServiceName`

The summary lets policy gate on failure counts or specific failed `checkId`s without carrying the full report inline. Pair with [`policyverify`](./policyverify) to gate promotion.

### Output shape

```json
{
  "summary": {
    "accountId": "123456789012",
    "provider": "aws",
    "totalChecks": 312,
    "passCount": 280,
    "failCount": 32,
    "bySeverity": {
      "critical": { "pass": 0, "fail": 2 },
      "high":     { "pass": 12, "fail": 8 },
      "medium":   { "pass": 140, "fail": 18 },
      "low":      { "pass": 128, "fail": 4 }
    },
    "failedChecks": [
      {
        "checkId": "iam_root_mfa_enabled",
        "checkTitle": "Ensure MFA is enabled for the root account",
        "severity": "Critical",
        "serviceName": "iam",
        "region": "us-east-1",
        "resourceId": "<root_account>",
        "resourceArn": "arn:aws:iam::123456789012:root",
        "statusExtended": "Root account does not have MFA enabled."
      }
    ],
    "reportFile": "prowler-output.json",
    "reportDigest": { "sha256": "..." }
  }
}
```

## Notes

**Service scoping.** `--services iam` ran 36 IAM checks in ~11s; dropping the flag scans every supported service in the target account, which usually takes minutes. Use `--services iam ec2 s3` to scope to multiple services.

**Compliance frameworks.** Instead of (or in addition to) service scoping, pass `-c <framework>` — e.g. `-c cis_2.0_aws`, `-c nist_800_53_revision_5_aws`, `-c hipaa_aws`, `-c pci_3.2.1_aws`. Run `prowler aws --list-compliance` for the full list. The `prowler/v0.1` predicate carries every finding regardless of framework selection.

**Output formats.** Prowler 3.x emits its native JSON via `-M json`; Prowler 4+ recommends `json-ocsf` (OCSF v1.1) and `json-asff` (AWS Security Hub) as the modern formats. The rookery `prowler` attestor accepts all three — see [`fix(prowler): accept Prowler 4 OCSF + ASFF input formats`](https://github.com/aflock-ai/rookery/pull/86).

**AWS auth model.** Prowler delegates to `boto3`, so any auth mechanism boto3 understands works: `AWS_PROFILE`, `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, EC2 instance role, ECS task role, EKS IRSA, SSO (`aws sso login --profile <profile>` first). The `environment/v0.1` attestor obfuscates any env var matching cilock's sensitive-key list — your AWS secret keys won't leak into the signed envelope as plaintext.

**Other clouds.** `prowler gcp`, `prowler azure`, `prowler kubernetes`, `prowler m365`. The cilock invocation shape is identical (swap `aws` for the provider), and the same `prowler/v0.1` predicate format is emitted across providers.

## Gotchas

- The attestor consumes a **product**, not a free-form file path. The Prowler JSON report must be registered with the attestation context as a product with MIME type `text/plain` or `application/json` — other MIME types are skipped.
- Each candidate file is re-digested and compared against the product digest; mismatches are silently skipped and the next candidate is tried.
- The file must be a JSON array of Prowler findings. Validation rejects empty arrays and requires every finding to have `CheckID`, `Provider`, and a `Status` in `{PASS, FAIL, MANUAL, NOT_AVAILABLE, MUTED}`. Non-Prowler JSON is rejected with "no prowler JSON output file found in products".
- `accountId` and `provider` are taken from the **first** finding only. Multi-account reports collapse to the first account on the summary line (failed checks retain their own resource ARNs).
- `MANUAL`, `NOT_AVAILABLE`, and `MUTED` statuses count as failures in both the totals and `failedChecks`. Policy authors filtering on `failCount` should be aware of this.

## FAQ

### Does cilock support Prowler?

Yes. Wrap `prowler aws --services <svc> -M json -o output -F <prefix> -z` with `cilock run --attestations prowler,environment,git`. Prowler's report becomes a signed v0.3 attestation under `https://aflock.ai/attestations/prowler/v0.1`, the literal Prowler argv is captured in `command-run/v0.1`, and the report file is hashed into the v0.3 Merkle tree.

### Which clouds does Prowler scan under cilock?

All clouds Prowler itself supports: AWS, GCP, Azure, Kubernetes, and Microsoft 365. The cilock invocation is the same shape across providers — swap `prowler aws` for `prowler gcp`, `prowler azure`, `prowler kubernetes`, or `prowler m365`. Each provider emits the same `prowler/v0.1` predicate format, so a single Rego policy can gate deploys against findings from any cloud.

### How is the rookery `prowler` attestor different from the `sarif` attestor?

The rookery `prowler` attestor parses Prowler's **native JSON** (or OCSF / ASFF in Prowler 4+) and produces a structured `prowler/v0.1` predicate carrying account, provider, `totalChecks`/`passCount`/`failCount`, a severity rollup, and a typed `failedChecks` list with each finding's `checkId`, `severity`, `resourceArn`, and `statusExtended`. The generic `sarif` attestor would flatten that into a single `results` array. Rego over `prowler/v0.1` gates on `summary.bySeverity.critical.fail > 0` directly; the same gate over SARIF requires counting and filtering. Use `prowler/v0.1` for compliance gates; use `sarif/v0.1` if you want one uniform predicate across many scanners.

### How do I gate deploys on Prowler findings?

Write a Rego policy over the captured `prowler/v0.1` predicate. The `attestation.summary.bySeverity.<level>.fail` counts give you per-severity gates (e.g. `deny if summary.bySeverity.critical.fail > 0`), and `attestation.summary.failedChecks[].checkId` lets you allowlist or denylist specific Prowler checks (e.g. allow `iam_root_mfa_enabled` failing on a sandbox account but block it on prod). The matching `attestation.summary.totalChecks > 0` guard catches the silent-scan-failure case — see [`28-prowler/policy/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/28-prowler/policy) for a worked multi-step verify recipe.

### Why pass `-z` / `--ignore-exit-code-3`?

Prowler exits `3` whenever any check fails — that's its default "I found something" signal. Without `-z`, a real-world scan returns non-zero from `command-run`, cilock treats the wrapped command as failed, and the postproduct stage (which is where the `prowler/v0.1` attestor parses the report) doesn't run. `-z` keeps the exit code at `0` so the report is captured and parsed; the findings themselves are recorded inside the predicate, so downstream policy still sees every failure.

## See also

- [Validated example: `tool-prowler-ocsf`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-prowler-ocsf) — the upstream README this page mirrors
- [Older example: `28-prowler/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/28-prowler) — multi-step verify-recipe policy over the same predicate
- [Prowler upstream](https://github.com/prowler-cloud/prowler) — upstream tool homepage
- [`aws-config`](./aws-config), [`asff`](./asff)
- [Tools index](./)
