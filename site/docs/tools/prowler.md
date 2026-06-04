---
title: Prowler
description: Scan AWS, GCP, Azure, Kubernetes, and Microsoft 365 against CIS, NIST, ISO 27001, HIPAA, and PCI-DSS with Prowler under CI/lock — findings become a signed v0.3 attestation parsed by the native prowler attestor.
sidebar_position: 14
---

# `Prowler` integration

Prowler is the most popular open-source multi-cloud security posture (CSPM) scanner — it audits AWS, GCP, Azure, Kubernetes, and Microsoft 365 against CIS, NIST 800-53, ISO 27001, HIPAA, GDPR, PCI-DSS, and roughly twenty other compliance frameworks. CI/lock wraps `prowler`, captures its real argv and exit code, hashes the report file it writes, and parses the findings into a structured `prowler/v0.1` predicate ready for Rego policy.

| | |
|---|---|
| Tool URL | [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) |
| License | Apache-2.0 |
| Category | multi-cloud CSPM / compliance auditor |
| Rookery attestor used today | [`prowler`](../attestors/prowler.mdx) (native — this page) |

## Validated invocation

CI/lock invokes `prowler` **directly** as the wrapped command — no `bash -c "cp …"` shim. The real tool is what CI/lock executes, traces, and records. The validated invocation against AWS:

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
| `https://aflock.ai/attestations/environment/v0.1` | host OS, kernel, env vars (sensitive ones obfuscated) |
| `https://aflock.ai/attestations/git/v0.1` | commit hash, branch, tags, dirty status, parents |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over the working directory before prowler runs |
| `https://aflock.ai/attestations/command-run/v0.1` | literal `["prowler","aws",…]` argv, exit code, ptrace |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over `output/prowler-iam.json` as a real product file |
| `https://aflock.ai/attestations/prowler/v0.1` | the parsed Prowler report — account, provider, totalChecks/passCount/failCount, severity rollup, failedChecks list (checkId, severity, resourceArn, statusExtended), report digest |

The `prowler/v0.1` predicate is what distinguishes this flow from a generic `sarif` ingestion: Rego policy can branch on `summary.bySeverity.critical.fail` directly without re-parsing SARIF runs/results.

## Why this shape

| Antipattern (older docs, see [`28-prowler/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/28-prowler)) | Correct shape (this example) |
|---|---|
| `cilock run ... -- bash -c "cp prowler.json prowler-out.json"` after running prowler outside CI/lock | `cilock run ... -- prowler aws --services iam -M json -o output -F prowler-iam -z` |
| `command-run.cmd` records `["bash","-c","cp …"]` — CI/lock "ran" cp | `command-run.cmd` records `["prowler","aws",…]` — the literal scanner argv is in the envelope |
| The ptrace spy traces `cp`, not prowler | The ptrace spy traces prowler's syscalls because CI/lock is its direct parent |
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

## Notes

**Service scoping.** `--services iam` ran 36 IAM checks in ~11s; dropping the flag scans every supported service in the target account, which usually takes minutes. Use `--services iam ec2 s3` to scope to multiple services.

**Compliance frameworks.** Instead of (or in addition to) service scoping, pass `-c <framework>` — e.g. `-c cis_2.0_aws`, `-c nist_800_53_revision_5_aws`, `-c hipaa_aws`, `-c pci_3.2.1_aws`. Run `prowler aws --list-compliance` for the full list. The `prowler/v0.1` predicate carries every finding regardless of framework selection.

**Output formats.** Prowler 3.x emits its native JSON via `-M json`; Prowler 4+ recommends `json-ocsf` (OCSF v1.1) and `json-asff` (AWS Security Hub) as the modern formats. The rookery `prowler` attestor accepts all three — see [`fix(prowler): accept Prowler 4 OCSF + ASFF input formats`](https://github.com/aflock-ai/rookery/pull/86).

**AWS auth model.** Prowler delegates to `boto3`, so any auth mechanism boto3 understands works: `AWS_PROFILE`, `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, EC2 instance role, ECS task role, EKS IRSA, SSO (`aws sso login --profile <profile>` first). The `environment/v0.1` attestor obfuscates any env var matching CI/lock's sensitive-key list — your AWS secret keys won't leak into the signed envelope as plaintext.

**Other clouds.** `prowler gcp`, `prowler azure`, `prowler kubernetes`, `prowler m365`. The CI/lock invocation shape is identical (swap `aws` for the provider), and the same `prowler/v0.1` predicate format is emitted across providers.

## FAQ

### Does CI/lock support Prowler?

Yes. Wrap `prowler aws --services <svc> -M json -o output -F <prefix> -z` with `cilock run --attestations prowler,environment,git`. Prowler's report becomes a signed v0.3 attestation under `https://aflock.ai/attestations/prowler/v0.1`, the literal Prowler argv is captured in `command-run/v0.1`, and the report file is hashed into the v0.3 Merkle tree.

### Which clouds does Prowler scan under CI/lock?

All clouds Prowler itself supports: AWS, GCP, Azure, Kubernetes, and Microsoft 365. The CI/lock invocation is the same shape across providers — swap `prowler aws` for `prowler gcp`, `prowler azure`, `prowler kubernetes`, or `prowler m365`. Each provider emits the same `prowler/v0.1` predicate format, so a single Rego policy can gate deploys against findings from any cloud.

### How is the rookery `prowler` attestor different from the `sarif` attestor?

The rookery `prowler` attestor parses Prowler's **native JSON** (or OCSF / ASFF in Prowler 4+) and produces a structured `prowler/v0.1` predicate carrying account, provider, `totalChecks`/`passCount`/`failCount`, a severity rollup, and a typed `failedChecks` list with each finding's `checkId`, `severity`, `resourceArn`, and `statusExtended`. The generic `sarif` attestor would flatten that into a single `results` array. Rego over `prowler/v0.1` gates on `summary.bySeverity.critical.fail > 0` directly; the same gate over SARIF requires counting and filtering. Use `prowler/v0.1` for compliance gates; use `sarif/v0.1` if you want one uniform predicate across many scanners.

### How do I gate deploys on Prowler findings?

Write a Rego policy over the captured `prowler/v0.1` predicate. The `attestation.summary.bySeverity.<level>.fail` counts give you per-severity gates (e.g. `deny if summary.bySeverity.critical.fail > 0`), and `attestation.summary.failedChecks[].checkId` lets you allowlist or denylist specific Prowler checks (e.g. allow `iam_root_mfa_enabled` failing on a sandbox account but block it on prod). The matching `attestation.summary.totalChecks > 0` guard catches the silent-scan-failure case — see [`28-prowler/policy/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/28-prowler/policy) for a worked multi-step verify recipe.

### Why pass `-z` / `--ignore-exit-code-3`?

Prowler exits `3` whenever any check fails — that's its default "I found something" signal. Without `-z`, a real-world scan returns non-zero from `command-run`, CI/lock treats the wrapped command as failed, and the postproduct stage (which is where the `prowler/v0.1` attestor parses the report) doesn't run. `-z` keeps the exit code at `0` so the report is captured and parsed; the findings themselves are recorded inside the predicate, so downstream policy still sees every failure.

## See also

- [`prowler` attestor](../attestors/prowler.mdx) — the underlying ingestion path
- [Validated example: `tool-prowler-ocsf`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-prowler-ocsf) — the upstream README this page mirrors
- [Older example: `28-prowler/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/28-prowler) — multi-step verify-recipe policy over the same predicate
- [Prowler upstream](https://github.com/prowler-cloud/prowler) — upstream tool homepage
- [Tools index](./)

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({
  "@context": "https://schema.org",
  "@type": "HowTo",
  "name": "Produce a signed Prowler cloud-posture attestation with cilock",
  "description": "Wrap prowler-cloud/prowler under cilock so its multi-cloud CSPM report becomes a signed v0.3 in-toto attestation with command-run, material, product, and parsed prowler predicates — gating deploys on CIS, NIST, ISO 27001, HIPAA, or PCI-DSS findings.",
  "tool": [
    {"@type": "HowToTool", "name": "cilock"},
    {"@type": "HowToTool", "name": "prowler"},
    {"@type": "HowToTool", "name": "jq"}
  ],
  "step": [
    {"@type": "HowToStep", "name": "Install prowler", "text": "brew install prowler  # or: pipx install prowler"},
    {"@type": "HowToStep", "name": "Authenticate to AWS", "text": "aws sso login --profile <profile>  # or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY"},
    {"@type": "HowToStep", "name": "Generate a signing key", "text": "openssl genpkey -algorithm ed25519 -out key.pem"},
    {"@type": "HowToStep", "name": "Run prowler under cilock", "text": "cilock run --step prowler-scan --signer-file-key-path key.pem --outfile attestation.json --attestations prowler,environment,git --enable-archivista=false -- prowler aws --services iam -M json -o output -F prowler-iam -z"},
    {"@type": "HowToStep", "name": "Validate the envelope", "text": "jq -r '.payload' attestation.json | base64 -d | jq '[.predicate.attestations[].type] | sort'"}
  ]
})}} />
