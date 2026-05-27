---
title: Checkov
description: Scan Terraform, CloudFormation, Kubernetes, Helm, and other IaC with Checkov under cilock — every misconfig becomes a signed v0.3 SARIF attestation.
sidebar_position: 7
examples_repo: tool-checkov-sarif
---

[Checkov](https://github.com/bridgecrewio/checkov) is Bridgecrew / Prisma Cloud's IaC misconfiguration scanner. It speaks Terraform, CloudFormation, Kubernetes manifests, Helm charts, ARM, Bicep, Dockerfiles, GitHub Actions workflows, and a long tail of other IaC formats. Under cilock, every Checkov run becomes a **signed v0.3 SARIF attestation** chained to the IaC inputs that produced the findings.

## Validated invocation

```bash
cilock run --step checkov-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- checkov -d fixtures -s -o sarif --output-file-path .
```

Two Checkov-specific quirks are baked into that command — both matter for clean attestations:

- **`-s` (soft-fail).** Checkov exits non-zero whenever it finds a misconfiguration. Without `-s`, the very thing you wrote the scan to detect — a finding — also makes `command-run` record a failed exit code. Soft-fail lets Checkov return `0` while the findings stay in the SARIF (and in the `sarif` attestor).
- **`--output-file-path .` is a directory, not a file.** Checkov takes the value you pass to `--output-file-path` and writes `results_sarif.sarif` *inside* it. Passing `--output-file-path checkov.sarif` does not create `checkov.sarif` — it creates a directory named `checkov.sarif/` containing `results_sarif.sarif`. The `product/v0.3` and `sarif` attestors discover the real file (`results_sarif.sarif`) in cwd.

## What gets captured
Each cilock run emits an in-toto envelope whose predicate carries the following attestor types:

| Attestor type                                          | Captures                                                  |
| ------------------------------------------------------ | --------------------------------------------------------- |
| `https://aflock.ai/attestations/command-run/v0.1`      | Real `checkov ...` argv, env, exit code, stdout/stderr   |
| `https://aflock.ai/attestations/material/v0.3`         | Merkle tree of the IaC inputs (the `-d` directory)        |
| `https://aflock.ai/attestations/product/v0.3`          | Merkle tree of outputs, including `results_sarif.sarif`   |
| `https://aflock.ai/attestations/sarif/v0.1`            | Parsed SARIF report + `reportDigestSet.sha256`            |
| `https://aflock.ai/attestations/environment/v0.1`      | OS, hostname, user, env vars (PII-filtered)               |
| `https://aflock.ai/attestations/git/v0.1`              | Commit SHA, branch, remotes                               |

The `sarif/v0.1` predicate's `reportDigestSet.sha256` exactly matches the digest of the `results_sarif.sarif` leaf in the `product/v0.3` tree. That is the chain that makes the findings verifiable — you can't swap in a different SARIF without invalidating the product tree.

## Why this shape

| Antipattern                                            | This page                                          |
| ------------------------------------------------------ | -------------------------------------------------- |
| `cilock run ... -- bash -c "cp output.sarif x.sarif"`  | `cilock run ... -- checkov ... --output-file-path .` |
| `command-run` records `bash -c "cp ..."` — useless     | `command-run` records the real Checkov argv       |
| Product attestor digests the `cp` destination          | Product attestor digests Checkov's actual output  |
| Tool execution happens outside the attestation         | Tool runs inside cilock; spy can trace its syscalls |

cilock invokes Checkov **directly** — no `bash -c` wrapper. That preserves the real argv in `command-run` and lets the spy attestors (`product`, `material`) observe the file Checkov actually wrote.

## Validate it locally

```bash
# Generate a signing key (one-time).
openssl genpkey -algorithm ed25519 -out key.pem

# Run cilock + Checkov against any IaC directory.
cilock run --step checkov-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- checkov -d fixtures -s -o sarif --output-file-path .

# Confirm the predicate carries the expected attestor types.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations | map(.type)'

# Confirm Checkov's real argv ended up in command-run.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'

# Confirm the SARIF report and its findings landed in the sarif attestor.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/sarif/v0.1")
        | .attestation
        | {reportFileName,
           digest: .reportDigestSet.sha256,
           findingCount: (.report.runs[0].results | length)}'
```

Against the [`tool-checkov-sarif`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-checkov-sarif) fixture you should see at least two findings — `CKV_AWS_24` and `CKV_AWS_23` — from the deliberately bad Terraform.

## Notes

- **`--output-file-path` is a directory.** Checkov interprets the value as a directory and writes `results_sarif.sarif` inside it. The `.` in the validated invocation means "drop the SARIF in cwd," which is where the `product` attestor is already looking.
- **IaC formats Checkov covers.** Terraform (HCL + plan JSON), CloudFormation, AWS SAM, Kubernetes manifests, Helm charts, Kustomize, Argo workflows, ARM, Bicep, OpenAPI, Dockerfile, GitHub Actions, GitLab CI, Bitbucket Pipelines, Circle CI, Azure Pipelines, Ansible, Serverless framework, and a long tail of others. Each becomes a SARIF run under the same cilock invocation.
- **Custom checks.** Checkov's `--external-checks-dir` (custom Python or YAML policies) is preserved end-to-end: the custom check definitions get digested into `material/v0.3` (they're inputs), the resulting findings flow through the SARIF, and cilock's `sarif/v0.1` predicate carries them. Your in-house rules are attested alongside the upstream ones.
- **Soft-fail does not mean "ignore findings."** The findings still ride in the signed attestation. Policy at the verify side (`cilock verify` + Rego) is where you decide whether their presence blocks a deploy — the scan itself shouldn't be where the gate lives.

## FAQ

### Does cilock support Checkov?

Yes. Cilock invokes the upstream `checkov` binary unchanged and captures its SARIF output via the built-in `sarif` attestor. No Checkov fork, no plugin install — Checkov is treated as a normal tool that happens to write SARIF.

### Which IaC formats can Checkov scan under cilock?

All of them — Terraform, CloudFormation, Kubernetes, Helm, Kustomize, Argo, ARM, Bicep, OpenAPI, Dockerfile, GitHub / GitLab / Bitbucket / Circle / Azure CI configs, Ansible, Serverless. cilock is format-agnostic: it captures the SARIF Checkov produces, and the same `sarif/v0.1` predicate shape applies whether the scan was over a Terraform module or a Helm chart.

### Why `-s` (soft-fail)?

Checkov exits non-zero on findings, which is exactly the case you ran it for. Without `-s`, `command-run` records a failed exit code on every scan with a misconfiguration, which makes downstream tooling treat the *scan itself* as broken. `-s` lets Checkov exit cleanly while the findings remain in the SARIF (and in the signed `sarif/v0.1` attestation). The gate belongs at `cilock verify` time, not at scan time.

### How are custom Checkov checks captured?

Pass `--external-checks-dir <dir>` to Checkov as usual. cilock's `material/v0.3` Merkle tree digests every input file under the working directory — including your custom check definitions — so the check sources themselves are part of the signed evidence. Any findings those custom checks produce flow into the same `sarif/v0.1` predicate as upstream checks.

## See also

- [`sarif` attestor](../attestors/sarif) — the underlying ingestion path and predicate schema
- [Verify in a release gate](../guides/verify-in-a-release-gate) — how a `sarif/v0.1` attestation feeds policy at deploy time
- [The spine of the graph](../concepts/the-spine-of-the-graph) — how subject digests chain `sarif` to `material`, `product`, and `git`
- [Tools index](./index)
