---
title: OpenSCAP
description: Run OpenSCAP (oscap) XCCDF baseline scans under CI/lock — every SCAP Security Guide profile evaluation becomes a signed in-toto envelope carrying parsed pass/fail/N/A counts plus the raw XCCDF results XML.
sidebar_position: 15
---

# `OpenSCAP` integration

| | |
|---|---|
| Tool URL | [https://www.open-scap.org/](https://www.open-scap.org/) |
| License | LGPL-2.1 |
| Category | Host baseline compliance (SCAP / XCCDF / OVAL) |
| Rookery attestor used today | `oscap` |
| Validated example | [`29-oscap`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/29-oscap) |

[OpenSCAP](https://www.open-scap.org/) is the Red Hat-maintained reference implementation of the SCAP (Security Content Automation Protocol) stack — it evaluates a host against XCCDF benchmarks (CIS, DoD STIG, PCI-DSS, ANSSI, CUI, etc.) using OVAL probes and writes an XCCDF results XML report. Under CI/lock, every `oscap xccdf eval` run becomes a **signed `oscap/v0.1` attestation** carrying the parsed pass/fail/notapplicable counts, the failed-rule list, and a digest of the raw XCCDF XML alongside the file itself in `product/v0.3`.

## Validated invocation

```bash
cilock run --step oscap-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations oscap,environment,git \
  -- oscap xccdf eval \
       --profile xccdf_org.ssgproject.content_profile_standard \
       --results oscap-results.xml \
       /usr/share/xml/scap/ssg/content/ssg-amzn2023-ds.xml
```

This is the [`29-oscap`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/29-oscap) example verbatim, validated end-to-end against a fresh Amazon Linux 2023 EC2 host using the SCAP Security Guide (SSG) `standard` profile from `ssg-amzn2023-ds.xml`. The scan produced **11 pass, 3 fail, 64 N/A** — real findings, not synthetic fixtures. The three failed rules (`rpm_verify_permissions`, `file_permissions_library_dirs`, `grub2_nousb_argument`) reflect actual gaps on the host.

A few things to know about this invocation:

- **No soft-fail flag needed.** `oscap xccdf eval` exits 0 when the scan completes, regardless of how many rules failed — the rule outcomes live inside the XCCDF results XML. `command-run/v0.1` records exit 0 even when `failCount > 0`. The gate belongs at `cilock verify` time over the parsed `oscap/v0.1` predicate, not at scan time.
- **`--results <file>` is required.** Without it `oscap` only prints to stdout and there is no XML file for CI/lock's `product/v0.3` and `oscap` attestors to ingest.
- **Datastream path is distribution-specific.** AL2023 ships SSG content at `/usr/share/xml/scap/ssg/content/ssg-amzn2023-ds.xml`; RHEL 9 uses `ssg-rhel9-ds.xml`, Ubuntu 22.04 uses `ssg-ubuntu2204-ds.xml`, etc. The `scap-security-guide` package (RHEL/Fedora) or `ssg-base` (Debian/Ubuntu) installs them.

## What gets captured

Each `cilock` run emits an in-toto envelope whose predicate carries the following attestor types:

| Attestor type                                          | Captures                                                                  |
| ------------------------------------------------------ | ------------------------------------------------------------------------- |
| `https://aflock.ai/attestations/command-run/v0.1`      | Real `oscap xccdf eval ...` argv, env, exit code, stdout/stderr           |
| `https://aflock.ai/attestations/material/v0.3`         | Merkle tree of inputs (the SSG datastream XML is read, not in cwd)        |
| `https://aflock.ai/attestations/product/v0.3`          | Merkle tree of outputs, including `oscap-results.xml`                     |
| `https://aflock.ai/attestations/oscap/v0.1`            | Parsed XCCDF: profile, benchmark, target host, per-result counts, failed-rule list, `reportDigestSet.sha256` |
| `https://aflock.ai/attestations/environment/v0.1`      | OS, arch, user, env vars (PII-filtered)                                   |
| `https://aflock.ai/attestations/git/v0.1`              | Commit SHA, branch, remotes                                               |

The `oscap/v0.1` predicate's `reportDigestSet.sha256` exactly matches the digest of the `oscap-results.xml` leaf in the `product/v0.3` tree. That is the chain that makes the findings verifiable — you can't swap in a different XCCDF report without invalidating the product tree. The `oscap` attestor also publishes three SHA-256 subjects on the envelope: `profile:<profile-id>`, `host:<target-hostname>`, and `benchmark:<benchmark-id>`, so a policy can pin "this attestation is the STIG scan for *this* host."

## Why this shape

| Antipattern                                                     | This page                                                              |
| --------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `cilock run ... -- bash -c "cp scan.xml results.xml"`           | `cilock run ... -- oscap xccdf eval --results oscap-results.xml ...`   |
| `command-run` records `bash -c "cp ..."` — useless              | `command-run` records the real `oscap xccdf eval` argv                 |
| Product attestor digests a copy of a file written outside CI/lock | Product attestor digests the XCCDF XML `oscap` actually wrote          |
| Tool execution happens outside CI/lock's syscall view             | `oscap` runs as CI/lock's direct child; the spy traces its syscalls     |
| `oscap` predicate parses a file of unknown provenance            | `oscap` predicate parses the same file CI/lock just hashed into product |

CI/lock invokes `oscap` **directly** — no `bash -c` wrapper, no `cp` of a pre-existing report, no `echo scan-done` placeholder. This page was promoted from the `29-oscap` validated example precisely because earlier internal docs used those antipatterns; the [antipattern sweep](https://github.com/aflock-ai/cilock-docs/pull/27) cleaned the attestor reference page, and this user-facing page inherits the corrected shape. The three guarantees — real argv in `command-run`, ptrace coverage of the scan, product digest matching the parsed report — only hold when CI/lock is the tool's direct parent.

## Validate it locally

```bash
# Generate a signing key (one-time).
openssl genpkey -algorithm ed25519 -out key.pem

# Run cilock + oscap against the host.
cilock run --step oscap-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations oscap,environment,git \
  -- oscap xccdf eval \
       --profile xccdf_org.ssgproject.content_profile_standard \
       --results oscap-results.xml \
       /usr/share/xml/scap/ssg/content/ssg-amzn2023-ds.xml

# Confirm the predicate carries the expected attestor types.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations | map(.type)'
```

Expected output:

```json
[
  "https://aflock.ai/attestations/environment/v0.1",
  "https://aflock.ai/attestations/git/v0.1",
  "https://aflock.ai/attestations/material/v0.3",
  "https://aflock.ai/attestations/command-run/v0.1",
  "https://aflock.ai/attestations/product/v0.3",
  "https://aflock.ai/attestations/oscap/v0.1"
]
```

Confirm `oscap`'s real argv ended up in `command-run`:

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'
```

Expected output (no `bash`, no `cp` — the literal `oscap` argv):

```json
[
  "oscap",
  "xccdf",
  "eval",
  "--profile",
  "xccdf_org.ssgproject.content_profile_standard",
  "--results",
  "oscap-results.xml",
  "/usr/share/xml/scap/ssg/content/ssg-amzn2023-ds.xml"
]
```

Extract the pass/fail/N/A counts and the failed-rule list from the `oscap/v0.1` predicate:

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/oscap/v0.1")
        | .attestation.scanSummary
        | {profile, benchmarkId, targetSystem,
           passCount, failCount, notApplicableCount, errorCount,
           failedRules: [.failedRules[] | {idref, severity}]}'
```

Against the `29-oscap` AL2023 host you should see `passCount: 11, failCount: 3, notApplicableCount: 64` and the three failed rules listed above.

## Notes

- **Profile selection.** SSG ships a dozen profiles per OS — the canonical ones are `xccdf_org.ssgproject.content_profile_standard` (baseline), `xccdf_org.ssgproject.content_profile_cis` / `_cis_server_l1` / `_cis_workstation_l1` (CIS), `xccdf_org.ssgproject.content_profile_stig` (DISA STIG), `xccdf_org.ssgproject.content_profile_pci-dss` (PCI), `xccdf_org.ssgproject.content_profile_cui` (NIST 800-171), and `xccdf_org.ssgproject.content_profile_anssi_bp28_high`. `oscap info <datastream>` lists every profile id available in a given DS.
- **Datastream paths by distro.** RHEL/CentOS/Rocky/Alma: `/usr/share/xml/scap/ssg/content/ssg-rhel{8,9,10}-ds.xml`. Fedora: `ssg-fedora-ds.xml`. AL2023: `ssg-amzn2023-ds.xml`. Ubuntu: `ssg-ubuntu{2004,2204,2404}-ds.xml`. Install via `dnf install scap-security-guide` (RHEL/Fedora) or `apt install ssg-base ssg-debderived` (Debian/Ubuntu).
- **SCAP spec triad.** SCAP is an umbrella for several XML grammars: **XCCDF** (the human-authored benchmark with rule descriptions, profiles, and remediation text), **OVAL** (the machine-checkable probes XCCDF rules delegate to), and **CPE** (the platform identifiers that gate which rules apply). `oscap xccdf eval` walks all three and writes a single XCCDF results XML — that file is what CI/lock attests.
- **ARF wrappers.** `oscap` can also emit an Asset Reporting Format (`--results-arf arf.xml`) that wraps XCCDF in a richer envelope. The rookery `oscap` attestor handles both: it walks XML tokens looking for the first `<Benchmark>` element regardless of nesting depth.
- **Result strings.** The attestor buckets rule outcomes by exact match on `pass`, `fail`, `notapplicable` (and `not applicable`), and `error`. Other XCCDF result values — `notchecked`, `informational`, `fixed`, `unknown` — are present in the raw XML but not counted in the predicate's roll-up.

## FAQ

### Does CI/lock support OpenSCAP?

Yes. CI/lock invokes the upstream `oscap` binary unchanged and captures its XCCDF results XML via the native `oscap` attestor. No OpenSCAP fork, no patched build — `oscap xccdf eval` runs exactly as it would outside CI/lock, and the resulting XML is parsed into a signed `oscap/v0.1` predicate.

### Which SCAP profiles can I scan under CI/lock?

Any profile shipped in your SCAP Security Guide datastream — CIS Level 1 / Level 2, DISA STIG, PCI-DSS, NIST 800-171 (CUI), ANSSI BP-028, the SSG `standard` baseline, and any custom profile you author. CI/lock is profile-agnostic: it captures whatever XCCDF results XML `oscap` writes, and the `oscap/v0.1` predicate records the profile id (`xccdf_org.ssgproject.content_profile_*`) alongside the per-rule outcomes.

### How does this differ from the `oscap` attestor reference page?

This page is the user-facing **integration walkthrough** — what command to run, what to expect, how to validate. The [`oscap` attestor](../attestors/oscap.mdx) page is the **schema reference** — the exact JSON shape of the predicate, the subject set published on the envelope, the XCCDF parsing rules and gotchas (file-suffix filter, namespace check, first-TestResult-only). Read this page to integrate OpenSCAP into a CI/lock pipeline; read the attestor page when authoring policy against the predicate.

### Can I use the SCAP results in a GRC platform?

Yes. The raw XCCDF results XML lands in `product/v0.3` as a Merkle leaf, so it's preserved verbatim — feed it directly into Tenable, Wazuh, Splunk Phantom, ServiceNow GRC, or any tool that already speaks XCCDF/ARF. The signed `oscap/v0.1` predicate gives you a tamper-evident roll-up (counts plus failed-rule list) that's easier to evaluate in Rego or OPA, and the envelope subjects (`profile:`, `host:`, `benchmark:`) let a verifier confirm the scan was the right benchmark on the right machine before trusting the counts.

### Does `oscap` exit non-zero on findings?

No — unlike SARIF tools like Checkov or gosec, `oscap xccdf eval` exits 0 whenever the scan completes successfully, even if many rules failed. The rule outcomes are inside the XCCDF XML, not in the process exit code. That means CI/lock's `command-run/v0.1` records exit 0 and no soft-fail flag is needed. Enforce thresholds in policy (e.g., `failCount == 0` in Rego against the `oscap/v0.1` predicate at `cilock verify` time).

## See also

- [`oscap` attestor](../attestors/oscap.mdx) — the predicate schema, subject set, and XCCDF parsing rules
- [`29-oscap` validated example](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/29-oscap) — the AL2023 + SSG `standard` reference run this page is built from
- [SCAP Security Guide (ComplianceAsCode)](https://github.com/ComplianceAsCode/content) — the upstream source of every `ssg-*-ds.xml` datastream
- [OpenSCAP project](https://www.open-scap.org/) — the `oscap` CLI, libraries, and SCAP toolchain
- [Tools index](./index.md)

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({"@context": "https://schema.org", "@type": "HowTo", "name": "Produce a signed OpenSCAP baseline-compliance attestation for a Linux host", "description": "Use cilock to wrap an OpenSCAP XCCDF evaluation so the SCAP Security Guide scan output is captured as a signed in-toto attestation carrying the parsed pass/fail/N-A counts, the failed-rule list, and a digest of the raw XCCDF results XML.", "totalTime": "PT3M", "tool": [{"@type": "HowToTool", "name": "cilock"}, {"@type": "HowToTool", "name": "OpenSCAP"}, {"@type": "HowToTool", "name": "scap-security-guide"}, {"@type": "HowToTool", "name": "openssl"}, {"@type": "HowToTool", "name": "jq"}], "step": [{"@type": "HowToStep", "name": "Install OpenSCAP and SCAP Security Guide", "text": "On RHEL/Fedora/AL2023: dnf install openscap-scanner scap-security-guide. On Debian/Ubuntu: apt install libopenscap8 ssg-base ssg-debderived."}, {"@type": "HowToStep", "name": "Generate a signing key", "text": "Run openssl genpkey -algorithm ed25519 -out key.pem"}, {"@type": "HowToStep", "name": "Run oscap under cilock", "text": "cilock run --step oscap-scan --signer-file-key-path key.pem --outfile attestation.json --attestations oscap,environment,git -- oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard --results oscap-results.xml /usr/share/xml/scap/ssg/content/ssg-amzn2023-ds.xml"}, {"@type": "HowToStep", "name": "Verify the oscap predicate", "text": "Decode the payload and check that the oscap/v0.1 attestor's reportDigestSet.sha256 matches the oscap-results.xml digest in the product/v0.3 tree, and that scanSummary reports the expected pass/fail/N-A counts."}]})}} />
