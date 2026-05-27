---
title: testssl.sh
description: Run testssl.sh TLS connection scans under cilock — the testssl JSON output becomes a signed v0.3 attestation parsed by the rookery sarif attestor, capturing protocol negotiation, cipher matrix, named TLS vulnerabilities, and FIPS 140-2/140-3 compliance findings.
sidebar_position: 18
examples_repo: tool-testssl-sarif
---

[testssl.sh](https://testssl.sh) is the de-facto open-source TLS / SSL connection scanner — it probes a live endpoint and reports protocol negotiation, the full cipher matrix per protocol version, forward secrecy, server defaults, certificate chain detail, every named TLS-stack vulnerability (Heartbleed, ROBOT, BEAST, CRIME, POODLE, Lucky13, Logjam, FREAK, DROWN, Ticketbleed), and — via `--fips` — FIPS 140-2/140-3 compliance for ciphers, hash algorithms, and key sizes. Under cilock, the testssl JSON output becomes a signed in-toto attestation linked to the host environment, the git commit, and the literal `testssl.sh` argv that produced it.

testssl.sh probes a live service on the wire. Only scan targets you own or have written authorization to scan; see the Notes section for the permissions matrix.

## Validated invocation

```bash
cilock run --step testssl-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- testssl.sh --jsonfile-pretty testssl.json --quiet <target-host>
```

`<target-host>` accepts a hostname, `host:port`, or IP. For FIPS-targeted scans add `--fips`:

```bash
cilock run --step testssl-fips-scan ... \
  -- testssl.sh --fips --jsonfile-pretty testssl-fips.json --quiet <target>
```

This is the exact command exercised in [`tool-testssl-sarif`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-testssl-sarif). The wrapped command is `testssl.sh` itself — the same binary you'd run in your terminal. testssl writes `testssl.json` directly via `--jsonfile-pretty`; no shell redirection is needed, and `command-run/v0.1.cmd` records the literal argv.

`testssl.sh` exits 0 on a clean scan even when severity findings are present, so no soft-fail flag is required. An exit ≥1 indicates a connection problem (the target wouldn't negotiate any TLS), not findings; the [`tool-testssl-sarif`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-testssl-sarif) example captures that case too — the `testifysec-demo` ELB scan exits 246 because the ELB has no TLS listener on `:443`, and the cilock envelope still signs the finding.

## What gets captured

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, hostname, username, env vars (sensitive ones obfuscated) |
| `https://aflock.ai/attestations/git/v0.1` | commit hash, branch, tags, dirty status |
| `https://aflock.ai/attestations/material/v0.3` | Merkle root over the working tree before the scan |
| `https://aflock.ai/attestations/command-run/v0.1` | literal `testssl.sh --jsonfile-pretty testssl.json --quiet <target>` argv + exit code |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over `testssl.json` as testssl writes it |
| `https://aflock.ai/attestations/sarif/v0.1` | parsed testssl JSON exposed as SARIF-shaped findings |

## Why this shape

| Antipattern | Correct shape (this example) |
|---|---|
| `cilock run ... -- bash -c "testssl.sh ... > out.json && cp out.json testssl-product.json"` | `cilock run ... -- testssl.sh --jsonfile-pretty testssl.json --quiet <target>` |
| `command-run.cmd` records `["bash","-c","testssl.sh ... && cp ..."]` | `command-run.cmd` records the literal `testssl.sh` argv |
| The ptrace spy traces `bash` and `cp`, not testssl.sh | The spy traces testssl.sh's syscalls because cilock is its direct parent |
| The product is a copy of a file written outside cilock's view | The product is `testssl.json` as testssl wrote it during the wrapped step |

Three properties matter: (1) `command-run/v0.1.cmd` records the real argv (`testssl.sh --jsonfile-pretty ... <target>`), not a shell. (2) The ptrace spy traces testssl.sh's syscalls because cilock is its direct parent. (3) `product/v0.3` captures the file testssl actually wrote via `--jsonfile-pretty`, not a copy of one written outside cilock's view.

Because testssl.sh accepts `--jsonfile-pretty <path>` directly, there's no need for an `sh -c` redirect — testssl handles the write itself.

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
  "https://aflock.ai/attestations/sarif/v0.1"
]
```

Confirm `command-run.cmd` carries the literal testssl.sh argv:

```bash
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'
# ["testssl.sh","--jsonfile-pretty","testssl.json","--quiet","cilock.aflock.ai"]
```

Pull FIPS-relevant findings out of the captured testssl JSON:

```bash
jq '[.scanResult[0].protocols[]?, .scanResult[0].ciphers[]?, .scanResult[0].fs[]?]
    | map(select(.severity != "OK" and .severity != "INFO"))' testssl.json
```

## Notes

- **Permissions to scan.** Only scan targets you own or have written authorization to scan. Cloud-provider managed services on your own account are generally OK (AWS [explicitly allows penetration testing](https://aws.amazon.com/security/penetration-testing/) of your own resources without prior approval; GCP and Azure have similar policies). Third-party services are off-limits without consent — subject to the Computer Fraud and Abuse Act and equivalent laws elsewhere. [badssl.com](https://badssl.com/), [testssl.sh's own site](https://testssl.sh/), and [public-firing-range.appspot.com](https://public-firing-range.appspot.com/) are deliberately-vulnerable public testbeds designed to be scanned.
- **`--fips` mode.** Flags ciphers, hash algorithms, and key sizes that are non-approved under FIPS 140-2 / 140-3. The findings appear under `scanResult[0].fips` and `scanResult[0].ciphers[]` with severity `NOT ok` for non-approved entries. Run a normal scan and a `--fips` scan in parallel if you need both the general TLS posture and the FIPS-compliance posture in separate envelopes.
- **Hostnames vs `host:port`.** testssl defaults to port 443. For non-HTTPS TLS services (LDAP-S, SMTPS, IMAP-S) use `host:port`. STARTTLS protocols need `--starttls <protocol>` — e.g. `--starttls smtp` for port 25 STARTTLS. The cilock envelope captures the exact `host:port` or `--starttls` argv in `command-run/v0.1`.
- **Output formats.** `--jsonfile-pretty <path>` produces the structured JSON the SARIF attestor consumes. `--json` (legacy, single-line) also works. `--csvfile`, `--htmlfile`, `--logfile` are output-only formats that would not be parsed by the sarif attestor — capture them as additional products if you need them, but the `sarif/v0.1` predicate is driven by the JSON.
- **Exit code 246 / connection failure.** testssl exits non-zero when it cannot establish *any* TLS connection. This is a legitimate finding for a release gate ("the public endpoint has no TLS") — see the `aws-elb` scan in [`tool-testssl-sarif/raw/`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-testssl-sarif/raw). If you want non-zero exits to NOT fail the cilock step, use [`--ignore-command-exit-code`](https://github.com/aflock-ai/rookery/pull/144) and gate on the testssl JSON content via Rego instead.

## FAQ

### Does cilock support testssl.sh?

Yes. Wrap `testssl.sh --jsonfile-pretty <out>.json --quiet <target>` with `cilock run --attestations sarif,environment,git`. The testssl JSON becomes a signed v0.3 attestation under `https://aflock.ai/attestations/sarif/v0.1`, the literal `testssl.sh` argv is captured in `command-run/v0.1`, and the JSON file is hashed into the v0.3 Merkle tree as a real product.

### Can cilock capture a FIPS 140-2 / 140-3 TLS compliance scan?

Yes — add `--fips` to the testssl argv. testssl flags every non-approved cipher, hash algorithm, and key size against the FIPS 140-2 / 140-3 approved lists, and those findings end up in the same signed envelope as the general TLS posture, distinguishable via the `scanResult[0].fips` and `scanResult[0].ciphers[].severity` fields.

### What targets can I scan?

Any TLS-capable endpoint you own or are authorized to scan. testssl accepts `hostname`, `host:port`, IP, and STARTTLS protocols (`--starttls smtp`, `--starttls ldap`, etc.). Cloud-provider managed services on your own account are generally fine; third-party services require written authorization. Public deliberately-vulnerable testbeds like badssl.com are safe for demos.

### How does this differ from running testssl.sh standalone?

Standalone testssl.sh writes a JSON file with no provenance — nothing binds it to the source tree, the git commit, the host, or the binary that ran. cilock adds five predicates around the same scan: `git/v0.1` (the commit), `environment/v0.1` (the host), `material/v0.3` (the inputs), `command-run/v0.1` (the exact testssl argv + exit code), and `product/v0.3` (the JSON's content hash). The testssl JSON itself is unchanged — same bytes, same downstream pipeline — but the surrounding evidence is now signed and policy-checkable.

### Why does the `aws-elb` example exit 246?

testssl.sh exits 246 when it can't negotiate any TLS protocol with the target. In the validated `tool-testssl-sarif` example, the `testifysec-demo` Classic ELB listens on port 80 only — there's no TLS on `:443`. That's itself a release-gate finding: "this public endpoint has no TLS." The cilock envelope captures the failed scan with exit code 246, so a policy can deny on `command-run/v0.1.exitcode != 0` for the testssl step.

## See also

- [`sarif` attestor](../attestors/sarif) — the underlying ingestion path
- [Validated example: tool-testssl-sarif](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/tool-testssl-sarif) — four real scans (cilock.aflock.ai, aflock.ai, platform.testifysec.com, testifysec-demo ELB) + raw JSON + raw envelopes + reproduce script
- [testssl.sh project](https://testssl.sh) — upstream
- [Tools index](./)
