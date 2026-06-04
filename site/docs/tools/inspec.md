---
title: Chef InSpec
sidebar_position: 16
description: Run Chef InSpec (Progress) compliance profiles under CI/lock — every CIS, custom Ruby, or dev-sec.io scan becomes a signed v0.1 InSpec attestation linked to the profile and target it scanned.
---

# `Chef InSpec` integration

| | |
|---|---|
| Tool URL | [https://github.com/inspec/inspec](https://github.com/inspec/inspec) |
| License | Apache-2.0 (community) / Progress commercial for newer releases |
| Category | Compliance-as-code scanner |
| Rookery attestor used today | [`inspec`](../attestors/inspec.mdx) (native predicate) |
| Validated example | [`30-inspec`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/30-inspec) |

[Chef InSpec](https://github.com/inspec/inspec) (originally Chef Software, now maintained by [Progress Software](https://www.chef.io/products/chef-inspec) after the 2020 acquisition) is a compliance-as-code framework. You write profiles as Ruby DSL files — `describe` blocks asserting facts about the target — and `inspec exec` runs them against any host reachable over SSH, WinRM, Docker, Kubernetes, or the local filesystem. Under CI/lock, every `inspec exec` becomes a **signed v0.1 InSpec attestation** carrying the profile name, target platform, and per-control pass/fail/skip counts alongside the raw JSON report.

## Validated invocation

```bash
cilock run --step inspec-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations inspec,environment,git \
  --enable-archivista=false \
  -- inspec exec dev-sec/linux-baseline \
       --reporter json:inspec-results.json \
       --no-distinct-exit \
       --chef-license=accept-silent
```

Three InSpec-specific quirks are baked into that command — each matters for clean attestations:

- **`--reporter json:inspec-results.json`** — InSpec writes the machine-readable JSON to a file in cwd. The `inspec` attestor (a `postproduct` lifecycle attestor) reads that file out of CI/lock's product set, integrity-checks it against the recorded digest, and parses the profile / platform / per-control results into the predicate.
- **`--no-distinct-exit`** — InSpec normally exits `100` when controls fail and `101` when only skipped controls remain. Without this flag, the very fact that you ran the scan to surface a finding makes `command-run/v0.1` record a non-zero exit code. `--no-distinct-exit` folds both into a clean `0` while the failed control IDs stay in the JSON (and in the signed `inspec/v0.1` predicate).
- **`--chef-license=accept-silent`** — InSpec 5+ refuses to run interactively until the license is accepted. Passing the flag silently accepts the community license on the same invocation; without it, the run blocks on a TTY prompt that doesn't exist inside CI/lock.

## What gets captured

Each `cilock` run emits an in-toto envelope whose predicate carries the following attestor types:

| Attestor type                                          | Captures                                                              |
| ------------------------------------------------------ | --------------------------------------------------------------------- |
| `https://aflock.ai/attestations/command-run/v0.1`      | Real `inspec exec ...` argv, env, exit code, stdout/stderr            |
| `https://aflock.ai/attestations/material/v0.3`         | Merkle tree of inputs (profile sources, custom Ruby controls, fixtures) |
| `https://aflock.ai/attestations/product/v0.3`          | Merkle tree of outputs, including `inspec-results.json`               |
| `https://aflock.ai/attestations/inspec/v0.1`           | Profile name, platform `<name>-<release>`, pass/fail/skip counts, failed control IDs |
| `https://aflock.ai/attestations/environment/v0.1`      | OS, arch, user, env vars (PII-filtered)                               |
| `https://aflock.ai/attestations/git/v0.1`              | Commit SHA, branch, remotes                                           |

The `inspec/v0.1` predicate's `reportDigestSet.sha256` exactly matches the digest of the `inspec-results.json` leaf in the `product/v0.3` tree. That chain is what makes the compliance findings verifiable — you can't swap in a clean JSON without invalidating the product tree. Each failed control ID also becomes a subject (`inspec:control:<id>`) so a downstream Rego policy can gate on specific rule failures.

## Why this shape

| Antipattern                                                      | This page                                                        |
| ---------------------------------------------------------------- | ---------------------------------------------------------------- |
| `cilock run ... -- bash -c "cp inspec-out.json product.json"`    | `cilock run ... -- inspec exec <profile> --reporter json:...`    |
| `command-run` records `bash -c "cp ..."` — useless               | `command-run` records the real `inspec exec` argv                |
| Product attestor digests the `cp` destination                    | Product attestor digests InSpec's actual output file             |
| Tool execution happens outside the attestation                   | InSpec runs inside CI/lock; spy traces its syscalls and target connections |

CI/lock invokes `inspec exec` **directly** — no `bash -c` wrapper. That preserves the real argv in `command-run` (including the profile reference and target backend), and lets the spy attestors observe every file InSpec read and every report it wrote. The `inspec` attestor then picks the JSON file out of the products map, re-hashes it, and parses it.

## Validate it locally

```bash
# Generate a signing key (one-time).
openssl genpkey -algorithm ed25519 -out key.pem

# Run cilock + inspec exec against a profile (dev-sec/linux-baseline shown here;
# substitute any local path, git URL, or Automate-hosted profile reference).
cilock run --step inspec-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations inspec,environment,git \
  --enable-archivista=false \
  -- inspec exec dev-sec/linux-baseline \
       --reporter json:inspec-results.json \
       --no-distinct-exit \
       --chef-license=accept-silent

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
  "https://aflock.ai/attestations/inspec/v0.1"
]
```

```bash
# Confirm InSpec's real argv ended up in command-run.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/command-run/v0.1")
        | .attestation.cmd'
```

Expected output (literal InSpec argv — proof the `cp` antipattern is gone):

```json
[
  "inspec",
  "exec",
  "dev-sec/linux-baseline",
  "--reporter",
  "json:inspec-results.json",
  "--no-distinct-exit",
  "--chef-license=accept-silent"
]
```

```bash
# Pull the compliance roll-up out of the inspec attestor.
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[]
        | select(.type=="https://aflock.ai/attestations/inspec/v0.1")
        | .attestation
        | {reportFile,
           digest: .reportDigestSet.sha256,
           profile: .scanSummary.profileName,
           platform: .scanSummary.platform,
           total: .scanSummary.totalControls,
           failed: .scanSummary.failedControls,
           failedIds: [.scanSummary.failedDetails[].id]}'
```

Against the [`30-inspec`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/30-inspec) example (real `dev-sec/linux-baseline` scan on an AL2023 EC2 host) this surfaces the profile name (`linux-baseline`), the platform (`amazon-2023`), the total / failed control counts, and the IDs of every failed control — feeding directly into a `cilock verify` Rego gate.

## Notes

- **Profile selection.** InSpec accepts a profile as a local path (`./my-profile`), a git URL (`https://github.com/dev-sec/linux-baseline`), a [Chef Supermarket](https://supermarket.chef.io) shortname (`dev-sec/linux-baseline`, `dev-sec/ssh-baseline`), an Automate-hosted reference, or a `.tar.gz` archive. The community CIS profiles maintained by the [dev-sec.io](https://dev-sec.io) project are the most common starting point — they cover Linux baseline, SSH, NGINX, Apache, MySQL, PostgreSQL, and Windows. The same CI/lock invocation works for any of them; only the profile argument changes.
- **Target backends.** InSpec scans whatever target `-t` points at: `-t ssh://user@host` (SSH, key-auth recommended), `-t winrm://user@host` (Windows), `-t docker://<container-id>` (running container), `-t podman://<container-id>`, `-t k8s://<context>`, `-t aws://<region>` / `-t azure://` / `-t gcp://` (cloud-resource scanning), or omitted (local target). CI/lock is target-agnostic — it captures whatever the InSpec backend produces. The `--no-distinct-exit` and `--reporter json:...` flags apply uniformly.
- **Reporter formats.** InSpec supports `cli` (human), `json`, `json-min`, `junit`, `html`, `progress`, `documentation`, `yaml`, and `automate` reporters; multiples can stack (`--reporter cli json:results.json junit:results.xml`). Only the `json` reporter (or `json-min`) is parsed by the `inspec` attestor — the others ride along in the product Merkle tree as opaque files for human review.
- **Custom Ruby profiles.** Profile sources are inputs, so anything in your local profile directory (Ruby `controls/*.rb` files, custom resources, libraries, attribute files) gets digested into `material/v0.3`. Findings produced by custom controls flow into the same `inspec/v0.1` predicate as findings from upstream rules — your in-house compliance rules are attested alongside the dev-sec.io / CIS ones.
- **License model.** The InSpec engine itself is Apache-2.0, but newer releases ship under Progress's commercial agreement; the `--chef-license=accept-silent` flag covers the community use case. If you're running under a Progress commercial license, the same flag still works — the license is consumed locally and does not appear in the captured attestation.
- **Chef → Progress rename.** The tool is still binary-named `inspec` and the GitHub org is still `inspec/inspec`; only the corporate ownership changed. Documentation and marketing copy increasingly say "Progress Chef InSpec," but the CLI surface this page documents is stable.

## FAQ

### Does CI/lock support Chef InSpec?

Yes. CI/lock invokes the upstream `inspec` binary unchanged and captures its JSON reporter output via the native [`inspec` attestor](../attestors/inspec.mdx), which emits a `https://aflock.ai/attestations/inspec/v0.1` predicate. No InSpec fork, no plugin install — InSpec is treated as a normal tool that happens to write a documented JSON schema CI/lock knows how to parse.

### Which targets can InSpec scan under CI/lock?

All of them — local (`-t local://`, the default), SSH (`-t ssh://`), WinRM (`-t winrm://`), Docker / Podman containers (`-t docker://`, `-t podman://`), Kubernetes (`-t k8s://`), and the major cloud providers (`-t aws://`, `-t azure://`, `-t gcp://`). CI/lock is target-agnostic: it captures whatever the InSpec backend produces. The same flags (`--reporter json:...`, `--no-distinct-exit`) apply uniformly.

### Can I write custom Ruby controls?

Yes — custom controls work exactly as they do without CI/lock. Drop your `controls/*.rb` files into a profile directory, point `inspec exec` at it, and the findings flow into the same `inspec/v0.1` predicate alongside any upstream rules. The custom control sources themselves get digested into `material/v0.3`, so a verifier can prove which version of which control produced each finding.

### Why `--no-distinct-exit`?

InSpec exits `100` when any control fails and `101` when only skipped controls remain. Without `--no-distinct-exit`, `command-run/v0.1` records a non-zero exit code on every scan that surfaces a real finding — which makes downstream tooling treat the scan itself as broken. The flag folds 100/101 back to 0; the failed control IDs still ride in the signed `inspec/v0.1` attestation, and the gate belongs at `cilock verify` time (a Rego policy over `failedControls`), not at scan time.

### How does InSpec compare to OpenSCAP / `oscap`?

Both are compliance scanners; the differences are the rule language, the ecosystem, and the target shape. OpenSCAP consumes [SCAP](https://csrc.nist.gov/projects/security-content-automation-protocol) content (XCCDF / OVAL XML, mostly Red Hat / SCAP-Security-Guide profiles) and is best for Linux baseline scans. InSpec consumes Ruby DSL profiles, ships a much larger community library (dev-sec.io, CIS, vendor-specific), and natively scans remote SSH / WinRM / cloud-API targets that OpenSCAP can't reach. CI/lock has [a native attestor for each](../attestors/oscap.mdx) — pick the tool that matches your existing compliance content, not the attestor.

## See also

- [`inspec` attestor](../attestors/inspec.mdx) — the underlying predicate schema, MIME-type filter, and shape-detection rules
- [`oscap` tool integration](../attestors/oscap.mdx) — sibling compliance scanner with the same `cilock verify` gating pattern
- [Validated example: `30-inspec`](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/30-inspec) — real `dev-sec/linux-baseline` scan against an AL2023 EC2 host
- [Chef InSpec upstream](https://github.com/inspec/inspec) — the tool itself, maintained by Progress Software
- [dev-sec.io community profiles](https://dev-sec.io) — Linux, SSH, NGINX, Apache, MySQL, PostgreSQL, Windows hardening baselines
- [Tools index](./index.md)

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({"@context": "https://schema.org", "@type": "HowTo", "name": "Produce a signed InSpec compliance attestation with cilock", "description": "Use cilock to wrap a Chef InSpec scan so the JSON report is captured as a signed in-toto attestation linked to the profile, the target platform, and the per-control pass/fail counts.", "totalTime": "PT3M", "tool": [{"@type": "HowToTool", "name": "cilock"}, {"@type": "HowToTool", "name": "Chef InSpec"}, {"@type": "HowToTool", "name": "openssl"}, {"@type": "HowToTool", "name": "jq"}], "step": [{"@type": "HowToStep", "name": "Install InSpec", "text": "Install the inspec gem or download a release tarball from github.com/inspec/inspec."}, {"@type": "HowToStep", "name": "Generate a signing key", "text": "Run openssl genpkey -algorithm ed25519 -out key.pem"}, {"@type": "HowToStep", "name": "Run InSpec under cilock", "text": "cilock run --step inspec-scan --signer-file-key-path key.pem --outfile attestation.json --attestations inspec,environment,git -- inspec exec dev-sec/linux-baseline --reporter json:inspec-results.json --no-distinct-exit --chef-license=accept-silent"}, {"@type": "HowToStep", "name": "Validate the envelope", "text": "Decode the payload with jq and check that the inspec/v0.1 attestor's reportDigestSet matches the inspec-results.json digest in the product/v0.3 tree."}]})}} />
