---
title: Dogfooding CI/lock releases
sidebar_position: 16
---

# Dogfooding: how CI/lock secures its own release

If our policy or our attestor logic were unsound, our own release would
have shipped with that flaw. So we use CI/lock to verify CI/lock.

This page is the architecture-level walkthrough of how the CI/lock
release pipeline turns a git commit into a signed binary that you can
verify byte-for-byte against the same evidence we used to publish it.
The companion page [Verify the CI/lock
binary](../getting-started/verify-the-cilock-binary) is the operator's
side of the same story — the exact commands to run.

## The principle

Most supply-chain tooling lives outside the product it secures. SLSA
generators are GitHub Actions written by sigstore; cosign signs other
people's artifacts; SBOM tools attest other people's builds. The
tooling never has to defend against an attack on itself.

CI/lock takes the opposite approach. Every claim we make about what
CI/lock can detect — secrets in a binary, network egress during a build,
a tampered dependency, a non-FIPS toolchain — is something the CI/lock
release pipeline must itself pass before a binary is published. The
shape of the proof is identical to what we ask users to consume:

```text
Cilock's release process is the canonical example of a verified build.
Every gate in our pipeline is a gate you can apply to yours.
```

If we ever weaken a gate to ship a release, we have to do it visibly:
either remove the layer from `release.policy.json` (visible in git) or
add an exception (visible in the Rego). Hidden compromises aren't
possible without modifying the same policy code that's audited by
downstream consumers.

## The trust chain

Three signed boundaries, each binding the next:

```text
          ┌─────────────────────────────────────────────────────────────┐
          │ GIT COMMIT  (signed in every envelope's `git` predicate)    │
          │ - tree hash, parent hashes, refs, dirty-tree flag           │
          └────────────────────────┬────────────────────────────────────┘
                                   │
                                   ▼
          ┌─────────────────────────────────────────────────────────────┐
          │ STEP 1: vendor-cilock-deps                                  │
          │ - cilock-action wraps `go mod vendor`                       │
          │ - Products: every file under cilock/vendor/*                │
          │ - Signed by: Fulcio keyless, BuildSignerURI = release.yml   │
          │              at refs/tags/v1.1.0-rcN                        │
          └────────────────────────┬────────────────────────────────────┘
                                   │
        policy: release-build.artifactsFrom = [vendor-cilock-deps]
                                   ▼
          ┌─────────────────────────────────────────────────────────────┐
          │ STEP 2: release-build                                       │
          │ - cilock-action wraps `go build -mod=vendor` (under ptrace) │
          │ - Materials: every vendored file the compiler read          │
          │ - Products: cilock-bin-<platform>                           │
          │ - Inline predicates: env, git, github, command-run, product,│
          │   sbom (SPDX), secretscan, govulncheck, slsa, inclusion-    │
          │   proof — all in one DSSE envelope                          │
          │ - Signed by: same Fulcio keyless identity                   │
          └────────────────────────┬────────────────────────────────────┘
                                   │
                                   ▼
          ┌─────────────────────────────────────────────────────────────┐
          │ RELEASE ARTIFACT                                            │
          │ - cilock binary you download                                │
          │ - sha256(binary) == subject digest in release-build envelope│
          │ - tarball + cosign sig (only emitted after policy passes)   │
          └─────────────────────────────────────────────────────────────┘
```

A second independent runner builds every platform in parallel
(`ubuntu-24.04` vs `ubuntu-latest`). The release fails if the witness
runner's product digest doesn't match the primary's — the only check
in the pipeline that catches a compromised runner.

## Attack-by-attack

For each common supply-chain attack class, the table below names the
specific gate in `release.policy.json` (or the workflow / repo config)
that blocks it. Every gate is enforced before `cosign sign-blob` runs,
so a cosign signature on a published binary transitively proves all
gates held.

| Attack | What it would do | Gate that stops it |
|---|---|---|
| **Stolen maintainer credentials → force-push a release tag** | Repoint `v1.1.0` to a malicious commit | GitHub Ruleset on `v*` blocks `update`/`deletion`/`non_fast_forward`; only admins bypass |
| **Direct push to `main` bypassing review** | Sneak code in without PR review | Branch protection on `main` requires PR + 1 approval + linear history + status checks |
| **Trivy-style float-tag attack on a build action** | Move `actions/checkout@v4` to malicious commit | Every third-party action is SHA-pinned (e.g. `actions/checkout@34e114876b0b…`); a tag move doesn't affect us |
| **Compromised CI runner injects code at build time** | Bytes the build outputs differ from what the source says | Reproducible-build witness: independent second runner builds every platform; release fails if any product digest diverges |
| **Tampered module on proxy.golang.org** | Serve different bytes for an existing module | go.sum + GOSUMDB; vendor step recorded each module's digest, build step's materials must match (policy: `release-build.artifactsFrom = ["vendor-cilock-deps"]`) |
| **Renovate auto-merges a typosquatted new dep** | Add a malicious module the first time we see it | `govulncheck` Rego: deny if `summary.reachableCount > 0` or any HIGH/CRITICAL severity in the linked module graph |
| **Build phones home during compilation** | Exfiltrate runner secrets via `go:generate` or a malicious dep's `init()` | `--trace` on cilock-action captures every `connect()`/TLS-SNI; hermetic Rego denies any host outside the two-entry allowlist (`vuln.go.dev`, `storage.googleapis.com`) |
| **Tampered `cilock/vendor/*` between vendor and build steps** | Substitute a malicious go module after vendor recorded the legit digest | `artifactsFrom` chain check: every material the build step recorded must match a product the vendor step recorded — byte-for-byte |
| **Build runs with `CGO_ENABLED=1`** | Link system libc, opening dynamic-library injection | Environment-hardening Rego: deny if `CGO_ENABLED != "0"` |
| **Build runs without FIPS** | Ship a binary that fails FedRAMP 20x / CMMC checks | Environment-hardening Rego: deny if `GOFIPS140` unset, empty, or `"off"`. Binary metadata embeds `GOFIPS140=v1.0.0-c2097c7c` and `DefaultGODEBUG=fips140=on`. |
| **Build runs without `-trimpath`** | Leak local filesystem paths into the binary, breaking reproducibility | Build-hygiene Rego: deny if argv lacks `-trimpath` |
| **API token compiled into the release binary** | Embed a credential in the version-info ldflags or in a const | `secretscan` attestor (gitleaks) scans the built binary plus every prior envelope; deny on any finding not in the narrow FP allowlist (Go module pseudo-version SHAs in SBOM/govulncheck JSON) |
| **Compromised maintainer pushes a dirty working tree** | Slip an uncommitted modification past tests | Source-integrity Rego: deny if `count(input.status) > 0` (any modified/staged/untracked file) |
| **Single human approves + tags + publishes their own release** | Bypass the second-pair-of-eyes principle | Branch protection requires PR review by someone other than the author; tag protection blocks self-tagging from non-admin tokens |
| **Mirror serves wrong binary bytes** | Substitute a malicious binary at the download server | sha256 checksums file (cosign-signed) + per-tarball cosign signature; user verifies before extracting |
| **Replay attack: old release tag re-served as current** | Force a downgrade to a vulnerable old version | Tag protection prevents repointing; signed policy `expires` field gates the verifier against ancient policies; user pins the version explicitly |
| **Compromised proxy.golang.org during the vendor step** | Serve a bad module the FIRST time we vendor it (so go.sum doesn't catch it) | **NOT FULLY CAUGHT** — this is the trust-on-first-use boundary. Mitigations: vendor step is itself attested (vendor-cilock-deps); downstream auditors can compare vendor product digests across releases to detect changes; GOSUMDB cross-checks the hash against Google's transparency log. |

## Trust on first use — be honest

The vendor step is our weakest link. When `go mod vendor` runs in CI, it
fetches modules from `proxy.golang.org`, verifies the hashes against
`go.sum` (which is committed to git) and `GOSUMDB` (Google's
transparency log), and writes the bytes to `cilock/vendor/`. If a
NEW dep is added — and proxy.golang.org is compromised at the moment
that dep is first vendored — the malicious hash gets baked into our
go.sum and we'd never know.

Three things mitigate this:

1. **GOSUMDB.** Google's sum database is a separate transparency log
   from proxy.golang.org. Compromising both simultaneously is an
   attacker tier-up. GOSUMDB is consulted on first use of any module.
2. **Vendor step is independently attested.** The
   `vendor-cilock-deps` envelope records the vendor command's argv, the
   resulting product set, and the Fulcio identity. A downstream auditor
   comparing vendor product digests across consecutive releases can
   detect when a previously-stable module changed bytes — a strong
   signal of tampering at the proxy.
3. **Reproducibility witness.** If proxy.golang.org served different
   bytes to our primary runner vs our witness runner during the same
   release, the resulting binaries diverge and reproducibility fails.

For higher assurance, future work tracked in
[rookery#156](https://github.com/aflock-ai/rookery/issues/156)
considers committing `cilock/vendor/` to git so the bytes have a
permanent git-hash anchor independent of proxy.golang.org.

## Comparison to single-tool approaches

| Tool | What it gives you | What it misses |
|---|---|---|
| **cosign keyless signing only** | "These bytes were signed by this Fulcio identity." | No assertion about how the bytes were built, what code went in, what the build env looked like, or whether scans were run. |
| **SLSA generator only** | A SLSA v1.0 provenance predicate describing the build. | One predicate, not a multi-step chain. No vendor → build link. No secret scan, no vuln check. SLSA is a *format* for stating one thing; CI/lock is a *pipeline* for stating many things and linking them. |
| **GitHub-native attestations (`actions/attest-build-provenance`)** | Per-artifact provenance attestation signed by GitHub's identity. | Single-step. No policy language. No cross-step subject-digest matching. |
| **CI/lock** (the dogfood) | Multi-step chain of in-toto collections, each with 9 sub-attestation predicates, linked via policy `artifactsFrom`, verified offline against a signed policy. SLSA v1.0 predicate is *also* emitted alongside. | What every other tool also misses: correctness of the code itself. We're attesting the build, not the bug-freeness of the source. |

The CI/lock release uses all of these formats simultaneously:

- **DSSE envelope** wrapping an **in-toto Statement** with a
  **`https://aflock.ai/attestation-collection/v0.1`** predicate
  (canonical evidence shape)
- **`https://slsa.dev/provenance/v1.0`** predicate in the same envelope
  (SLSA-format consumer compatibility)
- **`https://aflock.ai/attestations/inclusion-proof/v0.1`** predicate
  embedding a per-file Merkle inclusion proof against the product tree
  root (offline replay; producer-signed, not a transparency-log receipt)
- **cosign keyless signatures** on every release asset (Sigstore PKI
  trust anchor)
- **RFC 3161 TSA** timestamp on every signature (long-term verifiability
  beyond Fulcio's 10-minute cert)

A downstream consumer who only knows cosign can verify; a consumer who
only knows SLSA can verify; a consumer who reads the in-toto collection
can verify. The same envelope satisfies all three.

## How a user verifies the dogfood

Three paths of increasing rigor, all leveraging the same evidence
chain. The exact commands live in
[Verify the `cilock` binary](../getting-started/verify-the-cilock-binary).

1. **30 seconds (Path 1):** `curl … install.sh && cosign verify-blob …
   && bash install.sh`. The signed install script does the rest.
2. **3 minutes (Path 2):** Download the offline evidence bundle + signed
   policy + pubkey, run `cilock verify --bundle … --artifactfile …`.
   Walks both steps of the chain, evaluates all six Rego layers,
   checks subject digests.
3. **Full audit (Path 3):** Download the release-evidence-kit tar.gz
   (cosign-signed, contains the bundle + policy + pubkey + per-platform
   VSAs + raw SBOM + `VERIFY.md`). Untar, run the included commands.
   No live network required after the initial download.

Each path produces output the user can attach to a compliance report:

```
level=info msg="Verification succeeded"
level=info msg="Step: vendor-cilock-deps"
level=info msg="Step: release-build"
```

## Apply the pattern to your own releases

The same pattern works for any Go (or non-Go) project. The CI/lock
release workflow is intentionally readable as a template:

- [`.github/workflows/release.yml`](https://github.com/aflock-ai/rookery/blob/main/.github/workflows/release.yml)
  — full workflow including the witness build leg, vendor step, and
  evidence-kit assembly
- [`deploy/cilock/release.policy.json`](https://github.com/aflock-ai/rookery/blob/main/deploy/cilock/release.policy.json)
  — the multi-step policy with `artifactsFrom` link
- [`deploy/cilock/release-rego-*.txt`](https://github.com/aflock-ai/rookery/tree/main/deploy/cilock)
  — plain-text Rego sources (the same modules base64-embedded in the
  policy)

The minimum viable port is:

1. Pick `cilock-action` v1.0.4+ in your workflow (SHA-pin it).
2. Wrap your build (and optionally your vendor / install steps) in
   one or more `cilock-action` invocations with distinct `step:`
   names.
3. Write a `release.policy.json` declaring those step names + the
   `artifactsFrom` link between them.
4. Sign the policy with an ephemeral ed25519 key in CI; cosign-sign
   the pubkey + policy.
5. Run `cilock verify` against your build's binary at the end of the
   workflow, before publishing anything.

The release pipeline we ship is two years of refinements compressed
into one YAML file. Steal it.

## Related reading

- [Trust model](./trust-model) — what CI/lock attests to and what's out
  of scope.
- [Defending against supply-chain attacks](../tutorials/defending-against-supply-chain-attacks)
  — the same three-layer defense applied to tj-actions, Trivy, and
  LiteLLM compromises.
- [Verify the `cilock` binary](../getting-started/verify-the-cilock-binary)
  — operator-side commands for the three verification paths.
- [Policy verification](./policy-verification) — how CI/lock evaluates
  Rego against signed envelopes.
- [The spine of the graph](./the-spine-of-the-graph) — how subject
  digests connect attestations into a verifiable DAG.
