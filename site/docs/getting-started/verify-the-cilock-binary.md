---
id: verify-the-cilock-binary
title: Verify the `cilock` binary
description: How CI/lock dogfoods its own release pipeline — every `cilock` binary you download from GitHub is signed via Sigstore Fulcio with the workflow's OIDC identity, comes with a Verification Summary Attestation (VSA) CI/lock produced by verifying itself against a 5-layer release policy, and ships a signed install.sh that scripts the cosign verification step before extraction.
sidebar_position: 2
---

# Verify the `cilock` binary

Three verification paths, pick the level of rigor you want. **Each path is strictly stronger than the previous one** — Path 3 ⊃ Path 2 ⊃ Path 1.

## 🟢 30-second verify (Path 1)

**For most users.** One command. cosign-verifies the install script against the canonical GitHub workflow identity, then runs it. The script auto-detects OS / arch / latest version and cosign-verifies the binary archive too.

```bash
curl -fsSL https://cilock.dev/install.sh -o install.sh && \
  curl -fsSL https://cilock.dev/install.sh.sig -o install.sh.sig && \
  curl -fsSL https://cilock.dev/install.sh.cert -o install.sh.cert && \
  cosign verify-blob \
    --certificate install.sh.cert \
    --signature install.sh.sig \
    --certificate-identity-regexp '^https://github\.com/aflock-ai/rookery/\.github/workflows/release\.yml@.+' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    install.sh && \
  bash install.sh
```

You should see:

```
Verified OK
[install.sh] resolving latest release ... v3.0.0
[install.sh] downloading cilock-3.0.0-linux-amd64.tar.gz ...
[install.sh] cosign-verifying archive ... Verified OK
[install.sh] installed cilock to /usr/local/bin/cilock
$ cilock version
cilock 3.0.0
```

If `Verified OK` doesn't appear, **stop** — see [Troubleshooting](#troubleshooting). Do not run an unverified `install.sh`.

## 🟡 3-minute verify (Path 2)

**For users who want to prove the binary itself passes the release policy**, not just that the archive bytes were signed. Uses CI/lock to walk the full source→vendor→build chain that the release pipeline recorded.

```bash
# Path 1 (above) must run first — installs cilock locally.

# Pull the release artifacts cilock will verify against itself.
VERSION="$(cilock version | awk '{print $2}')"
BASE="https://github.com/aflock-ai/rookery/releases/download/v${VERSION}"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; arm64|aarch64) ARCH=arm64 ;; esac

mkdir -p ~/cilock-verify && cd ~/cilock-verify

# Three artifacts: the binary archive, the offline evidence bundle, and
# the signed policy + pubkey. Everything else (per-platform envelopes,
# SBOM, scans, VSAs) is inside the bundle.
curl -fsLO "${BASE}/cilock-${VERSION}-${OS}-${ARCH}.tar.gz"
curl -fsLO "${BASE}/cilock-${VERSION}-evidence-bundle.tar.gz"
curl -fsLO "${BASE}/release-policy.json"
curl -fsLO "${BASE}/cilock-policy.pub"

# Extract the binary so cilock verify can hash it directly. The
# attestations bind to the binary bytes, not to the tarball wrapper.
tar -xzf "cilock-${VERSION}-${OS}-${ARCH}.tar.gz"

cilock verify \
  --policy release-policy.json \
  --publickey cilock-policy.pub \
  --bundle "cilock-${VERSION}-evidence-bundle.tar.gz" \
  --artifactfile ./cilock \
  --enable-archivista=false
```

You should see (last few lines):

```
level=info msg="policy signature verified"
level=info msg="Verification succeeded"
level=info msg="Step: vendor-cilock-deps"
level=info msg="Step: release-build"
```

**What just happened:** CI/lock loaded the offline bundle — 8 signed envelopes covering both the **vendor step** (the `go mod vendor` that pinned every dep) and the **build step** (the `go build -mod=vendor` that produced your binary). Policy enforced the [chain link](#source-vendor-build-chain): the build step's *materials* (every byte the compiler read) must match the vendor step's *products* (every byte the vendor command wrote). Any tampering between the two steps fails the policy. On top of that, all [six Rego layers](#what-the-release-policy-asserts) held — source integrity, build hygiene, environment hardening (FIPS + CGO), hermetic network egress, secretscan clean, govulncheck no reachable vulns.

## 🔴 Full chain (Path 3)

**For audit teams + offline / air-gapped verifiers.** Downloads a single self-contained evidence kit, untars it, and re-runs every check against the included envelopes — no live network required after the initial download.

```bash
# Single artifact: bundle + signed policy + pubkey + per-platform VSAs +
# raw SBOM + a VERIFY.md with the exact commands below.
curl -fsLO "${BASE}/cilock-${VERSION}-release-evidence-kit.tar.gz"
curl -fsLO "${BASE}/cilock-${VERSION}-release-evidence-kit.tar.gz.sig"
curl -fsLO "${BASE}/cilock-${VERSION}-release-evidence-kit.tar.gz.pem"

# (a) cosign-verify the kit itself was published by this workflow.
cosign verify-blob \
  --signature "cilock-${VERSION}-release-evidence-kit.tar.gz.sig" \
  --certificate "cilock-${VERSION}-release-evidence-kit.tar.gz.pem" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/aflock-ai/rookery/.github/workflows/release.yml@refs/tags/v.*' \
  "cilock-${VERSION}-release-evidence-kit.tar.gz"

# (b) Untar — everything you need to re-verify is now local.
tar -xzf "cilock-${VERSION}-release-evidence-kit.tar.gz"
cd "kit-${VERSION}/"
cat VERIFY.md           # The exact commands below, baked into the kit.

# (c) Re-run the chain verification against the bundle.
cilock verify \
  --policy release-policy.json \
  --publickey cilock-policy.pub \
  --bundle "cilock-${VERSION}-evidence-bundle.tar.gz" \
  --artifactfile ../cilock          # extracted in Path 2

# (d) Compare your local verify result against the per-platform VSA
# the release workflow itself computed at publish time.
jq -r '.predicate.verificationResult, .predicate.timeVerified' \
  "cilock-${VERSION}-${OS}-${ARCH}.vsa.json"
```

Expected from (c):

```
level=info msg="Verification succeeded"
level=info msg="Step: vendor-cilock-deps"
level=info msg="Step: release-build"
```

Expected from (d):

```
PASSED
2026-05-23T16:24:38Z
```

**What just happened:** every artifact a downstream verifier could possibly want is now in one cosign-signed tar.gz, with a copy-pasteable `VERIFY.md` next to it. If your local `Verification succeeded` matches the VSA's `PASSED`, you and the publisher agree on the policy outcome at signing time — that's the strongest signal we can give you short of building CI/lock yourself from source.

## What the release policy asserts

[`release-policy.json`](https://github.com/aflock-ai/rookery/blob/main/deploy/cilock/release.policy.json) is committed unsigned in the repo so reviewers can read it; the release workflow signs it at publish time. The policy declares two steps — `vendor-cilock-deps` and `release-build` — chained via `artifactsFrom`. Each step has its own functionary check + Rego layers; the chain link is the last check.

### Per-step gates

| Layer | Predicate | Asserts |
|---|---|---|
| Functionary identity | (envelope cert) | Sigstore Fulcio cert with `BuildSignerURI` glob-matching `.github/workflows/release.yml@refs/tags/v*`, issuer = GitHub Actions OIDC, root = sigstore-fulcio |
| **Source identity** | `github/v0.1` | `repository` == `aflock-ai/rookery` AND `reftype` starts with `tag` |
| **Source integrity** | `git/v0.1` | Working tree clean AND commit hash present |
| **Environment hardening** | `environment/v0.1` | `CGO_ENABLED=0` AND `GOFIPS140` set (not empty, not `off`) — required so the binary embeds the [FIPS 140-3 module](https://go.dev/doc/security/fips140) |
| **Build hygiene** | `command-run/v0.1` | argv contains `-trimpath` AND `cli.Version=` ldflags injection |
| **Hermeticity** | `command-run/v0.1` | Every traced TCP/TLS connection's SNI hostname is in the allowlist: `vuln.go.dev`, `storage.googleapis.com`. Anything else fails. Build uses `-mod=vendor`, so no proxy.golang.org. |
| **Vendor command** | `command-run/v0.1` (vendor step only) | Vendor step must literally invoke `go mod vendor` — catches a tampered workflow that runs `cp /tmp/poison-vendor cilock/vendor` |
| **No secrets** | `secretscan/v0.1` | gitleaks-scanned product set + every prior envelope; allowlist narrow FP class (Go module pseudo-version SHAs match the sourcegraph-access-token regex) |
| **No reachable vulns** | `govulncheck/v0.1` | govulncheck `summary.reachableCount == 0` AND `summary.bySeverity.{critical,high} == 0` |
| **Artifact identity** | `product/v0.3` (subject digest) | Verifier hashes the binary you pass via `--artifactfile`; if the digest doesn't match a subject in the envelope, no collection is found |
| **Required predicates** | (presence) | SBOM (`spdx.dev/Document`), SLSA v1.0 provenance, Rekor inclusion-proof — release fails if any is missing from the envelope |

### Cross-step chain link

| Check | Asserts |
|---|---|
| **`release-build.artifactsFrom = ["vendor-cilock-deps"]`** | Every material the build step recorded (every vendored file the compiler read) must match a product the vendor step recorded. If a malicious step modified `cilock/vendor/*` between vendor and build, the digests diverge and the policy denies. |

A release that fails any of these gates exits before `cosign sign-blob` runs. No signed artifacts get published.

:::tip Cosign signatures are policy-gated
The release workflow runs the policy verify **before** `cosign sign-blob`. If any platform fails policy, the job exits and no cosign signatures are produced. A cosign signature on a published binary therefore transitively proves the binary passed every Rego layer above.
:::

Plain-text Rego sources are committed alongside the policy at [`deploy/cilock/release-rego-*.txt`](https://github.com/aflock-ai/rookery/tree/main/deploy/cilock) so you can read each module without base64-decoding the policy JSON.

## Source→vendor→build chain {#source-vendor-build-chain}

The release pipeline records evidence at three boundaries, each signed by the same Fulcio identity (this workflow @ this tag) but in **separate envelopes**:

```text
          ┌─────────────────────────────────────────────────────────────┐
          │ GIT COMMIT  (b1d3a97…)                                      │
          │ - tree hash, parent hashes, refs                            │
          │ - signed in both vendor-cilock-deps and release-build       │
          └────────────────────────┬────────────────────────────────────┘
                                   │
                                   ▼
          ┌─────────────────────────────────────────────────────────────┐
          │ STEP: vendor-cilock-deps                                    │
          │ command:  go mod vendor                                     │
          │ products: every file under cilock/vendor/*                  │
          │ signed:   Fulcio keyless, this workflow @ v3.0.0            │
          └────────────────────────┬────────────────────────────────────┘
                                   │
            artifactsFrom enforces this digest chain ↓
                                   │
          ┌─────────────────────────────────────────────────────────────┐
          │ STEP: release-build                                         │
          │ command:  GOFIPS140=v1.0.0 ... go build -mod=vendor ...     │
          │ traced:   ptrace captures network egress (Rego allowlist)   │
          │ materials: every file the compiler read (= vendor products) │
          │ products: cilock-bin-<plat>                                 │
          │ signed:   Fulcio keyless, this workflow @ v3.0.0            │
          └────────────────────────┬────────────────────────────────────┘
                                   │
                                   ▼
          ┌─────────────────────────────────────────────────────────────┐
          │ ARTIFACT  cilock binary (your download)                     │
          │ subject digest in release-build envelope == sha256(binary)  │
          └─────────────────────────────────────────────────────────────┘
```

When you run `cilock verify --bundle <evidence-bundle> --artifactfile <binary>`, CI/lock walks the chain top-down:

1. Verify both envelopes' DSSE signatures against their Fulcio certs (cert constraint + Rekor entry).
2. Verify the policy's signature using `cilock-policy.pub`.
3. Find an envelope for each declared step (`vendor-cilock-deps`, `release-build`).
4. Run each step's Rego layers against its predicates.
5. Check `release-build`'s materials match `vendor-cilock-deps`'s products byte-for-byte.
6. Check the binary's sha256 equals a subject digest in `release-build`'s product attestation.
7. Emit a Verification Summary Attestation (VSA) recording PASSED / FAILED.

A break anywhere in the chain — wrong commit, tampered vendor file, bad build command, runtime env without FIPS, leaked secret in any envelope, reachable CVE — denies the verify.

## What each predicate proves

| Predicate | What it answers |
|---|---|
| `git/v0.1` | "What was the commit hash + branch + tag at the time of build, and was the working tree clean?" |
| `github/v0.1` | "Which GitHub workflow ran this, on which repo, on which trigger, with which OIDC identity?" |
| `command-run/v0.1` | "What was the literal `go build` argv? What was its exit code? **What network endpoints did the build contact** (via `--trace` ptrace capture of every `connect`/`sendto`/`bind` syscall + TLS SNI)?" |
| `product/v0.3` | "What is the SHA-256 of the binary archive CI/lock produced?" |
| `environment/v0.1` | "What OS, kernel, and env vars did the build see?" |
| `sbom/v0.1` | "What dependencies were linked into the binary? (SPDX, byte-identical to the published SBOM)" |

End-to-end, this is the same evidence shape you'd use for verifying *any* artifact under CI/lock — the release pipeline just applies it to CI/lock itself.

## Troubleshooting

| Symptom (in order of likelihood) | What it means | Fix |
|---|---|---|
| `cosign: command not found` | No cosign installed | Install via `brew install cosign` or [the official installer](https://docs.sigstore.dev/cosign/installation). |
| `cosign verify-blob: no matching identities found` | The archive came from somewhere other than the canonical workflow — a tampered mirror, a fork, or the wrong identity-regexp. | Re-download from the [canonical release page](https://github.com/aflock-ai/rookery/releases) and re-check the identity-regexp matches exactly: `^https://github\.com/aflock-ai/rookery/\.github/workflows/release\.yml@.+` |
| `policy verification failed: no passed collections present` | The attestation file doesn't match the artifact (subject digest mismatch). Usually you mixed files from different releases. | Re-download both `cilock-<VERSION>-<OS>-<ARCH>.tar.gz` and `<OS>-<ARCH>.attestation.json` from the **same** release tag. |
| `policy verification failed: ... functionary mismatch` | Fulcio cert in the envelope doesn't match policy's expected `buildConfigURI`. Means the binary was built by a different workflow. | **Halt and investigate.** Could be a release candidate from a non-canonical branch, or a supply-chain compromise. |
| `policy expired` | `release-policy.json` has an `expires` field; the file is past that date. | Download the latest published policy from the most recent release — we rotate when expiry is near. |
| The bundled VSA's `verificationResult` is `FAILED` | The release workflow itself caught a policy failure. | **Treat the release as poisoned.** [Report it on GitHub](https://github.com/aflock-ai/rookery/security/advisories/new). |
| `Verified OK` on the install script but `bash install.sh` exits non-zero | Network issue downloading the archive, or your `$CILOCK_BIN_DIR` isn't writable. | Set `CILOCK_BIN_DIR=$HOME/.local/bin` and re-run; ensure that path is on your `$PATH`. |

## Long-term verifiability via RFC 3161

Sigstore Fulcio issues **10-minute certificates**. That's deliberate — there's no long-lived signing key for an attacker to steal — but it means the cert is expired by the time you (or your auditor) check the signature months or years later. The fix is RFC 3161 timestamping: every CI/lock release DSSE envelope carries a **trusted timestamp** proving the signature existed *while the cert was still valid*.

The release pipeline ships both:

```yaml
# .github/workflows/release.yml
fulcio-url: "https://fulcio.sigstore.dev"
timestamp-servers: "https://timestamp.sigstore.dev/api/v1/timestamp"
```

Two artifacts per signature in the envelope: the Fulcio identity cert (`signedAt + certNotBefore + certNotAfter`) and the RFC 3161 TSA token (signed by Sigstore's TSA over the signature bytes + a timestamp).

When you run `cilock verify`, both checks happen automatically:

1. **Fulcio cert chain validates** against the policy's `certConstraint` (issuer + identity-regexp).
2. **TSA token validates** against the Sigstore TSA's trusted root, AND the TSA's timestamp falls within the cert's `notBefore`/`notAfter` window.

A signature with no TSA token (or a TSA from an untrusted authority) **fails verify** once the Fulcio cert expires. Audit teams that need to re-verify years later get the same answer — the TSA timestamp is the proof that "this signature was valid when made," independent of whether the issuing cert is still alive.

You can extract and inspect the TSA token from any release envelope:

```bash
jq -r '.signatures[0].extension.tsa_response' \
  "${OS}-${ARCH}.attestation.json" | base64 -d | openssl ts -reply -in /dev/stdin -text | head -20
# OID: 1.2.840.113549.1.9.16.1.4 (PKCS7 timestamp)
# Serial: ...
# Time: 2026-05-22 12:34:56 UTC
# Hash Algorithm: sha256
# Message data: <signature bytes>
```

## Verifying via the container image

The release also publishes a signed container image:

```bash
cosign verify ghcr.io/aflock-ai/cilock:v3.0.0 \
  --certificate-identity-regexp '^https://github\.com/aflock-ai/rookery/\.github/workflows/release\.yml@.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

The image's transparency-log entry is in Rekor. `cosign verify` also confirms presence + integrity of the SBOM attached to the image as a cosign attestation.

## Why we ship the policy + VSA, not just signatures

A cosign signature proves "these bytes were signed by this identity." A CI/lock VSA proves "these bytes passed THIS POLICY when this verifier ran it." When you're chaining CI/lock attestations across multiple stages — release-gate → audit → compliance report — every consumer needs the policy-level result, not just the bytes-level signature. The VSA travels with the artifact and is itself a signed DSSE envelope, so downstream verifiers can policy-check the verification result the same way they policy-check anything else.

## See also

- [Release policy source](https://github.com/aflock-ai/rookery/blob/main/deploy/cilock/release.policy.json) — the unsigned policy committed in the repo for reviewer transparency
- [`vsa` attestor](../attestors/vsa) — how CI/lock emits Verification Summary Attestations
- [`policyverify` attestor](../attestors/policyverify) — how CI/lock evaluates DSSE envelopes against a signed policy
- [Verify in a release gate](../guides/verify-in-a-release-gate) — apply the same pattern to your own artifacts
- [Cosign ecosystem page](../ecosystem/cosign) — how CI/lock and cosign relate at the wire-format level

<script type="application/ld+json" dangerouslySetInnerHTML={{__html: JSON.stringify({
  "@context": "https://schema.org",
  "@type": "HowTo",
  "name": "Verify a downloaded cilock binary with cosign and cilock's own release policy",
  "description": "Cilock dogfoods its release pipeline: each binary ships with a cosign signature, a Sigstore Fulcio certificate, a DSSE in-toto attestation of the go build step, a Verification Summary Attestation (VSA), and a signed release policy. Three verification paths of increasing rigor are documented — 30-second cosign-verified install.sh, 3-minute cilock policy verify, full chain with VSA comparison.",
  "tool": [
    {"@type": "HowToTool", "name": "cilock"},
    {"@type": "HowToTool", "name": "cosign"},
    {"@type": "HowToTool", "name": "curl"}
  ],
  "step": [
    {"@type": "HowToStep", "name": "30-second verify (Path 1)", "text": "Download install.sh + .sig + .cert; cosign verify-blob with certificate-identity-regexp pointing at the canonical workflow; if Verified OK, run bash install.sh. install.sh auto-detects OS / arch / latest version and cosign-verifies the binary archive too."},
    {"@type": "HowToStep", "name": "3-minute verify (Path 2)", "text": "After Path 1, run cilock verify --policy release-policy.json --artifactfile <archive> --attestations <env-arch>.attestation.json. Output 'Verification succeeded' means all five Rego layers (source identity, source integrity, build hygiene, hermeticity, artifact identity) plus SBOM presence held."},
    {"@type": "HowToStep", "name": "Full chain (Path 3)", "text": "After Path 2, download <archive>.vsa.json and jq-decode its predicate. Compare verificationResult against your local result; PASSED matching PASSED means you and the publisher agree on the policy outcome at signing time."}
  ]
})}} />
