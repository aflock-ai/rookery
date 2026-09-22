---
id: verify-the-cilock-binary
title: Verify the `cilock` binary
description: Two working verification paths for a downloaded cilock — SHA-256 integrity against the release manifest, and full SLSA provenance verification against the platform-signed release policy using the DSSE envelopes published beside every binary on cilock.dev. macOS and Windows binaries are not OS-signed; Path 2 is how to check them.
sidebar_position: 2
---

# Verify the `cilock` binary

Two verification paths, pick the level of rigor you want. **Path 2 is strictly stronger than Path 1.** Both use only files published on cilock.dev — no GitHub Releases, no platform login.

## 🟢 30-second integrity check (Path 1)

**For most users.** Confirms the bytes you downloaded are the bytes the release pipeline published, using the per-archive SHA-256 sidecar:

```bash
# OS: linux|darwin   ARCH: amd64|arm64
VERSION=v4.1.3
OS=darwin
ARCH=arm64
ARCHIVE="cilock-${VERSION#v}-${OS}-${ARCH}.tar.gz"
BASE="https://cilock.dev/dl/${VERSION}"

curl -fsSLO "${BASE}/${ARCHIVE}"
curl -fsSLO "${BASE}/${ARCHIVE}.sha256"
# The sidecar also lists the release's attestation files, so check only the
# archive's line. Each step below runs only if the one before it passed: a
# missing line or a mismatch stops the recipe before anything is extracted
# or run. Without shasum, use sha256sum --strict -c in its place.
grep " ${ARCHIVE}\$" "${ARCHIVE}.sha256" > "${ARCHIVE}.line" &&
  shasum -a 256 -c "${ARCHIVE}.line" &&
  tar xzf "${ARCHIVE}" cilock && ./cilock version
```

The install script (`curl -fsSL https://cilock.dev/install.sh | bash`) performs the same check automatically, against the SHA-256 recorded for the archive in the release manifest, [`/dl/manifest.json`](https://cilock.dev/dl/manifest.json). Nothing signs the manifest. It arrives over the same TLS connection as the archive, so the installer's check is integrity, like the sidecar's. (The 4.4.0 installer's log line calls the manifest signed. It is not.)

**What this proves:** integrity — the archive was not corrupted or swapped in transit. It does **not** prove who built it; that is Path 2.

:::note A signed installer is a planned fast-follow
An independent, pre-execution cosign verification of `install.sh` itself is planned but **not published yet** — `install.sh.sig`/`install.sh.cert` do not exist today, so any instructions referencing them will fail. Until they ship, Path 1's trust is TLS to cilock.dev plus the release pipeline's verify-then-upload gate; Path 2 removes even that dependency.
:::

## 🔴 Full provenance verify (Path 2)

**For auditors and anyone who wants proof of who built the binary and how.** Every release publishes its evidence beside the binary: the **build** and **source-git** DSSE envelopes and the platform-signed **release policy**. A trusted, release-built `cilock` checks the whole chain fully offline, anchored on the platform trust roots **embedded in the verifier at build time** — nothing fetched below acts as a trust anchor:

```bash
VERSION=4.1.3
PLAT=darwin-arm64
BASE="https://cilock.dev/dl/v${VERSION}"

curl -fsSLO "${BASE}/cilock-${VERSION}-${PLAT}.tar.gz"
curl -fsSLO "${BASE}/cilock-${VERSION}-${PLAT}.build.att.json"
curl -fsSLO "${BASE}/cilock-${VERSION}-${PLAT}.source-git.att.json"
curl -fsSL  "https://cilock.dev/policy/release-policy.json" -o release-policy.json

tar xzf "cilock-${VERSION}-${PLAT}.tar.gz" cilock

# Run the verify with a cilock you ALREADY trust — never ./cilock verifying itself:
TRUSTED_CILOCK=/path/to/a/cilock/you/already/trust   # e.g. a prior install
"$TRUSTED_CILOCK" verify ./cilock \
  --policy release-policy.json \
  --attestations "cilock-${VERSION}-${PLAT}.build.att.json" \
  --attestations "cilock-${VERSION}-${PLAT}.source-git.att.json" \
  --platform-url ""
```

**What this proves:** the policy signature chains to the TestifySec Platform Root CA with a valid RFC 3161 timestamp; the `build` and `source-git` envelopes were signed by the release workflow's keyless identity; and the binary you extracted is the exact subject those envelopes attest.

**Trust note — provenance verification requires a cilock you already trust.** Every input above — binary, policy, envelopes — came from the same origin, and so would the verifier if you ran the fresh download: a compromised origin can ship a `cilock` that simply **reports success**, no consistent evidence required. So running the downloaded binary against these files is at most a *functional smoke check* (it executes, the flags parse) — never an authenticity result. Use a **previously installed, trusted cilock** as the verifier: a release-built cilock embeds the platform Fulcio + TSA roots and the release policy-signer identity (inspect with `cilock version`), so trust anchors in *your* binary and the recipe needs no `--policy-*` trust flags. If your trusted verifier is a stock or source build with no embedded trust, supply `--policy-ca-roots`/`--policy-timestamp-servers` from a channel you trust **independently** of cilock.dev — feeding it the roots published beside the binary hands the download control of its own trust anchors.

The per-version `verification` block in [`/dl/manifest.json`](https://cilock.dev/dl/manifest.json) is the machine-readable index of every file above.

For the fully air-gapped variant of this flow — including verifying with **no network at all** after one download — see [Verify a release offline](./verify-a-release-offline).

## macOS and Windows binaries are not OS-signed

Each Linux binary is published with a `.cosign.bundle`: a keyless signature over the binary from the release workflow's GitHub identity, recorded in the public Sigstore transparency log. (If public Sigstore is unreachable during a release, a Linux binary ships a `.sign.skipped` marker instead.) The macOS and Windows binaries have no equivalent. Each ships a `.sign.skipped` marker instead, a one-line file that begins `unsigned: cilock signing skipped for <os>/<arch>`.

On macOS, neither binary is signed with an Apple Developer ID or notarized. The Apple Silicon binary carries only the ad-hoc signature the Go linker adds, and the Intel binary has no signature at all, so Gatekeeper's assessment (`spctl --assess --type execute`) rejects both. On Windows, `cilock.exe` has no Authenticode signature, so Windows cannot tie it to a publisher.

The release attestations do not depend on OS signing. Every platform publishes its own `build` and `source-git` envelopes, and the release pipeline verifies each binary against the signed release policy before it uploads it. So both checks on this page work on every platform. For Path 1 on Windows, use the PowerShell recipe under [Manual download](./installation#manual-download). For Path 2, extract `cilock.exe` from the zip and pass it as the subject, with the `windows-amd64` envelopes; the verifier can run on any OS, as long as it is a `cilock` you already trust.

**Browser downloads on macOS.** Gatekeeper evaluates files that carry the `com.apple.quarantine` attribute. Browsers set it. `curl` does not, which is why the install script and the `curl` recipes on this page run without a Gatekeeper prompt. If you downloaded the archive in a browser and macOS refuses to open `cilock`, run Path 1 and Path 2 first. Once both pass, clear the attribute:

```bash
xattr -d com.apple.quarantine ./cilock
```

## Troubleshooting

- **`policy signature` / `TSA verify` failures** — you are probably holding the retired `release-v1.policy.json` from an old instruction. The current signed policy is only ever `https://cilock.dev/policy/release-policy.json`.
- **`no attestations satisfied step`** — both envelopes are required: the policy declares a `source-git` step *and* a `build` step.
- **Checksum mismatch in Path 1** — stop; re-download once, and if it persists do not run the binary.
