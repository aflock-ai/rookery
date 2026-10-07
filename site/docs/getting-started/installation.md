---
title: Installation
sidebar_position: 1
---

# Installation

There are five supported ways to get CI/lock running.

## 1. Homebrew (macOS / Linux)

The friendliest path for dev and CI machines. The tap is public:

```bash
brew install aflock-ai/tap/cilock
```

Or tap once, then install (and reuse the short name for upgrades):

```bash
brew tap aflock-ai/tap
brew install cilock
```

Upgrade to the latest release:

```bash
brew upgrade cilock
```

Covers macOS (Intel + Apple Silicon) and Linux (x86_64 + arm64); Homebrew pins each download by SHA-256, and the tap formula is auto-bumped by the release pipeline.

For cryptographic provenance verification of the binary, see [Verify the `cilock` binary](./verify-the-cilock-binary).

## 2. Prebuilt binary

Binaries are distributed from **[cilock.dev](https://cilock.dev)** — every download is served (and counted) from our own infrastructure, and each artifact is uploaded only after the release pipeline verifies it against the signed release policy (verify-then-upload). Static binaries are published for:

| OS | Architectures |
|---|---|
| Linux | amd64, arm64 |
| macOS (Darwin) | amd64, arm64 |
| Windows | amd64 (a `.zip` holding `cilock.exe`) |

The Windows build has no `omnitrail` attestor (it is not supported on Windows) and no `--trace` backend.

Every binary is covered by the signed `build` and `source-git` attestations published beside it. OS code signing differs by platform. Linux binaries also carry a keyless Sigstore signature (`.cosign.bundle`). The macOS binaries are not signed with an Apple Developer ID or notarized, and the Windows binary has no Authenticode signature; [Verify the `cilock` binary](./verify-the-cilock-binary#macos-and-windows-binaries-are-not-os-signed) shows how to check them.

:::info Default binary signer set
The prebuilt `cilock` binary includes **`file`** and **`fulcio`** (keyless). That's it for the default release — two signers covering the two real production use cases: a private key file you own, or a keyless ephemeral identity certificate issued by the **TestifySec platform's Fulcio** from your CI's OIDC token. The cloud-broker signers (`kms/aws`, `kms/gcp`, `kms/azure`, `spiffe`, `vault`, `vault-transit`) and the test-only `debug-signer` are **not** in the default — they're opt-in via [`rookery-builder`](../guides/build-a-custom-cilock).

This is deliberate. The release binary is the one users verify; shipping debug helpers or cloud-broker clients in it would mean more code to trust and more code to verify, for use cases the default user doesn't need. Same CI/lock, smaller attack surface. The default binary still ships every attestor.
:::

### Quick install

```bash
curl -fsSL https://cilock.dev/install.sh | bash
```

The script runs on Linux and macOS; on Windows, use the [manual download](#manual-download). It auto-detects your OS/arch, resolves the latest stable version from `cilock.dev/dl/manifest.json`, downloads the matching archive, and verifies its SHA-256 against the manifest's per-file digest (falling back to the published `checksums-sha256.txt`) before installing. Nothing signs the manifest: it arrives over the same TLS connection as the archive, so this is an integrity check, not a provenance check. Knobs:

| Variable | Default | Purpose |
|---|---|---|
| `CILOCK_VERSION` | latest stable | Pin a version, e.g. `v4.4.0`. Required for pre-releases — they don't move `latest`. |
| `CILOCK_BIN_DIR` | `/usr/local/bin` if writable, else `$HOME/.local/bin` | Install directory. |
| `CILOCK_DIST_BASE` | `https://cilock.dev` | Override the distribution origin. |

### Manual download

Each release publishes, under `https://cilock.dev/dl/<version>/`:

| Family | Files | What it's for |
|---|---|---|
| **Binary** | `cilock-<version>-<os>-<arch>.tar.gz` (Windows: `.zip`) | The compressed binary archive. |
| **Checksum** | `cilock-<version>-<os>-<arch>.tar.gz.sha256` (Windows: `.zip.sha256`) | Per-archive SHA-256 sidecar (the same digest the release manifest, `/dl/manifest.json`, records; neither is signed). |
| **Per-platform attestations** | `cilock-<version>-<os>-<arch>.build.att.json` + `.source-git.att.json` | The build and source-git steps' signed DSSE envelopes — the inputs to `cilock verify`. |
| **OS signing** | `.cosign.bundle` + `.sign.att.json` (Linux), or `.sign.skipped` (macOS, Windows) | Linux: a keyless Sigstore signature over the binary, plus the attested `sign` step that made it. macOS and Windows: a marker saying the binary shipped without OS code signing. |
| **VSA** | `cilock-<version>-<os>-<arch>.vsa.json` | Verification Summary Attestation — the verify result the release pipeline itself computed. |
| **Trust roots** | `fulcio-roots.pem` + `tsa-chain.pem` | The platform Fulcio CA and RFC 3161 TSA chains, for fully offline verification. |
| **Signed policy** | `release-policy.json` (at `https://cilock.dev/policy/`) | The DSSE-signed release policy, anchored to the **TestifySec Platform Root CA** and the release workflow identity. |

```bash
# OS: linux|darwin   ARCH: amd64|arm64
VERSION=v4.4.0
OS=linux
ARCH=amd64
ARCHIVE="cilock-${VERSION#v}-${OS}-${ARCH}.tar.gz"
BASE="https://cilock.dev/dl/${VERSION}"

curl -fsSLO "${BASE}/${ARCHIVE}"
curl -fsSLO "${BASE}/${ARCHIVE}.sha256"

# Integrity: the bytes match the published checksum. The sidecar also lists
# the release's attestation files, so check only the archive's line. Each step
# below runs only if the one before it passed: a missing line or a mismatch
# stops the recipe before anything is extracted or run. Without shasum, use
# sha256sum --strict -c in its place.
grep " ${ARCHIVE}\$" "${ARCHIVE}.sha256" > "${ARCHIVE}.line" &&
  shasum -a 256 -c "${ARCHIVE}.line" &&
  tar xzf "${ARCHIVE}" cilock && chmod +x cilock && ./cilock version
```

:::tip macOS / Apple Silicon
Use `OS=darwin` and `ARCH=arm64` on Apple Silicon (M1 and later), or `ARCH=amd64` on Intel Macs. Running a Linux binary on macOS fails with `zsh: exec format error`.
:::

:::tip Windows
Windows ships as a `.zip` holding `cilock.exe`, and the install script does not cover it. In PowerShell:

```powershell
& {
  $ErrorActionPreference = 'Stop'
  $VERSION = "4.5.0"
  $ARCHIVE = "cilock-$VERSION-windows-amd64.zip"
  $BASE = "https://cilock.dev/dl/v$VERSION"
  Invoke-WebRequest "$BASE/$ARCHIVE" -OutFile $ARCHIVE -UseBasicParsing
  Invoke-WebRequest "$BASE/$ARCHIVE.sha256" -OutFile "$ARCHIVE.sha256" -UseBasicParsing
  # Refuse unless the archive matches its own line in the sidecar
  $line = @(Get-Content "$ARCHIVE.sha256" | Where-Object { $_.EndsWith("  $ARCHIVE") })
  if ($line.Count -ne 1) { throw "$ARCHIVE.sha256 has no single line for ${ARCHIVE}; do not run it" }
  if ((Get-FileHash $ARCHIVE -Algorithm SHA256).Hash -ne $line[0].Split(" ")[0]) { throw "SHA-256 mismatch for ${ARCHIVE}; do not run it" }
  # Extract into a directory this run creates, so the cilock.exe that runs is the one just checked
  $DEST = "cilock-$VERSION"
  New-Item -ItemType Directory $DEST | Out-Null
  Expand-Archive $ARCHIVE -DestinationPath $DEST -ErrorAction Stop
  & (Join-Path $DEST "cilock.exe") version
}
```

The recipe is one block, so the first failure stops all of it. A pasted line-by-line recipe would carry on past a failed checksum, and `Expand-Archive` does not overwrite a `cilock.exe` that is already there. If a `cilock-4.5.0` directory is left from an earlier run, the recipe refuses to reuse it; delete it and run the recipe again.

`cilock.exe` has no Authenticode signature. Path 2 of [Verify the `cilock` binary](./verify-the-cilock-binary#macos-and-windows-binaries-are-not-os-signed) checks its provenance.
:::

The SHA-256 check proves the bytes match the published checksums. To **cryptographically verify** the binary against the TestifySec platform signing identity — flagless `cilock verify` against the signed release policy + the per-platform attestation — see [Verify the `cilock` binary](./verify-the-cilock-binary).

## 3. GitHub Action

For GitHub Actions workflows, use the [`aflock-ai/cilock-action`](https://github.com/aflock-ai/cilock-action) Action. It downloads its own variant binary at runtime (containing every attestor — including `secretscan`, `govulncheck`, `slsa`, `inclusion-proof`, the trace-enabled product attestor) and wraps your commands.

```yaml
permissions:
  id-token: write   # required for keyless OIDC signing (Sigstore default)
  contents: read

steps:
  - uses: aflock-ai/cilock-action@v1.0.4   # example tag; use a reviewed full commit SHA for an immutable reference
    with:
      step: build
      command: "go build -o myapp ./cmd/myapp"
      attestations: environment git github product sbom secretscan govulncheck slsa
      enable-sigstore: "true"
      hashes: "sha256"
      trace: "true"      # ptrace network egress + file ops; required by hermetic Rego gates
```

`attestations` defaults to `environment git github` when omitted. The example uses a version tag, which can move. For an immutable action reference, review and pin the full 40-character commit SHA. An exact version tag is not equivalent to a SHA pin. See [GitHub's guidance](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions).

**Dogfood pattern:** CI/lock's own release pipeline uses this Action twice per platform — once to attest `go mod vendor` (step name `vendor-cilock-deps`), once to attest `go build -mod=vendor` (step name `release-build`). The policy declares `release-build.artifactsFrom = ["vendor-cilock-deps"]`, so the build's materials are checked digest-for-digest against the vendor's products. You can apply the same source→vendor→build chain pattern to your own releases — see [`.github/workflows/release.yml`](https://github.com/aflock-ai/rookery/blob/main/.github/workflows/release.yml) for the canonical example.

For a real five-step pipeline (lint, SAST, test, build+SBOM, docker build), see [`testifysec/dropbox-clone/.github/workflows/cilock-action-oidc.yaml`](https://github.com/testifysec/dropbox-clone/blob/main/.github/workflows/cilock-action-oidc.yaml). See the [GitHub Action reference](../reference/github-action) for the full input list.

## 4. GitLab CI template

For GitLab CI, include the reusable template:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/aflock-ai/cilock-action/v1/gitlab/cilock.gitlab-ci.yml'

build:
  extends: .cilock
  variables:
    CILOCK_STEP: build
    CILOCK_COMMAND: "go build -o myapp ./cmd/myapp"
```

See the [GitLab component reference](../reference/gitlab-component) for the full variable list.

<span id="4-build-from-source" />
<span id="5-build-from-source" />

<span id="build-from-source"></span>

## 5. Build from source

The `cilock` binary lives in the [rookery monorepo](../ecosystem/rookery) at `cilock/cmd/cilock/main.go`. You'll need [Go 1.26+](https://go.dev/dl/).

```bash
git clone https://github.com/aflock-ai/rookery
cd rookery/cilock
GOWORK=off CGO_ENABLED=0 go build -trimpath -o cilock ./cmd/cilock/
./cilock version
```

`GOWORK=off` is required because the default Go workspace is set up for monorepo development; `CGO_ENABLED=0` produces a static binary matching the released artifacts.

This rebuilds the **default** binary (file + fulcio signers, every attestor). To compose a binary with a different plugin set, use the [`rookery-builder`](../guides/build-a-custom-cilock) — it generates a real CI/lock with whatever attestors and signers you specify. The release pipeline (`.github/workflows/release.yml`) is the canonical template for a full multi-arch signed release build.

## Verifying your install

Whichever path you pick, sanity-check with:

```bash
cilock version
cilock attestors list
```

The `attestors list` output shows every attestor compiled into the binary, plus markers for which are always-run (`material`, `product`, `command-run`) and which are enabled by default. See [Getting Started](./first-attestation) to actually run it.
