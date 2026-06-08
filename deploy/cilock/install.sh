#!/usr/bin/env bash
#
# Cilock install script.
#
# cilock release artifacts are built + signed against the TestifySec Platform's
# keyless Fulcio + TSA (NOT public Sigstore) using the release workflow's GitHub
# Actions OIDC identity. The release pipeline's publisher then runs `cilock verify`
# against release-v1.policy.json and uploads ONLY artifacts that pass to
# cilock.dev — so everything this script fetches has already been cryptographically
# verified in a trusted CI context. Trust here is: TLS to cilock.dev (origin
# authenticity) + that verify-then-upload gate, with SHA256 integrity on the
# download.
#
# NOTE: independent CLIENT-SIDE cryptographic verification (cosign against the
# platform Fulcio root, before executing anything) is a deliberate fast-follow.
# Until it lands, verify provenance after install with a cilock you already trust
# (a release-built cilock embeds the platform Fulcio CA root, TSA root, and
# policy-signer identity, so it needs no trust flags):
#
#   curl -fsSLO https://cilock.dev/policy/release-v1.policy.json
#   curl -fsSLO https://cilock.dev/dl/<version>/<os>-<arch>.attestation.json
#   cilock verify "$(command -v cilock)" \
#     --policy release-v1.policy.json --attestations <os>-<arch>.attestation.json
#
# Convenience (curl-pipe-bash):
#
#   curl -fsSL https://cilock.dev/install.sh | bash
#
# Environment variables:
#   CILOCK_VERSION   Version (e.g. v2.0.0) to install. Defaults to the latest
#                    stable from cilock.dev/dl/manifest.json. Pre-releases
#                    (e.g. -rc1) do not move "latest" — install them explicitly.
#   CILOCK_BIN_DIR   Install directory. Defaults to /usr/local/bin if writable,
#                    else $HOME/.local/bin.
#   CILOCK_DIST_BASE Override the distribution origin (default https://cilock.dev).

set -euo pipefail

DIST_BASE="${CILOCK_DIST_BASE:-https://cilock.dev}"

CILOCK_VERSION="${CILOCK_VERSION:-}"
CILOCK_BIN_DIR="${CILOCK_BIN_DIR:-}"

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required (install: $2)"
}

# sha256_check verifies "<expected>  <file>" lines on stdin, portably across
# Linux (sha256sum) and macOS (shasum -a 256).
sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c -
  else
    die "need sha256sum or shasum to verify the download"
  fi
}

# manifest_latest extracts the "latest" stable tag from the manifest JSON on stdin.
# Trailing `|| true`: a no-match grep returns non-zero, which would trip the
# caller's `set -o pipefail`; an empty result is the caller's "not found" signal.
manifest_latest() {
  { grep -oE '"latest"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/'; } || true
}

# manifest_sha extracts the per-file sha256 for $1 (an archive filename) from the
# manifest JSON on stdin. The manifest's files[] entries are
# {"name":"<archive>","sha256":"<hex>",...}; splitting on '}' isolates one object
# per line so we read the sha256 from the SAME object as the matching name.
# Prints the hex digest, or nothing if the manifest doesn't carry it. This is the
# primary integrity source: it's always published with the manifest, unlike the
# aggregate checksums-sha256.txt which isn't present for every version.
manifest_sha() {
  # Trailing `|| true`: when the file has no sha256 entry the inner grep returns
  # non-zero, which would trip the caller's `set -o pipefail` and abort before the
  # checksums-sha256.txt fallback. An empty result is the "not found" signal.
  { tr '}' '\n' \
    | grep -F "\"$1\"" \
    | grep -oE '"sha256"[[:space:]]*:[[:space:]]*"[0-9a-f]+"' \
    | head -1 \
    | sed -E 's/.*"([0-9a-f]+)"$/\1/'; } || true
}

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux|darwin) ;;
    *) die "unsupported OS: $os (supported: linux, darwin)";;
  esac
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch=amd64;;
    arm64|aarch64) arch=arm64;;
    *) die "unsupported arch: $arch (supported: amd64, arm64)";;
  esac
  printf '%s %s\n' "$os" "$arch"
}

# resolve_version returns the version to install: an explicit CILOCK_VERSION, else
# the manifest's "latest" stable. $1 is the already-fetched manifest JSON.
resolve_version() {
  if [ -n "$CILOCK_VERSION" ]; then
    printf '%s\n' "$CILOCK_VERSION"
    return
  fi
  # Latest stable comes from the signed-publish manifest on cilock.dev — no
  # GitHub dependency. Pre-releases do not move "latest"; set CILOCK_VERSION for those.
  local tag
  tag="$(printf '%s' "$1" | manifest_latest)"
  [ -n "$tag" ] || die "could not resolve latest version from ${DIST_BASE}/dl/manifest.json (set CILOCK_VERSION to install a specific or pre-release version)"
  printf '%s\n' "$tag"
}

resolve_bin_dir() {
  if [ -n "$CILOCK_BIN_DIR" ]; then
    printf '%s\n' "$CILOCK_BIN_DIR"
    return
  fi
  if [ -w /usr/local/bin ] || sudo -n true 2>/dev/null; then
    printf '%s\n' "/usr/local/bin"
    return
  fi
  local fallback="${HOME}/.local/bin"
  mkdir -p "$fallback"
  printf '%s\n' "$fallback"
}

main() {
  require curl "https://curl.se"
  require tar "your package manager"

  read -r os arch <<<"$(detect_platform)"

  # Fetch the manifest once — it carries both the "latest" pointer and the
  # per-file sha256 used to verify the download.
  local manifest
  manifest="$(curl -fsSL "${DIST_BASE}/dl/manifest.json")" \
    || die "could not fetch ${DIST_BASE}/dl/manifest.json"

  local version bin_dir version_clean
  version="$(resolve_version "$manifest")"
  version_clean="${version#v}"
  bin_dir="$(resolve_bin_dir)"

  log "installing cilock ${version} for ${os}/${arch} to ${bin_dir}"

  local tmpdir
  tmpdir="$(mktemp -d)"
  # Guard with :- because the EXIT trap fires at script scope, after main()
  # returns and its `local tmpdir` is gone — a bare $tmpdir there is an unbound
  # variable under `set -u`, which made install.sh exit non-zero (looking like a
  # failure) right after a successful install.
  trap 'rm -rf "${tmpdir:-}"' EXIT

  local archive="cilock-${version_clean}-${os}-${arch}.tar.gz"
  # Versioned distribution path on cilock.dev (served from R2; the release
  # publisher only uploads artifacts that passed `cilock verify`). TLS to the
  # origin authenticates the source; SHA256 below covers transfer integrity.
  local base="${DIST_BASE}/dl/${version}"

  log "  downloading ${archive} from ${base}"
  curl -fsSL "${base}/${archive}" -o "${tmpdir}/${archive}"

  # Verify against the manifest's per-file sha256 (always published with the
  # manifest). Only fall back to the aggregate checksums-sha256.txt if the
  # manifest doesn't carry the digest — that file isn't present for every
  # version, and hard-requiring it broke installs of versions that are otherwise
  # complete and verifiable.
  local want_sha
  want_sha="$(printf '%s' "$manifest" | manifest_sha "$archive")"
  if [ -n "$want_sha" ]; then
    log "  verifying SHA256 against the signed manifest"
    printf '%s  %s\n' "$want_sha" "$archive" | (cd "${tmpdir}" && sha256_check) \
      || die "checksum verification failed (manifest sha256 mismatch for ${archive})"
  else
    log "  verifying SHA256 against checksums-sha256.txt"
    curl -fsSL "${base}/checksums-sha256.txt" -o "${tmpdir}/checksums-sha256.txt" \
      || die "no sha256 for ${archive} in the manifest and ${base}/checksums-sha256.txt is missing"
    (cd "${tmpdir}" && grep " ${archive}\$" checksums-sha256.txt | sha256_check) \
      || die "checksum verification failed"
  fi

  log "  extracting"
  tar -xzf "${tmpdir}/${archive}" -C "${tmpdir}"

  log "  installing to ${bin_dir}/cilock"
  if [ -w "$bin_dir" ]; then
    install -m 0755 "${tmpdir}/cilock" "${bin_dir}/cilock"
  else
    sudo install -m 0755 "${tmpdir}/cilock" "${bin_dir}/cilock"
  fi

  log
  log "cilock ${version} installed."
  log "  $ cilock --version"
  log
  log "Verify provenance against the platform-signed release policy (no trust"
  log "flags — platform roots + signer identity are compiled into cilock):"
  log "  curl -fsSLO ${DIST_BASE}/policy/release-v1.policy.json"
  log "  curl -fsSLO ${base}/${os}-${arch}.attestation.json"
  log "  cilock verify ${bin_dir}/cilock \\"
  log "    --policy release-v1.policy.json --attestations ${os}-${arch}.attestation.json"
}

main "$@"
