#!/usr/bin/env bash
#
# Cilock install script.
#
# Recommended (verifies the install script itself before running anything):
#
#   curl -fsSL https://cilock.aflock.ai/install.sh -o /tmp/install.sh
#   curl -fsSL https://cilock.aflock.ai/install.sh.sig -o /tmp/install.sh.sig
#   curl -fsSL https://cilock.aflock.ai/install.sh.cert -o /tmp/install.sh.cert
#   cosign verify-blob \
#     --certificate /tmp/install.sh.cert \
#     --signature /tmp/install.sh.sig \
#     --certificate-identity-regexp '^https://github\.com/aflock-ai/rookery/\.github/workflows/release\.yml@.+' \
#     --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
#     /tmp/install.sh
#   bash /tmp/install.sh
#
# Convenience (curl-pipe-bash):
#
#   curl -fsSL https://cilock.aflock.ai/install.sh | bash
#
# Environment variables:
#   CILOCK_VERSION  Tag (v1.0.0) or digest (sha256:abc...). Defaults to latest.
#   CILOCK_BIN_DIR  Install directory. Defaults to /usr/local/bin if writable,
#                   else $HOME/.local/bin.
#   CILOCK_VERIFY   "1" (default) to verify cosign signature before installing.
#                   "0" to skip (not recommended).

set -euo pipefail

REPO="aflock-ai/rookery"
DOCS_BASE="https://cilock.aflock.ai"
WORKFLOW_REGEX='^https://github\.com/aflock-ai/rookery/\.github/workflows/release\.yml@.+'
OIDC_ISSUER='https://token.actions.githubusercontent.com'

CILOCK_VERSION="${CILOCK_VERSION:-}"
CILOCK_BIN_DIR="${CILOCK_BIN_DIR:-}"
CILOCK_VERIFY="${CILOCK_VERIFY:-1}"

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required (install: $2)"
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

resolve_version() {
  if [ -n "$CILOCK_VERSION" ]; then
    printf '%s\n' "$CILOCK_VERSION"
    return
  fi
  require curl "https://curl.se"
  local tag
  tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -oE '"tag_name": *"[^"]+"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
  [ -n "$tag" ] || die "could not resolve latest release tag from GitHub"
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
  local version bin_dir
  version="$(resolve_version)"
  version_clean="${version#v}"
  bin_dir="$(resolve_bin_dir)"

  log "installing cilock ${version} for ${os}/${arch} to ${bin_dir}"

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  local archive="cilock-${version_clean}-${os}-${arch}.tar.gz"
  local base="https://github.com/${REPO}/releases/download/${version}"

  log "  downloading ${archive}"
  curl -fsSL "${base}/${archive}" -o "${tmpdir}/${archive}"
  curl -fsSL "${base}/${archive}.sig" -o "${tmpdir}/${archive}.sig"
  curl -fsSL "${base}/${archive}.pem" -o "${tmpdir}/${archive}.pem"
  curl -fsSL "${base}/checksums-sha256.txt" -o "${tmpdir}/checksums-sha256.txt"

  log "  verifying SHA256 against checksums-sha256.txt"
  (cd "${tmpdir}" && grep " ${archive}\$" checksums-sha256.txt | sha256sum -c -) \
    || die "checksum verification failed"

  if [ "${CILOCK_VERIFY}" = "1" ]; then
    if command -v cosign >/dev/null 2>&1; then
      log "  verifying cosign keyless signature (release workflow OIDC identity)"
      cosign verify-blob \
        --certificate "${tmpdir}/${archive}.pem" \
        --signature "${tmpdir}/${archive}.sig" \
        --certificate-identity-regexp "${WORKFLOW_REGEX}" \
        --certificate-oidc-issuer "${OIDC_ISSUER}" \
        "${tmpdir}/${archive}" >/dev/null \
        || die "cosign verification failed — refusing to install an unverified binary"
    else
      log "  cosign not found; skipping signature verification."
      log "  install cosign to enable end-to-end verification: https://docs.sigstore.dev/cosign/installation/"
      log "  (re-run with CILOCK_VERIFY=0 to suppress this warning explicitly)"
    fi
  else
    log "  CILOCK_VERIFY=0 — skipping signature check (not recommended)."
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
  log "Verify the install with cilock itself:"
  log "  cilock verify \\"
  log "    --policy ${DOCS_BASE}/policy/release-v1.policy.json \\"
  log "    ${bin_dir}/cilock"
}

main "$@"
