#!/bin/sh
#
# Cilock install script.
#
# cilock release artifacts are built + signed against the TestifySec Platform's
# keyless Fulcio + TSA (NOT public Sigstore) using the release workflow's GitHub
# Actions OIDC identity. The release pipeline's publisher then runs `cilock verify`
# against release-policy.json and uploads ONLY artifacts that pass to
# cilock.dev — so everything this script fetches has already been cryptographically
# verified in a trusted CI context. Trust here is: TLS to cilock.dev (origin
# authenticity) + that verify-then-upload gate, with SHA256 integrity on the
# download.
#
# NOTE: independent CLIENT-SIDE cryptographic verification (cosign against the
# platform Fulcio root, before executing anything) is a deliberate fast-follow.
# Until it lands, verify provenance after install with a cilock you already
# trust (a prior install or a second channel) — a release-built cilock embeds
# the platform Fulcio CA root, TSA root, and policy-signer identity, so it
# needs no trust flags. The verifier must be a DIFFERENT binary from the one
# just installed: after this script runs, `cilock` on PATH resolves to the new
# install, and a compromised binary verifying itself simply reports success —
# that is at most a functional smoke check, never provenance. With
# TRUSTED_CILOCK pointing at a cilock obtained BEFORE this install:
#
#   TRUSTED_CILOCK=/path/to/a/cilock/you/already/trust   # not the one just installed
#   curl -fsSLO https://cilock.dev/policy/release-policy.json
#   curl -fsSLO https://cilock.dev/dl/<version>/cilock-<ver>-<os>-<arch>.build.att.json
#   curl -fsSLO https://cilock.dev/dl/<version>/cilock-<ver>-<os>-<arch>.source-git.att.json
#   "$TRUSTED_CILOCK" verify "$(command -v cilock)" --policy release-policy.json \
#     --attestations <build.att.json> --attestations <source-git.att.json> \
#     -s sha1:<full 40-hex release commit> --platform-url ""
#
# cilock 4.5.0 and later verify source checks from the commit, so the command
# seeds the release's full commit next to the binary. cilock.dev/dl/manifest.json
# records it as the version's "commit" (`cilock version` prints only 8
# characters), and this script prints the command with it filled in.
#
# Convenience (curl-pipe-sh). The script is POSIX sh, so the host's own `sh`
# runs it (dash on Debian/Ubuntu, busybox ash on Alpine, bash on macOS), and
# `| bash` works too:
#
#   curl -fsSL https://cilock.dev/install.sh | sh
#
# Environment variables:
#   CILOCK_VERSION   Version (e.g. v2.0.0) to install. Defaults to the latest
#                    stable from cilock.dev/dl/manifest.json. Pre-releases
#                    (e.g. -rc1) do not move "latest" — install them explicitly.
#   CILOCK_BIN_DIR   Install directory. Defaults to /usr/local/bin if writable,
#                    else $HOME/.local/bin.
#   CILOCK_DIST_BASE Override the distribution origin (default https://cilock.dev).

# POSIX sh only: under `curl ... | sh` the shebang above is never read.
# install_test.sh enforces it with `shellcheck -s sh` and by piping this file
# into bash, sh and dash. No pipefail (dash 0.5.12, as Debian 12 and Ubuntu
# 24.04 ship it, rejects the option and runs nothing) and none is needed: no
# decision below rests on the exit status of a pipeline's EARLY stage. Every
# value a pipeline produces is validated where it is used (the platform by
# `case`, the version by -n, each sha256 by is_sha256), so an early stage that
# fails yields an empty or partial value, and that refuses.
set -eu

DIST_BASE="${CILOCK_DIST_BASE:-https://cilock.dev}"

CILOCK_VERSION="${CILOCK_VERSION:-}"
CILOCK_BIN_DIR="${CILOCK_BIN_DIR:-}"

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required (install: $2)"
}

# sha256_file prints the SHA-256 of file $1 as bare hex, portably across Linux
# (sha256sum) and macOS (its own sha256sum where it ships one, else shasum -a
# 256). The file goes in on stdin so the output is "<hex>  -" whatever its path
# looks like. The caller compares the digest itself, never via `sha256sum -c`:
# macOS's BSD sha256sum -c exits 0 on empty input and on an "improperly
# formatted" line, so an absent or truncated expected digest would verify
# nothing and still pass.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sum="$(sha256sum <"$1")" || return 1
  elif command -v shasum >/dev/null 2>&1; then
    sum="$(shasum -a 256 <"$1")" || return 1
  else
    die "need sha256sum or shasum to verify the download"
  fi
  printf '%s\n' "${sum%% *}"
}

# is_sha256 succeeds only for exactly one digest of 64 lowercase hex digits.
is_sha256() {
  case "$1" in
    *[!0123456789abcdef]*) return 1;;
  esac
  [ "${#1}" -eq 64 ]
}

# manifest_latest extracts the "latest" stable tag from the manifest JSON on stdin.
# An empty result is the caller's "not found" signal.
manifest_latest() {
  { grep -oE '"latest"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/'; } || true
}

# manifest_sha prints the per-file sha256 for archive $1 from the manifest JSON on
# stdin — the primary integrity source (checksums-sha256.txt isn't published every
# version). Split on '}' for one object per line, then match the "name":"<archive>"
# KEY, not a bare "<archive>" substring: the manifest also references the archive via
# "binary" in its attestation block, so a substring match could read that envelope's
# sha256 instead. A no-match grep must yield empty (the "not found" signal that
# selects the checksums fallback), never a failed status.
manifest_sha() {
  { tr '}' '\n' \
    | grep -F "\"name\":\"$1\"," \
    | grep -oE '"sha256"[[:space:]]*:[[:space:]]*"[0-9a-f]+"' \
    | head -n 1 \
    | sed -E 's/.*"([0-9a-f]+)"$/\1/'; } || true
}

# is_commit succeeds only for exactly one full git commit id: 40 lowercase hex.
is_commit() {
  case "$1" in
    *[!0123456789abcdef]*) return 1;;
  esac
  [ "${#1}" -eq 40 ]
}

# manifest_commit prints the full source commit that version $1's manifest entry
# records as "commit". Splitting on '{' leaves each version object's own scalar
# fields on one line that starts with its "version" key (the publisher writes
# "commit" before "files"), so the match cannot read another version's commit.
# An absent or duplicated entry yields empty or several lines, which is_commit
# refuses.
manifest_commit() {
  { tr '{' '\n' \
    | MANIFEST_VERSION="$1" awk 'index($0, "\"version\":\"" ENVIRON["MANIFEST_VERSION"] "\",") == 1' \
    | grep -oE '"commit":"[0-9a-f]{40}"' \
    | sed 's/.*:"\([0-9a-f]*\)"$/\1/'; } || true
}

# checksums_sha prints the sha256 that the sha256sum-format file on stdin lists
# for exactly the file name $1 ("<hex>  <name>", or "<hex> *<name>"), one line
# per listing, so a missing or duplicated listing fails is_sha256.
checksums_sha() {
  CHECKSUMS_NAME="$1" awk '$2 == ENVIRON["CHECKSUMS_NAME"] || $2 == ("*" ENVIRON["CHECKSUMS_NAME"]) { print $1 }'
}

detect_platform() {
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
  # Latest stable comes from the release manifest on cilock.dev (fetched over
  # TLS; nothing signs it), so there is no GitHub dependency. Pre-releases do
  # not move "latest"; set CILOCK_VERSION for those.
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
  fallback="${HOME}/.local/bin"
  mkdir -p "$fallback"
  printf '%s\n' "$fallback"
}

main() {
  require curl "https://curl.se"
  require tar "your package manager"

  # A plain assignment carries the command substitution's status, so a `die`
  # inside detect_platform stops the script here under `set -e`.
  platform="$(detect_platform)"
  os="${platform% *}"
  arch="${platform#* }"

  # Fetch the manifest once — it carries both the "latest" pointer and the
  # per-file sha256 used to verify the download.
  manifest="$(curl -fsSL "${DIST_BASE}/dl/manifest.json")" \
    || die "could not fetch ${DIST_BASE}/dl/manifest.json"

  version="$(resolve_version "$manifest")"
  version_clean="${version#v}"
  bin_dir="$(resolve_bin_dir)"

  log "installing cilock ${version} for ${os}/${arch} to ${bin_dir}"

  tmpdir="$(mktemp -d)"
  # The EXIT trap fires at script scope, after main() returns. tmpdir is a
  # global (POSIX sh has no `local`), so the trap still sees it and removes the
  # staging directory on success as well as on failure. Declared `local`, it
  # was gone by then and every successful install left the directory behind.
  trap 'rm -rf "${tmpdir:-}"' EXIT

  archive="cilock-${version_clean}-${os}-${arch}.tar.gz"
  # Versioned distribution path on cilock.dev (served from R2; the release
  # publisher only uploads artifacts that passed `cilock verify`). TLS to the
  # origin authenticates the source; SHA256 below covers transfer integrity.
  base="${DIST_BASE}/dl/${version}"

  log "  downloading ${archive} from ${base}"
  curl -fsSL "${base}/${archive}" -o "${tmpdir}/${archive}"

  # Verify against the manifest's per-file sha256 (always published with the
  # manifest). Only fall back to the aggregate checksums-sha256.txt if the
  # manifest doesn't carry the digest — that file isn't present for every
  # version, and hard-requiring it broke installs of versions that are otherwise
  # complete and verifiable.
  want_sha="$(printf '%s' "$manifest" | manifest_sha "$archive")"
  if [ -n "$want_sha" ]; then
    log "  verifying SHA256 against the release manifest"
  else
    log "  verifying SHA256 against checksums-sha256.txt"
    curl -fsSL "${base}/checksums-sha256.txt" -o "${tmpdir}/checksums-sha256.txt" \
      || die "no sha256 for ${archive} in the manifest and ${base}/checksums-sha256.txt is missing"
    want_sha="$(checksums_sha "$archive" <"${tmpdir}/checksums-sha256.txt")"
    [ -n "$want_sha" ] || die "no sha256 for ${archive} in the manifest or in ${base}/checksums-sha256.txt"
  fi
  is_sha256 "$want_sha" \
    || die "checksum verification failed (the published sha256 for ${archive} is not exactly one 64-hex-digit digest)"
  got_sha="$(sha256_file "${tmpdir}/${archive}")" \
    || die "checksum verification failed (could not hash ${archive})"
  [ "$got_sha" = "$want_sha" ] \
    || die "checksum verification failed (${archive}: expected sha256 ${want_sha}, got ${got_sha})"

  log "  extracting"
  tar -xzf "${tmpdir}/${archive}" -C "${tmpdir}"

  log "  installing to ${bin_dir}/cilock"
  if [ -w "$bin_dir" ]; then
    install -m 0755 "${tmpdir}/cilock" "${bin_dir}/cilock"
  else
    sudo install -m 0755 "${tmpdir}/cilock" "${bin_dir}/cilock"
  fi

  commit="$(printf '%s' "$manifest" | manifest_commit "$version")"
  if is_commit "$commit"; then
    seed="$commit"
  else
    seed="<full 40-hex commit of ${version}>"
  fi

  log
  log "cilock ${version} installed."
  log "  $ cilock version"
  log
  log "Verify provenance with an INDEPENDENTLY TRUSTED cilock — a DIFFERENT"
  log "binary from the one just installed. 'cilock' on PATH now resolves to"
  log "${bin_dir}/cilock, and a compromised binary verifying itself simply"
  log "reports success. Point TRUSTED_CILOCK at a prior install or a build"
  log "from a second channel (its embedded platform roots need no trust flags):"
  log "  TRUSTED_CILOCK=/path/to/a/cilock/you/already/trust  # not ${bin_dir}/cilock"
  log "  curl -fsSLO ${DIST_BASE}/policy/release-policy.json"
  log "  curl -fsSLO ${base}/cilock-${version_clean}-${os}-${arch}.build.att.json"
  log "  curl -fsSLO ${base}/cilock-${version_clean}-${os}-${arch}.source-git.att.json"
  log "cilock 4.5.0 and later verify source checks from the commit, so the command"
  if is_commit "$commit"; then
    log "seeds ${version}'s full commit, as the release manifest records it:"
  else
    log "seeds the release commit; ${version}'s manifest entry records none, so fill it in:"
  fi
  log "  \"\${TRUSTED_CILOCK}\" verify ${bin_dir}/cilock \\"
  log "    --policy release-policy.json \\"
  log "    --attestations cilock-${version_clean}-${os}-${arch}.build.att.json \\"
  log "    --attestations cilock-${version_clean}-${os}-${arch}.source-git.att.json \\"
  log "    -s sha1:${seed} \\"
  log "    --platform-url \"\""
}

main "$@"
