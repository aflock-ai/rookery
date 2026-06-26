#!/usr/bin/env bash
#
# Smoke test for install.sh — runs the real installer against a local file://
# "distribution" (no network), proving:
#   1. it installs using the manifest's per-file sha256 when the aggregate
#      checksums-sha256.txt is ABSENT (the regression this guards), and
#   2. it refuses to install a tampered archive (sha256 mismatch), and
#   3. it still works via checksums-sha256.txt when the manifest lacks a sha256.
#
# No cilock binary, no network, no secrets — just curl + tar + sha256sum/shasum.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="$HERE/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

VERSION="v9.9.9-test"
VERSION_CLEAN="9.9.9-test"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"; case "$ARCH" in x86_64|amd64) ARCH=amd64;; arm64|aarch64) ARCH=arm64;; esac
ARCHIVE="cilock-${VERSION_CLEAN}-${OS}-${ARCH}.tar.gz"

sha_of() { (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | awk '{print $1}'; }

# A fake "cilock" binary packed into the release tarball.
printf '#!/bin/sh\necho "cilock %s"\n' "$VERSION" > "$work/cilock"
chmod +x "$work/cilock"

build_dist() {
  # $1 = dist dir, $2 = "with-manifest-sha" | "no-manifest-sha"
  local dist="$1" mode="$2"
  rm -rf "$dist"; mkdir -p "$dist/dl/$VERSION"
  tar -C "$work" -czf "$dist/dl/$VERSION/$ARCHIVE" cilock
  local sha; sha="$(sha_of "$dist/dl/$VERSION/$ARCHIVE")"
  if [ "$mode" = "with-manifest-sha" ]; then
    cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"$VERSION","files":[{"name":"$ARCHIVE","sha256":"$sha","os":"$OS","arch":"$ARCH"}]}]}
JSON
    # Deliberately NO checksums-sha256.txt — the manifest must be sufficient.
  elif [ "$mode" = "envelopes-block-first" ]; then
    # Real-manifest shape: an attestation block references the archive via "binary"
    # with a BOGUS sha, ordered BEFORE files[] — a bare-substring lookup reads the
    # bogus digest and rejects the good download. manifest_sha must key on "name".
    local bogus="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"$VERSION","attestations":[{"binary":"$ARCHIVE","os":"$OS","arch":"$ARCH","envelopes":[{"step":"source-git","file":"$VERSION/x.source-git.att.json","sha256":"$bogus"}]}],"files":[{"name":"$ARCHIVE","sha256":"$sha","os":"$OS","arch":"$ARCH"}]}]}
JSON
  else
    cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"$VERSION","files":[{"name":"$ARCHIVE","os":"$OS","arch":"$ARCH"}]}]}
JSON
    printf '%s  %s\n' "$sha" "$ARCHIVE" > "$dist/dl/$VERSION/checksums-sha256.txt"
  fi
}

run_install() { # $1 = dist dir, $2 = bin dir
  CILOCK_DIST_BASE="file://$1" CILOCK_BIN_DIR="$2" bash "$INSTALL_SH"
}

# --- 1. manifest-sha path, no checksums-sha256.txt ---------------------------
dist="$work/dist1"; bin="$work/bin1"; mkdir -p "$bin"
build_dist "$dist" with-manifest-sha
run_install "$dist" "$bin" >/dev/null 2>&1 \
  || { echo "FAIL[1]: install errored on the manifest-sha path"; exit 1; }
[ -x "$bin/cilock" ] || { echo "FAIL[1]: cilock not installed via manifest sha256"; exit 1; }
echo "PASS[1]: installed via manifest sha256 with NO checksums-sha256.txt"

# --- 2. tamper → must be rejected --------------------------------------------
echo "corrupt" >> "$dist/dl/$VERSION/$ARCHIVE"   # invalidate the archive bytes
rm -f "$bin/cilock"
if run_install "$dist" "$bin" >/dev/null 2>&1; then
  echo "FAIL[2]: install succeeded on a tampered archive"; exit 1
fi
[ ! -e "$bin/cilock" ] || { echo "FAIL[2]: cilock installed despite a sha256 mismatch"; exit 1; }
echo "PASS[2]: rejected tampered archive (manifest sha256 mismatch)"

# --- 3. fallback to checksums-sha256.txt when the manifest lacks a sha --------
dist3="$work/dist3"; bin3="$work/bin3"; mkdir -p "$bin3"
build_dist "$dist3" no-manifest-sha
run_install "$dist3" "$bin3" >/dev/null 2>&1 \
  || { echo "FAIL[3]: install errored on the checksums-sha256.txt fallback"; exit 1; }
[ -x "$bin3/cilock" ] || { echo "FAIL[3]: cilock not installed via the checksums fallback"; exit 1; }
echo "PASS[3]: installed via checksums-sha256.txt fallback (manifest had no sha256)"

# --- 4. archive sha must come from files[] "name", not an envelope "binary" ---
dist4="$work/dist4"; bin4="$work/bin4"; mkdir -p "$bin4"
build_dist "$dist4" envelopes-block-first
run_install "$dist4" "$bin4" >/dev/null 2>&1 \
  || { echo "FAIL[4]: install read the wrong sha256 from the envelope-mapping block"; exit 1; }
[ -x "$bin4/cilock" ] || { echo "FAIL[4]: cilock not installed when an envelope block precedes files[]"; exit 1; }
echo "PASS[4]: read the archive sha256 from files[] name, ignoring the envelope block"

echo "ALL PASS"
