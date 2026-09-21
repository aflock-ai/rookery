#!/usr/bin/env bash
#
# Smoke test for install.sh: runs the real installer against a local file://
# "distribution" (no network).
#
# The documented invocation is `curl -fsSL https://cilock.dev/install.sh | sh`,
# so the shebang is never read and the script runs under whatever `sh` the host
# has: dash on Debian/Ubuntu, busybox ash on Alpine, bash on macOS/Fedora. So
#   0. `shellcheck -s sh` must find no construct outside POSIX sh, and
# every case below feeds the script on STDIN, through a pipe, to each shell in
# INSTALL_TEST_SHELLS (default "bash sh dash"). A listed shell that is not on
# PATH FAILS the run; it is never skipped. Per shell, the installer must:
#   1. install using the manifest's per-file sha256 when the aggregate
#      checksums-sha256.txt is ABSENT, and say it checked against the release
#      manifest (nothing signs that manifest);
#   2. refuse a tampered archive (sha256 mismatch);
#   3. still install via checksums-sha256.txt when the manifest lacks a sha256;
#   4. read the archive sha256 from files[] "name", not an envelope "binary";
#   5. refuse when checksums-sha256.txt has no line for the archive (with no
#      pipefail, and a BSD `sha256sum -c` that exits 0 on empty input, nothing
#      else stops this);
#   6. refuse a manifest sha256 that is not 64 hex digits (BSD `sha256sum -c`
#      exits 0 on an "improperly formatted" line);
# and, in every case, pass or fail, remove its staging directory.
#
# No cilock binary, no network, no secrets: curl, tar, sha256sum/shasum, dash
# and shellcheck.
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

failed=0
pass() { echo "PASS[$1]: $2"; }
fail() { # $1 = case label, $2 = reason; prints the installer's stderr from the last run
  echo "FAIL[$1]: $2"
  if [ -s "$work/err" ]; then sed 's/^/    | /' "$work/err"; fi
  failed=$((failed + 1))
}

# A fake "cilock" binary packed into the release tarball.
printf '#!/bin/sh\necho "cilock %s"\n' "$VERSION" > "$work/cilock"
chmod +x "$work/cilock"

# macOS `mktemp -d` ignores TMPDIR, so a shim pins the installer's staging
# parent to a directory this harness can inspect afterwards.
real_mktemp="$(command -v mktemp)"
mkdir -p "$work/shim"
# shellcheck disable=SC2016 # $INSTALL_TEST_STAGE expands when the shim runs, not here
printf '#!/bin/sh\nexec "%s" -d "$INSTALL_TEST_STAGE/tmp.XXXXXX"\n' "$real_mktemp" > "$work/shim/mktemp"
chmod +x "$work/shim/mktemp"

build_dist() {
  # $1 = dist dir, $2 = with-manifest-sha | envelopes-block-first | no-manifest-sha
  #                     | checksums-missing-line | manifest-bad-sha
  local dist="$1" mode="$2"
  rm -rf "$dist"; mkdir -p "$dist/dl/$VERSION"
  tar -C "$work" -czf "$dist/dl/$VERSION/$ARCHIVE" cilock
  local sha; sha="$(sha_of "$dist/dl/$VERSION/$ARCHIVE")"
  case "$mode" in
    with-manifest-sha)
      # Deliberately NO checksums-sha256.txt; the manifest must be sufficient.
      cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"$VERSION","files":[{"name":"$ARCHIVE","sha256":"$sha","os":"$OS","arch":"$ARCH"}]}]}
JSON
      ;;
    envelopes-block-first)
      # Real-manifest shape: an attestation block references the archive via "binary"
      # with a BOGUS sha, ordered BEFORE files[], so a bare-substring lookup reads the
      # bogus digest and rejects the good download. manifest_sha must key on "name".
      local bogus="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"$VERSION","attestations":[{"binary":"$ARCHIVE","os":"$OS","arch":"$ARCH","envelopes":[{"step":"source-git","file":"$VERSION/x.source-git.att.json","sha256":"$bogus"}]}],"files":[{"name":"$ARCHIVE","sha256":"$sha","os":"$OS","arch":"$ARCH"}]}]}
JSON
      ;;
    manifest-bad-sha)
      # Hex, but not a SHA-256: a truncated digest must refuse, never verify.
      cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"$VERSION","files":[{"name":"$ARCHIVE","sha256":"${sha%????????}","os":"$OS","arch":"$ARCH"}]}]}
JSON
      ;;
    no-manifest-sha|checksums-missing-line)
      cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"$VERSION","files":[{"name":"$ARCHIVE","os":"$OS","arch":"$ARCH"}]}]}
JSON
      if [ "$mode" = no-manifest-sha ]; then
        printf '%s  %s\n' "$sha" "$ARCHIVE" > "$dist/dl/$VERSION/checksums-sha256.txt"
      else
        printf '%s  %s\n' "$sha" "some-other-archive.tar.gz" > "$dist/dl/$VERSION/checksums-sha256.txt"
      fi
      ;;
    *) echo "build_dist: unknown mode $mode"; exit 2;;
  esac
}

run_install() { # $1 = dist dir, $2 = bin dir; stderr -> $work/err; returns the installer's status
  rm -rf "$work/stage"; mkdir -p "$work/stage"
  cat -- "$INSTALL_SH" | PATH="$work/shim:$PATH" INSTALL_TEST_STAGE="$work/stage" \
    CILOCK_DIST_BASE="file://$1" CILOCK_BIN_DIR="$2" "$sh" >/dev/null 2>"$work/err"
}

staging_left() { [ -n "$(ls -A "$work/stage")" ]; }

# A refusal only counts if the installer reached the SHA256 step and died there
# with an error. A shell that cannot even parse the script also "refuses".
refused_at_verify() { grep -qF 'verifying SHA256 against' "$work/err" && grep -qF 'error: ' "$work/err"; }

# --- 0. POSIX sh only ----------------------------------------------------------
rm -f "$work/err"
if ! command -v shellcheck >/dev/null 2>&1; then
  fail 0 "shellcheck is not on PATH; it is this harness's no-bashisms check, not optional"
elif ! shellcheck -s sh "$INSTALL_SH"; then
  fail 0 "install.sh uses a construct outside POSIX sh (shellcheck -s sh, above)"
else
  pass 0 "shellcheck -s sh finds no construct outside POSIX sh"
fi

read -r -a shells <<<"${INSTALL_TEST_SHELLS:-bash sh dash}"
n=0
for sh in "${shells[@]}"; do
  n=$((n + 1)); d="$work/s$n"; mkdir -p "$d"
  rm -f "$work/err"
  if ! command -v "$sh" >/dev/null 2>&1; then
    fail "$sh" "shell '$sh' is not on PATH (set INSTALL_TEST_SHELLS to choose the shells explicitly)"
    continue
  fi

  # --- 1. manifest-sha path, no checksums-sha256.txt --------------------------
  dist="$d/dist1"; bin="$d/bin1"; mkdir -p "$bin"
  build_dist "$dist" with-manifest-sha
  if ! run_install "$dist" "$bin"; then
    fail "1/$sh" "install errored on the manifest-sha path"
  elif [ ! -x "$bin/cilock" ]; then
    fail "1/$sh" "cilock not installed via manifest sha256"
  elif ! grep -qF 'verifying SHA256 against the release manifest' "$work/err" || grep -qF 'signed manifest' "$work/err"; then
    fail "1/$sh" "the log must say 'against the release manifest', never 'signed manifest' (nothing signs it)"
  elif staging_left; then
    fail "1/$sh" "left its staging directory behind after a successful install"
  else
    pass "1/$sh" "installed via manifest sha256 with NO checksums-sha256.txt"
  fi

  # --- 2. tamper → must be rejected -------------------------------------------
  echo "corrupt" >> "$dist/dl/$VERSION/$ARCHIVE"   # invalidate the archive bytes
  rm -f "$bin/cilock"
  if run_install "$dist" "$bin"; then
    fail "2/$sh" "install succeeded on a tampered archive"
  elif [ -e "$bin/cilock" ]; then
    fail "2/$sh" "cilock installed despite a sha256 mismatch"
  elif ! refused_at_verify; then
    fail "2/$sh" "refused before reaching the SHA256 check, so this proved nothing"
  elif staging_left; then
    fail "2/$sh" "left its staging directory behind after a refusal"
  else
    pass "2/$sh" "rejected tampered archive (manifest sha256 mismatch)"
  fi

  # --- 3. fallback to checksums-sha256.txt when the manifest lacks a sha ------
  dist="$d/dist3"; bin="$d/bin3"; mkdir -p "$bin"
  build_dist "$dist" no-manifest-sha
  if ! run_install "$dist" "$bin"; then
    fail "3/$sh" "install errored on the checksums-sha256.txt fallback"
  elif [ ! -x "$bin/cilock" ]; then
    fail "3/$sh" "cilock not installed via the checksums fallback"
  elif staging_left; then
    fail "3/$sh" "left its staging directory behind after a successful install"
  else
    pass "3/$sh" "installed via checksums-sha256.txt fallback (manifest had no sha256)"
  fi

  # --- 4. archive sha must come from files[] "name", not an envelope "binary" -
  dist="$d/dist4"; bin="$d/bin4"; mkdir -p "$bin"
  build_dist "$dist" envelopes-block-first
  if ! run_install "$dist" "$bin"; then
    fail "4/$sh" "install read the wrong sha256 from the envelope-mapping block"
  elif [ ! -x "$bin/cilock" ]; then
    fail "4/$sh" "cilock not installed when an envelope block precedes files[]"
  else
    pass "4/$sh" "read the archive sha256 from files[] name, ignoring the envelope block"
  fi

  # --- 5. checksums-sha256.txt present but silent on this archive → refuse ----
  dist="$d/dist5"; bin="$d/bin5"; mkdir -p "$bin"
  build_dist "$dist" checksums-missing-line
  if run_install "$dist" "$bin" || [ -e "$bin/cilock" ]; then
    fail "5/$sh" "installed an archive checksums-sha256.txt has no line for"
  elif ! refused_at_verify; then
    fail "5/$sh" "refused before reaching the SHA256 check, so this proved nothing"
  elif staging_left; then
    fail "5/$sh" "left its staging directory behind after a refusal"
  else
    pass "5/$sh" "refused: checksums-sha256.txt has no line for the archive"
  fi

  # --- 6. a manifest sha256 that is not 64 hex digits → refuse ----------------
  dist="$d/dist6"; bin="$d/bin6"; mkdir -p "$bin"
  build_dist "$dist" manifest-bad-sha
  if run_install "$dist" "$bin" || [ -e "$bin/cilock" ]; then
    fail "6/$sh" "installed against a manifest sha256 that is not 64 hex digits"
  elif ! refused_at_verify; then
    fail "6/$sh" "refused before reaching the SHA256 check, so this proved nothing"
  else
    pass "6/$sh" "refused a truncated manifest sha256"
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "FAILED: $failed check(s)"
  exit 1
fi
echo "ALL PASS"
