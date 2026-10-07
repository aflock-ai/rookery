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
#   9. print the provenance command with `-s sha1:<commit>` taken from THIS
#      version's manifest "commit", never from another version's entry, and print a fill-in placeholder, not a guess,
#      when this version records none or a malformed one;
#  10. on a Windows shell (uname -s MINGW64_NT/MSYS_NT/CYGWIN_NT), refuse but
#      name the windows .zip, cilock.exe and the installation page's recipe;
# and, in every case, pass or fail, remove its staging directory.
#
# The docs also print copy-paste recipes for installing by hand, and they
# must refuse the same archives. A reader pastes a recipe into an interactive
# shell, where a failed line does not stop the next one. So these checks run
# each recipe the way a paste runs it:
#   7. the POSIX recipes (installation.md "Manual download",
#      verify-the-cilock-binary.md Path 1), under bash without errexit;
#   8. the Windows PowerShell recipe in installation.md: its shape on every
#      run, and the recipe itself when INSTALL_TEST_PWSH names a pwsh.
#
# No cilock binary, no network, no secrets: curl, tar, sha256sum/shasum, dash
# and shellcheck (plus pwsh and python3 for case 8p, which is opt-in).
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

COMMIT="0123456789abcdef0123456789abcdef01234567"
OTHER_COMMIT="fedcba9876543210fedcba9876543210fedcba98"
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
  #                     | checksums-missing-line | manifest-bad-sha | with-commit
  #                     | other-version-commit | bad-commit
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
    with-commit|other-version-commit|bad-commit)
      # A newer version precedes this one, as in the real newest-first manifest,
      # carrying its own commit: the installer must read THIS version's.
      local mine="\"commit\":\"$COMMIT\","
      [ "$mode" = other-version-commit ] && mine=""
      [ "$mode" = bad-commit ] && mine="\"commit\":\"${COMMIT%????????}\","
      cat > "$dist/dl/manifest.json" <<JSON
{"schema":1,"latest":"$VERSION","versions":[{"version":"v9.9.10-test","commit":"$OTHER_COMMIT","files":[{"name":"x.tar.gz","sha256":"$sha"}]},{"version":"$VERSION",${mine}"files":[{"name":"$ARCHIVE","sha256":"$sha","os":"$OS","arch":"$ARCH"}]}]}
JSON
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

  # --- 9. the provenance command seeds THIS version's full commit ---------------
  for mode in with-commit other-version-commit bad-commit; do
    dist="$d/dist9-$mode"; bin="$d/bin9-$mode"; mkdir -p "$bin"
    build_dist "$dist" "$mode"
    if ! run_install "$dist" "$bin"; then
      fail "9/$mode/$sh" "install errored"
    elif grep -qF "$OTHER_COMMIT" "$work/err"; then
      fail "9/$mode/$sh" "printed another version's commit"
    elif [ "$mode" = with-commit ]; then
      if ! grep -qxF "    -s sha1:$COMMIT \\" "$work/err"; then
        fail "9/$mode/$sh" "the verify command does not seed -s sha1:$COMMIT"
      else
        pass "9/$mode/$sh" "the verify command seeds this version's commit"
      fi
    elif grep -qE 'sha1:[0-9a-f]' "$work/err"; then
      fail "9/$mode/$sh" "printed a commit this version's entry does not validly record"
    elif ! grep -qxF "    -s sha1:<full 40-hex commit of $VERSION> \\" "$work/err"; then
      fail "9/$mode/$sh" "no fill-in placeholder for the commit"
    else
      pass "9/$mode/$sh" "no valid commit recorded: printed a placeholder, not a guess"
    fi
  done

  # --- 10. Windows shells get the Windows path, not a bare refusal (#11531) -----
  # Git Bash, MSYS2 and Cygwin all run this script; uname -s names each one.
  dist="$d/dist10"; bin="$d/bin10"; mkdir -p "$bin" "$work/uname-win"
  build_dist "$dist" with-manifest-sha
  for kernel in MINGW64_NT-10.0 MSYS_NT-10.0 CYGWIN_NT-10.0; do
    # shellcheck disable=SC2016 # $1 expands when the fake uname runs, not here
    printf '#!/bin/sh\ncase "$1" in -s) echo %s;; -m) echo x86_64;; *) exit 1;; esac\n' "$kernel" > "$work/uname-win/uname"
    chmod +x "$work/uname-win/uname"
    rm -rf "$work/stage"; mkdir -p "$work/stage"
    if cat -- "$INSTALL_SH" | PATH="$work/uname-win:$work/shim:$PATH" INSTALL_TEST_STAGE="$work/stage" \
      CILOCK_DIST_BASE="file://$dist" CILOCK_BIN_DIR="$bin" "$sh" >/dev/null 2>"$work/err"; then
      fail "10/$kernel/$sh" "installed on Windows, which ships a .zip this script does not unpack"
    elif [ -e "$bin/cilock" ]; then
      fail "10/$kernel/$sh" "left a cilock in the bin dir on Windows"
    elif ! grep -qF 'cilock-<version>-windows-amd64.zip' "$work/err" \
      || ! grep -qF 'cilock.exe' "$work/err" \
      || ! grep -qF 'https://cilock.dev/docs/getting-started/installation' "$work/err"; then
      fail "10/$kernel/$sh" "refused without naming the windows zip, cilock.exe and the installation docs"
    else
      pass "10/$kernel/$sh" "refused, and pointed at the Windows zip and its PowerShell recipe"
    fi
  done
done

# --- 7/8 shared: the documented recipes -----------------------------------------
DOCS="$HERE/../../site/docs/getting-started"
mark="$work/marks"

# fence DOC LANG NEEDLE: print the one LANG fence in DOC with a line containing
# NEEDLE. Fails unless exactly one fence matches.
fence() {
  awk -v open="\`\`\`$2" -v needle="$3" '
    $0 == open { inblk = 1; body = ""; hit = 0; next }
    inblk && $0 == "```" { if (hit) { printf "%s", body; found++ } inblk = 0; next }
    inblk { body = body $0 "\n"; if (index($0, needle)) hit = 1 }
    END { exit found == 1 ? 0 : 1 }' "$1"
}

# fake_bin PATH LABEL: a stand-in cilock that records that it ran, then prints
# "cilock LABEL". Any marker other than the expected one is a failure.
fake_bin() {
  printf '#!/bin/sh\ntouch "%s/%s-ran"\necho "cilock %s"\n' "$mark" "$2" "$2" > "$1"
  chmod +x "$1"
}

ran() { [ -n "$(ls -A "$mark")" ]; }
ran_only() { [ -e "$mark/$1-ran" ] && [ "$(ls -A "$mark")" = "$1-ran" ]; }

# stage_release DIST VERSION_DIR ARCHIVE MODE PACK_CMD BIN: write ARCHIVE,
# holding one fake cilock named BIN, and its .sha256 sidecar under
# DIST/dl/VERSION_DIR. MODE good: the sidecar matches. tamper: an archive
# holding a "tampered" cilock replaces the one the sidecar names. no-line: the
# sidecar has no line for the archive, and the archive is the tampered one.
# PACK_CMD packs $work/r/pack into the archive path it is given.
other_sha="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
stage_release() {
  local dist="$1/dl/$2" archive="$3" mode="$4" pack="$5" bin="$6" sha
  mkdir -p "$dist" "$work/r/pack"
  rm -f "$work/r/pack/$bin"
  fake_bin "$work/r/pack/$bin" good
  "$pack" "$dist/$archive"
  sha="$(sha_of "$dist/$archive")"
  if [ "$mode" = no-line ]; then
    printf '%s  %s\n' "$sha" "some-other-archive.tar.gz" > "$dist/$archive.sha256"
  else
    # The sidecar also lists attestation files; the recipe must pick its line.
    printf '%s  %s\n%s  %s\n' "$other_sha" "${archive%.*}.build.att.json" \
      "$sha" "$archive" > "$dist/$archive.sha256"
  fi
  if [ "$mode" != good ]; then
    rm -f "$work/r/pack/$bin" "$dist/$archive"
    fake_bin "$work/r/pack/$bin" tampered
    "$pack" "$dist/$archive"
  fi
}
pack_tgz() { tar -C "$work/r/pack" -czf "$1" cilock; }
pack_zip() { (cd "$work/r/pack" && python3 -m zipfile -c "$1" cilock.exe); }

# --- 7. POSIX recipes: a failed check stops before anything runs -----------------
posix_recipe() { # $1 = label, $2 = doc
  local label="$1" doc="$2" recipe="$work/recipe.sh" version archive mode rc
  # shellcheck disable=SC2016 # the recipe's own text, matched literally
  if ! fence "$doc" bash 'curl -fsSLO "${BASE}/${ARCHIVE}"' > "$recipe"; then
    fail "$label" "$(basename "$doc") has no single bash fence that downloads \${ARCHIVE}"
    return
  fi
  read -r version archive < <(bash -c "$(grep -E '^[A-Z]+=' "$recipe")"'
    printf "%s %s\n" "$VERSION" "$ARCHIVE"')
  for mode in good tamper no-line; do
    rm -rf "$work/r" "$mark"; mkdir -p "$work/r/cwd" "$mark"
    stage_release "$work/r/dist" "$version" "$archive" "$mode" pack_tgz cilock
    fake_bin "$work/r/cwd/cilock" stale   # a cilock left in the directory
    sed "s#https://cilock.dev#file://$work/r/dist#" "$recipe" > "$work/r/recipe.sh"
    if ! grep -qF "file://$work/r/dist/dl/" "$work/r/recipe.sh"; then
      fail "$label/$mode" "recipe no longer downloads from https://cilock.dev, so this harness cannot serve it"
      continue
    fi
    if (cd "$work/r/cwd" && bash "$work/r/recipe.sh" > "$work/r/out" 2> "$work/err"); then rc=0; else rc=$?; fi
    { cat "$work/r/out"; echo; } >> "$work/err"
    if [ "$mode" = good ]; then
      if [ "$rc" -ne 0 ] || ! ran_only good || ! grep -qx 'cilock good' "$work/r/out"; then
        fail "$label/$mode" "a matching archive must run ITS cilock and only that (rc=$rc, ran: $(ls "$mark"))"
      else
        pass "$label/$mode" "ran the cilock from the archive that matched, not the one already there"
      fi
    elif [ ! -e "$work/r/cwd/$archive" ] || [ ! -e "$work/r/cwd/$archive.sha256" ]; then
      fail "$label/$mode" "the recipe never downloaded the archive and sidecar, so this proved nothing"
    elif ran || [ "$rc" -eq 0 ]; then
      fail "$label/$mode" "the recipe ran a cilock the checksum did not cover (rc=$rc, ran: $(ls "$mark"))"
    elif [ "$mode" = tamper ] && ! grep -qF 'FAILED' "$work/err"; then
      fail "$label/$mode" "stopped, but not at the checksum (no FAILED line), so this proved nothing"
    else
      pass "$label/$mode" "stopped before extracting or running anything (rc=$rc)"
    fi
  done
}
posix_recipe 7/installation "$DOCS/installation.md"
posix_recipe 7/verify-path-1 "$DOCS/verify-the-cilock-binary.md"

# --- 8. the Windows recipe ------------------------------------------------------
# Pasted into a console, each top-level PowerShell line runs even after the line
# before it threw, and Expand-Archive that finds cilock.exe already present only
# writes a non-terminating error. A flat recipe can therefore run a cilock.exe
# the checksum never covered. It must be one `& { }` block that stops on the
# first error and extracts into a directory the block itself creates.
ps_recipe="$work/recipe.ps1"
rm -f "$work/err"
if ! fence "$DOCS/installation.md" powershell 'Expand-Archive' > "$ps_recipe"; then
  fail 8s "installation.md has no single powershell fence that runs Expand-Archive"
else
  if [ "$(awk 'NF { print; exit }' "$ps_recipe")" != '& {' ] || [ "$(awk 'NF { l = $0 } END { print l }' "$ps_recipe")" != '}' ]; then
    fail 8s "the recipe is not one & { } block, so a throw stops only its own line"
  elif [ "$(awk 'NF && ++n == 2 { gsub(/^[ \t]+|[ \t]+$/, ""); print; exit }' "$ps_recipe")" != "\$ErrorActionPreference = 'Stop'" ]; then
    fail 8s "the block's first statement must be \$ErrorActionPreference = 'Stop'"
  elif ! awk '/Expand-Archive/ { n++; if (!/-ErrorAction Stop/) bad = 1 } END { exit !(n > 0 && !bad) }' "$ps_recipe"; then
    fail 8s "Expand-Archive needs -ErrorAction Stop: it is a script-module function and does not see the block's preference"
  elif grep -qE -- '-DestinationPath +\.( |$)' "$ps_recipe"; then
    fail 8s "the recipe extracts into the current directory, where an older cilock.exe can already sit"
  else
    pass 8s "one & { } block, stops on the first error, extracts into its own directory"
  fi
fi

# 8p runs the recipe itself, fed on stdin to `pwsh -Command -`, which executes it
# the way a console paste does. Invoke-WebRequest is shadowed by a function that
# serves the staged release from disk.
ps_recipe_run() { # $1 = mode label; runs in $work/r/cwd
  {
    # shellcheck disable=SC2016 # PowerShell text, expanded by pwsh
    printf '%s\n\n' 'function Invoke-WebRequest { param([Parameter(Position = 0)][string]$Uri, [string]$OutFile, [switch]$UseBasicParsing) Copy-Item -LiteralPath ($Uri -replace "^https://cilock\.dev", $env:RECIPE_DIST) -Destination $OutFile -ErrorAction Stop }'
    cat "$ps_recipe"
    printf '\n'
  } > "$work/r/input.ps1"
  (cd "$work/r/cwd" && RECIPE_DIST="$work/r/dist" TERM=dumb NO_COLOR=1 "$INSTALL_TEST_PWSH" -NoProfile -NonInteractive \
    -Command - < "$work/r/input.ps1" > "$work/r/out" 2> "$work/err") || true
  { cat "$work/r/out"; echo; } >> "$work/err"
}
if [ -z "${INSTALL_TEST_PWSH:-}" ]; then
  echo "NOT RUN[8p]: set INSTALL_TEST_PWSH to a pwsh to run the PowerShell recipe (8s checked its shape only)"
elif ! "$INSTALL_TEST_PWSH" -NoProfile -NonInteractive -Command 'exit 0' > /dev/null 2>&1; then
  rm -f "$work/err"; fail 8p "INSTALL_TEST_PWSH=$INSTALL_TEST_PWSH does not run"
elif ! command -v python3 > /dev/null 2>&1; then
  rm -f "$work/err"; fail 8p "python3 is not on PATH; 8p zips the staged release with it"
elif [ ! -s "$ps_recipe" ]; then
  rm -f "$work/err"; fail 8p "no PowerShell recipe to run (see 8s)"
else
  # shellcheck disable=SC2016 # PowerShell text, expanded by pwsh
  read -r ps_version ps_archive < <("$INSTALL_TEST_PWSH" -NoProfile -NonInteractive -Command \
    "$(grep -E '^[[:space:]]*\$(VERSION|ARCHIVE) = ' "$ps_recipe"); \"\$VERSION \$ARCHIVE\"")
  for mode in good tamper no-line rerun; do
    rm -rf "$work/r" "$mark"; mkdir -p "$work/r/cwd" "$mark"
    stage_release "$work/r/dist" "v$ps_version" "$ps_archive" "${mode/rerun/good}" pack_zip cilock.exe
    fake_bin "$work/r/cwd/cilock.exe" stale   # a cilock.exe left in the directory
    planted=0
    if [ "$mode" = rerun ]; then
      # A second run over the first run's directory must not run what it finds there.
      ps_recipe_run first
      rm -rf "$mark"; mkdir -p "$mark"
      while IFS= read -r exe; do fake_bin "$exe" stale; planted=$((planted + 1)); done \
        < <(find "$work/r/cwd" -mindepth 2 -name cilock.exe)
    fi
    ps_recipe_run "$mode"
    case "$mode" in
      tamper) want='SHA-256 mismatch' ;;
      no-line) want='no single line' ;;
      *) want='' ;;
    esac
    if [ "$mode" = rerun ]; then
      # Refusing to reuse the directory and re-extracting over it are both safe;
      # running what the earlier run left there is not.
      if [ "$planted" -eq 0 ]; then
        fail "8p/$mode" "the first run extracted no cilock.exe into a directory, so a rerun proves nothing"
      elif ran && ! ran_only good; then
        fail "8p/$mode" "the rerun ran a cilock.exe the earlier run left behind (ran: $(ls "$mark"))"
      else
        pass "8p/$mode" "the rerun did not run the cilock.exe the earlier run left behind"
      fi
    elif [ "$mode" = good ]; then
      if ! ran_only good || ! grep -q 'cilock good' "$work/r/out"; then
        fail "8p/$mode" "a matching archive must run ITS cilock.exe and only that (ran: $(ls "$mark"))"
      else
        pass "8p/$mode" "ran the cilock.exe from the archive that matched, not the one already there"
      fi
    elif [ ! -e "$work/r/cwd/$ps_archive" ]; then
      fail "8p/$mode" "the recipe never downloaded the archive, so this proved nothing"
    elif ran; then
      fail "8p/$mode" "the recipe ran a cilock.exe it did not just extract from a checked archive (ran: $(ls "$mark"))"
    elif ! grep -qF "$want" "$work/err"; then
      fail "8p/$mode" "stopped, but not with '$want', so this proved nothing"
    else
      pass "8p/$mode" "stopped with '$want' before running anything"
    fi
  done
fi

if [ "$failed" -ne 0 ]; then
  echo "FAILED: $failed check(s)"
  exit 1
fi
echo "ALL PASS"
