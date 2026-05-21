#!/usr/bin/env bash
# Validates .provenance/*.json entries — verifies each inlined-code record
# is consistent with the local file AND with the recorded upstream content.
#
# Exits non-zero if any entry drifts, points at a missing file, has an
# off-allowlist license, or doesn't match upstream when re-fetched.
#
# Also greps the repo for inlining-marker comments (`// inlined from`,
# `// copied from`, `// ported from`) and asserts each one is covered by
# an entry — catches the case where someone inlines code but forgets to
# record it.
#
# Tracking issue: https://github.com/aflock-ai/rookery/issues/72

set -e

cd "$(dirname "$0")/.."

PROV_DIR=".provenance"

# ── Allowlist of acceptable upstream licenses ─────────────────────────
# Source of truth: NOTICE.md. Keep in sync.
LICENSE_ALLOWLIST=(
  "Apache-2.0"
  "MIT"
  "BSD-2-Clause"
  "BSD-3-Clause"
  "ISC"
)

is_allowlisted_license() {
  local lic="$1"
  for ok in "${LICENSE_ALLOWLIST[@]}"; do
    if [ "$ok" = "$lic" ]; then return 0; fi
  done
  return 1
}

# ── Helpers ────────────────────────────────────────────────────────────
err() {
  echo "::error::$*"
  FAIL=1
}

sha256_of_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

sha256_of_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

FAIL=0

# ── 1. Validate each .provenance/*.json entry ──────────────────────────
shopt -s nullglob
ENTRIES=("$PROV_DIR"/*.json)
shopt -u nullglob

if [ ${#ENTRIES[@]} -eq 0 ]; then
  echo "No .provenance/*.json entries — clean state."
else
  for entry in "${ENTRIES[@]}"; do
    echo "=== checking $entry ==="

    # Required fields exist.
    for field in upstream_repo upstream_commit upstream_url license_spdx license_url local_path sha256_of_inlined_content sha256_of_upstream_content kind; do
      if ! jq -e ".${field}" "$entry" >/dev/null 2>&1; then
        err "$entry: missing required field '$field'"
        continue 2
      fi
    done

    UPSTREAM_REPO=$(jq -r .upstream_repo "$entry")
    UPSTREAM_COMMIT=$(jq -r .upstream_commit "$entry")
    UPSTREAM_URL=$(jq -r .upstream_url "$entry")
    LICENSE_SPDX=$(jq -r .license_spdx "$entry")
    LOCAL_PATH=$(jq -r .local_path "$entry")
    SHA_LOCAL_RECORDED=$(jq -r .sha256_of_inlined_content "$entry")
    SHA_UPSTREAM_RECORDED=$(jq -r .sha256_of_upstream_content "$entry")

    # Upstream commit must be a 40-char hex SHA.
    if ! echo "$UPSTREAM_COMMIT" | grep -qE '^[0-9a-f]{40}$'; then
      err "$entry: upstream_commit is not a 40-char SHA (got '$UPSTREAM_COMMIT'). Tags are not allowed — they move."
    fi

    # License must be on the allowlist.
    if ! is_allowlisted_license "$LICENSE_SPDX"; then
      err "$entry: license_spdx '$LICENSE_SPDX' is not on the NOTICE.md allowlist"
    fi

    # Local file must exist.
    if [ ! -f "$LOCAL_PATH" ]; then
      err "$entry: local_path '$LOCAL_PATH' does not exist"
      continue
    fi

    # Local file's actual SHA256 must match recorded.
    SHA_LOCAL_ACTUAL=$(sha256_of_file "$LOCAL_PATH")
    if [ "$SHA_LOCAL_ACTUAL" != "$SHA_LOCAL_RECORDED" ]; then
      err "$entry: local file SHA mismatch — file=$SHA_LOCAL_ACTUAL recorded=$SHA_LOCAL_RECORDED. Did you edit '$LOCAL_PATH' without updating the entry?"
    fi

    # Re-fetch upstream and verify its SHA256 still matches. Pipe
    # directly to the hasher — putting the body through a bash variable
    # would strip the trailing newline (variable assignment normalises
    # command-substitution output), producing a different SHA than the
    # one we recorded with `curl | sha256sum`.
    UPSTREAM_TMP=$(mktemp)
    if ! curl -fsSL --max-time 30 "$UPSTREAM_URL" -o "$UPSTREAM_TMP" 2>/dev/null; then
      err "$entry: failed to fetch upstream '$UPSTREAM_URL'"
      rm -f "$UPSTREAM_TMP"
      continue
    fi
    SHA_UPSTREAM_ACTUAL=$(sha256_of_file "$UPSTREAM_TMP")
    rm -f "$UPSTREAM_TMP"
    if [ "$SHA_UPSTREAM_ACTUAL" != "$SHA_UPSTREAM_RECORDED" ]; then
      err "$entry: upstream SHA mismatch — upstream now=$SHA_UPSTREAM_ACTUAL recorded=$SHA_UPSTREAM_RECORDED. Upstream may have rewritten history at the recorded commit; investigate."
    fi

    echo "  ok"
  done
fi

# ── 2. Marker scan: any "inlined from" comments must be covered ────────
#
# A code reviewer can spot a TODO or a "ported from" comment, but a CI scan
# is a better backstop. If a contributor writes a marker but forgets the
# .provenance entry, this catches it.
MARKER_GREP=$(grep -RIn -E "//[[:space:]]*(inlined from|copied from|ported from)" \
  --include='*.go' \
  --exclude-dir='.git' \
  --exclude-dir='vendor' \
  --exclude-dir='node_modules' \
  . 2>/dev/null || true)

if [ -n "$MARKER_GREP" ]; then
  while IFS= read -r line; do
    # line shape: ./path/file.go:NN: // inlined from foo
    FILE=$(echo "$line" | cut -d: -f1)
    REL="${FILE#./}"
    # Is there a provenance entry whose local_path matches REL?
    COVERED=0
    for entry in "${ENTRIES[@]}"; do
      LP=$(jq -r .local_path "$entry")
      if [ "$LP" = "$REL" ]; then
        COVERED=1
        break
      fi
    done
    if [ "$COVERED" -eq 0 ]; then
      err "$REL has an inlining marker comment but no .provenance/*.json entry"
    fi
  done <<<"$MARKER_GREP"
fi

if [ "$FAIL" -eq 0 ]; then
  echo
  echo "provenance: all entries clean."
else
  echo
  echo "provenance: failures above. See .provenance/README.md for the format."
fi

exit "$FAIL"
