#!/usr/bin/env bash
# Fail if presets/all/imports.go declares attestors that are NOT in the canonical
# cilock binary, unless the attestor is on the documented exclusion list.
#
# Rationale: end users running the prebuilt cilock binary should not silently
# miss attestors that are bundled into the kitchen-sink preset. Every drift
# must be a conscious decision documented in this script (the EXCLUDED list).
set -euo pipefail
cd "$(dirname "$0")/.."

PRESET=presets/all/imports.go
CANONICAL=cilock/cmd/cilock/main.go

# Attestors intentionally NOT in the canonical binary. Adding to this list
# requires a one-line reason for the exclusion. Removing from this list means
# you should also remove the blank-import from the file above.
EXCLUDED=(
  # Pulls a large transitive set including yara; available via --preset all.
  "trivy"
  # Aqua docker-bench-security parser; small, but the example flow requires
  # a docker-in-docker setup that's preset-territory.
  "docker-bench"
  # AWS Config recorder output; requires AWS Config to be deployed. The
  # attestor is preset-only because most users don't have a recorder set up.
  "aws-config"
  # AWS SecurityHub ASFF; requires SecurityHub subscription. preset-only.
  "asff"
  # Generic structured-data attestor — has a CLI-flag-registration gap
  # (rookery#issue) that needs resolving before it's surfaced in canonical.
  "structured-data"
  # Sinkhole flow attestor — special sidecar deployment; not a CI default.
  "sinkhole-flows"
  # Verification Summary Attestation — designed for verify-time chained
  # policies. Preset-only until the cilock verify --vsa-outfile flow is
  # documented as a first-class pattern.
  "vsa"
  # Falco runtime-security events — landing in canonical via rookery#147
  # (already on feat/kube-bench-attestor; this script will recheck after
  # that branch merges).
  "falco"
)

preset_attestors=$(grep -oE '/attestors/[a-z0-9-]+' "$PRESET" | sed 's|/attestors/||' | sort -u)
canonical_attestors=$(grep -oE '/attestors/[a-z0-9-]+' "$CANONICAL" | sed 's|/attestors/||' | sort -u)

# Fail CLOSED: an empty parse (moved/renamed file, changed import shape) would
# make `comm` produce no missing attestors and the check trivially pass. Both
# sets are known non-empty in a healthy tree, so refuse to proceed on empty.
if [[ -z "$preset_attestors" ]]; then
  echo "::error::parsed 0 attestors from $PRESET — parse is broken; refusing to pass" >&2
  exit 2
fi
if [[ -z "$canonical_attestors" ]]; then
  echo "::error::parsed 0 attestors from $CANONICAL — parse is broken; refusing to pass" >&2
  exit 2
fi

missing=$(comm -23 <(echo "$preset_attestors") <(echo "$canonical_attestors"))

unexplained=""
for attestor in $missing; do
  excluded=false
  for e in "${EXCLUDED[@]}"; do
    if [[ "$attestor" == "$e" ]]; then
      excluded=true
      break
    fi
  done
  if ! $excluded; then
    unexplained="$unexplained $attestor"
  fi
done

if [[ -n "$unexplained" ]]; then
  echo "ERROR: attestor(s) in presets/all but missing from canonical cilock:" >&2
  for a in $unexplained; do
    echo "  - $a" >&2
  done
  echo "" >&2
  echo "Either register them in cilock/cmd/cilock/main.go (+ cilock/go.mod replace)," >&2
  echo "or add them to the EXCLUDED list in scripts/check-canonical-attestors.sh with a reason." >&2
  exit 1
fi

excluded_count=${#EXCLUDED[@]}
preset_count=$(echo "$preset_attestors" | wc -l | tr -d ' ')
canonical_count=$(echo "$canonical_attestors" | wc -l | tr -d ' ')
echo "OK — preset=$preset_count canonical=$canonical_count excluded=$excluded_count (all drift documented)"
