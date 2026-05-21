#!/usr/bin/env bash
# Checks the cilock binary's transitive dependency tree against the budget
# committed in .dep-budget.yaml.
#
# Exits non-zero if either metric exceeds budget. To raise a ceiling, the
# caller must also commit an updated .dep-budget.yaml — that pairing makes
# any new dep visible in code review.
#
# Tracking issue: https://github.com/aflock-ai/rookery/issues/70
#
# Why binary introspection, not `go list -m all`:
#   The earlier version of this script counted `go list -m all` from cilock/,
#   which returns the MVS (Minimal Version Selection) resolved module graph
#   — every module reachable from the workspace, including ones that nothing
#   actually imports. In rookery's case that's ~1180 modules. The cilock
#   binary itself, however, only links ~233 modules. MVS over-reports the
#   real bloat by 5x. The metric that matters for binary size and supply-
#   chain attack surface is what `go build` actually pulls in, which we read
#   back out of the built binary via `go version -m`. See issue #70.
#
# Usage:
#   ./scripts/check-dep-budget.sh           # check against budget; exit non-zero on overage
#   ./scripts/check-dep-budget.sh --print   # just print current measurements

set -e

cd "$(dirname "$0")/.."

# ── Measure current ───────────────────────────────────────────────────
# Build cilock and read its linked module list from the binary itself.
# `go version -m <binary>` prints lines like:
#   dep    github.com/foo/bar    v1.2.3    h1:...
#   =>     github.com/foo/bar    v1.2.3-replace    h1:...   (for replace directives)
# We sum unique paths from both, excluding rookery's own modules (they're
# the source tree, not external deps).
build_and_list_linked_modules() {
  local tmpbin
  tmpbin=$(mktemp)
  (cd cilock && go build -o "$tmpbin" ./cmd/cilock/) >/dev/null
  go version -m "$tmpbin" 2>/dev/null \
    | awk '$1 == "dep" || $1 == "=>" {print $2}' \
    | grep -v '^github.com/aflock-ai/rookery' \
    | grep -v '^$' \
    | sort -u
  rm -f "$tmpbin"
}

current_transitive_pkgs() {
  build_and_list_linked_modules | wc -l | tr -d ' '
}

current_go_sum_bytes() {
  wc -c cilock/go.sum | awk '{print $1}'
}

PKGS=$(current_transitive_pkgs)
BYTES=$(current_go_sum_bytes)

if [ "${1:-}" = "--print" ]; then
  echo "cilock_transitive_pkgs: $PKGS"
  echo "cilock_go_sum_bytes:    $BYTES"
  exit 0
fi

# ── Read budget ────────────────────────────────────────────────────────
# Tiny YAML reader for our specific shape. Avoids a yq dependency on the
# runner — keeps the guardrail itself dep-light.
extract_budget() {
  local key="$1"
  awk -v key="$key" '
    $0 ~ "^" key ":" { sub(".*: ", ""); sub(" .*", ""); print; exit }
  ' .dep-budget.yaml
}

BUDGET_PKGS=$(awk '/^  transitive_pkgs:/ { print $2; exit }' .dep-budget.yaml)
BUDGET_BYTES=$(awk '/^  go_sum_bytes:/ { print $2; exit }' .dep-budget.yaml)

if [ -z "$BUDGET_PKGS" ] || [ -z "$BUDGET_BYTES" ]; then
  echo "::error::could not parse .dep-budget.yaml — expected transitive_pkgs and go_sum_bytes under cilock:"
  exit 2
fi

# ── Compare ────────────────────────────────────────────────────────────
echo "cilock dep budget:"
echo "  transitive_pkgs: current=$PKGS  budget=$BUDGET_PKGS  (binary-linked modules)"
echo "  go_sum_bytes:    current=$BYTES  budget=$BUDGET_BYTES"
echo

FAIL=0

if [ "$PKGS" -gt "$BUDGET_PKGS" ]; then
  OVER=$((PKGS - BUDGET_PKGS))
  echo "::error::cilock transitive_pkgs over budget by $OVER ($PKGS > $BUDGET_PKGS)"
  echo "  → If this growth is intentional, raise .dep-budget.yaml in the same PR."
  echo "  → First 20 linked module paths in the binary:"
  build_and_list_linked_modules | head -20 | sed 's/^/    /'
  FAIL=1
fi

if [ "$BYTES" -gt "$BUDGET_BYTES" ]; then
  OVER=$((BYTES - BUDGET_BYTES))
  echo "::error::cilock go.sum over budget by $OVER bytes ($BYTES > $BUDGET_BYTES)"
  echo "  → If this growth is intentional, raise .dep-budget.yaml in the same PR."
  FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
  echo "OK — within budget."
fi

exit "$FAIL"
