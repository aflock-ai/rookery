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
# Usage:
#   ./scripts/check-dep-budget.sh           # check against budget; exit non-zero on overage
#   ./scripts/check-dep-budget.sh --print   # just print current measurements

set -e

cd "$(dirname "$0")/.."

# ── Measure current ───────────────────────────────────────────────────
current_transitive_pkgs() {
  # `go list -m all` lists the module itself plus every transitive dep, one per
  # line. Exclude rookery's own modules — we don't ship those to consumers as
  # external deps, they're the source tree.
  (
    cd cilock
    go list -m -f '{{.Path}}' all 2>/dev/null \
      | grep -v '^github.com/aflock-ai/rookery' \
      | grep -v '^$' \
      | sort -u \
      | wc -l \
      | tr -d ' '
  )
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
echo "  transitive_pkgs: current=$PKGS  budget=$BUDGET_PKGS"
echo "  go_sum_bytes:    current=$BYTES  budget=$BUDGET_BYTES"
echo

FAIL=0

if [ "$PKGS" -gt "$BUDGET_PKGS" ]; then
  OVER=$((PKGS - BUDGET_PKGS))
  echo "::error::cilock transitive_pkgs over budget by $OVER ($PKGS > $BUDGET_PKGS)"
  echo "  → If this growth is intentional, raise .dep-budget.yaml in the same PR."
  echo "  → Top 20 module paths in the new tree:"
  ( cd cilock && go list -m -f '{{.Path}}' all 2>/dev/null \
      | grep -v '^github.com/aflock-ai/rookery' \
      | grep -v '^$' \
      | sort -u \
      | head -20 ) | sed 's/^/    /'
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
