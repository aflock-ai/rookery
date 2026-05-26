#!/usr/bin/env bash
# Autonomous validation loop. Runs validate-all.sh on a fixed interval
# and writes a one-line summary per iteration so a monitor can detect
# regressions.
#
# Each iteration:
#   - prints a timestamped header
#   - runs validate-all.sh, capturing output to ${LOG}
#   - emits a single summary line: "OK <stamp> <pass/total>" or "FAIL <stamp> <details>"
#
# Designed to be run by Monitor or by a long-lived shell. Exits cleanly
# on SIGTERM/SIGINT.

set -uo pipefail
cd "$(dirname "$0")/.."

INTERVAL_SECONDS="${VALIDATE_INTERVAL:-600}"   # 10 minutes default
LOG="${VALIDATE_LOG:-/tmp/cilock-validate.log}"
SUMMARY="${VALIDATE_SUMMARY:-/tmp/cilock-validate.summary}"

trap 'echo "STOPPED $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SUMMARY"; exit 0' INT TERM

echo "STARTED $(date -u +%Y-%m-%dT%H:%M:%SZ) interval=${INTERVAL_SECONDS}s" | tee -a "$SUMMARY"

while :; do
  stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if ./scripts/validate-all.sh >>"$LOG" 2>&1; then
    echo "OK   $stamp" | tee -a "$SUMMARY"
  else
    # Extract the failure details from the last validate-all run
    details=$(tail -200 "$LOG" | grep -E "^\[[0-9]\.|FAIL$" | grep -B 1 "FAIL$" | head -6 | tr '\n' ' ')
    echo "FAIL $stamp — $details" | tee -a "$SUMMARY"
  fi
  sleep "$INTERVAL_SECONDS"
done
