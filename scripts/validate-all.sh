#!/usr/bin/env bash
# Master validation script.
#
# Runs:
#   1. detection package unit tests
#   2. detectiontest helper tests
#   3. every per-plugin detector_test.go
#   4. every -tags=integration test (real tools, real outputs)
#   5. lint across detection + every plugin with detector.yaml
#   6. drift guard
#   7. real-tool fire validation (scripts/validate-detectors-against-real-tools.sh)
#
# Designed for continuous re-runs. Writes results to a log so the loop
# wrapper can detect regressions.

set -uo pipefail
cd "$(dirname "$0")/.."

LOG="${VALIDATE_LOG:-/tmp/cilock-validate.log}"
STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "==================== $STAMP ====================" | tee -a "$LOG"

fail_count=0
section() {
  echo "" | tee -a "$LOG"
  echo "[$1]" | tee -a "$LOG"
}
report() {
  local label="$1" status="$2"
  printf "  %-60s %s\n" "$label" "$status" | tee -a "$LOG"
  if [ "$status" != "OK" ] && [ "$status" != "SKIP" ]; then
    fail_count=$((fail_count+1))
  fi
}

section "1. detection package + detectiontest"
out=$(cd attestation && go test -count=1 ./detection/... 2>&1)
if echo "$out" | grep -qE "^(ok|FAIL)" && ! echo "$out" | grep -q "^FAIL"; then
  report "go test ./attestation/detection/..." OK
else
  report "go test ./attestation/detection/..." FAIL
  echo "$out" | tail -5 | sed 's/^/    /' | tee -a "$LOG"
fi

section "2. per-plugin detector_test.go (all 30+)"
plugin_pass=0; plugin_fail=0
for p in $(ls plugins/attestors); do
  d="plugins/attestors/$p"
  [ -f "$d/detector_test.go" ] || continue
  out=$(cd "$d" && go test -count=1 ./... 2>&1 | tail -3)
  if echo "$out" | grep -q "^ok"; then
    plugin_pass=$((plugin_pass+1))
  else
    plugin_fail=$((plugin_fail+1))
    echo "    $p FAIL:" | tee -a "$LOG"
    echo "$out" | sed 's/^/      /' | tee -a "$LOG"
  fi
done
if [ $plugin_fail -eq 0 ]; then
  report "$plugin_pass plugins, 0 failures" OK
else
  report "$plugin_pass plugins green, $plugin_fail FAILED" FAIL
fi

section "3. integration tests (real tools, -tags=integration)"
int_pass=0; int_fail=0; int_skip=0
for p in $(ls plugins/attestors); do
  d="plugins/attestors/$p"
  if [ -f "$d/detector_integration_test.go" ]; then
    # Run every test in the file marked with the integration build tag.
    # Listing names was too brittle as we add more tests.
    out=$(cd "$d" && go test -tags=integration -count=1 -v ./... 2>&1)
    pass=$(echo "$out" | grep -c -- "--- PASS" || true)
    fail=$(echo "$out" | grep -c -- "--- FAIL" || true)
    skip=$(echo "$out" | grep -c -- "--- SKIP" || true)
    if [ "$fail" -gt 0 ]; then
      echo "    $p:" | tee -a "$LOG"
      echo "$out" | sed 's/^/      /' | tee -a "$LOG"
      int_fail=$((int_fail+fail))
    fi
    int_pass=$((int_pass+pass))
    int_skip=$((int_skip+skip))
  fi
done
# gcp-iit + aws-iid have probe-injected tests in their detector_test.go,
# not gated by integration tag.
for p in gcp-iit aws-iid; do
  d="plugins/attestors/$p"
  out=$(cd "$d" && go test -count=1 -run "TestDetectorFiresOn|TestDetectorSkipsOff" -v 2>&1)
  pass=$(echo "$out" | grep -c -- "--- PASS")
  fail=$(echo "$out" | grep -c -- "--- FAIL")
  if [ "$fail" -gt 0 ]; then
    echo "    $p (probe injection):" | tee -a "$LOG"
    echo "$out" | tail -8 | sed 's/^/      /' | tee -a "$LOG"
    int_fail=$((int_fail+fail))
  fi
  int_pass=$((int_pass+pass))
done
if [ "$int_fail" -eq 0 ]; then
  report "$int_pass tests passed, $int_skip skipped, 0 failed" OK
else
  report "$int_pass passed, $int_skip skipped, $int_fail FAILED" FAIL
fi

section "4. lint (detection + all plugin detectors)"
out=$(golangci-lint run ./attestation/detection/... 2>&1 | tail -1)
if echo "$out" | grep -q "0 issues"; then
  report "detection package" OK
else
  report "detection package" FAIL
  golangci-lint run ./attestation/detection/... 2>&1 | tail -5 | sed 's/^/    /' | tee -a "$LOG"
fi
lint_fail=0
for p in $(ls plugins/attestors); do
  [ -f "plugins/attestors/$p/detector.yaml" ] || continue
  out=$(golangci-lint run "./plugins/attestors/$p/..." 2>&1 | tail -1)
  if echo "$out" | grep -q "0 issues"; then :; else
    lint_fail=$((lint_fail+1))
    echo "    $p:" | tee -a "$LOG"
    golangci-lint run "./plugins/attestors/$p/..." 2>&1 | tail -3 | sed 's/^/      /' | tee -a "$LOG"
  fi
done
if [ "$lint_fail" -eq 0 ]; then
  report "all $(ls plugins/attestors/*/detector.yaml | wc -l | tr -d ' ') plugins lint-clean" OK
else
  report "$lint_fail plugins lint-FAILED" FAIL
fi

section "5. detector.yaml drift guard"
out=$(./scripts/check-detector-yamls.sh 2>&1 | tail -1)
if echo "$out" | grep -q "^OK"; then
  report "$(echo $out)" OK
else
  report "$(echo $out)" FAIL
fi

section "6. real-tool fire validation"
out=$(./scripts/validate-detectors-against-real-tools.sh 2>&1)
summary=$(echo "$out" | grep "PASS=.*FAIL=" | tail -1)
if echo "$summary" | grep -qE "FAIL=0"; then
  report "$summary" OK
else
  report "$summary" FAIL
  echo "$out" | grep -E "^\s*FAIL" | sed 's/^/    /' | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
if [ $fail_count -eq 0 ]; then
  echo "==================== ALL GREEN ($STAMP) ====================" | tee -a "$LOG"
  exit 0
else
  echo "==================== $fail_count SECTION(S) FAILED ($STAMP) ====================" | tee -a "$LOG"
  exit 1
fi
