#!/usr/bin/env bash
# Pull all attestation artifacts from a cilock real-build matrix run
# and emit a single Markdown report summarizing limitations per cell.
#
# Usage:
#   scripts/aggregate-matrix-results.sh <run-id> [out-dir]
#
# Output:
#   <out-dir>/results.md       — human-readable report
#   <out-dir>/results.csv      — machine-readable table (target,mode,...)
#   <out-dir>/raw/             — extracted attestation payloads per cell

set -euo pipefail

RUN_ID="${1:?usage: $0 <run-id> [out-dir]}"
OUT_DIR="${2:-./matrix-results-$RUN_ID}"
REPO="${REPO:-aflock-ai/rookery}"

mkdir -p "$OUT_DIR/raw" "$OUT_DIR/artifacts"

echo "downloading artifacts for run $RUN_ID..."
gh run download "$RUN_ID" --repo "$REPO" --dir "$OUT_DIR/artifacts" \
  --pattern "attest-*" 2>&1 | tail -5

CSV="$OUT_DIR/results.csv"
MD="$OUT_DIR/results.md"

echo "workload,mode,attest_kb,procs,opened_files_top3,unhashed_opens,bpf_drops,fanotify_timeouts,fanotify_q_overflow,fanotify_only,fsverity_sealed,fsverity_failures,fanotify_available,fsverity_available,capture_mode,trace_mode_detail" > "$CSV"

echo "# cilock real-build matrix — run $RUN_ID" > "$MD"
echo "" >> "$MD"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$MD"
echo "" >> "$MD"
echo "| workload | mode | attest_kb | procs | unhashed | bpf_drops | fan_timeouts | fan_q_overflow | fan_only | verity_sealed | fan_avail | verity_avail |" >> "$MD"
echo "|----------|------|-----------|-------|----------|-----------|--------------|----------------|----------|---------------|-----------|--------------|" >> "$MD"

for dir in "$OUT_DIR"/artifacts/attest-*/; do
  base=$(basename "$dir")
  # name format: attest-<workload>-<mode>
  rest="${base#attest-}"
  # split rest into workload (everything before last dash that isn't part of mode-suffix)
  # modes: off, bpf-only, bpf+fanotify-auto, bpf+fanotify-on
  # but 'off' cells were skipped (no upload), so only mode tokens we see are dashed.
  workload=""
  mode=""
  for m in "bpf-only" "bpf+fanotify-auto" "bpf+fanotify-on"; do
    if [[ "$rest" == *"-$m" ]]; then
      mode="$m"
      workload="${rest%-$m}"
      break
    fi
  done
  if [ -z "$mode" ]; then
    echo "skip: cannot parse $base" >&2
    continue
  fi

  attest_path="$dir/attest.json"
  if [ ! -f "$attest_path" ]; then
    attest_path=$(find "$dir" -name 'attest.json' -print -quit)
  fi
  if [ ! -f "$attest_path" ]; then
    echo "no attest.json in $base" >&2
    continue
  fi

  attest_kb=$(( ($(wc -c < "$attest_path") + 1023) / 1024 ))
  payload="$OUT_DIR/raw/${workload}__${mode}.json"
  jq -r '.payload' "$attest_path" | base64 -d > "$payload" 2>/dev/null || cp "$attest_path" "$payload"

  # Diagnostics extraction with safe defaults.
  get() { jq -r "$1 // \"-\"" "$payload" 2>/dev/null || echo "-"; }

  diag_root='.predicate.summary.diagnostics'
  procs=$(jq -r '.predicate.processes | length // 0' "$payload" 2>/dev/null || echo 0)
  top3=$(jq -r '[.predicate.processes[]? | (.openedfiles | length // 0)] | sort | reverse | .[:3] | tostring' "$payload" 2>/dev/null || echo '[]')
  unhashed=$(get "$diag_root.unhashedOpensTotal")
  bpf_drops=$(get "$diag_root.ringbufOpenatDrops")
  fan_timeouts=$(get "$diag_root.fanotifyTimeouts")
  fan_q=$(get "$diag_root.fanotifyQueueOverflows")
  fan_only=$(jq -r '.predicate.summary.fanotifyOnlyDigests | length // 0' "$payload" 2>/dev/null || echo 0)
  verity_sealed=$(get "$diag_root.fsVeritySealed")
  verity_fail=$(get "$diag_root.fsVeritySealFailures")
  fan_avail=$(get "$diag_root.fanotifyAvailable")
  verity_avail=$(get "$diag_root.fsVerityAvailable")
  capture_mode=$(get '.predicate.summary.captureMode')
  trace_detail=$(get '.predicate.summary.traceModeDetail')

  echo "$workload,$mode,$attest_kb,$procs,$top3,$unhashed,$bpf_drops,$fan_timeouts,$fan_q,$fan_only,$verity_sealed,$verity_fail,$fan_avail,$verity_avail,$capture_mode,$trace_detail" >> "$CSV"

  echo "| $workload | $mode | $attest_kb | $procs | $unhashed | $bpf_drops | $fan_timeouts | $fan_q | $fan_only | $verity_sealed | $fan_avail | $verity_avail |" >> "$MD"
done

echo "" >> "$MD"
echo "## Per-cell payloads" >> "$MD"
echo "" >> "$MD"
echo "Raw attestation payloads are in \`$OUT_DIR/raw/\` for deeper analysis." >> "$MD"

echo ""
echo "wrote $CSV and $MD"
echo ""
column -t -s, < "$CSV"
