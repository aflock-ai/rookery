#!/usr/bin/env bash
# Re-record this fixture from a REAL prowler run under cilock. The fixture is the
# recorded output of a real run — NOT a hand-authored sample — so re-record when
# prowler changes and commit the diff (the version/hash in fixture.yaml is the
# staleness signal).
#
# This fixture scans a LIVE AWS account, so it is NOT hermetically re-runnable in
# CI (it needs read-only AWS creds + network). The committed prowler-output.json
# IS the real scan output; the catalog harness replays it hermetically. This
# script is the operator recipe for refreshing it.
#
# Requires:
#   - prowler 3.11.3 on PATH
#   - read-only AWS creds for the testifysec-demo account (898769392027):
#       AWS_PROFILE=testifysec-demo-readonly
#   - a cilock built with the prowler attestor (e.g. `go build ./presets/all/cmd/cilock-all`)
#   CILOCK=/path/to/cilock-all AWS_PROFILE=testifysec-demo-readonly ./record.sh
#
# Notes:
# - Modeled on the maven record.sh: a REPO-LOCAL .record-work workdir (never
#   mktemp / never /tmp) so no absolute temp path leaks into the attestation, and
#   an ephemeral ed25519 key generated per-run.
# - The prowler attestor is POSTPRODUCT: it parses the prowler JSON report from
#   the products. The wrapped command is a real `prowler aws` invocation; cilock
#   captures its command-run + the product file as evidence and the prowler
#   attestor normalizes the report into the signed summary.
# - `-F prowler-output -o .` writes ./prowler-output.json as a RELATIVE filename
#   in the workdir, so the attestor's reportFile/path is relative (not an
#   absolute home path) — required to keep public evidence path-clean.
# - `-z` (--ignore-exit-code-3) makes prowler exit 0 even when there are FAIL
#   findings. Without it prowler exits 3, which cilock treats as a fatal command
#   failure and DROPS the command-run attestation from the signed collection —
#   the recorded argv would then be missing and the catalog cross-check fails.
#   `-z` only suppresses the exit code; the findings (FAILs included) are intact.
# - --service cloudtrail keeps output small (4 findings) and references only the
#   account-root ARN, so no operator-username-shaped string lands in public
#   evidence, while still emitting all three subject families
#   (aws:account / aws:arn / aws:service).
# - --attestations prowler is MINIMAL on purpose: it omits the environment
#   attestor (which would dump host/env into the public attestation) and the git
#   attestor. cilock still adds command-run + product/material.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step prowler-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations prowler --enable-archivista=false \
    -- prowler aws --service cloudtrail --region us-east-1 -z -M json -F prowler-output -o . )
cp "$WORK/prowler-output.json" "$HERE/prowler-output.json"
cp "$WORK/attestation.json"    "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(prowler --version 2>/dev/null | awk '/^Prowler/{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v prowler)" | awk '{print $1}')\""
