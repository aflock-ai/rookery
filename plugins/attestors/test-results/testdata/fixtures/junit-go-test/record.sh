#!/usr/bin/env bash
# Re-record this fixture from a REAL `go test` + go-junit-report run under cilock.
# The fixture is the recorded output of a real run — NOT a hand-authored sample —
# so re-record when the toolchain changes and commit the diff (version/hash in
# fixture.yaml is the staleness signal). Requires: go + go-junit-report on PATH,
# and a cilock built with the test-results attestor
# (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes learned the hard way:
# - GOWORK=off is REQUIRED: a parent go.work excludes this nested throwaway demo
#   module, so `go test` would otherwise refuse "directory ... not in go.work".
# - `go test` exits non-zero when tests fail (this fixture intentionally has 2
#   failures so a `test-failure:` subject exists). The wrapper writes junit.xml
#   and then `exit 0` so cilock's command-run succeeds and the product attestor
#   digests junit.xml. The non-zero `go test` status is captured inside the pipe.
# - go-junit-report reads `go test -v` output on stdin and writes JUnit XML; the
#   product FILE junit.xml is what the test-results attestor consumes.
# - A repo-local .record-work dir is used (NOT mktemp): macOS mktemp lands under
#   /private/var/folders, which would leak a system path into the evidence.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step test-results-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations test-results --enable-archivista=false \
    -- bash -c 'GOWORK=off go test -v ./... 2>&1 | GOWORK=off go-junit-report > junit.xml; exit 0' )
cp "$WORK/junit.xml"        "$HERE/junit.xml"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(go version 2>/dev/null | awk '{print $3}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v go)" | awk '{print $1}')\""
