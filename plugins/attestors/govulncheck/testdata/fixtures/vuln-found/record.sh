#!/usr/bin/env bash
# Re-record this fixture from a REAL govulncheck run under cilock. The fixture is
# the recorded output of a real run — NOT a hand-copied sample — so re-record
# when govulncheck or the Go vuln DB changes and commit the diff. Requires:
# govulncheck on PATH, network (Go vuln DB), and a cilock built with the
# govulncheck attestor (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes learned the hard way:
# - GOWORK=off is REQUIRED: a parent go.work excludes this nested demo module,
#   so govulncheck/go would otherwise refuse "directory ... not in go.work".
# - govulncheck writes JSON to stdout, so it is wrapped in `bash -c '... >
#   govulncheck.json'` to produce a product FILE for the attestor to consume.
# - go:vuln: subjects require a SYMBOL-reachable finding: main.go calls
#   golang.org/x/text/language.ParseAcceptLanguage (the GO-2022-1059 symbol),
#   not just any function in the vulnerable package — package-level reachability
#   does not set Finding.Reachable, so it would emit go:module: but no go:vuln:.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step govulncheck-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations govulncheck --enable-archivista=false \
    -- bash -c 'GOWORK=off govulncheck -format json ./... > govulncheck.json' )
cp "$WORK/govulncheck.json" "$HERE/govulncheck.json"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(govulncheck -version 2>/dev/null | awk '/Scanner:/{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v govulncheck)" | awk '{print $1}')\""
