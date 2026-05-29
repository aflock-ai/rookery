#!/usr/bin/env bash
# Re-record this fixture from a REAL gosec run under cilock. The fixture is the
# recorded output of a real run — NOT a hand-copied sample — so re-record when
# gosec changes and commit the diff (version/hash in fixture.yaml is the
# staleness signal). Requires: gosec on PATH, and a cilock built with the sarif
# attestor (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# NOTE: the work dir is created under the repo (NOT mktemp) for parity with the
# other recorders. -quiet suppresses gosec's progress log — without it gosec
# writes the absolute import/check paths to stderr, which the command-run
# attestor would then capture into the committed (public) attestation.json.
# gosec is offline + deterministic; the SARIF body carries no invocation
# timestamps.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step sarif-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations sarif --enable-archivista=false \
    -- gosec -quiet -fmt=sarif -out=results.sarif.json -no-fail ./... )
cp "$WORK/results.sarif.json" "$HERE/results.sarif.json"
cp "$WORK/attestation.json"   "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(gosec --version 2>&1 | awk '/Version:/{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v gosec)" | awk '{print $1}')\""
