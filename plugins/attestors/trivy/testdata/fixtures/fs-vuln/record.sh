#!/usr/bin/env bash
# Re-record this fixture from a REAL trivy run under cilock. The fixture is the
# recorded output of a real run — NOT a hand-copied sample — so re-record when
# trivy changes and commit the diff (version/hash in fixture.yaml is the
# staleness signal). Requires: trivy on PATH, and a cilock built with the trivy
# attestor (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step trivy-scan --signer-file-key-path key.pem \
    --outfile attestation.json --attestations trivy --enable-archivista=false \
    -- trivy fs --format json --output trivy-results.json . )
cp "$WORK/trivy-results.json" "$HERE/trivy-results.json"
cp "$WORK/attestation.json"   "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(trivy --version 2>/dev/null | awk '/Version:/{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v trivy)" | awk '{print $1}')\""
