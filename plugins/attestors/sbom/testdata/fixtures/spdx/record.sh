#!/usr/bin/env bash
# Re-record this fixture from a REAL syft run under cilock (SPDX-JSON variant).
# The fixture is the recorded output of a real run — NOT a hand-copied sample —
# so re-record when syft changes and commit the diff (version/hash in
# fixture.yaml is the staleness signal). Requires: syft on PATH, and a cilock
# built with the sbom attestor (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Work dir is repo-local (NOT mktemp): on macOS mktemp lands under
# /private/var/folders, where `syft scan dir:.` walks far beyond the intended
# tree. --select-catalogers "-file" drops the per-file component (which would
# embed the input's absolute path); --source-name/--source-version give the SPDX
# document the name that backs the name: subject.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step sbom-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations sbom --enable-archivista=false \
    -- syft scan dir:. --source-name demo-app --source-version 1.0.0 --select-catalogers "-file" -o spdx-json=bom.spdx.json )
cp "$WORK/bom.spdx.json"   "$HERE/bom.spdx.json"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(syft version 2>/dev/null | awk '/Version:/{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v syft)" | awk '{print $1}')\""
