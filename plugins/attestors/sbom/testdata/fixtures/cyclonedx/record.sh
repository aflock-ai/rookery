#!/usr/bin/env bash
# Re-record this fixture from a REAL syft run under cilock. The fixture is the
# recorded output of a real run — NOT a hand-copied sample — so re-record when
# syft changes and commit the diff (version/hash in fixture.yaml is the
# staleness signal). Requires: syft on PATH, and a cilock built with the sbom
# attestor (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# NOTE: the work dir is created under the repo (NOT mktemp). On macOS, mktemp
# lands under /private/var/folders, and `syft scan dir:.` there walks far beyond
# the intended tree (system /private/var caches). A repo-local work dir keeps
# syft confined to the synthetic input. --select-catalogers "-file" drops the
# per-file component (which would otherwise embed the input's absolute path);
# --source-name/--source-version give metadata.component the name+version that
# back the name:/version: subjects.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step sbom-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations sbom --enable-archivista=false \
    -- syft scan dir:. --source-name demo-app --source-version 1.0.0 --select-catalogers "-file" -o cyclonedx-json=bom.cdx.json )
cp "$WORK/bom.cdx.json"     "$HERE/bom.cdx.json"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(syft version 2>/dev/null | awk '/Version:/{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v syft)" | awk '{print $1}')\""
