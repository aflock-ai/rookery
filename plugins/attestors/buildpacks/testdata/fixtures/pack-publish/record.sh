#!/usr/bin/env bash
# Re-record this fixture from a REAL `pack build` run under cilock. The fixture
# is the recorded output of a real build — NOT a hand-authored sample — so
# re-record when pack/lifecycle changes and commit the diff (version + binary
# digest in fixture.yaml is the staleness signal).
#
# Requires: pack + a docker daemon on PATH, a MULTI-ARCH builder (amd64-only
# builders crash under emulation on arm64 hosts — see the doc.md Gotchas), a
# registry reachable from the lifecycle (below: a local registry:2 container on
# :5001 with --network host; :5000 collides with macOS AirPlay), and a cilock
# built with the buildpacks attestor.
#   CILOCK=/path/to/cilock ./record.sh
#
# Notes:
# - The buildpacks attestor is POSTPRODUCT: it consumes the lifecycle's
#   report.toml product written by --report-output-dir. This recording is
#   deliberately REPORT-ONLY (no --sbom-output-dir, no labels dump): the testkit
#   product mode injects exactly one product on replay, and the recorded-evidence
#   cross-check requires replayed == recorded predicates. The labels/SBOM paths
#   are covered by the unit suite; a richer fixture needs multi-product testkit
#   support first.
# - --publish is REQUIRED for identity: a daemon export writes image-id only,
#   which mints no imagedigest subject by design.
# - --attestations buildpacks is MINIMAL on purpose: it omits the environment
#   attestor (host/env in a public attestation) and git (the work dir is not a
#   repo). cilock still adds command-run + product/material.
# - The committed report.toml IS the replay source; it must be byte-identical to
#   the product cilock recorded, so it is copied straight out of the run dir.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
BUILDER="${PACK_BUILDER:-heroku/builder:24}"
REGISTRY_IMAGE="${FIXTURE_IMAGE:-localhost:5001/bp-fixture}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step buildpacks-build --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations buildpacks --enable-archivista=false \
    -- pack build "$REGISTRY_IMAGE" --builder "$BUILDER" \
       --publish --network host --report-output-dir .
  rm -f key.pem )
cp "$WORK/report.toml"      "$HERE/report.toml"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(pack version 2>/dev/null)\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v pack)" | awk '{print $1}')\""
