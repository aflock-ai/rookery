#!/usr/bin/env bash
# Re-record this fixture from a REAL crane run under cilock. The fixture is the
# recorded output of a real run — NOT a hand-authored tarball — so re-record when
# crane (or the upstream hello-world image) changes and commit the diff
# (version/hash in fixture.yaml is the staleness signal). Requires: crane on
# PATH, network (pulls a tiny PUBLIC image, no creds), and a cilock built with
# the oci attestor (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes learned the hard way:
# - The oci attestor dispatches on product MIME application/x-tar (NOT filename).
#   crane --format=tarball writes a docker-save compatible tarball (manifest.json
#   + config blob + gzip layer) that the command-run attestor captures as a
#   product with that MIME; cilock then runs oci over it.
# - --platform=linux/amd64 is pinned so re-records are deterministic across the
#   recorder's host arch (hello-world is multi-arch; an unpinned pull would pick
#   the host platform and shift the image-id/layer/manifest digests).
# - hello-world is a TINY PUBLIC image (one tiny layer, no creds) — no secret,
#   no host path, no leak lands in the committed evidence. Keep --attestations
#   minimal (omit the environment attestor, which dumps env/host).
# - Work in a REPO-LOCAL dir (.record-work), never mktemp: macOS mktemp lands
#   under /private/var/folders, which would leak a system path into the signed,
#   un-editable attestation.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step oci-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations oci --enable-archivista=false \
    -- crane pull --platform=linux/amd64 --format=tarball hello-world:latest image.tar )
cp "$WORK/image.tar"        "$HERE/image.tar"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(crane version 2>/dev/null)\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v crane)" | awk '{print $1}')\""
