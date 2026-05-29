#!/usr/bin/env bash
# Re-record this fixture from a REAL CINC Auditor (open-source InSpec) run under
# cilock. The fixture is the recorded output of a real run — NOT a hand-authored
# sample. CINC Auditor is run in the cincproject/auditor container against the
# real, public dev-sec/linux-baseline profile (fetched from GitHub at record
# time), scanning the auditor container itself via the local transport. The json
# reporter output (inspec.json) is the genuine tool output, not invented.
#
# Re-record when CINC Auditor / the profile changes and commit the diff.
# Requires: docker (Docker Desktop up), network to GitHub (to fetch the profile),
# and a cilock built with the inspec attestor (e.g.
# `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes:
# - The inspec attestor is POSTPRODUCT: it consumes the json reporter output as a
#   Product (mime application/json) and derives subjects from the parsed report —
#   platform:<os>-<release>, profile:<name>, and inspec:control:<id> for each
#   FAILING control. So the recorded scan MUST have at least one failing control
#   for the inspec:control: family to appear (dev-sec/linux-baseline reliably
#   fails several controls on a stock ubuntu container).
# - cilock does NOT invoke the generator (it warns "no generator found on PATH");
#   it RECORDS the wrapped command's output. The wrapped `sh -c '...; true'` runs
#   the real `cinc-auditor exec` in the container, writing /work/inspec.json with
#   a RELATIVE basename (no host/absolute path leaks). The trailing `; true`
#   neutralizes ONLY the non-zero exit CINC returns on control failures so cilock
#   still records the command-run + product sub-attestations with the real argv.
#   The tool's actual output is not altered.
# - --chef-license accept-silent satisfies CINC's first-run license gate
#   non-interactively (no credential, just the OSS license acceptance).
# - --attestations inspec is MINIMAL on purpose: it omits the environment attestor
#   (which would dump host/env into the public attestation) and the git attestor
#   (the work dir is not a repo). cilock still adds command-run + product/material.
# - The work dir is repo-local (.record-work), NEVER mktemp/tmp, and is mounted
#   into the container as /work so the relative inspec.json lands there.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
IMAGE="${IMAGE:-cincproject/auditor}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step inspec-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations inspec --enable-archivista=false \
    -- sh -c "docker run --rm -v \"\$PWD\":/work -w /work $IMAGE exec https://github.com/dev-sec/linux-baseline --reporter json:/work/inspec.json --chef-license accept-silent; true" )
cp "$WORK/inspec.json" "$HERE/inspec.json"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(docker run --rm "$IMAGE" version 2>/dev/null | head -1)\""
echo "  binary_sha256: \"$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null | sed 's/.*@sha256://')\"  # image digest"
