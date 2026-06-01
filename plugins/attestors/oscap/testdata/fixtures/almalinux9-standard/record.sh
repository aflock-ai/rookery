#!/usr/bin/env bash
# Re-record this fixture from a REAL OpenSCAP run under cilock. The fixture is
# the recorded output of a real `oscap xccdf eval` — NOT a hand-authored sample.
#
# The scan runs inside an almalinux:9 container that carries the openscap
# scanner + the SCAP Security Guide content. We evaluate the AlmaLinux 9 SCAP
# datastream (ssg-almalinux9-ds.xml) against the ANSSI-BP-028 (minimal) profile
# and write the XCCDF results XML — that results file IS the product the oscap
# postproduct attestor parses.
#
# Re-record when openscap or the SSG content changes and commit the diff.
# Requires: docker (Linux container), and a cilock built with the oscap attestor
# (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes:
# - The oscap attestor is POSTPRODUCT: it consumes the .xml results file that the
#   wrapped command produced (cilock's always-on product attestor captures it).
#   The scanner's own output is recorded verbatim — we do NOT edit it.
# - The scan runs in a container; we mount the repo-local .record-work dir into
#   the container at /work and write a RELATIVE output name (oscap-results.xml)
#   so no absolute host path leaks into the recorded predicate's reportFile.
# - oscap exits 2 when any rule fails (it does — 1 fail here). We neutralize ONLY
#   the exit code with `|| true` so cilock still records the command-run
#   sub-attestation with the real argv. The tool's actual output is unchanged.
# - --attestations oscap is MINIMAL on purpose: it omits the environment attestor
#   (which would dump host/env into the public attestation) and the git attestor
#   (the work dir is not a repo). cilock still adds command-run + product/material.
# - The target host id in the report is the ephemeral docker container id (benign,
#   not a host hostname); it is identical in the recorded predicate and on replay
#   because both read the same committed results XML.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
PROFILE="xccdf_org.ssgproject.content_profile_anssi_bp28_minimal"
DS="/usr/share/xml/scap/ssg/content/ssg-almalinux9-ds.xml"

# Build the scanner image from the committed Dockerfile (idempotent).
docker build -t oscap-runner "$HERE/scanner-image"

WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step oscap-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations oscap --enable-archivista=false \
    -- sh -c "docker run --rm -v \"\$PWD\":/work -w /work oscap-runner oscap xccdf eval --profile $PROFILE --results oscap-results.xml $DS || true" )
cp "$WORK/oscap-results.xml" "$HERE/oscap-results.xml"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(docker run --rm oscap-runner oscap --version 2>/dev/null | awk '/^OpenSCAP/{print $NF; exit}')\""
echo "  binary_sha256: \"$(docker run --rm oscap-runner sh -c 'sha256sum "$(command -v oscap)"' 2>/dev/null | awk '{print $1}')\""
