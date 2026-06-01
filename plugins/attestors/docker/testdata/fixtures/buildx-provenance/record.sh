#!/usr/bin/env bash
# Re-record this fixture from a REAL `docker buildx build` run under cilock. The
# fixture is the recorded output of a real build — NOT a hand-authored sample —
# so re-record when docker/buildx changes and commit the diff (version + binary
# digest in fixture.yaml is the staleness signal).
#
# Requires: docker + buildx on PATH, a `docker-container` buildx builder (the
# legacy `docker` driver CANNOT emit SLSA provenance — see detector.yaml's
# DOCKER_NO_PROVENANCE warning), and a cilock built with the docker attestor
# (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes:
# - The docker attestor is POSTPRODUCT: it consumes the buildx --metadata-file
#   JSON product (keys containerimage.digest, image.name, buildx.build.provenance
#   materials) — it does NOT parse `docker image inspect`. So the wrapped command
#   is a genuine `docker buildx build` that WRITES ./metadata.json into the run
#   dir; cilock records that file as an application/json product and the docker
#   attestor keys on it.
# - `--builder multiarch` selects a docker-container builder so --provenance is
#   accepted. `--platform linux/<host-arch>` keeps the result a single manifest
#   so the OCI exporter succeeds; `--provenance=mode=max` emits the SLSA build
#   materials (the base image) that become the materialdigest:/materialuri:
#   subjects. The base image is PINNED BY DIGEST in the Dockerfile so the build
#   materials are reproducible.
# - `--output type=oci,dest=image.tar` is used (not type=docker) because the
#   provenance attestation turns the result into an image INDEX, which the
#   `docker` exporter rejects ("does not currently support exporting manifest
#   lists"). The image.tar is a throwaway build artifact; only metadata.json is
#   consumed by the attestor. We delete image.tar before copying the fixture.
# - --attestations docker is MINIMAL on purpose: it omits the environment attestor
#   (which would dump host/env into the public attestation) and the git attestor
#   (the work dir is not a repo). cilock still adds command-run + product/material.
# - The committed metadata.json IS the replay source the catalog harness re-runs
#   the attestor against; it MUST be byte-identical to the file cilock recorded
#   as a product (the recorded-evidence cross-check compares the two predicates),
#   so we copy it straight out of the run dir.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
BUILDER="${BUILDX_BUILDER:-multiarch}"
PLATFORM="${BUILDX_PLATFORM:-linux/arm64}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step docker-build --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations docker --enable-archivista=false \
    -- docker buildx build --builder "$BUILDER" --platform "$PLATFORM" \
       --provenance=mode=max --metadata-file metadata.json \
       --output type=oci,dest=image.tar -t dbx-fixture:test .
  rm -f image.tar key.pem )
cp "$WORK/metadata.json"    "$HERE/metadata.json"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(docker buildx version 2>/dev/null | awk '{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v docker)" | awk '{print $1}')\""
