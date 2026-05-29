#!/usr/bin/env bash
# Re-record this fixture from a REAL docker/docker-bench-security run under
# cilock. The fixture is the recorded output of a real audit of the LIVE Docker
# daemon — NOT a hand-authored sample — so re-record when docker-bench changes
# and commit the diff (the version/hash in fixture.yaml is the staleness
# signal).
#
# This fixture audits a LIVE Docker daemon via /var/run/docker.sock, so it is
# NOT hermetically re-runnable in CI (it needs a running dockerd + the host's
# container/image state). The committed docker-bench.log.json IS the real audit
# output; the catalog harness replays it hermetically. This script is the
# operator recipe for refreshing it.
#
# Requires:
#   - a running Docker daemon (Docker Desktop or dockerd) reachable at
#     /var/run/docker.sock
#   - the docker/docker-bench-security image (pulled on first run)
#   - a cilock built with the docker-bench attestor (presets/all/cmd/cilock-all)
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes:
# - Modeled on the prowler/trivy record.sh: a REPO-LOCAL .record-work workdir
#   (never mktemp / never /tmp) so no absolute temp path leaks into the
#   attestation, and an ephemeral ed25519 key generated per-run.
# - The docker-bench attestor is POSTPRODUCT: it parses the docker-bench JSON
#   report from the products. cilock runs in .record-work, the bench container
#   bind-mounts that dir to /report via a RELATIVE `-v ./:/report` source (NOT
#   $PWD) so no absolute home path lands in the recorded command-run argv, and
#   `-l /report/docker-bench.log` makes the tool write ./docker-bench.log.json
#   as a RELATIVE filename in the cilock workdir, so the attestor's report_file
#   path is relative (not an absolute home path) — both required to keep public
#   evidence path-clean. Do NOT pass `-w`: it breaks the tool's relative
#   sourcing of its check scripts.
# - A throwaway `dbfix-sleep` container is started before the audit and removed
#   after, so the Container Runtime section always reports at least one
#   container and a real `container:` subject is produced even on an otherwise
#   idle daemon. The host's other running containers are legitimately audited
#   too (their names are not secrets).
# - `--attestations docker-bench` is MINIMAL on purpose: it omits the
#   environment attestor (which would dump host/env into the public
#   attestation) and the git attestor. cilock still adds product + material.
# - `|| true` neutralizes ONLY the bench tool's exit code (it can exit non-zero
#   when WARN checks are present) so cilock keeps the command-run attestation;
#   the JSON output is unaltered.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT

docker rm -f dbfix-sleep >/dev/null 2>&1 || true
docker run -d --name dbfix-sleep alpine:3.20 sleep 600 >/dev/null
trap 'docker rm -f dbfix-sleep >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step docker-bench-audit --signer-file-key-path key.pem \
    --outfile attestation.json --attestations docker-bench --enable-archivista=false \
    -- docker run --rm --net host --pid host --userns host --cap-add audit_control \
       -v /var/run/docker.sock:/var/run/docker.sock -v ./:/report \
       docker/docker-bench-security -b -l /report/docker-bench.log || true )

cp "$WORK/docker-bench.log.json" "$HERE/docker-bench.log.json"
cp "$WORK/attestation.json"      "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(docker run --rm docker/docker-bench-security --version 2>/dev/null | head -1 || echo unknown)\""
echo "  binary_sha256: \"$(docker image inspect --format '{{.Id}}' docker/docker-bench-security 2>/dev/null | sed 's/^sha256://')\""
