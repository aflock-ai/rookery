#!/usr/bin/env bash
# Re-record this fixture from a REAL Falco run under cilock. The fixture is the
# recorded output of a real eBPF capture — NOT a hand-authored sample — so
# re-record when Falco changes and commit the diff (the version/hash in
# fixture.yaml is the staleness signal).
#
# Falco is a LIVE runtime threat detector: it loads an eBPF probe into the kernel
# and streams syscall events. Its output is inherently NON-REPRODUCIBLE (every
# event carries a fresh timestamp / evt id, and each references a short-lived
# container id that exists only for that run), so this fixture is LIVE-EXEMPT for
# the catalog live re-verify gate — there is deliberately NO recording-input/
# directory for it to re-run, the same as prowler's live AWS scan. The committed
# falco-events.jsonl IS real eBPF output; the hermetic catalog gate replays it.
#
# Requirements (macOS dev env used here):
#   - Docker Desktop running (Falco loads its eBPF probe into the LinuxKit VM
#     kernel; on this box: Linux 6.10.14-linuxkit, aarch64).
#   - falcosecurity/falco:latest pulled (Falco 0.44.0 here).
#   - a cilock built with the falco attestor (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes:
# - Two-phase by necessity. Phase 1 is the GENUINE Falco capture: a privileged
#   container loads the modern-eBPF probe and writes line-delimited JSON events
#   to falco-events.real.jsonl while a trigger loop spawns throwaway containers
#   that read /etc/shadow (firing the stable "Read sensitive file untrusted"
#   rule). Falco cannot run as a plain on-PATH binary in this env (no host eBPF),
#   so it is not the cilock-wrapped command.
# - Phase 2 records under cilock: a PATH-CLEAN `sh -c 'cat … > …'` emits the real
#   captured events as the product falco-events.jsonl, which the falco
#   PostProduct attestor parses. cilock signs the command-run + product/material
#   + falco attestation. The recorded argv is this emit (it matches
#   recording.argv in fixture.yaml); the real Falco argv is documented below.
# - REPO-LOCAL .record-work (never /tmp) and an ephemeral ed25519 key keep the
#   recording free of absolute home/temp paths. --attestations falco is MINIMAL
#   (omits environment/git which would dump host/env into public evidence).
# - --enable-archivista=false keeps it offline; relative product paths only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null

  # ---- Phase 1: GENUINE live Falco eBPF capture --------------------------------
  : > falco-events.real.jsonl; chmod 666 falco-events.real.jsonl
  # Trigger loop: spawn throwaway containers reading /etc/shadow for the window.
  END=$(( $(date +%s) + 60 ))
  ( while [ "$(date +%s)" -lt "$END" ]; do
      docker run --rm alpine:latest sh -c 'cat /etc/shadow >/dev/null 2>&1' >/dev/null 2>&1
    done ) &
  TRIGGER=$!
  # Falco loads the modern-eBPF probe and writes JSON events to the mounted file.
  # NOTE: the -v mount needs an absolute path for docker; this container runs
  # OUTSIDE cilock so that absolute path is never recorded into public evidence.
  docker run --rm --privileged \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e HOST_ROOT=/host -v /etc:/host/etc:ro -v /proc:/host/proc:ro \
    -v "$WORK":/out \
    falcosecurity/falco:latest \
    falco -o engine.kind=modern_ebpf -o json_output=true \
          -o stdout_output.enabled=false \
          -o file_output.enabled=true -o file_output.keep_alive=false \
          -o file_output.filename=/out/falco-events.real.jsonl \
          -o log_level=warning -M 25
  kill "$TRIGGER" 2>/dev/null || true
  if [ ! -s falco-events.real.jsonl ]; then
    echo "ERROR: Falco captured zero events — the eBPF probe may not have attached, or no triggers fired in the window. Re-run." >&2
    exit 1
  fi

  # ---- Phase 2: path-clean cilock recording of the real events -----------------
  "$CILOCK" run --step falco-runtime-capture --workload manual \
    --signer-file-key-path key.pem \
    --outfile attestation.json --attestations falco --enable-archivista=false \
    -- sh -c 'cat falco-events.real.jsonl > falco-events.jsonl' )

cp "$WORK/falco-events.jsonl" "$HERE/falco-events.jsonl"
cp "$WORK/attestation.json"   "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(docker run --rm falcosecurity/falco:latest falco --version 2>/dev/null | awk '/Falco version:/{print $4; exit}')\""
echo "  binary_sha256: \"$(docker run --rm --entrypoint sh falcosecurity/falco:latest -c 'sha256sum /usr/bin/falco' 2>/dev/null | awk '{print $1}')\""
