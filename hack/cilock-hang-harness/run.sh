#!/usr/bin/env bash
# Fast-iteration cilock hang repro harness.
#
# Reproduces the exact ci.yml attest invocation inside a privileged Linux
# container (colima) so we can see WHERE cilock hangs in seconds, not a 15-min
# CI cycle. The probe.sh watchdog inside the container dumps process State +
# kernel stack on hang (D = uninterruptible/SIGKILL-immune, S = network wait).
#
# Loop: edit cilock → `make cilock` → `./run.sh <scenario>` → read the State.
#
# Scenarios (mirror the real ci.yml steps):
#   offline      no platform/upload/trace — isolates signing from the network.
#                If clean, the hang is in the upload/OIDC path, not local.
#   source-git   bare source attest → Archivista (ci.yml build-images step 1).
#                Ambient OIDC is absent locally so upload AUTH fails — but a
#                FAILURE is fine; we hunt a HANG. Hang here = no upload deadline.
#   stall        attest against a black-hole TCP endpoint that accepts then
#                never replies — the canonical "TCP-accept-then-stall" that a
#                missing client timeout turns into a 20-min hang.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCENARIO="${1:-offline}"
PLATFORM_URL="${PLATFORM_URL:-https://platform.aws-sandbox-staging.testifysec.dev}"
WATCHDOG_SECS="${WATCHDOG_SECS:-90}"
# Image with git + openssl + ca-certs so the git attestor and TLS work.
IMAGE="${IMAGE:-alpine:3.20}"

[ -x "$HERE/bin/cilock-linux" ] || { echo "missing bin/cilock-linux — run 'make cilock'" >&2; exit 1; }
[ -f "$HERE/k.key" ] || { echo "missing k.key — run: openssl ecparam -name prime256v1 -genkey -noout -out k.key" >&2; exit 1; }

case "$SCENARIO" in
  offline)
    INNER='/h/probe.sh /h/bin/cilock-linux run \
      --step source-git --workingdir /work \
      --platform-url "" --no-default-attestor material \
      -k /h/k.key -a environment,git \
      -- /bin/true'
    PRE='setup_repo'
    ;;
  source-git)
    INNER="/h/probe.sh /h/bin/cilock-linux run \
      --step source-git --workingdir /work \
      --platform-url '$PLATFORM_URL' \
      --archivista-server '$PLATFORM_URL/archivista' \
      --enable-archivista \
      --attestations environment,git \
      -- /bin/true"
    PRE='setup_repo'
    ;;
  stall)
    # nc -l accepts the TCP connection then holds it open, never sending an
    # HTTP response — the exact TCP-accept-then-stall shape. Point cilock's
    # archivista-server at it: a bounded client errors in ~Ns, an unbounded
    # one parks until the watchdog.
    INNER="( nc -l -p 9099 >/dev/null & sleep 1; \
      /h/probe.sh /h/bin/cilock-linux run \
        --step source-git --workingdir /work \
        --platform-url http://127.0.0.1:9099 \
        --archivista-server http://127.0.0.1:9099 \
        --enable-archivista \
        -k /h/k.key --no-default-attestor material -a environment \
        -- /bin/true )"
    PRE='setup_repo'
    ;;
  *)
    echo "unknown scenario: $SCENARIO (offline|source-git|stall)" >&2; exit 1 ;;
esac

echo "▶ scenario=$SCENARIO platform=$PLATFORM_URL watchdog=${WATCHDOG_SECS}s image=$IMAGE"

docker run --rm --privileged \
  -e WATCHDOG_SECS="$WATCHDOG_SECS" -e LABEL="$SCENARIO" \
  -v "$HERE:/h:ro" -w /work \
  "$IMAGE" \
  sh -c "
    set -e
    apk add --no-cache bash git openssl ca-certificates netcat-openbsd >/dev/null 2>&1 || true
    setup_repo() { mkdir -p /work && cd /work && git init -q . && \
      git config user.email a@b.c && git config user.name t && \
      git commit -q --allow-empty -m init; }
    $PRE
    $INNER
  "
