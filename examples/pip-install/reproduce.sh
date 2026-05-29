#!/usr/bin/env bash
# Reproduce the pip-install attestor example: run a REAL `pip install` under
# cilock inside a clean Python container and capture the REAL signed
# attestation.
#
# pip-install is a LIVE-ENVIRONMENT INTROSPECTOR: it shells out to
# pip3/python3 against the freshly-installed environment AND makes live,
# unauthenticated HTTP calls to pypi.org to check PEP 740 provenance. It
# therefore CANNOT be replayed hermetically by the catalog-coverage harness
# the way the artifact-parsing attestors are. The committed examples/pip-install
# /attestation.json IS the real signed (ed25519) collection from one such run;
# this script regenerates an equivalent one.
#
# The captured predicate is NOT bit-for-bit reproducible: package versions
# float as PyPI publishes new releases, install Location varies by interpreter,
# and pep740Verification depends on PyPI's current provenance state and network
# availability. What IS stable and is the proof: a real `pip install requests`
# yields real package coordinates and real `pip://<name>@<version>` subjects.
#
# Requires: Docker. The cilock binary must be a linux/amd64 build FROM THIS
# TREE so the recorded evidence matches the attestor code under test (it runs
# under qemu/Rosetta emulation on arm64 hosts transparently).
#
# Usage:
#   ./reproduce.sh                       # builds cilock-all from the tree
#   CILOCK_BIN=/path/to/cilock-all ./reproduce.sh   # use a prebuilt binary
set -euo pipefail

PKG="${PKG:-requests}"          # any real PyPI package; requests pulls 4 deps
CONTAINER="pip-install-example"
IMAGE="python:3.12-slim"

# 1. Build (or reuse) a linux/amd64 cilock-all FROM THIS TREE.
#    The repo root is two levels up from examples/pip-install/.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CILOCK_BIN="${CILOCK_BIN:-/tmp/cilock-all}"
if [ ! -x "$CILOCK_BIN" ]; then
  echo ">> building cilock-all (linux/amd64) from $REPO_ROOT"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -o "$CILOCK_BIN" ./presets/all/cmd/cilock-all )
fi
echo ">> cilock binary sha256:"
shasum -a 256 "$CILOCK_BIN"

# 2. Start a clean Python container (needs network for the real pip download
#    AND for the attestor's live PyPI PEP 740 calls).
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" "$IMAGE" sleep infinity >/dev/null
trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1 || true' EXIT

docker cp "$CILOCK_BIN" "$CONTAINER:/usr/local/bin/cilock"
docker exec "$CONTAINER" chmod +x /usr/local/bin/cilock

# 3. Generate an EPHEMERAL ed25519 signing key INSIDE the container. It never
#    leaves the container and is destroyed with it (step 6). NEVER copy the
#    private key out; NEVER commit it. (openssl ships in python:3.12-slim.)
docker exec "$CONTAINER" sh -c \
  'openssl genpkey -algorithm ed25519 -out /tmp/key.pem && \
   openssl pkey -in /tmp/key.pem -pubout -out /tmp/pub.pem'

# 4. Run a REAL `pip install` wrapped by cilock with the pip-install attestor.
#    --platform-url "" keeps the run fully offline (no TSA) — the only network
#    is pip's own download + the attestor's PyPI provenance lookups.
#    --workload manual makes --attestations the exact set (product is always on).
docker exec "$CONTAINER" mkdir -p /work
docker exec -w /work "$CONTAINER" sh -c "cilock run \
  --step pip-install-capture \
  --workload manual \
  --platform-url '' \
  --signer-file-key-path /tmp/key.pem \
  --attestations product,pip-install \
  --enable-archivista=false \
  --outfile /work/attestation.json \
  -- pip install $PKG"

# 5. Pull the real signed collection out.
docker cp "$CONTAINER:/work/attestation.json" ./attestation.json
echo ">> attestation.json sha256:"
shasum -a 256 ./attestation.json

# 6. Verify the ed25519 signature over the DSSE PAE, using the public key
#    copied out of the container (the PRIVATE key stays inside).
docker cp "$CONTAINER:/tmp/pub.pem" /tmp/pip-example-pub.pem
python3 - <<'PYEOF'
import json, base64
d = json.load(open('attestation.json'))
payload = base64.b64decode(d['payload'])
ptype = d['payloadType'].encode()
sig = base64.b64decode(d['signatures'][0]['sig'])
# DSSE Pre-Authentication Encoding
pae = b"DSSEv1 " + str(len(ptype)).encode() + b" " + ptype + b" " \
    + str(len(payload)).encode() + b" " + payload
open('/tmp/pip-example-pae.bin','wb').write(pae)
open('/tmp/pip-example-sig.bin','wb').write(sig)
PYEOF
openssl pkeyutl -verify -pubin -inkey /tmp/pip-example-pub.pem \
  -rawin -in /tmp/pip-example-pae.bin -sigfile /tmp/pip-example-sig.bin

# 7. TEARDOWN (also runs via the EXIT trap): destroys the container and the
#    ephemeral private key with it. Scrub the local verify scratch files.
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
trap - EXIT
rm -f /tmp/pip-example-pub.pem /tmp/pip-example-pae.bin /tmp/pip-example-sig.bin
echo ">> done. container removed; ephemeral key destroyed."
