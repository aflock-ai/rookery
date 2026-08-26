#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOKERY_ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CILOCK_BIN="${CILOCK_BIN:-$WORK/cilock}"
if [[ ! -x "$CILOCK_BIN" ]]; then
  (
    cd "$ROOKERY_ROOT/cilock"
    GOWORK=off go build -trimpath -o "$CILOCK_BIN" ./cmd/cilock
  )
fi

openssl genpkey -algorithm ed25519 -out "$WORK/key.pem"
(
  cd "$ROOKERY_ROOT"
  "$CILOCK_BIN" run \
    --step alps-evidence-reproduction \
    --workload manual \
    --platform-url '' \
    --signer-file-key-path "$WORK/key.pem" \
    --attestations alps-evidence \
    --enable-archivista=false \
    --outfile "$WORK/attestation.json" \
    -- true
)

python3 - "$WORK/attestation.json" <<'PY'
import base64
import json
import sys

envelope = json.load(open(sys.argv[1], encoding="utf-8"))
statement = json.loads(base64.b64decode(envelope["payload"]))
items = statement["predicate"]["attestations"]
item = next(
    entry for entry in items
    if entry["type"] == "https://aflock.ai/attestations/alps-evidence/v0.1"
)
predicate = item["attestation"]
assert predicate["status"] in {"detected", "not-detected", "incomplete", "unavailable"}
assert predicate["assurance"]["enforcement"] is False
print(json.dumps({
    "status": predicate["status"],
    "invoker": predicate.get("invoker", {}).get("product"),
    "enforcement": predicate["assurance"]["enforcement"],
}, sort_keys=True))
PY
