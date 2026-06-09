#!/usr/bin/env bash
# Local end-to-end test for MULTI-STEP policy verification using INLINE LEAVES
# (the v0.3 default — no chain sidecar required):
#   source step (produces a material) -> binary-build step (consumes it via
#   artifactsFrom, produces the binary) -> cilock verify <binary>.
#
# The product/material v0.3 attestors embed their per-file Merkle leaves in the
# signed predicate by default, so the engine rehydrates upstream Products() and
# downstream Materials() from the (signed, root-checked) leaves and verifies the
# artifactsFrom chain with NO sidecar. This proves:
#   POSITIVE   — chain verifies from inline leaves alone (off-envelope chain sidecars were removed).
#   NEGATIVE 1 — forging an inline leaf so it no longer reconstructs to the
#                signed merkleRoot is rejected (VerifyInlineLeaves fails closed).
#   NEGATIVE 2 — a downstream material whose digest disagrees with the upstream
#                product for the same path is rejected (compareArtifacts).
#
# Run: CILOCK=/path/to/cilock ./multistep_verify_e2e.sh
set -euo pipefail

CILOCK="${CILOCK:-cilock}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
echo "workdir: $WORK"

openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
openssl pkey -in key.pem -pubout -out pub.pem 2>/dev/null
KEYID="$("$CILOCK" keyid show pub.pem 2>/dev/null | awk 'NR==1{print $1}')"
echo "keyid: $KEYID"

# --- Step "source": produce a shared material the build will consume. ---
mkdir -p src
"$CILOCK" run --step source --workingdir "$WORK/src" \
  --attestations environment --signer-file-key-path key.pem \
  --outfile source.att.json \
  -- bash -c "printf 'shared-library-content\n' > $WORK/src/libshared.so" >/dev/null 2>&1
ls source.att.json

# --- Carry source's product into the build workdir so it's a MATERIAL there. ---
mkdir -p build
cp "$WORK/src/libshared.so" "$WORK/build/libshared.so"
LIBDIGEST="$(sha256sum "$WORK/build/libshared.so" | awk '{print $1}')"
echo "consumed material libshared.so sha256=$LIBDIGEST"

# --- Step "binary-build": consume libshared.so, produce judge-api. ---
"$CILOCK" run --step binary-build --workingdir "$WORK/build" \
  --attestations environment --signer-file-key-path key.pem \
  --outfile bb.att.json \
  -- bash -c "printf 'judge-api-binary\n' > $WORK/build/judge-api" >/dev/null 2>&1
BIN="$WORK/build/judge-api"
ls bb.att.json "$BIN"

# --- Two-step policy: binary-build artifactsFrom source. ---
python3 - "$KEYID" > policy.json <<'PY'
import json,sys,base64
k=sys.argv[1]; pub=base64.b64encode(open("pub.pem","rb").read()).decode()
fn=[{"type":"publickey","publickeyid":k}]
prod=[{"type":"https://aflock.ai/attestations/product/v0.3","regopolicies":[],"aipolicies":[]}]
policy={
  "expires":"2030-01-01T00:00:00Z",
  "publickeys":{k:{"keyid":k,"key":pub}},
  "steps":{
    "source":{"name":"source","functionaries":fn,"attestations":prod},
    "binary-build":{"name":"binary-build","functionaries":fn,"attestations":prod,"artifactsFrom":["source"]},
  }
}
print(json.dumps(policy))
PY
"$CILOCK" sign --signer-file-key-path key.pem --infile policy.json --outfile policy.signed.json >/dev/null 2>&1

# --- POSITIVE: verify the binary across the full 2-step chain, INLINE only. ---
echo "=== POSITIVE: cilock verify <binary> (multi-step, inline leaves, NO sidecar) ==="
set +e
"$CILOCK" verify "$BIN" -p policy.signed.json --publickey pub.pem \
  --attestations source.att.json,bb.att.json --platform-url "" >pos.log 2>&1
pos_rc=$?
set -e
echo "positive VERIFY_EXIT=$pos_rc (want 0)"

# --- NEGATIVE: break the artifactsFrom chain. Build a SECOND binary-build
# collection that consumed a DIFFERENT libshared.so than source produced (same
# path, different content/digest). The inline leaves rehydrate the real upstream
# product and downstream material; compareArtifacts must reject the digest
# disagreement for the shared path. (Forged-leaf↔root-mismatch is covered by the
# Go adversarial unit tests, which can re-sign DSSE to isolate VerifyInlineLeaves
# from the signature check.) ---
echo "=== NEGATIVE: downstream material digest disagrees with upstream product (must fail) ==="
mkdir -p build2
printf 'TAMPERED-shared-library\n' > "$WORK/build2/libshared.so"
"$CILOCK" run --step binary-build --workingdir "$WORK/build2" \
  --attestations environment --signer-file-key-path key.pem \
  --outfile bb2.att.json \
  -- bash -c "printf 'judge-api-binary\n' > $WORK/build2/judge-api" >/dev/null 2>&1
BIN2="$WORK/build2/judge-api"
set +e
"$CILOCK" verify "$BIN2" -p policy.signed.json --publickey pub.pem \
  --attestations source.att.json,bb2.att.json --platform-url "" >neg.log 2>&1
neg_rc=$?
set -e
echo "negative VERIFY_EXIT=$neg_rc (want non-zero)"

if [ "$pos_rc" = "0" ] && [ "$neg_rc" != "0" ]; then
  echo "RESULT: PASS (inline chain verified with NO sidecar; mismatched material rejected)"
  exit 0
fi
echo "RESULT: FAIL (pos=$pos_rc neg=$neg_rc)"
echo '--- positive log ---'; tail -25 pos.log
echo '--- negative log ---'; tail -25 neg.log
exit 1
