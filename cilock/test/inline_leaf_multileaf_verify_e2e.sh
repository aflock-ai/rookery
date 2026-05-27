#!/usr/bin/env bash
# End-to-end test for inline-leaf consumption in the primary-artifact verify
# bridge (multi-leaf trees).
#
#   cilock run (build emits 3 products -> a 3-leaf product Merkle tree with
#   inline leaves) -> sign a key-based policy -> cilock verify <one-file> -p
#   policy  WITH NO inclusion-proof envelope and NO sidecar.
#
# Before the fix the bridge only consumed inline leaves for single-leaf trees,
# so verifying ONE file of a multi-file build required a separate
# inclusion-proof envelope. This proves a multi-file build verifies any one of
# its files from the signed collection alone, and that a file NOT in the tree
# still fails closed.
#
# Run: CILOCK=/path/to/cilock ./inline_leaf_multileaf_verify_e2e.sh
set -euo pipefail

CILOCK="${CILOCK:-cilock}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
echo "workdir: $WORK  cilock: $CILOCK"

# 1. Signing key (signs both attestations and policy).
openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
openssl pkey -in key.pem -pubout -out pub.pem 2>/dev/null
KEYID="$("$CILOCK" keyid show pub.pem 2>/dev/null | awk 'NR==1{print $1}')"
echo "keyid: $KEYID"
[ -n "$KEYID" ] || { echo "FAIL: empty keyid"; exit 1; }

# 2. multi-file build: three products -> a 3-leaf product tree (treeSize==3),
#    so the single-leaf reconstruct shortcut does NOT apply.
mkdir -p build
"$CILOCK" run --step binary-build --workingdir "$WORK/build" \
  --attestations environment --signer-file-key-path key.pem \
  --outfile bb.att.json \
  -- bash -c "printf 'app-one\n' > $WORK/build/app1; \
              printf 'app-two\n' > $WORK/build/app2; \
              printf 'app-three\n' > $WORK/build/app3" >/dev/null 2>&1
ls -la bb.att.json "$WORK/build/app1" "$WORK/build/app2" "$WORK/build/app3"

# Confirm the tree really is multi-leaf (treeSize 3) and carries inline leaves.
TS="$(python3 -c "import json,base64;p=json.loads(base64.b64decode(json.load(open('bb.att.json'))['payload']));print([a for a in p['predicate']['attestations'] if a['type'].endswith('product/v0.3')][0]['attestation']['treeSize'])")"
HAS_LEAVES="$(python3 -c "import json,base64;p=json.loads(base64.b64decode(json.load(open('bb.att.json'))['payload']));a=[a for a in p['predicate']['attestations'] if a['type'].endswith('product/v0.3')][0]['attestation'];print(len(a.get('leaves',[])))")"
echo "product treeSize=$TS  inline_leaves=$HAS_LEAVES (want treeSize=3, leaves=3)"
[ "$TS" = "3" ] || { echo "FAIL: expected multi-leaf tree (treeSize=3), got $TS"; exit 1; }
[ "$HAS_LEAVES" = "3" ] || { echo "FAIL: expected 3 inline leaves, got $HAS_LEAVES"; exit 1; }

# 3. Key-based policy: one step, requires the product attestor, signed by our key.
python3 - "$KEYID" > policy.json <<'PY'
import json,sys,base64
keyid=sys.argv[1]
pub=base64.b64encode(open("pub.pem","rb").read()).decode()
policy={
  "expires":"2030-01-01T00:00:00Z",
  "publickeys":{keyid:{"keyid":keyid,"key":pub}},
  "steps":{
    "binary-build":{
      "name":"binary-build",
      "functionaries":[{"type":"publickey","publickeyid":keyid}],
      "attestations":[
        {"type":"https://aflock.ai/attestations/product/v0.3","regopolicies":[],"aipolicies":[]}
      ]
    }
  }
}
print(json.dumps(policy,indent=2))
PY
"$CILOCK" sign --signer-file-key-path key.pem --infile policy.json --outfile policy.signed.json >/dev/null 2>&1
echo "signed policy ready"

# 4. POSITIVE: verify ONE file of the multi-file build with NO proof, NO sidecar
#    — bridged purely from the collection's inline leaves.
echo "=== POSITIVE: cilock verify <app2> (multi-leaf, inline leaves, no envelope) ==="
set +e
"$CILOCK" verify "$WORK/build/app2" -p policy.signed.json --publickey pub.pem \
  --attestations bb.att.json --platform-url "" >pos.log 2>&1
pos_rc=$?
set -e
grep -iE 'Verification succeeded|policy signature verified' pos.log || true
echo "positive VERIFY_EXIT=$pos_rc (want 0)"

# 5. NEGATIVE: a file NOT committed in the tree must fail closed.
printf 'not-a-product\n' > "$WORK/build/app-bogus"
echo "=== NEGATIVE: cilock verify <bogus> (must fail) ==="
set +e
"$CILOCK" verify "$WORK/build/app-bogus" -p policy.signed.json --publickey pub.pem \
  --attestations bb.att.json --platform-url "" >neg.log 2>&1
neg_rc=$?
set -e
echo "negative VERIFY_EXIT=$neg_rc (want non-zero)"

if [ "$pos_rc" = "0" ] && [ "$neg_rc" != "0" ]; then
  echo "RESULT: PASS (one file of a multi-file build verified from inline leaves; non-product rejected)"
  exit 0
fi
echo "RESULT: FAIL (pos=$pos_rc neg=$neg_rc)"
echo "--- positive log tail ---"; tail -20 pos.log
echo "--- negative log tail ---"; tail -10 neg.log
exit 1
