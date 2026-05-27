#!/usr/bin/env bash
# Local end-to-end test for the inclusion-proof verify path:
#   cilock run (product Merkle tree) -> cilock prove (inclusion proof)
#   -> sign a key-based policy -> cilock verify <artifact> -p policy
#
# Proves that a customer holding ONLY the built binary + the signed policy
# + the inclusion-proof envelope can verify provenance — no Fulcio/OIDC,
# no GitHub Actions. Run: CILOCK=/path/to/cilock ./inclusion_verify_e2e.sh
set -euo pipefail

CILOCK="${CILOCK:-cilock}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
echo "workdir: $WORK"

# 1. Signing key (one key signs both the attestations and the policy).
openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
openssl pkey -in key.pem -pubout -out pub.pem 2>/dev/null
KEYID="$("$CILOCK" keyid show pub.pem 2>/dev/null | awk 'NR==1{print $1}')"
echo "keyid: $KEYID"
[ -n "$KEYID" ] || { echo "FAIL: empty keyid"; exit 1; }

# 2. binary-build step: build a binary into an isolated workdir so the product
#    attestor commits exactly one product (the binary) as a tree:products root.
mkdir -p build
"$CILOCK" run --step binary-build --workingdir "$WORK/build" \
  --attestations environment --signer-file-key-path key.pem \
  --outfile bb.att.json \
  -- bash -c "printf 'pretend-judge-api-binary\n' > $WORK/build/judge-api" >/dev/null 2>&1
BIN="$WORK/build/judge-api"
ls -la bb.att.json bb.att.product.tree.json "$BIN"

# 3. Inclusion proof for the binary against the product tree.
"$CILOCK" prove --tree-sidecar bb.att.product.tree.json \
  --file judge-api --signer-file-key-path key.pem -o proof.json >/dev/null 2>&1
ls -la proof*.json

# 4. Key-based policy: one step, requires the product attestor, signed by our key.
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

# 5. Sign the policy with the same key.
"$CILOCK" sign --signer-file-key-path key.pem --infile policy.json --outfile policy.signed.json >/dev/null 2>&1
echo "signed policy ready"

# 6. POSITIVE: verify the real binary (positional artifact). Single-leaf:
#    only the build collection is needed — NO inclusion-proof envelope, NO
#    sidecar (the bridge reconstructs the single-product tree root directly).
echo "=== POSITIVE: cilock verify <binary> (single-leaf, no sidecar) ==="
set +e
"$CILOCK" verify "$BIN" -p policy.signed.json --publickey pub.pem \
  --attestations bb.att.json --platform-url "" >pos.log 2>&1
pos_rc=$?
set -e
grep -iE 'Verification succeeded|policy signature verified' pos.log || true
echo "positive VERIFY_EXIT=$pos_rc (want 0)"

# 7. NEGATIVE: a tampered artifact NOT committed in the tree must FAIL closed.
#    Its sha256 won't match the proof's FileDigest, so no bridge, no collection.
printf 'tampered-not-the-real-binary\n' > "$WORK/build/judge-api-tampered"
echo "=== NEGATIVE: cilock verify <tampered> (must fail) ==="
set +e
"$CILOCK" verify "$WORK/build/judge-api-tampered" -p policy.signed.json --publickey pub.pem \
  --attestations bb.att.json,proof.json --platform-url "" >neg.log 2>&1
neg_rc=$?
set -e
echo "negative VERIFY_EXIT=$neg_rc (want non-zero)"

# Verdict: positive must pass, negative must fail.
if [ "$pos_rc" = "0" ] && [ "$neg_rc" != "0" ]; then
  echo "RESULT: PASS (positive verified, tampered rejected)"
  exit 0
fi
echo "RESULT: FAIL (pos=$pos_rc neg=$neg_rc)"
echo "--- positive log tail ---"; tail -15 pos.log
echo "--- negative log tail ---"; tail -8 neg.log
exit 1
