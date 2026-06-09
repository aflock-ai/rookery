#!/usr/bin/env bash
# Local end-to-end test for the ISOLATED-WORKDIR artifactsFrom case that broke
# the self-host-minimal release on rc4 — and the fix.
#
# A downstream step ("binary-build", mirroring the real pipeline) runs in an
# isolated, empty workingdir, so its material attestor records NOTHING. In v0.4
# the material attestor still INLINES its (empty) leaf set, which is a signed
# commitment that the step consumed nothing. Its artifactsFrom edge to the
# upstream step is therefore legitimately vacuous, but AUTHORITATIVELY so.
#
# Inline-leaves-only mode (off-envelope sidecars removed) MUST accept this with
# NO flag: an inline, authoritatively-empty material set is a verified fact, not
# the v0.3 vacuous-pass surface. (The leaf-less case — where empty Materials()
# is merely unknown and must fail closed — is covered by the engine unit test
# TestInlineLeaves_VacuousFailsUnderStrict.)
#
# rc4 only surfaced this because rc3 accidentally had leftover binaries in the
# build workdir (non-empty materials). This harness makes the empty case
# deterministic so the regression can never return silently.
#
# Run: CILOCK=/path/to/cilock ./isolated_workdir_verify_e2e.sh
set -euo pipefail

CILOCK="${CILOCK:-cilock}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cd "$W"
echo "workdir: $W"

openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
openssl pkey -in key.pem -pubout -out pub.pem 2>/dev/null
KEYID="$("$CILOCK" keyid show pub.pem 2>/dev/null | awk 'NR==1{print $1}')"

mkdir -p src build
# Upstream "source": produces a product.
"$CILOCK" run --step source --workingdir "$W/src" \
  --attestations environment --signer-file-key-path key.pem --outfile s.att.json \
  -- bash -c "printf 'lib\n' > $W/src/lib.so" >/dev/null 2>&1

# Downstream "binary-build": ISOLATED empty workingdir -> empty (but inline,
# authoritative) materials, exactly like the release pipeline's /tmp/build.
"$CILOCK" run --step binary-build --workingdir "$W/build" \
  --attestations environment --signer-file-key-path key.pem --outfile b.att.json \
  -- bash -c "printf 'app\n' > $W/build/app" >/dev/null 2>&1
BIN="$W/build/app"

python3 - "$KEYID" > policy.json <<'PY'
import json,sys,base64
k=sys.argv[1]; pub=base64.b64encode(open("pub.pem","rb").read()).decode()
fn=[{"type":"publickey","publickeyid":k}]
prod=[{"type":"https://aflock.ai/attestations/product/v0.3","regopolicies":[],"aipolicies":[]}]
print(json.dumps({"expires":"2030-01-01T00:00:00Z","publickeys":{k:{"keyid":k,"key":pub}},"steps":{
 "source":{"name":"source","functionaries":fn,"attestations":prod},
 "binary-build":{"name":"binary-build","functionaries":fn,"attestations":prod,"artifactsFrom":["source"]}}}))
PY
"$CILOCK" sign --signer-file-key-path key.pem --infile policy.json --outfile policy.signed.json >/dev/null 2>&1

echo "=== INLINE-ONLY: isolated/empty-materials downstream must PASS flaglessly ==="
set +e
"$CILOCK" verify "$BIN" -p policy.signed.json --publickey pub.pem \
  --attestations s.att.json,b.att.json --platform-url "" >strict.log 2>&1
strict_rc=$?
set -e
echo "strict VERIFY_EXIT=$strict_rc (want 0)"

if [ "$strict_rc" = "0" ] && grep -q "Verification succeeded" strict.log; then
  echo "RESULT: PASS (isolated-workdir authoritative-empty materials verified under strict, no flags)"
  exit 0
fi
echo "RESULT: FAIL (strict=$strict_rc)"
echo '--- strict log ---'; tail -12 strict.log
exit 1
