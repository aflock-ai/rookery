#!/usr/bin/env bash
# Offline release-verify smoke test — proves the cilock.dev "self-verifying fully
# offline" contract at the COMMAND level: a downloader with NO platform / tenant /
# Archivista access can verify a binary from the locally-exported per-step DSSE
# envelopes alone.
#
# It mirrors the release fan-out (.github/workflows/release-fanout.yml build job):
#   * two `cilock run` steps per binary — `source-git` and `build` — each writing
#     its signed DSSE envelope to a local file via `-o` (the change that lets the
#     publisher upload the envelopes instead of locking them in Archivista);
#   * a two-step signed policy chaining build artifactsFrom source-git;
#   * `cilock verify <binary> -a <source-git>,<build> --platform-url ""` — FULLY
#     OFFLINE, no --enable-archivista, no --platform-url <host>.
#
# Trust here is a local file-signer keypair (--publickey), NOT the platform's
# keyless Fulcio + RFC3161 TSA. That keeps the smoke test hermetic (a live Fulcio
# can't run in CI's offline lane). The KEYLESS variant the real fan-out publishes
# swaps `--publickey` for `--policy-ca-roots fulcio-roots.pem
# --policy-timestamp-servers tsa-chain.pem --policy-emails <signer>
# --policy-fulcio-oidc-issuer <issuer>` (the published trust material). The
# multi-cert parsing those two files require is unit-tested in
# cli/verify_policycerts_test.go; the ONLINE `verify` job in release-fanout.yml
# exercises the same envelopes against the platform. This script locks in the
# offline command MECHANICS (local `-o` export + offline multi-step verify) so a
# pipeline change can't silently regress them.
#
# Wiring into the fan-out: call this in the rc dry-run lane after the build job,
#   CILOCK=<in-tree cilock> bash subtrees/rookery/cilock/test/offline_release_verify_e2e.sh
# and fail the dry-run on a non-zero exit. It needs only the freshly-built cilock.
#
# Run locally: CILOCK=/path/to/cilock ./offline_release_verify_e2e.sh
set -euo pipefail

CILOCK="${CILOCK:-cilock}"

# This hermetic smoke test mints a throwaway ed25519 file key with openssl. If
# openssl isn't on the host (e.g. a minimal CI runner), skip gracefully rather
# than failing closed — the offline-verify MECHANICS this guards are also covered
# by cli/verify_policycerts_test.go, and a missing build tool must never block a
# release. Install openssl on the runner to enable the full smoke test.
if ! command -v openssl >/dev/null 2>&1; then
  echo "::warning::openssl not found — skipping the hermetic offline-verify smoke test (mechanics covered by verify_policycerts_test.go)"
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
echo "workdir: $WORK"

VERSION="9.9.9"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in x86_64 | amd64) ARCH=amd64 ;; arm64 | aarch64) ARCH=arm64 ;; esac
PREFIX="cilock-${VERSION}-${OS}-${ARCH}"
SRC_ATT="${PREFIX}.source-git.att.json"
BUILD_ATT="${PREFIX}.build.att.json"

openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
openssl pkey -in key.pem -pubout -out pub.pem 2>/dev/null
KEYID="$("$CILOCK" keyid show pub.pem 2>/dev/null | awk 'NR==1{print $1}')"
echo "keyid: $KEYID"

# --- Step source-git: provenance step. The fan-out wraps /bin/true; here we wrap
# a trivial product-producing command so the run is portable across OSes AND
# stays hermetic — `--platform-url ""` + `--enable-archivista=false` so the
# smoke test never touches a real platform regardless of an ambient login. ---
mkdir -p src
"$CILOCK" run --step source-git --workingdir "$WORK/src" \
  --attestations environment --signer-file-key-path key.pem \
  --platform-url "" --enable-archivista=false \
  --outfile "$SRC_ATT" \
  -- bash -c "printf 'source-marker\n' > $WORK/src/SOURCE" >/dev/null 2>&1
ls "$SRC_ATT" >/dev/null

# --- Step build: produce the cilock binary in an isolated workdir. The `-o`
# envelope is written OUTSIDE the build workingdir (here, the parent $WORK) so it
# isn't captured as a spurious build product (the same reason the fan-out writes
# to /tmp/att, not /tmp/build). ---
mkdir -p build
"$CILOCK" run --step build --workingdir "$WORK/build" \
  --attestations environment --signer-file-key-path key.pem \
  --platform-url "" --enable-archivista=false \
  --outfile "$BUILD_ATT" \
  -- bash -c "printf 'cilock-release-binary\n' > $WORK/build/cilock" >/dev/null 2>&1
BIN="$WORK/build/cilock"
ls "$BUILD_ATT" "$BIN" >/dev/null

# --- Two independent steps, mirroring the REAL release policy
# (deploy/dist/release-policy-platform.json): source-git + build, correlated by
# shared subjects, NOT artifactsFrom. Verify binds the binary to the build step's
# product/v0.3 subject. ---
python3 - "$KEYID" >policy.json <<'PY'
import json, sys, base64
k = sys.argv[1]
pub = base64.b64encode(open("pub.pem", "rb").read()).decode()
fn = [{"type": "publickey", "publickeyid": k}]
prod = [{"type": "https://aflock.ai/attestations/product/v0.3", "regopolicies": [], "aipolicies": []}]
policy = {
    "expires": "2035-01-01T00:00:00Z",
    "publickeys": {k: {"keyid": k, "key": pub}},
    "steps": {
        "source-git": {"name": "source-git", "functionaries": fn, "attestations": prod},
        "build": {"name": "build", "functionaries": fn, "attestations": prod},
    },
}
print(json.dumps(policy))
PY
"$CILOCK" sign --signer-file-key-path key.pem --infile policy.json --outfile policy.signed.json >/dev/null 2>&1

# --- POSITIVE: verify the binary FULLY OFFLINE from the two exported envelopes. ---
echo "=== POSITIVE: cilock verify <binary> -a source-git,build --platform-url \"\" (offline) ==="
set +e
"$CILOCK" verify "$BIN" -p policy.signed.json --publickey pub.pem \
  --attestations "${SRC_ATT},${BUILD_ATT}" --platform-url "" >pos.log 2>&1
pos_rc=$?
set -e
echo "positive VERIFY_EXIT=$pos_rc (want 0)"

# --- NEGATIVE: tamper the binary — its sha256 no longer matches the build
# product subject, so offline verify must fail closed. ---
echo "=== NEGATIVE: tampered binary must fail offline verify ==="
printf 'TAMPERED\n' >"$WORK/build/cilock"
set +e
"$CILOCK" verify "$WORK/build/cilock" -p policy.signed.json --publickey pub.pem \
  --attestations "${SRC_ATT},${BUILD_ATT}" --platform-url "" >neg.log 2>&1
neg_rc=$?
set -e
echo "negative VERIFY_EXIT=$neg_rc (want non-zero)"

if [ "$pos_rc" = "0" ] && [ "$neg_rc" != "0" ]; then
  echo "RESULT: PASS (offline verify from exported envelopes succeeds; tampered binary rejected)"
  exit 0
fi
echo "RESULT: FAIL (pos=$pos_rc neg=$neg_rc)"
echo '--- positive log ---'; tail -25 pos.log
echo '--- negative log ---'; tail -25 neg.log
exit 1
