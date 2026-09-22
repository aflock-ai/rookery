#!/usr/bin/env bash
# Offline release-verify smoke test: proves the cilock.dev "self-verifying fully
# offline" contract at the COMMAND level: a downloader with NO platform / tenant /
# Archivista access can verify a binary from the locally-exported per-step DSSE
# envelopes alone.
#
# It mirrors the release fan-out (.github/workflows/release-fanout.yml build job):
#   * two `cilock run` steps per binary, `source-git` (git provenance of the
#     release commit) and `build`, each writing its signed DSSE envelope to a
#     local file via `-o` (the change that lets the publisher upload the
#     envelopes instead of locking them in Archivista);
#   * a two-step signed policy: source-git requires git, build requires the
#     product, with no artifactsFrom between them;
#   * `cilock verify <binary> -s sha1:<commit> -a <source-git>,<build>
#     --platform-url ""`: FULLY OFFLINE, no --enable-archivista, no
#     --platform-url <host>.
#
# TWO SEEDS, the same two the fan-out's verifies and install.sh's printed
# command pass. cilock 4.5.0 verifies source checks from the commit: the binary's
# digest finds the build step, and the release commit (`-s sha1:<40-hex>`) finds
# the source-git step through its git attestor's commithash. The steps share no
# other subject here, so the negatives below also prove the commit seed is what
# reaches source-git: without it, or with a commit the release did not attest,
# verify must fail.
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
# Wiring: ci.yml runs it on every PR (telemetry-smoke-rookery) and the fan-out's
# verify job runs it before the blocking verifies:
#   CILOCK=<in-tree cilock> bash subtrees/rookery/cilock/test/offline_release_verify_e2e.sh
# It needs only the freshly-built cilock, openssl and git.
#
# Run locally: CILOCK=/path/to/cilock ./offline_release_verify_e2e.sh
set -euo pipefail

CILOCK="${CILOCK:-cilock}"

# This hermetic smoke test mints a throwaway ed25519 file key with openssl. If
# openssl isn't on the host (e.g. a minimal CI runner), skip gracefully rather
# than failing closed. The offline-verify MECHANICS this guards are also covered
# by cli/verify_policycerts_test.go, and a missing build tool must never block a
# release. Install openssl on the runner to enable the full smoke test.
if ! command -v openssl >/dev/null 2>&1; then
  echo "::warning::openssl not found - skipping the hermetic offline-verify smoke test (mechanics covered by verify_policycerts_test.go)"
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

# --- The release source: a real one-commit repository. Isolated from the
# host's git config (hooks, signing, identity) so the commit is reproducible on
# any runner. ---
g() { git -C "$WORK/src" -c user.name=release -c user.email=release@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
mkdir -p src
printf 'package main\n' >"$WORK/src/main.go"
g init -q
g add main.go
g commit -q -m "release source"
COMMIT="$(g rev-parse HEAD)"
# A real commit object the release did NOT attest (same tree, not on HEAD).
OTHER_COMMIT="$(g commit-tree 'HEAD^{tree}' -m "not the release")"
echo "release commit: $COMMIT"

# --- Step source-git: provenance step. Like the fan-out it wraps `true`: the
# attestation IS the artifact (the git commit). `--platform-url ""` +
# `--enable-archivista=false` so the smoke test never touches a real platform
# regardless of an ambient login. ---
"$CILOCK" run --step source-git --workingdir "$WORK/src" \
  --attestations git,environment --signer-file-key-path key.pem \
  --platform-url "" --enable-archivista=false \
  --outfile "$SRC_ATT" \
  -- true >src.log 2>&1 || { echo "source-git run failed:"; tail -25 src.log; exit 1; }
ls "$SRC_ATT" >/dev/null

# --- Step build: produce the cilock binary in an isolated workdir with no git
# (the fan-out builds in /tmp/build). The `-o` envelope is written OUTSIDE the
# build workingdir (here, the parent $WORK) so it isn't captured as a spurious
# build product (the same reason the fan-out writes to /tmp/att, not /tmp/build).
mkdir -p build
"$CILOCK" run --step build --workingdir "$WORK/build" \
  --attestations environment --signer-file-key-path key.pem \
  --platform-url "" --enable-archivista=false \
  --outfile "$BUILD_ATT" \
  -- bash -c "printf 'cilock-release-binary\n' > $WORK/build/cilock" >build.log 2>&1 || { echo "build run failed:"; tail -25 build.log; exit 1; }
BIN="$WORK/build/cilock"
ls "$BUILD_ATT" "$BIN" >/dev/null

# --- Two steps, mirroring the REAL release policy
# (deploy/dist/release-policy-platform.json): source-git carries git, build
# carries the product, and nothing chains them. ---
python3 - "$KEYID" >policy.json <<'PY'
import json, sys, base64
k = sys.argv[1]
pub = base64.b64encode(open("pub.pem", "rb").read()).decode()
fn = [{"type": "publickey", "publickeyid": k}]
att = lambda t: [{"type": "https://aflock.ai/attestations/" + t, "regopolicies": [], "aipolicies": []}]
policy = {
    "expires": "2035-01-01T00:00:00Z",
    "publickeys": {k: {"keyid": k, "key": pub}},
    "steps": {
        "source-git": {"name": "source-git", "functionaries": fn, "attestations": att("git/v0.1")},
        "build": {"name": "build", "functionaries": fn, "attestations": att("product/v0.3")},
    },
}
print(json.dumps(policy))
PY
"$CILOCK" sign --signer-file-key-path key.pem --infile policy.json --outfile policy.signed.json >/dev/null 2>&1

# verify_offline LOG BINARY [SEED...]: the customer's offline command.
verify_offline() {
  local log="$1" bin="$2"
  shift 2
  set +e
  "$CILOCK" verify "$bin" -p policy.signed.json --publickey pub.pem \
    --attestations "${SRC_ATT},${BUILD_ATT}" --platform-url "" "$@" >"$log" 2>&1
  local rc=$?
  set -e
  return "$rc"
}

# --- POSITIVE: verify the binary FULLY OFFLINE from the two exported envelopes. ---
echo "=== POSITIVE: cilock verify <binary> -s sha1:<commit> -a source-git,build --platform-url \"\" (offline) ==="
pos_rc=0; verify_offline pos.log "$BIN" -s "sha1:${COMMIT}" || pos_rc=$?
echo "positive VERIFY_EXIT=$pos_rc (want 0)"

# --- NEGATIVE: no commit seed. Nothing else reaches source-git. ---
echo "=== NEGATIVE: without the commit seed, source-git must not be found ==="
noseed_rc=0; verify_offline noseed.log "$BIN" || noseed_rc=$?
echo "no-seed VERIFY_EXIT=$noseed_rc (want non-zero)"

# --- NEGATIVE: a real commit the release did not attest. ---
echo "=== NEGATIVE: a commit the release did not attest must fail ==="
other_rc=0; verify_offline other.log "$BIN" -s "sha1:${OTHER_COMMIT}" || other_rc=$?
echo "other-commit VERIFY_EXIT=$other_rc (want non-zero)"

# --- NEGATIVE: tamper the binary; its sha256 no longer matches the build
# product subject, so offline verify must fail closed. ---
echo "=== NEGATIVE: tampered binary must fail offline verify ==="
printf 'TAMPERED\n' >"$BIN"
neg_rc=0; verify_offline neg.log "$BIN" -s "sha1:${COMMIT}" || neg_rc=$?
echo "tampered VERIFY_EXIT=$neg_rc (want non-zero)"

if [ "$pos_rc" = "0" ] && [ "$noseed_rc" != "0" ] && [ "$other_rc" != "0" ] && [ "$neg_rc" != "0" ]; then
  echo "RESULT: PASS (offline verify from exported envelopes + the release commit succeeds; no seed, another commit and a tampered binary are rejected)"
  exit 0
fi
echo "RESULT: FAIL (pos=$pos_rc noseed=$noseed_rc other=$other_rc tampered=$neg_rc)"
for f in pos noseed other neg; do
  echo "--- $f log ---"
  tail -25 "$f.log"
done
exit 1
