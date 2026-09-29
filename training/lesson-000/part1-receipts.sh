#!/usr/bin/env bash
# Lesson 000, part 1: build receipts for a small desktop app.
#
# A tiny C app goes through build -> test -> package. Each step runs under
# `cilock run`, which writes a signed receipt (an attestation collection).
# Before release, `cilock verify` checks the receipts against a signed policy
# with three rules. You see one PASS and three BLOCKED cases.
#
# Runs on Linux, macOS, and Windows (Git Bash). Needs: cilock, a C compiler
# (cc, gcc or clang; override with CC=...), git, openssl, tar, python3.
#
#   ./part1-receipts.sh                 interactive pace
#   DEMO_FAST=1 ./part1-receipts.sh     no pauses (CI uses this)
#   WORK=/some/dir ./part1-receipts.sh  where it writes its files (default ./part1-work)
#
# Uses ./bin/cilock if build-cilock.sh has been run, else cilock on PATH.
#
# Exit code is 0 only if every case ended the way the lesson expects.
set -uo pipefail

LESSON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${WORK:-$LESSON_DIR/part1-work}"
FAST="${DEMO_FAST:-0}"
CILOCK="${CILOCK:-$(ls "$LESSON_DIR"/bin/cilock* 2>/dev/null | head -1)}"
CILOCK="${CILOCK:-cilock}"

B=$'\e[1m'; DIM=$'\e[2m'; CY=$'\e[36m'; GR=$'\e[32m'; RD=$'\e[31m'; YL=$'\e[33m'; RS=$'\e[0m'

pause() { [[ $FAST == 1 ]] || sleep "${1:-1.5}"; }
say()   { echo; printf '%s\n' "${CY}${B}# $*${RS}"; pause 2; }
note()  { printf '%s\n' "${DIM}  $*${RS}"; pause 1; }

# Print a command the way you would type it, quoting only where needed.
show_cmd() {
    local out="" a i=0
    for a in "$@"; do
        # Display only: short names instead of absolute paths.
        if [[ $i -eq 0 && $a == "$CILOCK" ]]; then a=cilock
        elif [[ $i -eq 0 && $a == "$PY" ]]; then a=python3
        fi
        a="${a/#$LESSON_DIR/$REPO_REL}"
        i=$((i + 1))
        if [[ -z $a ]]; then out+=' ""'
        elif [[ $a =~ [[:space:]\'\&\;\|\<\>\$\`] ]]; then out+=" '$a'"
        else out+=" $a"; fi
    done
    printf '%s\n' "${GR}\$${RS}${out}"
    pause 0.5
}
run() { show_cmd "$@"; "$@"; pause 1; }

# --- tool detection -------------------------------------------------------
PY=$(command -v python3 || command -v python) || { echo "python3 not found"; exit 2; }
CC="${CC:-$(command -v cc || command -v gcc || command -v clang)}" || true
[[ -n $CC ]] || { echo "no C compiler found (set CC=...)"; exit 2; }
CC=$(basename "$CC")
command -v "$CILOCK" >/dev/null || { echo "cilock not found (run ./build-cilock.sh, see README)"; exit 2; }
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) BIN=photo-lite.exe ;; *) BIN=photo-lite ;; esac

# --- script helpers (not cilock commands) ---------------------------------
# demo_step <step> <command...>
#   Prints and runs the real cilock command that wraps one build step.
#   cilock's own log goes to logs/<step>.log to keep the screen readable.
demo_step() {
    local step=$1; shift
    rm -f "../evidence/$step".json*          # a new run of a step replaces its old receipt
    local cmd=("$CILOCK" run --step "$step"
        -k ../keys/build-machine.key         # the build machine's signing key
        -a git                               # record the source commit
        --material-manifest                  # keep the input file list, needed for artifactsFrom
        -o "../evidence/$step.json"
        -- "$@")
    show_cmd "${cmd[@]}"
    if "${cmd[@]}" >"../logs/$step.log" 2>&1; then
        echo "  ${GR}✔${RS} signed receipt saved: evidence/$step.json"
    else
        echo "  ${YL}⚠${RS} signed receipt saved: evidence/$step.json ${YL}(the step failed, and the receipt records that)${RS}"
    fi
    pause 1
}

# demo_verify <artifact>
#   Prints and runs the real cilock verify command, then explains the verdict.
EVIDENCE_ARGS=()
demo_verify() {
    local f
    EVIDENCE_ARGS=()
    for f in ../evidence/*.json; do
        case $f in *-material-inventory.json|*.detection.json) continue ;; esac
        EVIDENCE_ARGS+=(-a "$f")
    done
    local cmd=("$CILOCK" verify "$1"
        -p ../policy/policy.signed.json      # the signed rulebook
        -k ../keys/release-team.pub          # who signed the rulebook
        -s "sha1:$(git rev-parse HEAD)"      # the release: this commit
        "${EVIDENCE_ARGS[@]}")
    show_cmd "${cmd[@]}"
    "${cmd[@]}" >../logs/verify.log 2>&1
    LAST_RC=$?
    if [[ $LAST_RC -eq 0 ]]; then
        echo; echo "  ${GR}${B}✅ PASS: every rule met. OK to sign and release.${RS}"
    else
        echo; echo "  ${RD}${B}⛔ BLOCKED: do not release.${RS}"
        grep -oE 'policy was denied due to: [^"\\]*|mismatched digests for [^"\\]*|no collection passed verification for step [a-z]+' \
            ../logs/verify.log | sort -u | while read -r why; do
            case $why in
                "mismatched digests for "*) plain="The ${why#mismatched digests for } in the package is not the one the build produced." ;;
                "no collection passed verification for step "*) plain="There is no valid receipt for the '${why##* }' step." ;;
                "policy was denied due to: "*) plain="Rule broken: ${why#policy was denied due to: }." ;;
            esac
            echo "    ${B}$plain${RS}"
            echo "    ${DIM}(cilock: $why)${RS}"
        done
    fi
    pause 1
}

# expect <pass|blocked> <label> [reason regex]
FAILURES=0
expect() {
    local want=$1 label=$2 reason=${3:-}
    local ok=1
    if [[ $want == pass ]]; then
        [[ $LAST_RC -eq 0 ]] || ok=0
    else
        [[ $LAST_RC -ne 0 ]] || ok=0
        [[ -z $reason ]] || grep -qE "$reason" ../logs/verify.log || ok=0
    fi
    if [[ $ok == 1 ]]; then
        echo "  ${DIM}[check] $label: $want, as expected${RS}"
    else
        echo "  ${RD}[check] $label: expected $want, got exit $LAST_RC. See $WORK/logs/verify.log${RS}"
        FAILURES=$((FAILURES + 1))
    fi
}

# --- setup (not part of the lesson) ---------------------------------------
setup() {
    rm -rf "$WORK"
    mkdir -p "$WORK"/{project/app,keys,evidence,policy,logs,untrusted}
    cp "$LESSON_DIR/app/photo_lite.c" "$WORK/project/app/"
    printf 'int main(void) { return 0; }\n' > "$WORK/untrusted/other.c"
    (cd "$WORK/untrusted" && "$CC" other.c -o "$BIN" && rm other.c)
    (cd "$WORK/project" && git init -q . && git add app \
        && git -c user.name="Lesson" -c user.email=lesson@example.com commit -qm "Photo Lite 1.0")
    for k in build-machine release-team; do
        openssl genpkey -algorithm ED25519 -out "$WORK/keys/$k.key" 2>/dev/null
        openssl pkey -in "$WORK/keys/$k.key" -pubout -out "$WORK/keys/$k.pub"
    done
}
fresh_run() { rm -f ../evidence/* "$BIN" photo-lite.tar.gz; }

setup || { echo "setup failed"; exit 2; }
cd "$WORK/project" || exit 2
REPO_REL=$("$PY" -c 'import os,sys; print(os.path.relpath(sys.argv[1]).replace(os.sep, "/"))' "$LESSON_DIR")

echo "${B}Build receipts with cilock: a small desktop app, checked before release${RS}"
note "Working folder: $WORK"
note "Compiler: $CC. cilock contacts a public timestamp server (TSA); nothing is uploaded."

say "Step 0. The release team writes the policy (we call it the rulebook). Three rules:"
note "1. The build ran and finished cleanly."
note "2. The tests ran against that build and passed."
note "3. The package holds the exact binary the build produced."
note "Each rule is a few lines of Rego. Rule 2:"
run cat "$LESSON_DIR/rules/test.rego"
note "tools/make_policy.py puts the three rules and the build machine's public key into one policy file."
run "$PY" "$LESSON_DIR/tools/make_policy.py" ../keys/build-machine.pub ../policy/policy.json
run "$CILOCK" policy validate -p ../policy/policy.json
say "The release team signs the policy, so nobody can change it quietly."
run "$CILOCK" sign -k ../keys/release-team.key -f ../policy/policy.json -o ../policy/policy.signed.json

say "Step 1. Build, test, package. Each existing command is prefixed with 'cilock run --step <name> ... --'."
demo_step build   "$CC" app/photo_lite.c -o "$BIN"
demo_step test    "./$BIN"
demo_step package tar czf photo-lite.tar.gz "$BIN"

say "Step 2. A receipt records what ran, what went in, what came out, and who signed it."
run "$PY" "$LESSON_DIR/tools/show_receipt.py" ../evidence/build.json
note "Store receipts next to the package, in whatever artifact store you already use."

say "Step 3. Before release: check this package, from this commit, against the signed rulebook."
demo_verify photo-lite.tar.gz
expect pass "normal release"

say "Now three things that go wrong in real pipelines."

say "A. Someone swaps the binary after the tests ran, then packages it."
rm -f photo-lite.tar.gz
run cp "../untrusted/$BIN" "$BIN"
demo_step package tar czf photo-lite.tar.gz "$BIN"
demo_verify photo-lite.tar.gz
expect blocked "swapped binary" "mismatched digests for $BIN"

say "B. A rushed release skips the tests."
fresh_run
demo_step build   "$CC" app/photo_lite.c -o "$BIN"
demo_step package tar czf photo-lite.tar.gz "$BIN"
demo_verify photo-lite.tar.gz
expect blocked "skipped tests" "no collection passed verification for step test"

say "C. The tests run and fail, and the release goes ahead anyway."
fresh_run
demo_step build   "$CC" app/photo_lite.c -o "$BIN"
demo_step test    sh -c "./$BIN && exit 3"
demo_step package tar czf photo-lite.tar.gz "$BIN"
demo_verify photo-lite.tar.gz
expect blocked "failed tests" "the tests failed \\(exit code 3\\)"

say "Summary"
note "Build steps stay the same. Each one is prefixed with 'cilock run --step <name> ... --'."
note "The release team keeps one signed policy and runs one 'cilock verify' before release."
note "The answer is PASS, or BLOCKED with the reason."
echo
if [[ $FAILURES -eq 0 ]]; then
    echo "${GR}All 4 cases ended as expected.${RS}"
else
    echo "${RD}$FAILURES case(s) did not end as expected.${RS}"
fi
exit "$FAILURES"
