#!/usr/bin/env bash
# Lesson 000, part 2: iterate a policy against known-good and known-bad builds
# (the loop an AI agent runs).
#
# Builds four fixtures once, each a real set of signed receipts with a known
# right answer:
#   good     build, test, package            expect PASS
#   swapped  binary replaced before package  expect BLOCKED
#   skipped  no test step                    expect BLOCKED
#   failed   test step exits 3               expect BLOCKED
# Then runs three policy rounds. Each round: build the policy, run
# `cilock policy validate`, sign it, `cilock verify` every fixture, score.
# Stop condition: zero validate findings AND 4/4 verdicts correct.
#
# `cilock policy validate` prints "PASSED" even when it lists findings, so the
# loop counts the numbered findings instead of trusting the exit code.
#
# Writes part2-work/loop.jsonl (one record per round). Exit code 0 only if
# the three rounds end exactly as the lesson describes.
# Works with bash 3.2 (the macOS default): no associative arrays.
set -uo pipefail

LESSON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="${WORK:-$LESSON_DIR/part2-work}"
CILOCK="${CILOCK:-$(ls "$LESSON_DIR"/bin/cilock* 2>/dev/null | head -1)}"
CILOCK="${CILOCK:-cilock}"
PY=$(command -v python3 || command -v python) || { echo "python3 not found"; exit 2; }
CC="${CC:-$(command -v cc || command -v gcc || command -v clang)}" || true
[[ -n $CC ]] || { echo "no C compiler found (set CC=...)"; exit 2; }
command -v "$CILOCK" >/dev/null || { echo "cilock not found (run ./build-cilock.sh, see README)"; exit 2; }
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) BIN=photo-lite.exe ;; *) BIN=photo-lite ;; esac

rm -rf "$T"; mkdir -p "$T"/{project/app,keys,fixtures,untrusted,rounds}
cp "$LESSON_DIR/app/photo_lite.c" "$T/project/app/"
cd "$T/project" && git init -q . && git add app \
    && git -c user.name="Lesson" -c user.email=lesson@example.com commit -qm "Photo Lite 1.0"
for k in build-machine release-team; do
    openssl genpkey -algorithm ED25519 -out "$T/keys/$k.key" 2>/dev/null
    openssl pkey -in "$T/keys/$k.key" -pubout -out "$T/keys/$k.pub"
done
printf 'int main(void) { return 0; }\n' > "$T/untrusted/other.c"
(cd "$T/untrusted" && "$CC" other.c -o "$BIN")
COMMIT=$(git rev-parse HEAD)

# fixture_step <fixture> <step> <command...>: one receipt, written outside the workspace.
fixture_step() {
    local fx=$1 name=$2; shift 2
    mkdir -p "$T/fixtures/$fx"
    "$CILOCK" run --step "$name" -k "$T/keys/build-machine.key" -a git --platform-url "" \
        --material-manifest -o "$T/fixtures/$fx/$name.json" -- "$@" >/dev/null 2>&1
}
fixture_done() { cp photo-lite.tar.gz "$T/fixtures/$1/"; rm -f "$BIN" photo-lite.tar.gz; }

echo "Building 4 fixtures (real signed receipts)..."
fixture_step good build "$CC" app/photo_lite.c -o "$BIN"
fixture_step good test "./$BIN"
fixture_step good package tar czf photo-lite.tar.gz "$BIN"
fixture_done good

fixture_step swapped build "$CC" app/photo_lite.c -o "$BIN"
fixture_step swapped test "./$BIN"
cp "$T/untrusted/$BIN" "$BIN"
fixture_step swapped package tar czf photo-lite.tar.gz "$BIN"
fixture_done swapped

fixture_step skipped build "$CC" app/photo_lite.c -o "$BIN"
fixture_step skipped package tar czf photo-lite.tar.gz "$BIN"
fixture_done skipped

fixture_step failed build "$CC" app/photo_lite.c -o "$BIN"
fixture_step failed test sh -c "./$BIN && exit 3"
fixture_step failed package tar czf photo-lite.tar.gz "$BIN"
fixture_done failed

expected() { case $1 in good) echo PASS ;; *) echo BLOCKED ;; esac; }
now() { "$PY" -c 'import time; print(time.time())'; }

# round <n> <label> <make_policy args...>: sets FINDINGS and CORRECT.
round() {
    local n=$1 label=$2; shift 2
    local dir="$T/rounds/$n" start fx f got want results=""
    local -a att
    mkdir -p "$dir"
    start=$(now)
    "$PY" "$LESSON_DIR/tools/make_policy.py" "$T/keys/build-machine.pub" "$dir/policy.json" "$@"
    "$CILOCK" policy validate -p "$dir/policy.json" >"$dir/validate.log" 2>&1
    FINDINGS=$(grep -cE '^ +[0-9]+\. ' "$dir/validate.log")
    "$CILOCK" sign --offline -k "$T/keys/release-team.key" -f "$dir/policy.json" \
        -o "$dir/policy.signed.json" >/dev/null 2>&1
    CORRECT=0
    for fx in good swapped skipped failed; do
        att=()
        for f in "$T/fixtures/$fx"/*.json; do
            case $f in *-material-inventory.json|*.detection.json) ;; *) att+=(-a "$f") ;; esac
        done
        if "$CILOCK" verify "$T/fixtures/$fx/photo-lite.tar.gz" -p "$dir/policy.signed.json" \
            -k "$T/keys/release-team.pub" -s "sha1:$COMMIT" --offline "${att[@]}" \
            >"$dir/verify-$fx.log" 2>&1; then got=PASS; else got=BLOCKED; fi
        want=$(expected "$fx")
        [[ $got == "$want" ]] && CORRECT=$((CORRECT + 1))
        results+="$fx=$got/$want "
    done
    local secs; secs=$("$PY" -c "print(round($(now) - $start, 1))")
    N=$n LABEL=$label ARGS="$*" RESULTS=$results CORRECT=$CORRECT FINDINGS=$FINDINGS SECS=$secs \
    DIR=$dir "$PY" -c '
import json, os
e = os.environ
print(json.dumps({"round": int(e["N"]), "label": e["LABEL"], "make_policy_args": e["ARGS"],
    "validate_findings": int(e["FINDINGS"]),
    "validate_output": open(os.path.join(e["DIR"], "validate.log")).read(),
    "verdicts": dict(r.split("=") for r in e["RESULTS"].split()),
    "correct": int(e["CORRECT"]), "of": 4, "seconds": float(e["SECS"]),
    "policy": json.load(open(os.path.join(e["DIR"], "policy.json")))}))' >>"$T/loop.jsonl"
    printf 'round %s  %-46s findings: %s  verdicts correct: %s/4  (%ss)\n' \
        "$n" "$label" "$FINDINGS" "$CORRECT" "$secs"
    printf '         %s\n' "$results"
}

FAILS=0
check() {  # check <round> <want findings> <want correct>
    if [[ $FINDINGS -eq $2 && $CORRECT -eq $3 ]]; then
        echo "         [check] round $1: $2 findings, $3/4, as expected"
    else
        echo "         [check] round $1: expected $2 findings and $3/4, got $FINDINGS and $CORRECT/4"
        FAILS=$((FAILS + 1))
    fi
}

: >"$T/loop.jsonl"
echo
round 1 "first draft" --rules "$LESSON_DIR/rules-v1" --no-artifacts-from
check 1 6 3
round 2 "add artifactsFrom (tie test+package to build)" --rules "$LESSON_DIR/rules-v1"
check 2 6 4
round 3 "fix the guard the validator flagged" --rules "$LESSON_DIR/rules"
check 3 0 4

echo
if [[ $FINDINGS -eq 0 && $CORRECT -eq 4 ]]; then
    echo "Stop condition met in round 3: zero validate findings and 4/4 verdicts correct."
fi
echo "Full record: $T/loop.jsonl"
exit "$FAILS"
