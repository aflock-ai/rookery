# Lesson 000: build receipts, and how to get a policy right

Two parts, about 15 minutes, fully offline.

- **Part 1:** a small desktop app goes through build, test and package. Every step leaves a signed receipt. One
  `cilock verify` before release answers **PASS** or **BLOCKED**, with the reason.
- **Part 2:** iterate the policy from a weak first draft to a correct one, testing each round against builds whose
  right answer you already know. This is the loop an AI agent can run for you.

No supply-chain background needed.

## Watch first

A 4.5-minute explainer covers both parts, with subtitles:

- [Explainer video, subtitled](https://github.com/aflock-ai/cilock-training/raw/main/media/cilock-build-receipts-explainer.mp4)
- [Explainer video, narrated and subtitled](https://github.com/aflock-ai/cilock-training/raw/main/media/cilock-build-receipts-explainer-narrated.mp4)
- [Slides (HTML)](https://github.com/aflock-ai/cilock-training/blob/main/media/cilock-build-receipts-slides.html), [slides (PDF)](https://github.com/aflock-ai/cilock-training/raw/main/media/cilock-build-receipts-slides.pdf), [one-page summary (PDF)](https://github.com/aflock-ai/cilock-training/raw/main/media/cilock-build-receipts-onepager.pdf)

Commands, verdicts and timings on screen come from a real run of this lesson on Linux. The policy iteration table
comes from part 2's harness. The media lives in
[aflock-ai/cilock-training](https://github.com/aflock-ai/cilock-training) to keep binaries out of this repo.

## Quickstart

You need Go (version in [`.go-version`](../../.go-version)), `git`, `openssl`, `tar`, `python3`, and a C compiler
(`cc`, `gcc` or `clang`; set `CC=` to pick one).

```bash
cd training/lesson-000
./build-cilock.sh                   # builds ./bin/cilock from this checkout
./part1-receipts.sh                 # paced for reading; DEMO_FAST=1 for no pauses
./part2-policy-loop.sh
```

Each script exits 0 only if every case ends the way the lesson says. CI runs both on Linux, macOS and Windows
([training workflow](../../.github/workflows/training.yml)). On Windows, use Git Bash with a C compiler on `PATH`
(CI uses MinGW `gcc`).

## Part 1: receipts and one check

Today a release team usually signs and ships the file it is handed. It cannot see what happened before that:
was the app built from the right code, did the tests really pass, is the packaged file the one that was built?

**Receipts.** Each build step runs under `cilock run`, which writes a receipt: the command, the files that went in,
the files that came out, whether it succeeded, and the source commit. The build machine signs it.

**The rulebook** is a cilock policy with three rules, signed by the release team:

1. The build ran and finished cleanly.
2. The tests ran against that build and passed.
3. The package holds the exact binary the build produced.

**The check** is `cilock verify` on the package. The lesson runs four cases:

| Case | Result | Why |
|---|---|---|
| Normal release | ✅ PASS | All three rules hold |
| Binary swapped after the tests, then packaged | ⛔ BLOCKED | Rule 3: the packaged binary is not the built one |
| Tests skipped | ⛔ BLOCKED | Rule 2: no receipt for the `test` step |
| Tests failed, release went ahead | ⛔ BLOCKED | Rule 2: the test receipt records exit code 3 |

### The commands

The script prints every cilock command in full before running it. `demo_step` and `demo_verify` in the script are
helpers that print and run these commands with the lesson's paths; they are not cilock commands.

```bash
# The rulebook: rules/*.rego plus the build machine's public key, validated and signed.
python3 tools/make_policy.py keys/build-machine.pub policy/policy.json
cilock policy validate -p policy/policy.json
cilock sign --offline -k keys/release-team.key -f policy/policy.json -o policy/policy.signed.json

# Receipts: each existing command is prefixed with `cilock run --step <name> ... --`.
cilock run --step build   -k keys/build-machine.key -a git --platform-url "" --material-manifest \
    -o evidence/build.json   -- cc app/photo_lite.c -o photo-lite
cilock run --step test    -k keys/build-machine.key -a git --platform-url "" --material-manifest \
    -o evidence/test.json    -- ./photo-lite
cilock run --step package -k keys/build-machine.key -a git --platform-url "" --material-manifest \
    -o evidence/package.json -- tar czf photo-lite.tar.gz photo-lite

# The check. Exit 0 is PASS; anything else is BLOCKED and the log says which step and rule.
cilock verify photo-lite.tar.gz \
    -p policy/policy.signed.json -k keys/release-team.pub \
    -s "sha1:$(git rev-parse HEAD)" --offline \
    -a evidence/build.json -a evidence/test.json -a evidence/package.json
```

## Part 2: iterate a policy against known-good and known-bad builds (the loop an AI agent runs)

Part 1 hands you a finished policy. Part 2 shows how you get there. It builds four fixtures once, each a real set of
signed receipts with a known right answer (`good` PASS; `swapped`, `skipped`, `failed` BLOCKED), then runs three
rounds. Each round builds the policy, runs `cilock policy validate`, signs it, and verifies every fixture:

| Round | Change | Validate findings | Verdicts correct |
|---|---|---|---|
| 1 | First draft (`rules-v1/`, no `artifactsFrom`) | 6 | 3/4: the swapped binary passes |
| 2 | Add `artifactsFrom` so test and package must use the build's output | 6 | 4/4 |
| 3 | Fix the Rego guard the validator flagged (`rules/`) | 0 | 4/4 |

**Stop condition: zero validate findings and all four verdicts correct.** Round 2 already gets every verdict right,
but the validator still reports that `not is_number(input.exitcode)` inside `deny` can never fire when the field is
missing, so a receipt without an exit code would pass. The fixtures do not cover that case; the validator does.

`cilock policy validate` prints `Policy validation: PASSED` and exits 0 even when it lists findings. The script
counts the numbered findings instead of trusting the exit code.

A person decides the fixtures and the stop condition. An agent can then run the rounds. Letting the same agent
define "done" and chase it is how you end up with a policy that passes its own tests and nothing else.

Every round is written to `part2-work/loop.jsonl`: the policy, the validate output, each verdict and the time. The
script avoids bash associative arrays, so it runs on the bash 3.2 that macOS ships.

## Gotchas

- **Keep receipts outside the build workspace.** A step's inputs are every file in its working directory; a receipt
  written inside the project shows up as an input no earlier step produced, and `artifactsFrom` rejects it.
- **`--material-manifest` is required for `artifactsFrom`.** Without it the per-file input list is omitted and
  verify fails with "required file inventory is unavailable".
- **Seed verify with the commit** (`-s sha1:<commit>`). With only the package as the seed, the build and test
  receipts are not found.
- **Key ID is the sha256 of the public key as Go re-encodes it** (PEM, LF line endings). On Windows openssl writes
  CRLF, so hashing the file gives the wrong ID. `tools/make_policy.py` re-encodes first.
- **Guard Rego rules with a helper rule** (`has_exit_code { is_number(input.exitcode) }`, then
  `not has_exit_code` in `deny`).
- **A failed step still writes a receipt**, which is how the rulebook can name the failure.

## Layout

| Path | What it is |
|---|---|
| `build-cilock.sh` | Builds `./bin/cilock` from this checkout |
| `part1-receipts.sh` | Part 1 |
| `part2-policy-loop.sh` | Part 2 |
| `app/photo_lite.c` | The app |
| `rules/*.rego` | The final rules, one per step |
| `rules-v1/*.rego` | Part 2's deliberately weak first draft |
| `tools/make_policy.py` | Builds the policy from a rules directory (`--rules DIR`, `--no-artifacts-from`) |
| `tools/show_receipt.py` | Prints a receipt in plain English |
