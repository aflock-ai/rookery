---
title: test-results
description: Sign JUnit XML or CTRF JSON test reports as a normalized test-results attestation under cilock, and gate on pass/fail counts with Rego that reads input.predicate.summary.
sidebar_position: 24
---

## You already run your tests. Here's what cilock adds.

A test runner writes a JUnit XML or CTRF JSON report. On its own that file proves nothing: it can be edited, it is not tied to the commit it ran against, and nobody downstream can tell whether the suite that "passed" contained any tests at all. Cilock wraps the same test command, hashes the report as a product, and emits a **signed, normalized summary** (totals, failed tests, tool identity, report digest) that a policy can gate on.

### What cilock adds

**Signed counts.** `total`, `passed`, `failed`, `skipped`, `errors` are recomputed from the report's `<testcase>` entries at every nesting level, including cases directly under `<testsuites>` and inside nested `<testsuite>` elements (JUnit), or read from `results.summary` (CTRF), then signed by the CI identity. A case marked `status="notrun"` or `status="disabled"` never counts as passed. CTest writes a test it could not run (missing executable, missing `REQUIRED_FILES`, failed fixture setup) as `<skipped>` while itself reporting it FAILED; the attestor counts it as an error. Only CTest's deliberate skips (`SKIP_RETURN_CODE`, `SKIP_REGULAR_EXPRESSION`, `DISABLED`) count as skipped. A case with no outcome element passes only when nothing else in the report contradicts it: a `status` or `result` value the attestor does not recognize, or a lone Surefire `<rerunFailure>`/`<rerunError>`, is an error or failure. When a suite's or the root's `failures`/`errors` attributes claim more than its cases show, each shortfall stays in its own category: missing failures raise `summary.failed` and missing errors raise `summary.errors`, taken from `passed` first. A file with more than one root element is refused, and so is any declared count (JUnit `tests`/`failures`/`errors`/`skipped` at any level, or a CTRF `results.summary` field) that is negative or above 2147483647. "Tests passed" becomes a defensible statement, not a green checkmark.

**Format-agnostic policy.** JUnit and CTRF both land in the same predicate shape, so one Rego module gates a Go, Python, JavaScript, or Java suite without caring which runner produced the file.

**Linked to the commit and the artifact.** The `git`, `github`, and `product` attestations in the same collection tie the counts to a commit hash and to the report file's digest. The `test-failure:<name>` subjects let a graph query find every run in which a given test failed.

**SLSA Level 3 evidence.** L3 expects proof that tests ran and passed; this attestor closes that loop.

## Validated invocation

The attestor is post-product: it reads a report the wrapped command wrote to the products. Plain `go test` has no JUnit flag, so route through `gotestsum` (or `go-junit-report`):

```bash
cilock run --step unit-test \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations environment,git,test-results \
  -- gotestsum --junitfile junit.xml -- ./...
```

`pytest --junitxml=junit.xml`, `jest --reporters=jest-junit`, Node's built-in runner (`node --test --test-reporter=junit --test-reporter-destination=junit.xml`), CTest (`ctest --test-dir build --output-junit junit.xml`, written inside the build directory), Gradle, Surefire and Terraform (`terraform test -junit-xml=junit.xml`, 1.11 or newer) all write a file the detector picks up (`junit*.xml`, `TEST-*.xml`, `ctrf-report.json`, `ctrf.json`). Terraform writes one `<testcase>` per `run` block. A run that never started because its test file failed first (for example a `mock_provider` whose provider is not installed) appears as a bare `<testcase>` with no outcome. Terraform reports it as neither passed nor failed and exits 1, so the attestor counts it under `errors`, not `passed`. Note that most runners exit non-zero when a test fails; if you want the report signed even on a red run, wrap the command so the report is written before the exit code propagates, and let the policy, not the exit code, decide.

## What gets captured

| Predicate type | Source |
|---|---|
| `https://aflock.ai/attestations/environment/v0.1` | host OS, kernel, env vars (sensitive ones obfuscated) |
| `https://aflock.ai/attestations/git/v0.1` | commit hash, branch, dirty status |
| `https://aflock.ai/attestations/command-run/v0.2` | the literal test argv and exit code |
| `https://aflock.ai/attestations/product/v0.3` | Merkle root over the report file |
| `https://aflock.ai/attestations/test-results/v0.1` | the normalized summary below |

The `test-results/v0.1` predicate:

| Field | Type | Meaning |
|---|---|---|
| `format` | string | `junit-xml` or `ctrf-json` |
| `toolName`, `toolVersion` | string | runner identity when the report carries it (CTRF always does; JUnit rarely) |
| `summary.total` | int | test cases seen |
| `summary.passed` | int | cases that ran and passed |
| `summary.failed` | int | cases that ran and failed |
| `summary.skipped` | int | cases skipped |
| `summary.errors` | int | cases that errored before reaching a verdict, including a CTest test that could not run, a case with an unrecognized status, and failures the report's attributes claim but its cases do not show; **omitted when zero** |
| `summary.durationSeconds` | float | wall-clock time reported by the runner |
| `failedTests[]` | array | up to 50 `{name, suite, classname, message, duration}` entries; counts in `summary` stay exact past the cap |
| `reportFile` | string | product path of the report |
| `reportDigest` | digest set | the report file's digest |

Subjects: `test-suite:<name>` for each top-level suite and `test-failure:<fqName>` for each failed case, both as SHA-256 of the identifier string.

## Rego input shape

**This attestor's fields sit under `input.predicate`, not at the top of `input`.** The verifier hands Rego the JSON of the registered attestor struct, and `test-results` registers

```go
type Attestor struct {
    Predicate Predicate `json:"predicate"`
}
```

so what a policy receives is

```json
{"predicate": {"format": "junit-xml", "summary": {"total": 6, "passed": 3, "failed": 2, "skipped": 1}, "failedTests": [...], "reportFile": "junit.xml", "reportDigest": {...}}}
```

Most attestors register a flat struct, which is why their policies read `input.exitcode` (command-run), `input.commithash` (git), or `input.findings` (secretscan). `test-results` is one of four that wrap the predicate: `test-results`, `steampipe`, `scubagoggles`, and `structured-data` all read as `input.predicate.<field>`. Neither convention is a bug; the shape is per-attestor, and the wrapper is part of the signed `v0.1` wire format, so it is not going to move without a new predicate type.

Copy this and start from it:

```rego
package testresults

# Fields are under input.predicate (this attestor wraps its predicate).
# Read every count through object.get with a non-numeric default: an
# ABSENT field makes is_number(...) itself undefined, so `not is_number(x)`
# does NOT fire for a missing count — the guard has to compare a value that
# always exists.

summary := object.get(input.predicate, "summary", {})

deny[msg] {
	not is_number(object.get(summary, "failed", null))
	msg := "unreadable evidence: test-results summary.failed missing or malformed"
}

deny[msg] {
	not is_number(object.get(summary, "passed", null))
	msg := "unreadable evidence: test-results summary.passed missing or malformed"
}

deny[msg] {
	object.get(summary, "failed", 0) > 0
	msg := sprintf("%d test(s) failed", [summary.failed])
}

deny[msg] {
	is_number(object.get(summary, "passed", null))
	summary.passed < 1
	msg := "no test passed: an empty suite proves nothing"
}

deny[msg] {
	object.get(summary, "errors", 0) > 0
	msg := sprintf("%d test(s) errored before reaching a verdict", [summary.errors])
}
```

| You wrote | What happens | Write instead |
|---|---|---|
| `input.summary.failed > 0` | `input.summary` is undefined; the rule body never matches, and the verifier refuses the step (#9820) instead of evaluating your rule | `input.predicate.summary.failed > 0` |
| `input.failedTests[_].name` | undefined, same refusal | `input.predicate.failedTests[_].name` |
| `input.predicate.summary.errors > 0` | `errors` is omitted when zero, so on a clean run the read is undefined and the verifier refuses the step (#9820) | `object.get(input.predicate.summary, "errors", 0) > 0` |

Rego treats an undefined path in a `deny` body as "this rule does not fire". The flat form used to fail **open** that way; since #9820 the verifier refuses an admit that rests on such a read, with an error naming the missing path. The `not is_number(object.get(...))` rules above still earn their place: they turn a missing count into a deny that says what is wrong, and there should be one **per count the policy depends on**.

Two details in that guard are load-bearing, and both were wrong in an earlier draft of this page:

- **`object.get(summary, "failed", null)`, not `input.predicate.summary.failed`.** An absent field makes `is_number(...)` itself undefined, and an undefined expression makes the whole rule body undefined — so `not is_number(input.predicate.summary.failed)` does **not** fire for the missing count it was written to catch. Comparing a value that always exists (the default) is what makes the guard reachable.
- **`summary := object.get(input.predicate, "summary", {})`**, so a predicate with no summary at all takes the same path as one with an empty summary, instead of leaving every rule undefined. `cilock policy validate` also warns when a module bound to `test-results/v0.1` reads a top-level predicate field.

When the step uses `attestationsFrom` or `externalFrom`, the whole input is re-shaped to `{attestation, steps, external}` and this attestor's own fields move to `input.attestation.predicate.summary.*`; see the [policy schema](../reference/policy-schema#verification-process).

## Gotchas

- **`summary.errors` is omitted when zero.** Read it through `object.get(..., "errors", 0)`; a policy that requires the key present refuses every clean run.
- **The runner's exit code is not the verdict.** `gotestsum`, `pytest`, and `jest` exit non-zero on a failed test, which makes `command-run` record a non-zero `exitcode` and the run fail before the report is signed unless you wrap the command. Decide pass/fail from `input.predicate.summary`, and gate `command-run` separately if you want the exit code enforced.
- **Format detection is by content, not extension.** The first non-whitespace byte selects the parser (`<` is JUnit XML, `{` is CTRF JSON), so a `.xml` file containing JSON is parsed as CTRF.
- **`failedTests` is capped at 50 entries.** `summary.failed` remains exact; the cap only trims the per-test detail.
- **Timing and messages vary run to run.** `summary.durationSeconds`, `failedTests[].duration`, and `failedTests[].message` are volatile; do not pin them in a golden compare.
