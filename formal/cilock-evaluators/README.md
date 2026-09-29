# cilock policy evaluators: a Lean 4 model

A machine-checked model of how cilock's policy engine turns evaluator
results into a verdict, and of what a Verification Summary Attestation (VSA)
proves when a later verification consumes it. It covers:

- **Rego.** `EvaluateRegoPolicy` / `evaluateRegoInput` in
  `attestation/policy/rego.go`, the deny-only convention, the
  duplicate-package hardening flag, the unread-`allow` refusal
  (`regoallow.go`), the missing-field refusal (`regostrict.go`) and the
  deadline refusal (`regorefusal.go`).
- **AI policies.** Validation (`ai_validate.go`), the generative provider
  (`ai.go`), the typed-decision Jev provider (`ai_jev.go`), the checks
  `EvaluateAIPolicyWithProvider` holds every provider to (one answer per
  policy, status exactly PASS or FAIL, answered by the policy's own model),
  and the pass/fail mapping.
- **The step gate.** `gateOneContext` in `step.go`: how Rego and AI verdicts
  combine per attestor, per required type, and per collection.
- **External attestations.** The envelope gate and the external result
  (`policy.go`), plus the verify aggregation `VerifyWithExternals`.
- **VSAs.** Emission (`plugins/attestors/policyverify`) and consumption as an
  external attestation (`plugins/attestors/vsa`).

Trust and linking are not modelled here: functionaries, signatures, subject
search and cross-step artifact linking are covered by `formal/cilock-policy`.
They enter as inputs. A collection reaches the gate already
functionary-authorised, and a step's pass bits are whatever trust, linking and
this gate produced.

Lean `v4.34.1` (pinned in `lean-toolchain`). Core only, no Mathlib.

## Build and run

```bash
lake build                                   # model, proofs, audit, oracle binary (~21 s clean)
go test ./attestation/policy -run TestFormalDifferential -v   # Go vs Lean, from the rookery root
```

Every theorem is closed. `CilockEvaluators/Audit.lean` prints
`#print axioms` for each exported result, and every line lists only Lean's
core axioms (`propext`, `Quot.sound`, `Classical.choice`). There is no
`sorry`, no `native_decide` and no user axiom.

## Layout

| File | What it models |
| --- | --- |
| `Types.lean` | Shared vocabulary: `Digest`, `PolicyDigest`, `Subject`, `VerifierIdentity`, `Timestamp`, `Verdict`. A later common library can replace this one file by refinement; no proof looks inside these types. |
| `Rego.lean` | The Rego evaluator with its unread-`allow`, missing-field and deadline refusals, E1/E2/E3 for Rego, and the hoisted-negation hazard it now closes. |
| `Ai.lean` | AI policies, both providers, the response checks (`checked`), the gate, E1/E2/E4/E5 for AI. |
| `Gate.lean` | Step gate, external gate, verify aggregation, **`evaluators_fail_closed`**. |
| `Vsa.lean` | VSA emission and consumption, `Assumptions`, **`vsa_exact_policy_sound`**, `vsa_non_amplification`. |
| `Nested.lean` | Nested externals (`childPolicyDigest`, `timestampConstraint`): the newest admitted child VSA decides, at its signed time. **`latest_sound`**, **`parent_sound`**, `admit_time_is_signed`; `tsa_ordering_restamp_passes` refutes ordering by TSA time. |
| `Holdout.lean` | Predictions for four real test fixtures (below). |
| `Oracle.lean`, `OracleMain.lean` | The model as an executable (`cilock-evaluators-oracle`) for differential testing. |
| `Audit.lean` | `#print axioms` for every result. |

## Results

"Proved" means a Lean theorem over the model. "Refuted" means a concrete Lean
trace, checked by `decide`, showing that the stated property does not hold as
built.

| # | Property | Status | Theorems |
| --- | --- | --- | --- |
| E1 | Fail-closed evaluators | **Proved.** Parse errors, OPA faults, an undefined `deny`, a non-collection `deny`, an unread `allow`, an admit that rests on a missing input field, invalid policy sets, provider errors and refusals, malformed, mistyped or out-of-schema answers, a wrong response count, and model mismatch all reject. The 30 s deadline is a refusal, never a pass or a deny (#9872). The former boundary, an undefined sub-expression *inside* a deny body, was **refuted as built** by the first version of this model (`hoisted_negation_admits_missing_field`, testifysec/judge#9820) and is **fixed by #9869**: after an admit, `regostrict.go` asks Rego whether any read an admitting deny body depended on was undefined, and refuses. The model takes the probe's report as an input; which reads it covers (not positive reads in helper rules, for one) is stated in `regostrict.go` and not modelled. | `Rego.eval_pass_iff`, `Rego.*_rejects`, `Rego.refused_only_on_deadline`, `Gate.env_rego_deadline_refuses`, `Gate.optional_external_rego_deadline_is_refusal`, `Rego.hoisted_negation_missing_field_rejected`, `Rego.missing_read_never_passes`, `Ai.gate_pass_iff`, `Ai.provider_error_rejects`, `Ai.jev_failures_refuse` |
| E2 | Conjunction | **Proved, exact combinator.** A collection passes iff it is named for the step, the step requires something, the collection has no verification errors, every required type is present, and every attestor of every type passes every Rego module (one conjunctive query) and every AI policy, with one exact `PASS` per policy. A passing duplicate cannot shadow a failing one. | `Gate.gate_passed_iff`, `Rego.modules_conjunctive`, `Gate.no_shadowing`, `Gate.verify_accepts_iff`, `Ai.gate_pass_all_pass` |
| E3 | Polarity | **Proved as deny-only.** The verdict reads only `<pkg>.deny`; the value of `allow` is never queried. A module that defines no `deny` cannot pass. A module that defines an `allow` no deny rule reaches is refused before evaluation (#9870, `regoallow.go`, which uses `regopolarity.go`'s reachability index), so `deny := []` with `allow := false`, which **passed as built** in the first version of this model (`both_defined_allow_false_passes`, testifysec/judge#9820), is now an error. Duplicate packages merge unless `RejectDuplicateRegoPackage` is set. | `Rego.only_deny_is_read`, `Rego.allow_is_inert`, `Rego.neither_rejects`, `Rego.allow_unread_rejects`, `Rego.both_defined_allow_unread_rejected`, `Rego.duplicate_package_merged_by_default` |
| E4 | AI determinism | **Proved for typed decisions.** The verdict is `decideAnswer decision answer`, with a constant reason string. Every bound is inclusive (`>=` and `<=`), and `deny` wins over `allow`. On the generative path the verdict is the model's own `status` text. | `Ai.jevOne_verdict`, `Ai.*_inclusive`, `Ai.choice_deny_wins`, `Ai.generative_status_is_model_output` |
| E5 | Model pinning | **Proved on both paths.** Jev requires a `jev-X.Y.Z` name and `resolved == requested`. The generative path was **refuted as built** by the first version of this model (`generative_model_not_verified`, testifysec/judge#9820): the verdict recorded the policy's model and never learned which model the server ran. **Fixed by #9871**: the Ollama reply's `model` must equal the policy's, and `EvaluateAIPolicyWithProvider` refuses any answer whose recorded model is empty or differs, for every provider. | `Ai.jev_model_pinned`, `Ai.generative_model_pinned`, `Ai.generative_other_model_refused`, `Ai.gate_pass_all_pass` |
| E6 | VSA exact policy | **Proved under `Assumptions` and `ExactPolicyRego`.** The engine itself guarantees the signature, the requested subject and an allowed signer (`accepts_iff`). Result, policy digest and freshness hold when the consumer's Rego checks them. | `Vsa.accepts_iff`, `Vsa.vsa_exact_policy_sound` |
| E7 | VSA non-amplification | **Proved under the same premises.** An accepted VSA stands for a real upstream run that accepted, under the byte-identical policy, about the requested subject. | `Vsa.vsa_non_amplification`, `Vsa.emit_sound`, `Vsa.emit_refusal_none` |

Two further facts matter to anyone composing on this model. `Vsa.policy_subject_matches_every_artifact`: every VSA of a policy names that policy's digest as a subject. And `Gate.refusal_is_not_a_verdict`: a refusal, an AI refusal or a Rego deadline, never becomes a completed pass or fail.

### Assumptions

Everything the VSA results trust is stated as a named field of
`Vsa.Assumptions`, and no definition depends on it:

- `unforgeable`: a verified DSSE signature means the named signer produced exactly those bytes.
- `honestVerifier`: an allowed identity signs only VSAs that `emit` produced from a real run.
- `digestInjective`: collision resistance of the digest over exact bytes.

AI provider honesty is **not** assumed, and since #9873 nothing is assumed
about the provider code either: `EvaluateAIPolicyWithProvider` enforces the
provider contract (one answer per policy, each exactly `PASS` or `FAIL`)
for any provider (`Ai.checked_contract`). Both in-tree providers also honour
it on their own (`Ai.ollama_contract`, `Ai.jev_contract`).

## Code binding

Every citation of code in these Lean files is a line of the form

```
-- cite: <path>:<start>-<end> sha256:<hash>
```

The path is relative to the rookery root. The hash is SHA-256 over the exact
bytes of lines `start..end`, each line including its trailing newline. When
the code under a citation changes, the hash stops matching. Re-read the code,
correct the model if its meaning changed, then re-stamp.

The hash is the anchor and the line span is a hint. The checker searches the
file for a span of the same length with that hash and passes when exactly one
exists, wherever it now sits, so an edit that only moves the code fails
nothing. `jade check formal-citations --fix` rewrites the hint. No match, or
more than one, fails.

## Differential testing

`attestation/policy/formal_differential_test.go` generates random cases, runs
the real Go code on each, pipes the same cases to `cilock-evaluators-oracle`,
and fails on any disagreement. Without the binary it skips. The four suites:

- **rego.** Random module sets: duplicate packages, parse errors, every `deny` shape including builtin faults, the hoisted negation and a positive read of the same missing field, an unread and a read `allow`, and the hardening flag on and off.
- **ai.** Typed decisions through the real Jev provider against a local server. Replies cover transport failures, HTTP errors, malformed bodies, model mismatch, and missing, bad, mistyped and out-of-range answers. Bounds are biased to their edges.
- **gate.** `gateOneContext` with random collections, Rego, and an in-process provider, including outcomes that break the contract and answers that name no model or another model.
- **vsa.** Externals-only policies consuming VSA candidates with varied subject, signer, signature, result, policy digest and age, under three consumer Rego shapes.

Results at the time of writing: 3 seeds × 3,000 cases × 4 suites, then the
default 600 per suite, with **0 mismatches** after one triaged model gap. That
gap was a Jev refusal of a score ladder shorter than two levels, which
`Validate` accepts and the provider refuses (`invalid_score_levels`). The Go
behaviour is the fail-closed one, and the model was corrected. Planting a
wrong hardening flag or a wrong signer check in the oracle produced 29 and
84 mismatches respectively, so the harness does see differences.

Re-run on 2026-09-25, after the model was brought up to #9869 to #9873: the
model as first merged disagreed with the code on 12 of 600 rego cases (the
missing-field refusal) and 53 of 600 gate cases (the response checks and
the missing-field refusal). The updated model reads three more inputs, which
the driver now emits: each module's unread `allow`, the missing-field
probe's report, and the model each gate response names. The rego suite also
gained an unread and a read `allow`, and a positive read of the missing
field; the gate suite, answers that name no model or another model. After
the update, seed 1 at 600 cases and seeds 7, 31, 977 and 4242 at 3,000
cases gave **0 mismatches** in all four suites. No suite generates a Rego
deadline, so the deadline refusal (`Rego.refused_only_on_deadline`,
`Gate.env_rego_deadline_refuses`) is checked by proof only.

## Holdout

Four real fixtures were chosen before the model was written and never used to
tune it:

| Fixture | Cases | Model prediction | Go test |
| --- | --- | --- | --- |
| `TestJevProviderContractThresholdsAreLocal` | 6 threshold cases | pass, fail, fail, pass, pass, fail | PASS |
| `TestJevProviderContractRefusalsAreNotFindings` | 12 reply classes of its 19 | refusal, no response | PASS |
| `TestExternal_09_TwoExternalsSamePredicateDifferentRego` | 1 | `accepted false`, no error | PASS |
| `TestRed_D_NonStringDenyMustFailClosed` | 1 | `deny` | PASS |

All predictions held on the first build, and all four tests still pass
against the code of #9869 to #9873.

## Abstractions to know about

- **Numbers.** float64 is modelled as fixed point with ten decimals. Comparisons are exact; decimal-to-binary rounding is not modelled.
- **OPA.** Not modelled. The model takes OPA's `deny` value per package, a fault flag and whether the fault is the deadline, whether a module's `allow` is unread (`regoallow.go`), and what the missing-field probe reported (`regostrict.go`). The Rego texts the differential emits are what tie those abstract values back to OPA.
- **Jev.** Answer shape checks beyond kind, range and option membership (distribution sums, legends) collapse into "does not parse". Request grouping by model and state is not modelled.
- **Envelope order.** When a candidate both fails its signature and names another subject, the model treats it as unbound. That order belongs to the verified source, which the trust model owns.
