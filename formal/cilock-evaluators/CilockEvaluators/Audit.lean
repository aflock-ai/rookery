/-
  CilockEvaluators.Audit: the exported results and the axioms they rest on.
  `lake build` prints each `#print axioms` line; every one must list only
  Lean's core axioms (propext, Quot.sound, Classical.choice). `sorryAx` or
  `Lean.ofReduceBool` in any line fails the axiom audit.
-/
import CilockEvaluators.Holdout

open CilockEvaluators

-- Exported for the composed cilock proof.
#print axioms Gate.evaluators_fail_closed
#print axioms Vsa.vsa_exact_policy_sound
#print axioms Vsa.vsa_non_amplification

-- E1
#print axioms Rego.eval_pass_iff
#print axioms Rego.fault_rejects
#print axioms Rego.parse_error_rejects
#print axioms Rego.undefined_deny_rejects
#print axioms Rego.scalar_deny_rejects
#print axioms Rego.nonempty_deny_rejects
#print axioms Ai.gate_pass_iff
#print axioms Ai.provider_error_rejects
#print axioms Ai.invalid_set_rejects
#print axioms Ai.jev_failures_refuse
#print axioms Ai.decision_without_provider_rejects
#print axioms Rego.hoisted_negation_admits_missing_field
-- E2
#print axioms Rego.modules_conjunctive
#print axioms Gate.gate_passed_iff
#print axioms Gate.gate_fail_closed
#print axioms Gate.no_shadowing
#print axioms Gate.envGate_passed_iff
#print axioms Gate.external_pass_has_witness
#print axioms Gate.verify_accepts_iff
#print axioms Gate.refusal_is_not_a_verdict
#print axioms Ai.gate_pass_all_pass
#print axioms Ai.ollama_contract
#print axioms Ai.jev_contract
-- E3
#print axioms Rego.only_deny_is_read
#print axioms Rego.allow_is_inert
#print axioms Rego.neither_rejects
#print axioms Rego.both_defined_allow_false_passes
#print axioms Rego.duplicate_package_merged_by_default
-- E4
#print axioms Ai.jevOne_verdict
#print axioms Ai.yesNo_min_inclusive
#print axioms Ai.yesNo_max_inclusive
#print axioms Ai.choice_minConf_inclusive
#print axioms Ai.score_bounds_inclusive
#print axioms Ai.choice_deny_wins
#print axioms Ai.generative_status_is_model_output
-- E5
#print axioms Ai.jev_model_pinned
#print axioms Ai.generative_model_not_verified
-- E6 / E7
#print axioms Vsa.emit_refusal_none
#print axioms Vsa.emit_sound
#print axioms Vsa.accepts_iff
#print axioms Vsa.policy_subject_matches_every_artifact
-- Holdout
#print axioms Holdout.h1_thresholds
#print axioms Holdout.h2_refusals
#print axioms Holdout.h3_optional_rejected_external_fails
#print axioms Holdout.h4_nonstring_deny
