/-
  CilockPolicy.Audit: every headline result and the axioms it rests on.
  `lake build` prints one `#print axioms` line per theorem; each must list only
  Lean's core axioms (propext, Quot.sound, Classical.choice). `sorryAx` or
  `Lean.ofReduceBool` in any line fails the Lean model gate.
-/
import CilockPolicy.Launder
import CilockPolicy.TrustCounterexamples
import CilockPolicy.LinkingCounterexamples
import CilockPolicy.Order
import CilockPolicy.Holdout
import CilockPolicy.BoundProof
import CilockPolicy.NonVacuity

namespace CilockPolicy

-- Theorem 1 / exported
#print axioms verifyFixed_spec
#print axioms policy_sound
#print axioms NonVacuity.assumptions_inhabited
#print axioms NonVacuity.unscoped_tsaNotFuture_refuted
-- Theorem 2
#print axioms no_cross_step
-- Theorem 3 / L1
#print axioms anchor_sound
-- Theorem 4
#print axioms expired_fails_fixed
#print axioms expired_fails_asBuilt
#print axioms untrusted_never_triaged
#print axioms unknown_key_no_verifier
-- Theorem 5 / L5
#print axioms attestationsFrom_wellFounded
#print axioms prune_fixed
#print axioms prune_keep
-- Theorem 6
#print axioms order_independent
-- Theorem 7 / L6
#print axioms flood_resistant
#print axioms flood_resistant_asBuilt
-- L3
#print axioms no_laundering
-- V1, V2
#print axioms listOk_nonvacuous
#print axioms fValidate_enforce
#print axioms fValidate_mono
#print axioms triage_mono
#print axioms hardening_monotone
-- V3, V4, V5, V6
#print axioms commit_bound
#print axioms external_commit_bound
#print axioms about_irrelevant
#print axioms about_needs_v02
#print axioms lazy_eq_eager
#print axioms LinkingCounterexamples.requireAll_consumes
-- V7
#print axioms timestamp_sound
#print axioms verifier_times_tsa
#print axioms meetsMin_sound
#print axioms absent_never_meets
#print axioms repeated_never_meets
#print axioms unknown_min_never_meets
#print axioms ccCheck_min_assurance
#print axioms assurance_examples
#print axioms policy_signer_min_assurance
#print axioms triage_skew_irrelevant
-- Counterexamples (kernel-decided traces)
#print axioms Launder.control_fails
#print axioms Launder.flooded_passes
#print axioms Launder.scanClean_pruned
#print axioms Launder.fixed_flooded_fails
#print axioms TrustCounterexamples.v1_all_star_admits_anyone
#print axioms TrustCounterexamples.r3_181_off_admits
#print axioms TrustCounterexamples.r3_181_on_refuses
#print axioms TrustCounterexamples.r3_184_off_admits
#print axioms TrustCounterexamples.r3_184_on_refuses
#print axioms TrustCounterexamples.v2_timestamp_counterexample
#print axioms TrustCounterexamples.timestamp_after_expiry_passes
#print axioms LinkingCounterexamples.l2_algorithm_label_compared
#print axioms LinkingCounterexamples.l4_backref_not_followed
#print axioms LinkingCounterexamples.v6_untracked_material
#print axioms LinkingCounterexamples.v6_overlap_not_allowed
#print axioms LinkingCounterexamples.v6_re2_grammar
#print axioms LinkingCounterexamples.GitSubject.null_oid_not_matchable
#print axioms LinkingCounterexamples.GitSubject.commit_forms_matchable
#print axioms LinkingCounterexamples.GitSubject.commit_forms_refused
#print axioms LinkingCounterexamples.fanout_flood_flips
#print axioms LinkingCounterexamples.l5_artifact_cycle_passes
#print axioms LinkingCounterexamples.l5_oscillation_fails_closed
-- #9813 fix: round bound (1c49f05539)
#print axioms fix9813_converges
#print axioms verifyFix9813_eq_verifyFixed
#print axioms jointFixed_unique
#print axioms bound_counterexample_validators
#print axioms bound_scope_gap
#print axioms Bound9813.m2_passes
#print axioms Bound9813.m3_refused
#print axioms Bound9813.m3_converges_later
-- Holdout
#print axioms Holdout.dr_prediction
#print axioms Holdout.release_prediction
#print axioms Holdout.release_prediction_after_9866
#print axioms Holdout.shm_prediction

end CilockPolicy
