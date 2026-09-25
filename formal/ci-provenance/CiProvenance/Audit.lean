import CiProvenance.AlpsProofs
import CiProvenance.Slsa
import CiProvenance.Subjects
import CiProvenance.Verdict
import CiProvenance.Actors
import CiProvenance.SlsaL3Workflow

/-! Axiom audit: every headline theorem must depend only on Lean's core
axioms (propext, Quot.sound, Classical.choice). No `native_decide`. -/

open CiProvenance

-- ALPS 1
#print axioms alps1_who
#print axioms harness_faithful_what
#print axioms alps1_guarantee
#print axioms asBuilt_is_alps1
#print axioms asBuilt_content_is_harness_report
#print axioms alps1_unfaithful_harness
#print axioms human_session_not_alps1
-- ALPS 2
#print axioms alps2_sound
#print axioms alps2_products
#print axioms alps2_lax_boundary
#print axioms alps2_products_need_sibling_closed
#print axioms alps2_attribution_needs_harness
-- ALPS 3 (designed)
#print axioms alps3_sound
#print axioms alps3_products
#print axioms cilockdLinuxTpm_is_alps3
#print axioms alps3_products_need_sibling_closed
#print axioms alps3_attribution_needs_harness
#print axioms no_attested_key_not_alps3
#print axioms same_uid_daemon_not_alps3
#print axioms alps3_needs_daemon_trust
#print axioms alps3_needs_hw_root_trust
-- attribution and forgery
#print axioms deriveAlps_ignores_attribution
#print axioms execution_forgeable_iff
#print axioms products_forgeable_iff
#print axioms harness_forges_execution_iff
#print axioms harness_forges_products_iff
-- SLSA
#print axioms slsa_l1
#print axioms slsa_l2
#print axioms slsa_l3
#print axioms cilockInJob_is_l2
#print axioms isolatedBuilder_is_l3
#print axioms localRun_is_l1
#print axioms naive_l3_accepts_step_forgery
-- subjects
#print axioms subject_binding
#print axioms provenance_subject_is_product_digest
#print axioms seed_match_binds_product
#print axioms file_key_collision_overwrites
#print axioms second_producer_overwrites
#print axioms value_match_crosses_algorithms
-- verdict
#print axioms positive_verdict_needs_complete_walk
#print axioms detected_iff
#print axioms verdict_never_unavailable
-- SLSA L3 provenance workflow (designed, not implemented)
open CiProvenance.L3 in #print axioms l3_sound
open CiProvenance.L3 in #print axioms l3_signer_not_controlled
open CiProvenance.L3 in #print axioms l3_sound_platform
open CiProvenance.L3 in #print axioms l3_sound_public
open CiProvenance.L3 in #print axioms honest_accepted
open CiProvenance.L3 in #print axioms honest_world_producible
open CiProvenance.L3 in #print axioms tag_pinned_swapped
open CiProvenance.L3 in #print axioms caller_inputs_into_fields
open CiProvenance.L3 in #print axioms other_run_outputs_mixed_in
open CiProvenance.L3 in #print axioms pull_request_target_accepted
open CiProvenance.L3 in #print axioms inline_l2_accepted_as_l3
open CiProvenance.L3 in #print axioms builder_id_without_extension
open CiProvenance.L3 in #print axioms self_hosted_runner_accepted
open CiProvenance.L3 in #print axioms both_roots_need_both
