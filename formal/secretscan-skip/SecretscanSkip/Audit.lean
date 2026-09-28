/-
  SecretscanSkip.Audit: the exported results and the axioms they rest on.
  `lake build` prints each `#print axioms` line; every one must list only
  Lean's core axioms (propext, Quot.sound, Classical.choice). `sorryAx` or
  `Lean.ofReduceBool` in any line fails the audit.
-/
import SecretscanSkip.Theorems

open SecretscanSkip

#print axioms skip_proven
#print axioms skip_implies_untracked
#print axioms tracked_never_skipped
#print axioms skip_implies_own
#print axioms symlink_never_skipped
#print axioms symlink_to_stream_never_skipped
#print axioms no_git_never_skipped
#print axioms outside_never_skipped
#print axioms dirty_residual_scanned
#print axioms not_own_never_skipped
#print axioms skip_iff
#print axioms gitlink_never_skipped
#print axioms nested_repo_never_skipped
#print axioms tree_scope_skipped_only_by_stream
#print axioms round2_skipped_nested_repo_tracked
#print axioms current_scans_nested_repo
#print axioms round2_skipped_tree_scope_envelope
#print axioms current_scans_tree_scope_envelope
#print axioms recorded_product_skipped_only_by_stream
#print axioms recorded_non_stream_scanned
#print axioms current_skips_recorded_own_stream
#print axioms round2_skipped_gitlink_tracked
#print axioms current_scans_gitlink
#print axioms round2_skipped_recorded_product
#print axioms current_scans_recorded_product
#print axioms round2_breaks_untracked
#print axioms round1_skipped_tracked
#print axioms current_scans_parent_symlink
#print axioms round0_skipped_tracked
#print axioms round1_scans_final_symlink
#print axioms current_scans_final_symlink
#print axioms round1_breaks_untracked
#print axioms round0_breaks_untracked
