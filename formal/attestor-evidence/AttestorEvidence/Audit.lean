/-
  AttestorEvidence.Audit: the results, and the axioms they rest on. `lake build`
  prints the `#print axioms` lines; every one must name only Lean's core axioms
  (propext, Quot.sound, Classical.choice). No sorry, no native_decide.
-/
import AttestorEvidence.Vectors

namespace AttestorEvidence

-- SBOM image-digest backref
#print axioms Sbom.version_backref_needs_container
#print axioms Sbom.version_backref_is_exact
#print axioms Sbom.purl_wins
-- commandrun program record
#print axioms Program.rooted_takes_dir_volume
#print axioms Program.absolute_unchanged
#print axioms Program.oldConcat_measures_a_decoy
#print axioms Program.not_setid_needs_established_absence
#print axioms Program.read_error_is_unknown
#print axioms Program.record_never_verified
-- cilock-action script capture
#print axioms Script.exec_is_sh_c
#print axioms Script.capture_mode_never_changes_exec
#print axioms Script.read_only_plain_sh
#print axioms Script.functions_abstain
#print axioms Script.sensitive_value_refused
#print axioms Script.shape_refused
#print axioms Script.passes_iff
-- Vectors
#print axioms Vectors.sbomVectors_hold
#print axioms Vectors.programVectors_hold
#print axioms Vectors.oldRule_wrong_on_five
#print axioms Vectors.setIdVectors_hold
#print axioms Vectors.shVectors_hold
#print axioms Vectors.guardVectors_hold
#print axioms Vectors.multibyte_value_at_floor_refused

end AttestorEvidence
