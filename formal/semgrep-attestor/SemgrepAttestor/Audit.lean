/-
  SemgrepAttestor.Audit: every headline result and the axioms it rests on.
  `lake build` prints one `#print axioms` line per theorem; each must list
  only Lean's core axioms (propext, Quot.sound, Classical.choice).
  `sorryAx` or `Lean.ofReduceBool` in any line is a failure.
-/
import SemgrepAttestor.Select
import SemgrepAttestor.Summary

namespace SemgrepAttestor

-- selection
#print axioms select_attest_iff
#print axioms select_soft_iff
#print axioms broken_refuses
#print axioms two_goods_refuse
#print axioms select_perm
-- summary
#print axioms scanComplete_iff
#print axioms bucketTotal_eq_live
#print axioms live_add_ignored
#print axioms finding_subject_live
#print axioms file_subject_recorded

end SemgrepAttestor
