import TestResults.Model

/-!
# The verdict invariant

`failed + errors` never decreases along the walk, a case classified as a
failure or error raises it, and a suite claiming more than its subtree shows
raises it. So a report with any non-passing signal never summarizes as clean.
-/

namespace TestResults

theorem count_bad_mono (s : Summary) (o : Outcome) : s.bad ≤ (count s o).bad := by
  cases o <;> simp [count, Summary.bad] <;> omega

theorem count_bad_of_bad (s : Summary) (o : Outcome) (h : o.bad = true) :
    s.bad + 1 ≤ (count s o).bad := by
  cases o <;> simp_all [count, Summary.bad, Outcome.bad] <;> omega

theorem reconcile_bad_mono (s before : Summary) (f e : Nat) : s.bad ≤ (reconcile s before f e).bad := by
  simp only [reconcile, Summary.bad]; omega

/-- A reconciled suite shows at least what it claims, in each category. -/
theorem reconcile_covers_each (s before : Summary) (f e : Nat)
    (hf : before.failed ≤ s.failed) (he : before.errors ≤ s.errors) :
    f ≤ (reconcile s before f e).failed - before.failed ∧
      e ≤ (reconcile s before f e).errors - before.errors := by
  simp only [reconcile]; omega

/-- ... and so at least the larger claim in total. -/
theorem reconcile_covers_claim (s before : Summary) (f e : Nat)
    (hf : before.failed ≤ s.failed) (he : before.errors ≤ s.errors) :
    max f e ≤ (reconcile s before f e).bad - before.bad := by
  simp only [reconcile, Summary.bad]; omega

theorem step_bad_mono (st : St) (x : Step) : st.sum.bad ≤ (step st x).sum.bad := by
  cases x with
  | case n c => exact count_bad_mono _ _
  | enter => simp [step]
  | exit f e =>
    simp only [step]
    split <;> exact reconcile_bad_mono _ _ _ _

theorem run_bad_mono (st : St) (xs : List Step) : st.sum.bad ≤ (run st xs).sum.bad := by
  induction xs generalizing st with
  | nil => simp [run]
  | cons x xs ih =>
    simp only [run, List.foldl_cons] at *
    exact Nat.le_trans (step_bad_mono st x) (ih _)

theorem run_cases_mono (st : St) (xs : List Step) : st.cases ≤ (run st xs).cases := by
  induction xs generalizing st with
  | nil => simp [run]
  | cons x xs ih =>
    simp only [run, List.foldl_cons] at *
    refine Nat.le_trans ?_ (ih _)
    cases x <;> simp [step] <;> split <;> simp

/-- Any bad case anywhere in the walk leaves `failed + errors > 0` and at
least one counted case. -/
theorem run_bad_of_case (st : St) (xs : List Step) (n : String) (c : Case)
    (hmem : Step.case n c ∈ xs) (hb : (classify n c).bad = true) :
    0 < (run st xs).sum.bad ∧ 0 < (run st xs).cases := by
  induction xs generalizing st with
  | nil => simp at hmem
  | cons x xs ih =>
    simp only [run, List.foldl_cons] at *
    rcases List.mem_cons.mp hmem with h | h
    · subst h
      have hb1 : st.sum.bad + 1 ≤ (step st (Step.case n c)).sum.bad :=
        count_bad_of_bad st.sum (classify n c) hb
      have hc1 : st.cases + 1 ≤ (step st (Step.case n c)).cases := by simp [step]
      have hm := run_bad_mono (step st (Step.case n c)) xs
      have hc := run_cases_mono (step st (Step.case n c)) xs
      show 0 < (run (step st (Step.case n c)) xs).sum.bad ∧ 0 < (run (step st (Step.case n c)) xs).cases
      exact ⟨by omega, by omega⟩
    · exact ih _ h

/-- **nonpassing_signal_counts**: if any case in the report is classified as
a failure or error, the summary has `failed + errors > 0`. -/
theorem nonpassing_signal_counts (r : Report) (n : String) (c : Case)
    (hmem : Step.case n c ∈ r.steps) (hb : (classify n c).bad = true) :
    0 < (summarize r).bad := by
  obtain ⟨hbad, hcases⟩ := run_bad_of_case {} r.steps n c hmem hb
  unfold summarize
  simp only [show (run {} r.steps).cases ≠ 0 by omega, ite_false]
  exact Nat.lt_of_lt_of_le hbad (reconcile_bad_mono _ _ _ _)

/-- **root_claim_counts**: a root that claims failures or errors over a report
with cases always leaves `failed + errors` at least that claim. -/
theorem root_claim_counts (r : Report) (h : (run {} r.steps).cases ≠ 0) :
    max r.failures r.errors ≤ (summarize r).bad := by
  unfold summarize
  simp only [h, ite_false]
  have := reconcile_covers_claim (run {} r.steps).sum {} r.failures r.errors (Nat.zero_le _) (Nat.zero_le _)
  simpa [Summary.bad] using this

/-- **root_claimed_failures_counted**: a root that claims failures over a
report with cases always has at least that many in `summary.failed`, so a
policy reading only `failed` still refuses it. -/
theorem root_claimed_failures_counted (r : Report) (h : (run {} r.steps).cases ≠ 0) :
    r.failures ≤ (summarize r).failed := by
  unfold summarize
  simp only [h, ite_false]
  have := (reconcile_covers_each (run {} r.steps).sum {} r.failures r.errors (Nat.zero_le _) (Nat.zero_le _)).1
  simpa using this

/-- **summary_only_uses_attributes**: a report with no case at all is summarized
from its attributes, so reconciliation never overwrites them. -/
theorem summary_only_uses_attributes (r : Report) (h : (run {} r.steps).cases = 0) :
    summarize r = fromAttributes r := by
  simp [summarize, h]

end TestResults
