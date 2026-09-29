/-
  CilockEvaluators.Verdict: what a failed verify reports, and what a VSA's
  stepResults extension lets a reader conclude.

  1. **Deny reasons** (`policy.DenyReasons`, evidence_unavailable.go). A
     rejection reason is a tree of wrapped errors. The deny messages are the
     Reasons of every `ErrPolicyDenied` node, depth first. `errors.As` stops at
     the first one (`firstDenied`, which dropped the rest when a collection's
     attestors were denied separately: `first_denied_drops_the_rest`).
  2. **No verdict** (`policy.NoVerdict`). A failure reached no decision when
     the evidence could not be read, an evaluator refused, or the external
     assignment walk stopped short. `cilock verify` exits 2 for those, 1 for a
     denial, 0 for a pass (`exitCode`, verify_verdict.go).
  3. **Reading stepResults**. A
     reader looks up one check's verdict in a step's rejections. A PASSED VSA
     reads every check its policy decides as passed; a check its policy does
     not decide reads as nothing, never as a pass.
-/
import CilockEvaluators.Gate

namespace CilockEvaluators.Verdict

-- cite: attestation/policy/evidence_unavailable.go:51-78 sha256:3991a1e997eaa03ef43dbef7a6509804fbae318eb8fe78ed356ba12bdebaa2b1
/-- An error as the engine returns it. `denied` is `ErrPolicyDenied`; the
no-verdict markers are `ErrEvidenceUnavailable`, the AI and Rego refusals and
`ErrExternalAssignmentsExceedBound`; `wrap` is one `%w` (Unwrap() error),
`join` a multi-error (Unwrap() []error: errors.Join, several `%w`,
`ErrCollectionValidationFailed`). `other` is any leaf with nothing to say. -/
inductive ErrTree where
  | denied (reasons : List String)
  | unavailable
  | aiRefused
  | regoRefused
  | assignmentBound
  | other
  | wrap (e : ErrTree)
  | join (es : List ErrTree)
  deriving Repr, Inhabited

mutual
/-- DenyReasons: every denied node's reasons, depth first. -/
def ErrTree.denies : ErrTree → List String
  | .denied rs => rs
  | .wrap e => e.denies
  | .join es => deniesAll es
  | _ => []

def deniesAll : List ErrTree → List String
  | [] => []
  | e :: es => e.denies ++ deniesAll es
end

mutual
-- cite: attestation/policy/evidence_unavailable.go:32-41 sha256:ef36b4b0f86d0e64d3311b8a5e78b55fa46877396b7add208c8e519bfe8942dc
/-- NoVerdict: some node anywhere is a no-verdict marker. -/
def ErrTree.noVerdict : ErrTree → Bool
  | .unavailable | .aiRefused | .regoRefused | .assignmentBound => true
  | .wrap e => e.noVerdict
  | .join es => noVerdictAny es
  | _ => false

def noVerdictAny : List ErrTree → Bool
  | [] => false
  | e :: es => e.noVerdict || noVerdictAny es
end

mutual
/-- `errors.As(err, &ErrPolicyDenied{})`: the first denied node only. -/
def ErrTree.firstDenied : ErrTree → Option (List String)
  | .denied rs => some rs
  | .wrap e => e.firstDenied
  | .join es => firstDeniedAny es
  | _ => none

def firstDeniedAny : List ErrTree → Option (List String)
  | [] => none
  | e :: es => match e.firstDenied with
    | some rs => some rs
    | none => firstDeniedAny es
end

-- cite: cilock/cli/verify_verdict.go:377-382 sha256:b5a6db351c122bf6fe62d1162dd0b0946baeadde40f557f6db5bfdea749148f5
/-- The exit code of `cilock verify -p`: 0 pass, 1 denial, 2 no verdict. A
failed verify always carries an error. -/
def exitCode : Option ErrTree → Nat
  | none => 0
  | some e => if e.noVerdict then 2 else 1

theorem deniesAll_append (a b : List ErrTree) : deniesAll (a ++ b) = deniesAll a ++ deniesAll b := by
  induction a with
  | nil => rfl
  | cons e es ih => simp [deniesAll, ih, List.append_assoc]

/-- Joining keeps every child's denials, in order. -/
theorem denies_join (es : List ErrTree) : (ErrTree.join es).denies = es.flatMap ErrTree.denies := by
  simp only [ErrTree.denies]
  induction es with
  | nil => rfl
  | cons e es ih => simp [deniesAll, ih]

/-- Wrapping never loses a denial. -/
theorem denies_wrap (e : ErrTree) : (ErrTree.wrap e).denies = e.denies := rfl

/-- A deny message is kept whole: it is a reason, never split out of text. -/
theorem denied_reasons_verbatim (rs : List String) : (ErrTree.denied rs).denies = rs := rfl

theorem noVerdictAny_iff (es : List ErrTree) : noVerdictAny es = true ↔ ∃ e ∈ es, e.noVerdict = true := by
  induction es with
  | nil => simp [noVerdictAny]
  | cons e es ih => simp [noVerdictAny, ih]

/-- A no-verdict marker anywhere in a join makes the whole error no-verdict:
an outage behind one attestor's leg is not hidden by a denial in another. -/
theorem noVerdict_join (es : List ErrTree) (e : ErrTree) (he : e ∈ es) (hn : e.noVerdict = true) :
    (ErrTree.join es).noVerdict = true := by
  simp only [ErrTree.noVerdict]
  exact (noVerdictAny_iff es).2 ⟨e, he, hn⟩

/-- A failure that reached no verdict never exits as a denial or a pass. -/
theorem noVerdict_exits_two (e : ErrTree) (h : e.noVerdict = true) : exitCode (some e) = 2 := by
  simp [exitCode, h]

/-- A failure exits non-zero: exit 2 is not a pass either. -/
theorem failure_never_zero (e : ErrTree) : exitCode (some e) ≠ 0 := by
  simp only [exitCode]; split <;> simp

/-- A Rego denial with no marker exits 1. -/
theorem denial_exits_one (rs : List String) : exitCode (some (.wrap (.denied rs))) = 1 := by
  simp [exitCode, ErrTree.noVerdict]

/-- **Refuted for errors.As.** A collection whose two attestors were denied:
the first match keeps only the first attestor's reasons. -/
theorem first_denied_drops_the_rest :
    let e := ErrTree.join [.wrap (.denied ["check:a"]), .other, .wrap (.denied ["check:b, want c"])]
    e.firstDenied = some ["check:a"] ∧ e.denies = ["check:a", "check:b, want c"] := by
  decide

/-- The engine's own refusal flag (`Gate.verify`'s `.failed true`) is a
no-verdict failure, so a step refusal exits 2 (`Gate.refusal_is_not_a_verdict`). -/
def outcomeExit : Gate.VerifyOutcome → (unavailable : Bool) → Nat
  | .accepted true, _ => 0
  | .accepted false, _ => 1
  | .failed true, _ => 2
  | .failed false, u => if u then 2 else 1

theorem step_refusal_exits_two (policyOk : Bool) (steps : List Gate.StepSummary) (exts : List Gate.ExtOutcome)
    (s : Gate.StepSummary) (hs : s ∈ steps) (hnp : s.hasPassed = false) (hr : s.refusal = true)
    (hext : ∀ x ∈ exts, Gate.isExtErr x = false) (hpol : policyOk = true) (u : Bool) :
    outcomeExit (Gate.verify policyOk steps exts) u = 2 := by
  rw [Gate.refusal_is_not_a_verdict policyOk steps exts s hs hnp hr hext hpol]
  rfl

/-! ## Reading stepResults -/

-- cite: attestation/slsa/verificationsummary.go:48-64 sha256:d58fff02454d3c8ec83c3d4596958de3a33afde9144b7ce9d61bc0de291c160f
structure Rejection where
  reference : String
  collection : String
  denies : List String
  deriving DecidableEq, Repr

structure StepResult where
  step : String
  passed : List String
  rejected : List Rejection
  /-- The check ids this step's Rego can deny, read from the signed policy,
  not from the VSA. A VSA says nothing about a check its policy does not
  decide. -/
  decides : List String
  deriving DecidableEq, Repr

structure SummaryView where
  passed : Bool
  steps : List StepResult
  deriving DecidableEq, Repr

/-- What cilock guarantees of a PASSED verdict: every step has a passed
collection (`verify_accepts_iff`: every step analyzes true). The converse does
not hold: externals can fail a verdict whose steps all passed. -/
def SummaryView.passedHasSteps (v : SummaryView) : Prop := v.passed = true → ∀ s ∈ v.steps, s.passed ≠ []

def denyId (check : String) : String := "check:" ++ check

def Rejection.judgedChecks (r : Rejection) : Bool := r.denies.any (·.startsWith "check:")

/-- A check's verdict read from the VSA: `none` for a check the step's Rego
does not decide; `some true` when its step passed, or when a collection's Rego
judged checks and did not deny this one; `some false` when Rego denied it;
`none` when no collection of the step had its checks judged. -/
def SummaryView.check (v : SummaryView) (step check : String) : Option Bool :=
  match v.steps.find? (·.step == step) with
  | none => none
  | some s =>
    if !s.decides.contains check then none
    else if !s.passed.isEmpty then some true
    else if s.rejected.any (fun r => r.denies.contains (denyId check)) then some false
    else if s.rejected.any Rejection.judgedChecks then some true
    else none

theorem undecided_reads_nothing (v : SummaryView) (s : StepResult) (check : String)
    (hs : v.steps.find? (·.step == s.step) = some s) (hd : s.decides.contains check = false) :
    v.check s.step check = none := by
  unfold SummaryView.check
  rw [hs]
  simp only [hd, Bool.not_false, ite_true]

theorem denied_reads_failed (v : SummaryView) (s : StepResult) (check : String)
    (hs : v.steps.find? (·.step == s.step) = some s) (hdec : s.decides.contains check = true) (hp : s.passed = [])
    (hd : s.rejected.any (fun r => r.denies.contains (denyId check)) = true) :
    v.check s.step check = some false := by
  unfold SummaryView.check
  rw [hs]
  simp only [hdec, Bool.not_true, Bool.false_eq_true, ite_false, hp, List.isEmpty_nil, hd, ite_true]

theorem passed_vsa_no_denials (v : SummaryView) (hc : v.passedHasSteps) (hp : v.passed = true)
    (s : StepResult) (hs : v.steps.find? (·.step == s.step) = some s) (check : String)
    (hdec : s.decides.contains check = true) : v.check s.step check = some true := by
  have hne : s.passed ≠ [] := hc hp s (List.mem_of_find?_eq_some hs)
  have : s.passed.isEmpty = false := by
    cases h : s.passed with
    | nil => exact absurd h hne
    | cons _ _ => rfl
  unfold SummaryView.check
  rw [hs]
  simp only [hdec, Bool.not_true, Bool.false_eq_true, ite_false, this, Bool.not_false, ite_true]

end CilockEvaluators.Verdict
