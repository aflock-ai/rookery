/-
  SemgrepAttestor.Select: which product the attestor signs, if any.

  Every product in a step is classified (design doc §3.5):
    * foreign: not a Semgrep report (no marker under the decoder's reading),
    * broken:  claims to be a Semgrep report but cannot be attested (bytes
               that differ from the recorded digest, cut off, a required
               member absent, a repeated or misspelled member, ...),
    * good:    a verified, complete Semgrep report.
  The step's outcome is one of
    * soft:   "nothing to do" (the predicate is absent, the run goes on),
    * refuse: a plain error (the payload is dropped, the run exits non-zero),
    * attest: the one good report is signed.

  The invariants this file proves are the fail-closed contract:
    * a report is attested only when it is the ONLY claiming product, so no
      findings are ever dropped beside a signed report;
    * the outcome is soft only when NOTHING claims, so a broken report can
      never read as "Semgrep did not run";
    * the outcome does not depend on product order (Go iterates a map).
-/
namespace SemgrepAttestor

inductive Class where
  | foreign
  | broken
  | good
  deriving DecidableEq, Repr

inductive Outcome where
  | soft
  | refuse
  | attest
  deriving DecidableEq, Repr

/-- The number of good reports in the step. -/
def goods (l : List Class) : Nat := l.countP (· == .good)

/-- The number of broken reports in the step. -/
def brokens (l : List Class) : Nat := l.countP (· == .broken)

-- As built: Attest refuses on any refused product, then on two good ones,
-- and is soft on none.
-- cite: plugins/attestors/semgrep/semgrep.go:394-403 sha256:cbd743bea61eda7e3f0a493a69bf0b24cf501f9f5533aee4b14efaa9cd87bf65
/-- The required selection rule: any broken report refuses; otherwise zero
    good reports is soft, one is attested, and two or more refuse. -/
def select (l : List Class) : Outcome :=
  if brokens l ≠ 0 then .refuse
  else match goods l with
    | 0 => .soft
    | 1 => .attest
    | _ + 2 => .refuse

theorem goods_eq_zero {l : List Class} : goods l = 0 ↔ ∀ c ∈ l, c ≠ .good := by
  unfold goods
  rw [List.countP_eq_zero]
  constructor
  · intro h c hc hg
    exact h c hc (by simp [hg])
  · intro h c hc hb
    exact h c hc (by simpa using hb)

theorem brokens_eq_zero {l : List Class} : brokens l = 0 ↔ ∀ c ∈ l, c ≠ .broken := by
  unfold brokens
  rw [List.countP_eq_zero]
  constructor
  · intro h c hc hg
    exact h c hc (by simp [hg])
  · intro h c hc hb
    exact h c hc (by simpa using hb)

/-- A report is signed exactly when no product is broken and exactly one is
    good: nothing that claims to be a Semgrep report is left out. -/
theorem select_attest_iff (l : List Class) :
    select l = .attest ↔ brokens l = 0 ∧ goods l = 1 := by
  unfold select
  by_cases hb : brokens l = 0
  · simp only [hb, ne_eq, not_true_eq_false, ite_false, true_and]
    match h : goods l with
    | 0 => simp
    | 1 => simp
    | n + 2 => simp
  · simp [hb]

/-- The outcome is soft exactly when every product is foreign: a broken or a
    good report is never skipped as "no report". -/
theorem select_soft_iff (l : List Class) :
    select l = .soft ↔ ∀ c ∈ l, c = .foreign := by
  constructor
  · intro h c hc
    unfold select at h
    by_cases hb : brokens l = 0
    · simp only [hb, ne_eq, not_true_eq_false, ite_false] at h
      have hg : goods l = 0 := by
        match hgl : goods l with
        | 0 => rfl
        | 1 => rw [hgl] at h; simp at h
        | n + 2 => rw [hgl] at h; simp at h
      have nb := brokens_eq_zero.mp hb c hc
      have ng := goods_eq_zero.mp hg c hc
      cases c <;> simp_all
    · simp [hb] at h
  · intro h
    have hb : brokens l = 0 := brokens_eq_zero.mpr (fun c hc => by simp [h c hc])
    have hg : goods l = 0 := goods_eq_zero.mpr (fun c hc => by simp [h c hc])
    unfold select
    simp [hb, hg]

/-- A broken report refuses the step, whatever else is in it. -/
theorem broken_refuses {l : List Class} (h : Class.broken ∈ l) : select l = .refuse := by
  have hb : brokens l ≠ 0 := by
    intro h0
    exact brokens_eq_zero.mp h0 _ h rfl
  unfold select
  simp [hb]

/-- Two good reports refuse the step: signing one would drop the other's
    findings, and no rule for choosing is safe. -/
theorem two_goods_refuse {l : List Class} (h : 2 ≤ goods l) : select l = .refuse := by
  unfold select
  by_cases hb : brokens l = 0
  · simp only [hb, ne_eq, not_true_eq_false, ite_false]
    match hg : goods l with
    | 0 => omega
    | 1 => omega
    | n + 2 => rfl
  · simp [hb]

/-- Product order never decides the outcome. -/
theorem select_perm {l l' : List Class} (p : l.Perm l') : select l = select l' := by
  unfold select goods brokens
  rw [p.countP_eq, p.countP_eq]

end SemgrepAttestor
