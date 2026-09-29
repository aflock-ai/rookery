/-
  CilockPolicy.Soundness: Theorem 1 against the fixed (joint fixed-point)
  semantics, and the exported `policy_sound`.
-/
import CilockPolicy.Lemmas
import CilockPolicy.Assumptions

namespace CilockPolicy

/-! ## Step lookups -/

theorem lookup_map_name {β} (f : Step → β) (n : String) :
    ∀ l : List Step, (l.map fun s => (s.name, f s)).lookup n = (l.find? (·.name == n)).map f
  | [] => rfl
  | s :: l => by
    simp only [List.map_cons, List.find?_cons]
    rw [List.lookup_cons]
    by_cases hn : n = s.name
    · subst hn; simp
    · have h1 : (n == s.name) = false := by simpa using hn
      have h2 : (s.name == n) = false := by
        simp only [beq_eq_false_iff_ne, ne_eq]; exact fun e => hn e.symm
      simp only [h1, h2]
      exact lookup_map_name f n l

theorem contains_append_single (seen : List String) (a b : String) :
    (seen ++ [a]).contains b = false ↔ seen.contains b = false ∧ b ≠ a := by
  simp

theorem validSteps_not_seen :
    ∀ (l : List Step) (seen : List String), validSteps seen l = true →
      ∀ s ∈ l, seen.contains s.name = false
  | [], _, _, _, hs => absurd hs List.not_mem_nil
  | t :: rest, seen, h, s, hs => by
    simp only [validSteps, Bool.and_eq_true, Bool.not_eq_true'] at h
    rcases List.mem_cons.mp hs with rfl | hr
    · exact h.1.1
    · have := validSteps_not_seen rest (seen ++ [t.name]) h.2 s hr
      exact ((contains_append_single _ _ _).mp this).1

theorem validSteps_find :
    ∀ (l : List Step) (seen : List String), validSteps seen l = true →
      ∀ s ∈ l, l.find? (·.name == s.name) = some s
  | [], _, _, _, hs => absurd hs List.not_mem_nil
  | t :: rest, seen, h, s, hs => by
    have h' := h
    simp only [validSteps, Bool.and_eq_true] at h'
    rw [List.find?_cons]
    by_cases hst : s = t
    · subst hst; simp
    · have hr : s ∈ rest := by
        rcases List.mem_cons.mp hs with h | h
        · exact absurd h hst
        · exact h
      have hns := validSteps_not_seen rest (seen ++ [t.name]) h'.2 s hr
      have hne := ((contains_append_single _ _ _).mp hns).2
      have : (t.name == s.name) = false := by
        simp only [beq_eq_false_iff_ne, ne_eq]
        exact fun e => hne e.symm
      simp only [this]
      exact validSteps_find rest (seen ++ [t.name]) h'.2 s hr

theorem validate_steps {p : Policy} (h : validate p = true) : validSteps [] p.steps = true := by
  simp only [validate, Bool.and_eq_true] at h
  exact h.1.1.1.1

theorem stepOf_self {p : Policy} (hv : validate p = true) {s : Step} (hs : s ∈ p.steps) :
    stepOf p s.name = some s :=
  validSteps_find p.steps [] (validate_steps hv) s hs

theorem get_phaseFrom (rego : Rego) (h : Hardening) {p : Policy} (o : Options) (E : List Envelope)
    (α : Assign) (prev : State) (hv : validate p = true) {s : Step} (hs : s ∈ p.steps) :
    (phaseFrom rego h p o E α prev).get s.name =
      passedFor rego h p o E s ⟨stepsCtx s prev, extCtx s α⟩ := by
  unfold State.get phaseFrom
  rw [lookup_map_name, validSteps_find p.steps [] (validate_steps hv) s hs]
  rfl

/-! ## The joint fixed point -/

/-- A state the fixed semantics settles on: pruning the step phase read from
    it gives it back. -/
def JointFixed (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) (F : State) : Prop :=
  F = prune p o (phaseFrom rego h p o E α F)

theorem fixLoop_fixed (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) : ∀ (n : Nat) (prev F : State), fixLoop rego h p o E α n prev = some F →
      JointFixed rego h p o E α F
  | 0, _, _, hf => by simp [fixLoop] at hf
  | n + 1, prev, F, hf => by
    simp only [fixLoop] at hf
    split at hf
    · rename_i heq
      have heq' := beq_iff_eq.mp heq
      injection hf with hf
      subst hf
      unfold JointFixed
      conv => rhs; rw [heq']
    · exact fixLoop_fixed rego h p o E α n _ F hf

/-! ## What a surviving collection has passed -/

/-- Everything the engine checked about collection `e` for step `s`, with the
    Rego context read from the final survivors `F`. -/
structure Admitted (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) (F : State) (s : Step) (e : Envelope) : Prop where
  inEvidence : e ∈ E
  /-- No cross-step reuse: the signed collection is named for this step. -/
  named      : e.payload.name = s.name
  /-- Anchored: a matchable SIGNED subject is one of the seed digests. -/
  anchored   : anchored o.seeds e.payload = true
  /-- Functionary triage: DSSE, functionary match, timestamp constraint. -/
  triaged    : triage h p o s e = true
  fanout     : fanoutAdmit o (E.filter (authorized h p o s)) e = true
  /-- The gate ran with input.steps read from SURVIVORS. -/
  gated      : gate rego o s ⟨stepsCtx s F, extCtx s α⟩ e.payload = true
  /-- Every artifactsFrom edge has a surviving upstream partner. -/
  chained    : ∀ d ∈ s.artifactsFrom, ∃ u ∈ F.get d, edgeOk o e.payload u.payload = true
  /-- No untracked material: under EnforceAllowedUntracked every material is
      an artifact of a surviving upstream partner or allow-listed (#9815). -/
  untracked  : untrackedOk o F s e.payload = true

theorem survivor_admitted {rego : Rego} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} {α : Assign} {F : State} (hF : JointFixed rego h p o E α F)
    (hv : validate p = true) {s : Step} (hs : s ∈ p.steps) {e : Envelope}
    (he : e ∈ F.get s.name) : Admitted rego h p o E α F s e := by
  have hkeep : keep o F s e = true := by
    have := prune_keep (stepOf_self hv hs) (hF ▸ he)
    rwa [← hF] at this
  have hmem : e ∈ passedFor rego h p o E s ⟨stepsCtx s F, extCtx s α⟩ := by
    rw [← get_phaseFrom rego h o E α F hv hs]
    exact mem_prune (hF ▸ he)
  simp only [passedFor, List.mem_filter, Bool.and_eq_true] at hmem
  obtain ⟨⟨hE, hauth⟩, hfan, hgate⟩ := hmem
  simp only [authorized, Bool.and_eq_true, beq_iff_eq] at hauth
  simp only [keep, Bool.and_eq_true, List.all_eq_true, List.any_eq_true] at hkeep
  refine ⟨hE, hauth.1.1, hauth.1.2, hauth.2, hfan, hgate, ?_, hkeep.2⟩
  intro d hd
  exact hkeep.1 d hd

/-! ## Theorem 1 (fixed semantics) -/

/-- Unpacking `verifyFixed = true`: admissible, and for some external
    assignment a joint fixed point on which every step has a survivor, every
    survivor is `Admitted`, and every external passes. -/
theorem verifyFixed_spec {rego : Rego} {regoExt : RegoExt} {h : Hardening} {p : Policy}
    {o : Options} {E : List Envelope} (hpass : verifyFixed rego regoExt h p o E = true) :
    admissible p o = true ∧ ∃ α F, JointFixed rego h p o E α F ∧
      (∀ s ∈ p.steps, F.get s.name ≠ []) ∧
      (∀ s ∈ p.steps, ∀ e ∈ F.get s.name, Admitted rego h p o E α F s e) ∧
      (∀ x ∈ p.externals, externalOk regoExt h p o E x = true) := by
  simp only [verifyFixed, Bool.and_eq_true, List.any_eq_true] at hpass
  obtain ⟨hadm, α, _, hα⟩ := hpass
  have hv : validate p = true := by
    simp only [admissible, Bool.and_eq_true] at hadm; exact hadm.2
  split at hα
  · rename_i F hloop
    have hF := fixLoop_fixed rego h p o E α _ _ F hloop
    simp only [verdictOn, Bool.and_eq_true, List.all_eq_true] at hα
    refine ⟨hadm, α, F, hF, ?_, ?_, hα.1.2⟩
    · intro s hs hnil
      have := hα.1.1 s hs
      simp [hnil] at this
    · intro s hs e he
      exact survivor_admitted hF hv hs he
  · simp at hα

end CilockPolicy
