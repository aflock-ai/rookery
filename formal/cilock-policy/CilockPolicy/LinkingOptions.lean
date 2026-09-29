/-
  CilockPolicy.LinkingOptions: the lazy witness (V5), verdict-level hardening
  monotonicity (V2), and flood resistance (Theorem 7 / L6).
-/
import CilockPolicy.Linking
import CilockPolicy.Vacuity

namespace CilockPolicy

/-! ## Shared: verdicts only read non-emptiness -/

theorem any_congr_mem {α} {f g : α → Bool} : ∀ {l : List α}, (∀ x ∈ l, f x = g x) → l.any f = l.any g
  | [], _ => rfl
  | a :: l, h => by
    simp only [List.any_cons]
    rw [h a List.mem_cons_self, any_congr_mem (fun x hx => h x (List.mem_cons_of_mem _ hx))]

theorem all_congr_mem {α} {f g : α → Bool} : ∀ {l : List α}, (∀ x ∈ l, f x = g x) → l.all f = l.all g
  | [], _ => rfl
  | a :: l, h => by
    simp only [List.all_cons]
    rw [h a List.mem_cons_self, all_congr_mem (fun x hx => h x (List.mem_cons_of_mem _ hx))]

/-- The untracked check reads a state only at the step's artifactsFrom names,
    and only through `any` over their collections. -/
theorem untrackedOk_congr {o : Options} {X Y : State} {s : Step} {c : Collection}
    (h : ∀ d ∈ s.artifactsFrom, ∀ f : Envelope → Bool, (X.get d).any f = (Y.get d).any f) :
    untrackedOk o X s c = untrackedOk o Y s c := by
  have hc : ∀ path, coveredPath o X s c path = coveredPath o Y s c path := fun path =>
    any_congr_mem fun d hd => h d hd _
  unfold untrackedOk
  simp only [hc]

theorem verdictOn_mono {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} {F F' : State} (hle : State.le F F')
    (hv : verdictOn regoExt h p o E F = true) : verdictOn regoExt h p o E F' = true := by
  simp only [verdictOn, Bool.and_eq_true, List.all_eq_true, Bool.not_eq_true',
    List.isEmpty_eq_false_iff] at hv ⊢
  refine ⟨⟨fun s hs => ?_, hv.1.2⟩, hv.2⟩
  obtain ⟨e, he⟩ := List.exists_mem_of_ne_nil _ (hv.1.1 s hs)
  exact List.ne_nil_of_mem (hle _ _ he)

/-- With no attestationsFrom anywhere, the as-built phase is the context-free
    phase: order and pruning timing cannot matter. -/
theorem stepsCtx_nil {s : Step} (hs : s.attestationsFrom = []) (st : State) : stepsCtx s st = [] := by
  simp [stepsCtx, hs]

theorem foldl_append_map {β : Type} (f : Step → β) :
    ∀ (l : List Step) (acc : List (String × β)),
      l.foldl (fun st s => st ++ [(s.name, f s)]) acc = acc ++ l.map fun s => (s.name, f s)
  | [], acc => by simp
  | s :: l, acc => by
    simp only [List.foldl_cons, List.map_cons]
    rw [foldl_append_map f l]; simp

def NoAttFrom (p : Policy) : Prop := ∀ s ∈ p.steps, s.attestationsFrom = []

theorem phaseAsBuilt_eq {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E : List Envelope}
    {α : Assign} (hn : NoAttFrom p) (prev : State) :
    phaseAsBuilt rego h p o E α = phaseFrom rego h p o E α prev := by
  unfold phaseAsBuilt phaseFrom
  have : ∀ st : State, ∀ s ∈ p.steps,
      (s.name, passedFor rego h p o E s ⟨stepsCtx s st, extCtx s α⟩) =
      (s.name, passedFor rego h p o E s ⟨[], extCtx s α⟩) := by
    intro st s hs; rw [stepsCtx_nil (hn s hs)]
  have hfold : ∀ (l : List Step), (∀ s ∈ l, s ∈ p.steps) → ∀ acc : State,
      l.foldl (fun st s => st ++ [(s.name, passedFor rego h p o E s ⟨stepsCtx s st, extCtx s α⟩)]) acc =
      acc ++ l.map fun s => (s.name, passedFor rego h p o E s ⟨[], extCtx s α⟩) := by
    intro l
    induction l with
    | nil => intro _ acc; simp
    | cons s l ih =>
      intro hl acc
      simp only [List.foldl_cons, List.map_cons]
      rw [this acc s (hl s List.mem_cons_self)]
      rw [ih (fun x hx => hl x (List.mem_cons_of_mem _ hx))]
      simp
  rw [hfold p.steps (fun _ h => h) []]
  simp only [List.nil_append]
  apply List.map_congr_left
  intro s hs
  rw [stepsCtx_nil (hn s hs)]

/-! ## V5: the lazy witness gives the eager verdict -/

def truncate (st : State) : State := st.map fun x => (x.1, x.2.take 1)

theorem truncate_le (st : State) : State.le (truncate st) st := by
  intro n e he
  unfold State.get at he ⊢
  unfold truncate at he
  induction st with
  | nil => simpa using he
  | cons x l ih =>
    obtain ⟨k, v⟩ := x
    simp only [List.map_cons, List.lookup_cons] at he ⊢
    cases hk : (n == k)
    · simp only [hk] at he ⊢; exact ih he
    · simp only [hk, Option.getD_some] at he ⊢; exact List.mem_of_mem_take he

/-- WithLazyStepSatisfaction (`lazy.go`): eligible only without
    attestationsFrom, with the fan-out guard off and a canonical-order source.
    A step's stream stops at its first passing candidate (`take 1`); when the
    verify does not settle on those witnesses the demand valve re-runs the
    truncated steps exhaustively, i.e. the eager result.
    -- cite: attestation/policy/lazy.go:83-162 sha256:d94cfec424506893542e91f08bb83fd2e6c7970975fd9afbbd98a1bd0adc5b91
    -/
def verifyLazy (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options)
    (canonical : Bool) (E : List Envelope) : Bool :=
  admissible p o &&
  (assignments regoExt h p o E).any fun α =>
    let full := phaseAsBuilt rego h p o E α
    if canonical && p.steps.all (·.attestationsFrom.isEmpty) && o.maxFanout == 0 then
      verdictOn regoExt h p o E (prune p o (truncate full)) ||
      verdictOn regoExt h p o E (prune p o full)
    else verdictOn regoExt h p o E (prune p o full)

/-- V5. Lazy and eager give the same verdict, for every source. -/
theorem lazy_eq_eager (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options)
    (canonical : Bool) (E : List Envelope) :
    verifyLazy rego regoExt h p o canonical E = verifyAsBuilt rego regoExt h p o E := by
  unfold verifyLazy verifyAsBuilt
  congr 1
  apply any_congr_mem  -- per assignment
  intro α _
  split
  · dsimp only
    cases hv : verdictOn regoExt h p o E (prune p o (truncate (phaseAsBuilt rego h p o E α)))
    · rw [Bool.false_or]
    · have := verdictOn_mono (prune_mono (truncate_le _)) hv
      rw [this]; rfl
  · rfl

/-! ## V2 at the verdict level, for the monotone class -/

/-- The shapes whose verdict is monotone in each step's candidate set: no
    attestationsFrom, no externalFrom, no timestamp constraint, no fan-out. -/
def Monotone (p : Policy) (o : Options) : Prop :=
  NoAttFrom p ∧ (∀ s ∈ p.steps, s.externalFrom = [] ∧ s.tsc = none) ∧ o.maxFanout = 0

theorem passedFor_mono {rego : Rego} {g h : Hardening} (hle : Hardening.le g h) {p : Policy}
    {o : Options} {E : List Envelope} {s : Step} {ctx : Ctx} (hts : s.tsc = none) (hf : o.maxFanout = 0)
    {e : Envelope} (he : e ∈ passedFor rego h p o E s ctx) : e ∈ passedFor rego g p o E s ctx := by
  simp only [passedFor, List.mem_filter, Bool.and_eq_true, authorized, fanoutAdmit, hf,
    beq_self_eq_true, Bool.true_or] at he ⊢
  obtain ⟨⟨hE, ⟨hn, ha⟩, ht⟩, _, hg⟩ := he
  exact ⟨⟨hE, ⟨hn, ha⟩, triage_mono hle hts ht⟩, trivial, hg⟩

theorem get_phaseFrom_any {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E : List Envelope}
    {α : Assign} {prev : State} {n : String} {e : Envelope}
    (he : e ∈ (phaseFrom rego h p o E α prev).get n) :
    ∃ s ∈ p.steps, p.steps.find? (·.name == n) = some s ∧
      e ∈ passedFor rego h p o E s ⟨stepsCtx s prev, extCtx s α⟩ := by
  unfold State.get phaseFrom at he
  rw [lookup_map_name] at he
  cases hf : p.steps.find? (·.name == n) with
  | none => rw [hf] at he; simp at he
  | some s =>
    rw [hf] at he
    exact ⟨s, List.mem_of_find?_eq_some hf, rfl, by simpa using he⟩

theorem phaseFrom_mono {rego : Rego} {g h : Hardening} (hle : Hardening.le g h) {p : Policy}
    {o : Options} {E : List Envelope} {α : Assign} {prev : State} (hm : Monotone p o) :
    State.le (phaseFrom rego h p o E α prev) (phaseFrom rego g p o E α prev) := by
  intro n e he
  obtain ⟨s, hs, hfind, hmem⟩ := get_phaseFrom_any he
  unfold State.get phaseFrom
  rw [lookup_map_name, hfind]
  simpa using passedFor_mono hle (hm.2.1 s hs).2 hm.2.2 hmem

theorem assignments_noExtFrom {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} (hn : ∀ s ∈ p.steps, s.externalFrom = []) :
    assignments regoExt h p o E = [[]] := by
  unfold assignments
  have : p.externals.filter (fun x => p.steps.any (·.externalFrom.contains x.name)) = [] := by
    rw [List.filter_eq_nil_iff]
    intro x _
    simp only [List.any_eq_true, not_exists, not_and, Bool.not_eq_true]
    intro s hs; simp [hn s hs]
  rw [this]; rfl

theorem externalOk_mono {regoExt : RegoExt} {g h : Hardening} (hle : Hardening.le g h) {p : Policy}
    {o : Options} {E : List Envelope} {x : External} (hx : externalOk regoExt h p o E x = true) :
    externalOk regoExt g p o E x = true := by
  simp only [externalOk, Bool.or_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at hx ⊢
  rcases hx with hx | hx
  · left
    obtain ⟨e, he⟩ := List.exists_mem_of_ne_nil _ hx
    apply List.ne_nil_of_mem (a := e)
    simp only [extPassed, List.mem_filter, Bool.and_eq_true, List.any_eq_true] at he ⊢
    obtain ⟨hE, ⟨⟨⟨hpt, hvn⟩, hb⟩, v, hv, f, hf, hfv⟩, hr⟩ := he
    exact ⟨hE, ⟨⟨⟨hpt, hvn⟩, hb⟩, v, hv, f, hf, fValidate_mono hle hfv⟩, hr⟩
  · right; exact hx

/-- V2 (verdict level) for the monotone class: turning any hardening flag ON
    never turns a FAIL into a PASS. Outside the class it can, benignly, when
    the collection a stricter flag drops was the one making a gate fail
    (`v2_timestamp_counterexample`; an attestationsFrom Rego can do the same). -/
theorem hardening_monotone {rego : Rego} {regoExt : RegoExt} {g h : Hardening} (hle : Hardening.le g h)
    {p : Policy} {o : Options} {E : List Envelope} (hm : Monotone p o)
    (hpass : verifyAsBuilt rego regoExt h p o E = true) : verifyAsBuilt rego regoExt g p o E = true := by
  have hn : ∀ s ∈ p.steps, s.externalFrom = [] := fun s hs => (hm.2.1 s hs).1
  simp only [verifyAsBuilt, Bool.and_eq_true, List.any_eq_true, assignments_noExtFrom hn,
    List.mem_singleton, exists_eq_left] at hpass ⊢
  refine ⟨hpass.1, ?_⟩
  have hv := hpass.2
  rw [phaseAsBuilt_eq hm.1 []] at hv ⊢
  have hv' := verdictOn_mono (prune_mono (phaseFrom_mono (α := []) (prev := []) hle hm)) hv
  simp only [verdictOn, Bool.and_eq_true, List.all_eq_true, Bool.not_eq_true',
    List.isEmpty_eq_false_iff, Bool.or_eq_true, List.any_eq_true] at hv' ⊢
  refine ⟨⟨hv'.1.1, fun x hx => externalOk_mono hle (hv'.1.2 x hx)⟩, ?_⟩
  rcases hv'.2 with h1 | ⟨x, hx, hxp⟩
  · exact Or.inl h1
  · right
    refine ⟨x, hx, ?_⟩
    obtain ⟨e, he⟩ := List.exists_mem_of_ne_nil _ hxp
    apply List.ne_nil_of_mem (a := e)
    simp only [extPassed, List.mem_filter, Bool.and_eq_true, List.any_eq_true] at he ⊢
    obtain ⟨hE, ⟨⟨⟨hpt, hvn⟩, hb⟩, v, hv, f, hf, hfv⟩, hr⟩ := he
    exact ⟨hE, ⟨⟨⟨hpt, hvn⟩, hb⟩, v, hv, f, hf, fValidate_mono hle hfv⟩, hr⟩

/-! ## Theorem 7 / L6: flood resistance -/

/-- Evidence that no step authorizes and no external searches for. -/
def Junk (h : Hardening) (p : Policy) (o : Options) (j : Envelope) : Prop :=
  (∀ s ∈ p.steps, authorized h p o s j = false) ∧
  (∀ x ∈ p.externals, (j.payload.predicateType == x.predicateType) = false)

theorem passedFor_junk {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E J : List Envelope}
    (hJ : ∀ j ∈ J, Junk h p o j) {s : Step} (hs : s ∈ p.steps) (ctx : Ctx) :
    passedFor rego h p o (E ++ J) s ctx = passedFor rego h p o E s ctx := by
  have : (E ++ J).filter (authorized h p o s) = E.filter (authorized h p o s) := by
    rw [List.filter_append]
    have : J.filter (authorized h p o s) = [] := by
      rw [List.filter_eq_nil_iff]; intro j hj; simp [(hJ j hj).1 s hs]
    rw [this, List.append_nil]
  simp only [passedFor, this]

theorem phaseFrom_junk {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E J : List Envelope}
    (hJ : ∀ j ∈ J, Junk h p o j) (α : Assign) (prev : State) :
    phaseFrom rego h p o (E ++ J) α prev = phaseFrom rego h p o E α prev := by
  unfold phaseFrom
  apply List.map_congr_left
  intro s hs
  rw [passedFor_junk hJ hs]

theorem extPassed_junk {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options} {E J : List Envelope}
    (hJ : ∀ j ∈ J, Junk h p o j) {x : External} (hx : x ∈ p.externals) :
    extPassed regoExt h p o (E ++ J) x = extPassed regoExt h p o E x := by
  unfold extPassed
  rw [List.filter_append]
  have : J.filter (fun e => e.payload.predicateType == x.predicateType && !(verifiers p e).isEmpty &&
      extBound p o e && (verifiers p e).any (fun v => x.functionaries.any fun f => fValidate h p.roots f v.cred) &&
      regoExt x.gate e.payload) = [] := by
    rw [List.filter_eq_nil_iff]; intro j hj; simp [(hJ j hj).2 x hx]
  rw [this, List.append_nil]

theorem extCandidates_junk {h : Hardening} {p : Policy} {o : Options} {E J : List Envelope}
    (hJ : ∀ j ∈ J, Junk h p o j) {x : External} (hx : x ∈ p.externals) :
    extCandidates p o (E ++ J) x = extCandidates p o E x := by
  unfold extCandidates
  rw [List.filter_append]
  have : J.filter (fun e => e.payload.predicateType == x.predicateType && extBound p o e) = [] := by
    rw [List.filter_eq_nil_iff]; intro j hj; simp [(hJ j hj).2 x hx]
  rw [this, List.append_nil]

theorem assignments_junk {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E J : List Envelope} (hJ : ∀ j ∈ J, Junk h p o j) :
    assignments regoExt h p o (E ++ J) = assignments regoExt h p o E := by
  unfold assignments
  have key : ∀ l : List External, (∀ x ∈ l, x ∈ p.externals) →
      l.foldr (fun x acc => match extPassed regoExt h p o (E ++ J) x with
        | [] => acc | ps => ps.flatMap fun e => acc.map ((x.name, e.payload) :: ·)) [[]] =
      l.foldr (fun x acc => match extPassed regoExt h p o E x with
        | [] => acc | ps => ps.flatMap fun e => acc.map ((x.name, e.payload) :: ·)) [[]] := by
    intro l hl
    induction l with
    | nil => rfl
    | cons x l ih =>
      simp only [List.foldr_cons]
      rw [ih (fun y hy => hl y (List.mem_cons_of_mem _ hy)), extPassed_junk hJ (hl x List.mem_cons_self)]
  exact key _ (fun x hx => (List.mem_filter.mp hx).1)

theorem verdictOn_junk {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E J : List Envelope} (hJ : ∀ j ∈ J, Junk h p o j) (F : State) :
    verdictOn regoExt h p o (E ++ J) F = verdictOn regoExt h p o E F := by
  unfold verdictOn
  have h1 : p.externals.all (externalOk regoExt h p o (E ++ J)) = p.externals.all (externalOk regoExt h p o E) := by
    apply all_congr_mem; intro x hx
    simp only [externalOk, extPassed_junk hJ hx, extCandidates_junk hJ hx]
  have h2 : p.externals.any (fun x => !(extPassed regoExt h p o (E ++ J) x).isEmpty) =
      p.externals.any (fun x => !(extPassed regoExt h p o E x).isEmpty) := by
    apply any_congr_mem; intro x hx; rw [extPassed_junk hJ hx]
  rw [h1, h2]

theorem fixLoop_junk {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E J : List Envelope}
    (hJ : ∀ j ∈ J, Junk h p o j) (α : Assign) :
    ∀ (n : Nat) (st : State), fixLoop rego h p o (E ++ J) α n st = fixLoop rego h p o E α n st
  | 0, _ => rfl
  | n + 1, st => by
    simp only [fixLoop, phaseFrom_junk hJ]
    split
    · rfl
    · exact fixLoop_junk hJ α n _

/-- Theorem 7 / L6, fixed semantics. Adding evidence that no step authorizes
    (wrong name, bad signature, unanchored, untrusted signer, failed timestamp)
    and no external searches for never changes the verdict, in either
    direction, with or without the fan-out guard. -/
theorem flood_resistant (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options)
    (E J : List Envelope) (hJ : ∀ j ∈ J, Junk h p o j) :
    verifyFixed rego regoExt h p o (E ++ J) = verifyFixed rego regoExt h p o E := by
  unfold verifyFixed
  rw [assignments_junk hJ]
  congr 1
  apply any_congr_mem
  intro α _
  rw [phaseFrom_junk hJ, fixLoop_junk hJ]
  split
  · exact verdictOn_junk hJ _
  · rfl

/-- The same holds for the as-built engine: the #9813 flip needs evidence that
    IS authorized and gated but later pruned, which `Junk` excludes. -/
theorem flood_resistant_asBuilt (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy)
    (o : Options) (E J : List Envelope) (hJ : ∀ j ∈ J, Junk h p o j) :
    verifyAsBuilt rego regoExt h p o (E ++ J) = verifyAsBuilt rego regoExt h p o E := by
  unfold verifyAsBuilt
  rw [assignments_junk hJ]
  congr 1
  apply any_congr_mem
  intro α _
  have : phaseAsBuilt rego h p o (E ++ J) α = phaseAsBuilt rego h p o E α := by
    unfold phaseAsBuilt
    have key : ∀ (l : List Step), (∀ s ∈ l, s ∈ p.steps) → ∀ acc : State,
        l.foldl (fun st s => st ++ [(s.name, passedFor rego h p o (E ++ J) s ⟨stepsCtx s st, extCtx s α⟩)]) acc =
        l.foldl (fun st s => st ++ [(s.name, passedFor rego h p o E s ⟨stepsCtx s st, extCtx s α⟩)]) acc := by
      intro l
      induction l with
      | nil => intro _ _; rfl
      | cons s l ih =>
        intro hl acc
        simp only [List.foldl_cons]
        rw [passedFor_junk hJ (hl s List.mem_cons_self)]
        exact ih (fun x hx => hl x (List.mem_cons_of_mem _ hx)) _
    exact key p.steps (fun _ h => h) []
  rw [this, verdictOn_junk hJ]

end CilockPolicy
