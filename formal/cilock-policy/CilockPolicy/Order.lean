/-
  CilockPolicy.Order: Theorem 6. The verdict does not depend on the order the
  evidence arrives in.

  Every state entry the pipeline builds is `E.filter P` for a predicate that
  reads `E` only through permutation-invariant facts (membership, counts), so
  a permuted `E'` yields `E'.filter P` with the SAME predicate. The single
  hypothesis is on Rego: its input.steps lists may be permuted. The engine
  earns that by sorting each dependency's collections by Reference
  (`step.go`); with two passed collections sharing one Reference the
  stable sort keeps arrival order, so the hypothesis also assumes References
  are unique (MemorySource refuses duplicates, `memory.go`).
  -- cite: attestation/policy/step.go:657-661 sha256:cc962de5d14a0ed07d32878eba6935c50fce704017003ee62ffe4ecfd53a61c2
  -- cite: attestation/source/memory.go:85-87 sha256:9c3f0ac460d94fbf85a0b217369e3809ac787a24c629bf6256c469a84042e57d
-/
import CilockPolicy.LinkingOptions

namespace CilockPolicy

/-! ## Relating two evidence lists -/

/-- Two lists related entrywise by `R`. -/
def SimL {α β} (R : α → β → Prop) : List α → List β → Prop
  | [], [] => True
  | a :: l, b :: l' => R a b ∧ SimL R l l'
  | _, _ => False

/-- A state entry built from `E`, and its counterpart built from `E'`, with
    the same predicate. -/
def SimEntry (E E' : List Envelope) (x x' : String × List Envelope) : Prop :=
  x.1 = x'.1 ∧ ∃ P : Envelope → Bool, x.2 = E.filter P ∧ x'.2 = E'.filter P

abbrev Sim (E E' : List Envelope) : State → State → Prop := SimL (SimEntry E E')

/-- Rego is blind to the order of each input.steps list. -/
def CtxSim (c c' : Ctx) : Prop :=
  c.ext = c'.ext ∧ SimL (fun (x y : String × List Collection) => x.1 = y.1 ∧ x.2.Perm y.2) c.steps c'.steps

def RegoPermInvariant (rego : Rego) : Prop :=
  ∀ g a c c', CtxSim c c' → rego g a c = rego g a c'

variable {E E' : List Envelope}

theorem get_sim (hp : E.Perm E') : ∀ {st st' : State}, Sim E E' st st' → ∀ n,
    ∃ P : Envelope → Bool, st.get n = E.filter P ∧ st'.get n = E'.filter P
  | [], [], _, n => ⟨fun _ => false, by simp [State.get], by simp [State.get]⟩
  | x :: l, x' :: l', h, n => by
    obtain ⟨⟨hk, P, hx, hx'⟩, hl⟩ := h
    unfold State.get
    obtain ⟨k, v⟩ := x
    obtain ⟨k', v'⟩ := x'
    simp only at hk hx hx'
    subst hk
    rw [List.lookup_cons, List.lookup_cons]
    cases hn : (n == k)
    · exact get_sim hp hl n
    · exact ⟨P, by simp [hx], by simp [hx']⟩
  | [], _ :: _, h, _ => absurd h (by simp [SimL])
  | _ :: _, [], h, _ => absurd h (by simp [SimL])

theorem mem_filter_perm (hp : E.Perm E') (P : Envelope → Bool) (e : Envelope) :
    e ∈ E.filter P ↔ e ∈ E'.filter P := (hp.filter P).mem_iff

theorem any_filter_perm (hp : E.Perm E') (P q : Envelope → Bool) :
    (E.filter P).any q = (E'.filter P).any q := by
  apply Bool.eq_iff_iff.mpr
  simp only [List.any_eq_true]
  constructor
  · rintro ⟨x, hx, hq⟩; exact ⟨x, (mem_filter_perm hp P x).mp hx, hq⟩
  · rintro ⟨x, hx, hq⟩; exact ⟨x, (mem_filter_perm hp P x).mpr hx, hq⟩

theorem isEmpty_perm {α} {l l' : List α} (h : l.Perm l') : l.isEmpty = l'.isEmpty := by
  have := h.length_eq
  cases l <;> cases l' <;> simp_all

theorem isEmpty_filter_perm (hp : E.Perm E') (P : Envelope → Bool) :
    (E.filter P).isEmpty = (E'.filter P).isEmpty := isEmpty_perm (hp.filter P)

/-! ## Context, step phase -/

theorem stepsCtx_sim (hp : E.Perm E') {s : Step} {st st' : State} (h : Sim E E' st st') :
    SimL (fun (x y : String × List Collection) => x.1 = y.1 ∧ x.2.Perm y.2)
      (stepsCtx s st) (stepsCtx s st') := by
  have hne : (s.attestationsFrom.all fun d => !(st.get d).isEmpty) =
      (s.attestationsFrom.all fun d => !(st'.get d).isEmpty) := by
    apply all_congr_mem; intro d _
    obtain ⟨P, h1, h2⟩ := get_sim hp h d
    rw [h1, h2, isEmpty_filter_perm hp]
  unfold stepsCtx
  rw [hne]
  split
  · generalize s.attestationsFrom = ds
    induction ds with
    | nil => simp [SimL]
    | cons d ds ih =>
      refine ⟨⟨rfl, ?_⟩, ih⟩
      obtain ⟨P, h1, h2⟩ := get_sim hp h d
      simp only [h1, h2]
      exact (hp.filter P).map _
  · simp [SimL]

/-- A step's Passed set, as one filter over the evidence. -/
def passedPred (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (s : Step) (ctx : Ctx) (e : Envelope) : Bool :=
  (fanoutAdmit o (E.filter (authorized h p o s)) e && gate rego o s ctx e.payload) && authorized h p o s e

theorem passedFor_filter (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (s : Step) (ctx : Ctx) : passedFor rego h p o E s ctx = E.filter (passedPred rego h p o E s ctx) := by
  unfold passedFor passedPred
  exact List.filter_filter

theorem fanoutAdmit_perm (hp : E.Perm E') (o : Options) (A : Envelope → Bool) (e : Envelope) :
    fanoutAdmit o (E.filter A) e = fanoutAdmit o (E'.filter A) e := by
  unfold fanoutAdmit
  congr 1
  apply any_congr_mem; intro d _
  rw [(hp.filter A).countP_eq]

theorem passedPred_perm {rego : Rego} (hr : RegoPermInvariant rego) (hp : E.Perm E') (h : Hardening)
    (p : Policy) (o : Options) (s : Step) {c c' : Ctx} (hc : CtxSim c c') :
    passedPred rego h p o E s c = passedPred rego h p o E' s c' := by
  funext e
  unfold passedPred
  rw [fanoutAdmit_perm hp o (authorized h p o s) e]
  have hg : gate rego o s c e.payload = gate rego o s c' e.payload := by
    unfold gate
    congr 1
    apply all_congr_mem; intro r _
    dsimp only
    congr 1
    apply all_congr_mem; intro a _
    exact hr _ _ _ _ hc
  rw [hg]

theorem phaseFrom_sim {rego : Rego} (hr : RegoPermInvariant rego) (hp : E.Perm E') (h : Hardening)
    (p : Policy) (o : Options) (α : Assign) {st st' : State} (hs : Sim E E' st st') :
    Sim E E' (phaseFrom rego h p o E α st) (phaseFrom rego h p o E' α st') := by
  unfold phaseFrom
  generalize p.steps = l
  induction l with
  | nil => simp [SimL]
  | cons s l ih =>
    refine ⟨⟨rfl, ?_⟩, ih⟩
    refine ⟨passedPred rego h p o E s ⟨stepsCtx s st, extCtx s α⟩, passedFor_filter .., ?_⟩
    show passedFor rego h p o E' s ⟨stepsCtx s st', extCtx s α⟩ = _
    rw [passedFor_filter, passedPred_perm hr hp h p o s (c := ⟨stepsCtx s st, extCtx s α⟩)
      (c' := ⟨stepsCtx s st', extCtx s α⟩) ⟨rfl, stepsCtx_sim hp hs⟩]

/-! ## Pruning -/

theorem keep_sim (hp : E.Perm E') {o : Options} {st st' : State} (h : Sim E E' st st') (s : Step) :
    keep o st s = keep o st' s := by
  funext e
  have hany : ∀ d, ∀ f : Envelope → Bool, (st.get d).any f = (st'.get d).any f := fun d f => by
    obtain ⟨P, h1, h2⟩ := get_sim hp h d
    rw [h1, h2, any_filter_perm hp]
  unfold keep
  rw [untrackedOk_congr (fun d _ f => hany d f)]
  congr 1
  exact all_congr_mem fun d _ => hany d _

theorem passWith_sim (hp : E.Perm E') {p : Policy} {o : Options} {ref ref' : State}
    (hr : Sim E E' ref ref') : ∀ {l l' : State}, Sim E E' l l' → Sim E E' (passWith p o ref l) (passWith p o ref' l')
  | [], [], _ => trivial
  | x :: l, x' :: l', h => by
    obtain ⟨⟨hk, P, hx, hx'⟩, hl⟩ := h
    refine ⟨⟨hk, ?_⟩, passWith_sim hp hr hl⟩
    simp only
    rw [← hk]
    cases stepOf p x.1 with
    | none => exact ⟨P, hx, hx'⟩
    | some s =>
      refine ⟨fun e => keep o ref s e && P e, ?_, ?_⟩
      · show List.filter (keep o ref s) x.2 = _
        rw [hx, List.filter_filter]
      · show List.filter (keep o ref' s) x'.2 = _
        rw [hx', List.filter_filter, keep_sim hp hr s]
  | [], _ :: _, h => absurd h (by simp [SimL])
  | _ :: _, [], h => absurd h (by simp [SimL])

theorem size_sim (hp : E.Perm E') : ∀ {st st' : State}, Sim E E' st st' → size st = size st'
  | [], [], _ => rfl
  | x :: l, x' :: l', h => by
    obtain ⟨⟨_, P, hx, hx'⟩, hl⟩ := h
    rw [size_cons, size_cons, size_sim hp hl, hx, hx', (hp.filter P).length_eq]
  | [], _ :: _, h => absurd h (by simp [SimL])
  | _ :: _, [], h => absurd h (by simp [SimL])

theorem pruneLoop_sim (hp : E.Perm E') {p : Policy} {o : Options} :
    ∀ (n : Nat) {st st' : State}, Sim E E' st st' → Sim E E' (pruneLoop p o n st) (pruneLoop p o n st')
  | 0, _, _, h => h
  | n + 1, st, st', h => by
    simp only [pruneLoop]
    have hpass : Sim E E' (prunePass p o st) (prunePass p o st') := by
      rw [prunePass_eq, prunePass_eq]; exact passWith_sim hp h h
    rw [size_sim hp hpass, size_sim hp h]
    split
    · exact h
    · exact pruneLoop_sim hp n hpass

theorem prune_sim (hp : E.Perm E') {p : Policy} {o : Options} {st st' : State} (h : Sim E E' st st') :
    Sim E E' (prune p o st) (prune p o st') := by
  unfold prune; rw [size_sim hp h]; exact pruneLoop_sim hp _ h

/-! ## The equality test of the joint iteration -/

theorem filter_eq_iff_mem (l : List Envelope) (P Q : Envelope → Bool) :
    l.filter P = l.filter Q ↔ ∀ x ∈ l, P x = Q x := by
  constructor
  · intro h x hx
    have hP : x ∈ l.filter P ↔ x ∈ l.filter Q := by rw [h]
    simp only [List.mem_filter, hx, true_and] at hP
    cases hPx : P x <;> cases hQx : Q x <;> simp_all
  · intro h; exact List.filter_congr h

theorem beq_sim (hp : E.Perm E') : ∀ {a a' b b' : State}, Sim E E' a a' → Sim E E' b b' →
    (a == b) = (a' == b')
  | [], [], [], [], _, _ => rfl
  | x :: a, x' :: a', y :: b, y' :: b', ha, hb => by
    obtain ⟨⟨hkx, P, hx, hx'⟩, ha⟩ := ha
    obtain ⟨⟨hky, Q, hy, hy'⟩, hb⟩ := hb
    have ih := beq_sim hp ha hb
    obtain ⟨kx, vx⟩ := x; obtain ⟨kx', vx'⟩ := x'; obtain ⟨ky, vy⟩ := y; obtain ⟨ky', vy'⟩ := y'
    simp only at hkx hky hx hx' hy hy'
    subst hkx; subst hky; subst hx; subst hx'; subst hy; subst hy'
    have hv : (E.filter P = E.filter Q) ↔ (E'.filter P = E'.filter Q) := by
      rw [filter_eq_iff_mem, filter_eq_iff_mem]
      exact ⟨fun h x hx => h x (hp.mem_iff.mpr hx), fun h x hx => h x (hp.mem_iff.mp hx)⟩
    have ih' : a = b ↔ a' = b' := by rw [← beq_iff_eq, ih, beq_iff_eq]
    apply Bool.eq_iff_iff.mpr
    simp only [beq_iff_eq, List.cons.injEq, Prod.mk.injEq]
    rw [hv, ih']
  | [], [], _ :: _, _ :: _, _, _ => rfl
  | _ :: _, _ :: _, [], [], _, _ => rfl
  | [], _ :: _, _, _, h, _ => absurd h (by simp [SimL])
  | _ :: _, [], _, _, h, _ => absurd h (by simp [SimL])
  | [], [], [], _ :: _, _, h => absurd h (by simp [SimL])
  | [], [], _ :: _, [], _, h => absurd h (by simp [SimL])
  | _ :: _, _ :: _, [], _ :: _, _, h => absurd h (by simp [SimL])
  | _ :: _, _ :: _, _ :: _, [], _, h => absurd h (by simp [SimL])

def OptSim (E E' : List Envelope) : Option State → Option State → Prop
  | none, none => True
  | some F, some F' => Sim E E' F F'
  | _, _ => False

theorem fixLoop_sim {rego : Rego} (hr : RegoPermInvariant rego) (hp : E.Perm E') (h : Hardening)
    (p : Policy) (o : Options) (α : Assign) :
    ∀ (n : Nat) {st st' : State}, Sim E E' st st' →
      OptSim E E' (fixLoop rego h p o E α n st) (fixLoop rego h p o E' α n st')
  | 0, _, _, _ => by simp [fixLoop, OptSim]
  | n + 1, st, st', hs => by
    have hF := prune_sim hp (p := p) (o := o) (phaseFrom_sim hr hp h p o α hs)
    simp only [fixLoop]
    rw [beq_sim hp hF hs]
    by_cases hc : (prune p o (phaseFrom rego h p o E' α st') == st') = true
    · simp only [hc, ite_true]; exact hF
    · simp only [hc, Bool.false_eq_true, ite_false]; exact fixLoop_sim hr hp h p o α n hF

/-! ## Externals and assignments -/

theorem extPassed_perm (hp : E.Perm E') {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    (x : External) : (extPassed regoExt h p o E x).Perm (extPassed regoExt h p o E' x) := hp.filter _

theorem extCandidates_perm (hp : E.Perm E') {p : Policy} {o : Options} (x : External) :
    (extCandidates p o E x).Perm (extCandidates p o E' x) := hp.filter _

theorem verdictOn_sim (hp : E.Perm E') {regoExt : RegoExt} {h : Hardening} {p : Policy}
    {o : Options} {F F' : State} (hF : Sim E E' F F') :
    verdictOn regoExt h p o E F = verdictOn regoExt h p o E' F' := by
  unfold verdictOn externalOk
  have h1 : (p.steps.all fun s => !(F.get s.name).isEmpty) = (p.steps.all fun s => !(F'.get s.name).isEmpty) := by
    apply all_congr_mem; intro s _
    obtain ⟨P, h1, h2⟩ := get_sim hp hF s.name
    rw [h1, h2, isEmpty_filter_perm hp]
  rw [h1]
  simp only [isEmpty_perm (extPassed_perm hp _), isEmpty_perm (extCandidates_perm hp _)]

theorem mem_assignments_perm (hp : E.Perm E') {regoExt : RegoExt} {h : Hardening} {p : Policy}
    {o : Options} (α : Assign) :
    α ∈ assignments regoExt h p o E ↔ α ∈ assignments regoExt h p o E' := by
  unfold assignments
  generalize p.externals.filter (fun x => p.steps.any (·.externalFrom.contains x.name)) = l
  induction l generalizing α with
  | nil => rfl
  | cons x l ih =>
    simp only [List.foldr_cons]
    have hperm := extPassed_perm hp (regoExt := regoExt) (h := h) (p := p) (o := o) x
    generalize extPassed regoExt h p o E x = ps at hperm
    generalize extPassed regoExt h p o E' x = ps' at hperm
    cases ps with
    | nil =>
      have : ps' = [] := hperm.nil_eq.symm
      subst this; exact ih α
    | cons e es =>
      cases ps' with
      | nil => exact absurd hperm.symm.nil_eq (by simp)
      | cons e' es' =>
        simp only [List.mem_flatMap, List.mem_map]
        constructor
        · rintro ⟨y, hy, γ, hγ, rfl⟩
          exact ⟨y, hperm.mem_iff.mp hy, γ, (ih γ).mp hγ, rfl⟩
        · rintro ⟨y, hy, γ, hγ, rfl⟩
          exact ⟨y, hperm.mem_iff.mpr hy, γ, (ih γ).mpr hγ, rfl⟩

/-! ## Theorem 6 -/

/-- Theorem 6. Permuting the evidence never changes the fixed-semantics
    verdict, given Rego that is blind to input.steps order. -/
theorem order_independent {rego : Rego} (hr : RegoPermInvariant rego) (regoExt : RegoExt)
    (h : Hardening) (p : Policy) (o : Options) (hp : E.Perm E') :
    verifyFixed rego regoExt h p o E = verifyFixed rego regoExt h p o E' := by
  unfold verifyFixed
  congr 1
  apply Bool.eq_iff_iff.mpr
  simp only [List.any_eq_true]
  have key : ∀ α, (match fixLoop rego h p o E α o.fixFuel (prune p o (phaseFrom rego h p o E α [])) with
      | some F => verdictOn regoExt h p o E F | none => false) =
      (match fixLoop rego h p o E' α o.fixFuel (prune p o (phaseFrom rego h p o E' α [])) with
      | some F => verdictOn regoExt h p o E' F | none => false) := by
    intro α
    have h0 : Sim E E' (prune p o (phaseFrom rego h p o E α [])) (prune p o (phaseFrom rego h p o E' α [])) :=
      prune_sim hp (phaseFrom_sim hr hp h p o α (st := []) (st' := []) trivial)
    have hs := fixLoop_sim hr hp h p o α o.fixFuel h0
    generalize fixLoop rego h p o E α o.fixFuel (prune p o (phaseFrom rego h p o E α [])) = A at hs ⊢
    generalize fixLoop rego h p o E' α o.fixFuel (prune p o (phaseFrom rego h p o E' α [])) = B at hs ⊢
    cases A <;> cases B <;> simp only [OptSim] at hs ⊢
    exact verdictOn_sim hp hs
  constructor
  · rintro ⟨α, hα, hv⟩; exact ⟨α, (mem_assignments_perm hp α).mp hα, (key α).symm.trans hv⟩
  · rintro ⟨α, hα, hv⟩; exact ⟨α, (mem_assignments_perm hp α).mpr hα, (key α).trans hv⟩

end CilockPolicy
