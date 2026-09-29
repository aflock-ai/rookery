/-
  CilockPolicy.Linking: the anchor, the links between collections, and the
  options that change reach (commit binding, About, fan-out, lazy witness).

  The as-built engine follows NO relationship edge: evidence is found only by a
  seed digest (`policy.go`, `policy.go`). The links that remain are
  artifactsFrom (products -> materials, by path and DigestSet.Equal) and
  attestationsFrom (Rego input). Both are proved here for the fixed semantics.
  -- cite: attestation/policy/policy.go:296-302 sha256:622ef1746c7cbd22794ce5b31a655ad8578aa11f15a245e63b8434b4c875e82a
  -- cite: attestation/policy/policy.go:974-979 sha256:02729af599c32c78c149bc44223b5c85ab327eaf880015995a092724246ced22
-/
import CilockPolicy.TrustProofs

namespace CilockPolicy

/-! ## Theorem 3 / L1: every contributing collection is anchored -/

theorem anchored_spec {seeds : List String} {c : Collection} (h : anchored seeds c = true) :
    ∃ sub ∈ c.subjects, matchable c.hardenedGit sub = true ∧ (seeds.map normSeed).contains (subjectKey sub) = true := by
  simp only [anchored, anchorHits, Bool.not_eq_true', List.isEmpty_eq_false_iff] at h
  obtain ⟨v, hv⟩ := List.exists_mem_of_ne_nil _ h
  simp only [List.mem_map, List.mem_filter, Bool.and_eq_true] at hv
  obtain ⟨sub, ⟨hs, hm, hseed⟩, _⟩ := hv
  exact ⟨sub, hs, hm, hseed⟩

/-- L1 (anchor soundness). On a passing verify every collection that counts,
    as a step survivor, as an artifactsFrom partner, or as Rego input, is a
    survivor, and every survivor carries a matchable SIGNED subject whose
    algorithm:value key is a (normalized) seed. There is no hop: nothing is
    reached through a BackRef. -/
theorem anchor_sound {rego : Rego} {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} (hpass : verifyFixed rego regoExt h p o E = true) :
    ∃ α F, JointFixed rego h p o E α F ∧
      ∀ s ∈ p.steps, ∀ e ∈ F.get s.name,
        ∃ sub ∈ e.payload.subjects, matchable e.payload.hardenedGit sub = true ∧
          (o.seeds.map normSeed).contains (subjectKey sub) = true := by
  obtain ⟨_, α, F, hF, _, hall, _⟩ := verifyFixed_spec hpass
  exact ⟨α, F, hF, fun s hs e he => anchored_spec (hall s hs e he).anchored⟩

/-! ## L3: no transitive laundering (fixed semantics) -/

/-- Every collection a step's Rego saw under input.steps is a SURVIVOR of the
    dependency it was listed under. Refuted for as-built: Launder.lean (#9813). -/
theorem stepsCtx_survivors {s : Step} {F : State} {d : String} {cs : List Collection}
    (hd : (d, cs) ∈ stepsCtx s F) {c : Collection} (hc : c ∈ cs) : ∃ u ∈ F.get d, u.payload = c := by
  unfold stepsCtx at hd
  split at hd
  · simp only [List.mem_map] at hd
    obtain ⟨d', _, hpair⟩ := hd
    injection hpair with h1 h2
    subst h1; subst h2
    simpa using hc
  · cases hd

theorem no_laundering {rego : Rego} {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} (hpass : verifyFixed rego regoExt h p o E = true) :
    ∃ α F, JointFixed rego h p o E α F ∧
      ∀ s ∈ p.steps, ∀ e ∈ F.get s.name,
        gate rego o s ⟨stepsCtx s F, extCtx s α⟩ e.payload = true ∧
        ∀ d cs, (d, cs) ∈ stepsCtx s F → ∀ c ∈ cs, ∃ u ∈ F.get d, u.payload = c := by
  obtain ⟨_, α, F, hF, _, hall, _⟩ := verifyFixed_spec hpass
  exact ⟨α, F, hF, fun s hs e he =>
    ⟨(hall s hs e he).gated, fun d cs hd c hc => stepsCtx_survivors hd hc⟩⟩

/-! ## V3: commit binding -/

theorem commit_bound {rego : Rego} {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} {k : String} (hk : o.commit = some k)
    (hpass : verifyFixed rego regoExt h p o E = true) :
    ∃ α F, JointFixed rego h p o E α F ∧
      ∀ s ∈ p.steps, ∀ e ∈ F.get s.name,
        gitHashes e.payload ≠ [] ∧ ∀ g ∈ gitHashes e.payload, lower g = lower k := by
  obtain ⟨_, α, F, hF, _, hall, _⟩ := verifyFixed_spec hpass
  refine ⟨α, F, hF, fun s hs e he => ?_⟩
  have hg := (hall s hs e he).gated
  simp only [gate, Bool.and_eq_true] at hg
  have hc := hg.1.1.2
  simp only [commitOk, hk, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff,
    List.all_eq_true, beq_iff_eq] at hc
  exact hc

/-- V3 for externals: a passed external under a commit binding is a
    collection-typed statement whose git attestations all name the commit
    (bare predicates are unbound, `commit_binding.go`). The model's externals
    have no `commitSubject`; #10067 lets an external that declares one bind a
    bare predicate through a signed sha1 subject, which is not modelled.
    -- cite: attestation/policy/commit_binding.go:270-297 sha256:8c96a3dacca5b6c4d21e3161a40e10d21dc446dee8e245360a5436d716a2c115
    -/
theorem external_commit_bound {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} {x : External} {k : String} (hk : o.commit = some k) {e : Envelope}
    (he : e ∈ extPassed regoExt h p o E x) :
    e.payload.isCollection = true ∧ gitHashes e.payload ≠ [] ∧ ∀ g ∈ gitHashes e.payload, lower g = lower k := by
  simp only [extPassed, List.mem_filter, Bool.and_eq_true] at he
  have hb := he.2.1.1.2
  have hv := he.2.1.1.1.2
  simp only [extBound, Bool.or_eq_true, Bool.and_eq_true, hk, Option.isNone_some, Bool.false_or] at hb
  rcases hb with hb | hb
  · simp only [Bool.not_eq_true', List.isEmpty_eq_false_iff] at hv
    simp only [List.isEmpty_iff] at hb; exact absurd hb hv
  · simp only [commitOk, hk, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff,
      List.all_eq_true, beq_iff_eq] at hb
    exact ⟨hb.2.1, hb.2.2.1, hb.2.2.2⟩

/-! ## V4: About never adds or removes a candidate -/

/-- About is read only by the refusal check (`decode.go`); every
    per-collection decision is the same with it cleared.
    -- cite: attestation/policy/decode.go:152-173 sha256:b1bdf78ab77e9be7b918cf7657a02c7dd0cc6775385d65b517a3b176ca69daab
    -/
theorem about_irrelevant (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (s : Step) (ctx : Ctx) (a : String) :
    passedFor rego h p o E { s with about := a } ctx = passedFor rego h p o E s ctx ∧
    (∀ st e, keep o st { s with about := a } e = keep o st s e) := ⟨rfl, fun _ _ => rfl⟩

/-- ...and outside a v0.2 policy it is refused before any evidence is read. -/
theorem about_needs_v02 {p : Policy} {s : Step} (hs : s ∈ p.steps) (ha : s.about ≠ "")
    (hv : p.v02 = false) : validate p = false := by
  cases h : validate p
  · rfl
  · simp only [validate, Bool.and_eq_true, List.all_eq_true] at h
    have := h.1.2 s hs
    simp [hv, ha] at this

/-! ## Theorem 5 / L5: attestationsFrom is well-founded; pruning terminates -/

theorem validSteps_deps :
    ∀ (l1 : List Step) (seen : List String) (s : Step) (l2 : List Step),
      validSteps seen (l1 ++ s :: l2) = true →
      (∀ d ∈ s.attestationsFrom, d ∈ seen ∨ d ∈ l1.map (·.name)) ∧
      s.name ∉ seen ∧ s.name ∉ l1.map (·.name)
  | [], seen, s, l2, h => by
    simp only [List.nil_append, validSteps, Bool.and_eq_true, Bool.not_eq_true',
      List.all_eq_true] at h
    refine ⟨fun d hd => Or.inl (by simpa using h.1.2 d hd), by simpa using h.1.1, by simp⟩
  | t :: l1, seen, s, l2, h => by
    simp only [List.cons_append, validSteps, Bool.and_eq_true, Bool.not_eq_true'] at h
    obtain ⟨hd, hns, hnl⟩ := validSteps_deps l1 (seen ++ [t.name]) s l2 h.2
    simp only [List.mem_append, List.mem_singleton, not_or] at hns
    refine ⟨fun d hdd => ?_, hns.1, ?_⟩
    · rcases hd d hdd with h1 | h1
      · simp only [List.mem_append, List.mem_singleton] at h1
        rcases h1 with h1 | h1
        · exact Or.inl h1
        · exact Or.inr (by simp [h1])
      · exact Or.inr (by simp [h1])
    · simp only [List.map_cons, List.mem_cons, not_or]
      exact ⟨hns.2, hnl⟩

/-- Theorem 5. In a validated policy every attestationsFrom dependency names
    a step listed strictly EARLIER, and no step depends on itself. The
    dependency relation therefore has no cycle; there is nothing to loop on,
    and an invalid (cyclic, self, unknown) policy fails before any search. -/
theorem attestationsFrom_wellFounded {p : Policy} (hv : validate p = true)
    {l1 l2 : List Step} {s : Step} (hsplit : p.steps = l1 ++ s :: l2) :
    (∀ d ∈ s.attestationsFrom, d ∈ l1.map (·.name)) ∧ s.name ∉ s.attestationsFrom := by
  have h := validSteps_deps l1 [] s l2 (hsplit ▸ validate_steps hv)
  have hdeps : ∀ d ∈ s.attestationsFrom, d ∈ l1.map (·.name) := fun d hd => by
    rcases h.1 d hd with h1 | h1
    · cases h1
    · exact h1
  exact ⟨hdeps, fun hself => h.2.2 (hdeps _ hself)⟩

/-! ## Pruning is monotone (the greatest-fixed-point argument) -/

/-- Pointwise inclusion of states. -/
def State.le (X Y : State) : Prop := ∀ n e, e ∈ X.get n → e ∈ Y.get n

/-- `X` is post-fixed: every member keeps its partners inside `X`. -/
def PostFixed (p : Policy) (o : Options) (X : State) : Prop :=
  ∀ n s e, stepOf p n = some s → e ∈ X.get n → keep o X s e = true

theorem untrackedOk_mono {o : Options} {X Y : State} (hle : State.le X Y) {s : Step} {c : Collection}
    (h : untrackedOk o X s c = true) : untrackedOk o Y s c = true := by
  simp only [untrackedOk, coveredPath, Bool.or_eq_true, List.all_eq_true, List.any_eq_true,
    Bool.and_eq_true] at h ⊢
  rcases h with h | h
  · exact .inl h
  · refine .inr fun m hm => ?_
    rcases h m hm with ⟨d, hd, u, hu, hc⟩ | ha
    · exact .inl ⟨d, hd, u, hle d u hu, hc⟩
    · exact .inr ha

theorem keep_mono {o : Options} {X Y : State} (hle : State.le X Y) {s : Step} {e : Envelope}
    (h : keep o X s e = true) : keep o Y s e = true := by
  simp only [keep, Bool.and_eq_true, List.all_eq_true, List.any_eq_true] at h ⊢
  refine ⟨fun d hd => ?_, untrackedOk_mono hle h.2⟩
  obtain ⟨u, hu, he⟩ := h.1 d hd
  exact ⟨u, hle d u hu, he⟩

theorem postFixed_pass {p : Policy} {o : Options} {X st : State} (hX : PostFixed p o X)
    (hle : State.le X st) : State.le X (prunePass p o st) := by
  intro n e he
  rw [prunePass_eq, get_passWith]
  cases hs : stepOf p n
  · exact hle n e he
  · exact List.mem_filter.mpr ⟨hle n e he, keep_mono hle (hX n _ e hs he)⟩

theorem postFixed_loop {p : Policy} {o : Options} {X : State} (hX : PostFixed p o X) :
    ∀ (k : Nat) (st : State), State.le X st → State.le X (pruneLoop p o k st)
  | 0, _, hle => hle
  | k + 1, st, hle => by
    simp only [pruneLoop]
    split
    · exact hle
    · exact postFixed_loop hX k _ (postFixed_pass hX hle)

theorem prune_postFixed (p : Policy) (o : Options) (st : State) : PostFixed p o (prune p o st) :=
  fun _ _ _ hs he => prune_keep hs he

/-- Pruning is monotone: more candidates never lose a survivor. -/
theorem prune_mono {p : Policy} {o : Options} {st st' : State} (hle : State.le st st') :
    State.le (prune p o st) (prune p o st') :=
  postFixed_loop (prune_postFixed p o st) _ _ (fun n e he => hle n e (mem_prune he))

end CilockPolicy
