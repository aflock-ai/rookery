/-
  CilockPolicy.BoundProof: the #9813 fix's round bound, for policies whose
  step LIST is a topological order of the combined attestationsFrom ∪
  artifactsFrom graph (`validateAcyclic`). That is narrower than the validator
  #9860 shipped (`unionAcyclic`, which accepts an acyclic graph in any list
  order): `bound_scope_gap` exhibits a policy the shipped validator accepts
  that no theorem here covers.
-/
import CilockPolicy.Bound9813
import CilockPolicy.LinkingOptions

namespace CilockPolicy

/-! ## The ordered validator the proofs assume -/

/-- Both relations point strictly EARLIER in the step list: the list is a
    topological order of the combined graph, so the graph is acyclic. -/
def acyclicOrder : List String → List Step → Bool
  | _, [] => true
  | seen, s :: rest =>
    !seen.contains s.name && s.attestationsFrom.all seen.contains && s.artifactsFrom.all seen.contains &&
    acyclicOrder (seen ++ [s.name]) rest

def validateAcyclic (p : Policy) : Bool := validate p && acyclicOrder [] p.steps

/-! ## States: keys and extensionality -/

def keys (st : State) : List String := st.map (·.1)

theorem get_cons_self (k : String) (v : List Envelope) (l : State) : State.get ((k, v) :: l) k = v := by
  simp [State.get]

theorem get_cons_ne {k n : String} (v : List Envelope) (l : State) (h : n ≠ k) :
    State.get ((k, v) :: l) n = l.get n := by
  have : (n == k) = false := by simpa using h
  simp [State.get, List.lookup_cons, this]

theorem get_not_key : ∀ {l : State} {n : String}, n ∉ keys l → l.get n = []
  | [], _, _ => rfl
  | (k, v) :: l, n, h => by
    simp only [keys, List.map_cons, List.mem_cons, not_or] at h
    rw [get_cons_ne v l h.1]
    exact get_not_key h.2

/-- Two states with the same duplicate-free keys and the same lookups are equal. -/
theorem state_ext : ∀ {X Y : State}, keys X = keys Y → (keys X).Nodup →
    (∀ n, X.get n = Y.get n) → X = Y
  | [], [], _, _, _ => rfl
  | (k, v) :: X, (k', w) :: Y, hk, hnd, hg => by
    simp only [keys, List.map_cons, List.cons.injEq] at hk
    obtain ⟨rfl, hk⟩ := hk
    simp only [keys, List.map_cons, List.nodup_cons] at hnd
    have hv : v = w := by have := hg k; rwa [get_cons_self, get_cons_self] at this
    subst hv
    congr 1
    apply state_ext hk hnd.2
    intro n
    by_cases hn : n = k
    · subst hn
      rw [get_not_key hnd.1, get_not_key (by rw [keys, ← hk]; exact hnd.1)]
    · have := hg n; rwa [get_cons_ne _ _ hn, get_cons_ne _ _ hn] at this
  | [], _ :: _, hk, _, _ => by simp [keys] at hk
  | _ :: _, [], hk, _, _ => by simp [keys] at hk

theorem keys_passWith (p : Policy) (o : Options) (ref l : State) : keys (passWith p o ref l) = keys l := by
  simp [keys, passWith]

theorem keys_pruneLoop (p : Policy) (o : Options) : ∀ (n : Nat) (st : State), keys (pruneLoop p o n st) = keys st
  | 0, _ => rfl
  | n + 1, st => by
    simp only [pruneLoop]
    split
    · rfl
    · rw [keys_pruneLoop p o n, prunePass_eq, keys_passWith]

theorem keys_prune (p : Policy) (o : Options) (st : State) : keys (prune p o st) = keys st :=
  keys_pruneLoop p o _ st

theorem keys_phaseFrom (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) (st : State) : keys (phaseFrom rego h p o E α st) = p.steps.map (·.name) := by
  simp [keys, phaseFrom]

/-! ## Pruning results are filters of their input -/

theorem prune_get_filter (p : Policy) (o : Options) :
    ∀ (k : Nat) (st : State) (n : String), ∃ Q : Envelope → Bool, (pruneLoop p o k st).get n = (st.get n).filter Q
  | 0, st, n => ⟨fun _ => true, (List.filter_eq_self.mpr fun _ _ => rfl).symm⟩
  | k + 1, st, n => by
    simp only [pruneLoop]
    split
    · exact ⟨fun _ => true, (List.filter_eq_self.mpr fun _ _ => rfl).symm⟩
    · obtain ⟨Q, hQ⟩ := prune_get_filter p o k (prunePass p o st) n
      rw [hQ, prunePass_eq, get_passWith]
      cases stepOf p n with
      | none => exact ⟨Q, rfl⟩
      | some s => exact ⟨fun e => Q e && keep o st s e, by rw [List.filter_filter]⟩

/-! ## Restriction to a set of step names -/

def restrict (N : List String) (Z : State) : State := Z.map fun x => (x.1, if N.contains x.1 then x.2 else [])

theorem get_restrict (N : List String) : ∀ (Z : State) (n : String),
    (restrict N Z).get n = if N.contains n then Z.get n else []
  | [], n => by simp [restrict, State.get]
  | (k, v) :: Z, n => by
    simp only [restrict, List.map_cons]
    by_cases hn : n = k
    · subst hn; rw [get_cons_self, get_cons_self]
    · rw [get_cons_ne _ _ hn, get_cons_ne _ _ hn]; exact get_restrict N Z n

/-- `N` is closed under artifactsFrom: a step named in `N` reads only
    upstreams named in `N`. -/
def ArtClosed (p : Policy) (N : List String) : Prop :=
  ∀ n s, N.contains n = true → stepOf p n = some s → ∀ d ∈ s.artifactsFrom, N.contains d = true

def Agree (N : List String) (X Y : State) : Prop := ∀ n, N.contains n = true → X.get n = Y.get n

theorem restrict_postFixed {p : Policy} {o : Options} {N : List String} (hN : ArtClosed p N)
    {Z : State} (hZ : PostFixed p o Z) : PostFixed p o (restrict N Z) := by
  intro n s e hs he
  rw [get_restrict] at he
  split at he
  · rename_i hn
    have hk := hZ n s e hs he
    have hget : ∀ d ∈ s.artifactsFrom, (restrict N Z).get d = Z.get d := fun d hd => by
      rw [get_restrict, if_pos (hN n s hn hs d hd)]
    unfold keep at hk ⊢
    rw [untrackedOk_congr (Y := Z) (fun d hd f => by rw [hget d hd])]
    simp only [Bool.and_eq_true, List.all_eq_true, List.any_eq_true] at hk ⊢
    refine ⟨fun d hd => ?_, hk.2⟩
    obtain ⟨u, hu, heu⟩ := hk.1 d hd
    exact ⟨u, (hget d hd) ▸ hu, heu⟩
  · cases he

theorem prune_sub_of_agree {p : Policy} {o : Options} {N : List String} (hN : ArtClosed p N)
    {X Y : State} (hXY : Agree N X Y) :
    ∀ n, N.contains n = true → ∀ e, e ∈ (prune p o X).get n → e ∈ (prune p o Y).get n := by
  intro n hn e he
  have hpost := restrict_postFixed (o := o) hN (prune_postFixed p o X)
  have hle : State.le (restrict N (prune p o X)) Y := by
    intro m e' he'
    rw [get_restrict] at he'
    split at he'
    · rename_i hm; rw [← hXY m hm]; exact mem_prune he'
    · cases he'
  have := postFixed_loop hpost (size Y + 1) Y hle n e
  apply this
  rw [get_restrict, if_pos hn]
  exact he

/-- (B) Pruning is local: inputs that agree on an artifactsFrom-closed name
    set give outputs that agree on it. -/
theorem prune_agree {p : Policy} {o : Options} {N : List String} (hN : ArtClosed p N)
    {X Y : State} (hXY : Agree N X Y) : Agree N (prune p o X) (prune p o Y) := by
  intro n hn
  obtain ⟨Q1, h1⟩ := prune_get_filter p o (size X + 1) X n
  obtain ⟨Q2, h2⟩ := prune_get_filter p o (size Y + 1) Y n
  have e1 : (prune p o X).get n = (X.get n).filter Q1 := h1
  have e2 : (prune p o Y).get n = (X.get n).filter Q2 := by rw [hXY n hn]; exact h2
  rw [e1, e2]
  apply List.filter_congr
  intro x hx
  have a := prune_sub_of_agree (o := o) hN hXY n hn x
  have b := prune_sub_of_agree (o := o) hN (fun m hm => (hXY m hm).symm) n hn x
  rw [e1, e2] at a
  rw [e1, e2] at b
  simp only [List.mem_filter, hx, true_and] at a b
  cases h1x : Q1 x <;> cases h2x : Q2 x <;> simp_all

/-! ## Order facts from the ordered validator -/

def names (l : List Step) : List String := l.map (·.name)

theorem acyclicOrder_split :
    ∀ (l1 : List Step) (seen : List String) (t : Step) (l2 : List Step),
      acyclicOrder seen (l1 ++ t :: l2) = true →
      (∀ d ∈ t.attestationsFrom, d ∈ seen ∨ d ∈ names l1) ∧
      (∀ d ∈ t.artifactsFrom, d ∈ seen ∨ d ∈ names l1)
  | [], seen, t, l2, h => by
    simp only [List.nil_append, acyclicOrder, Bool.and_eq_true, List.all_eq_true] at h
    exact ⟨fun d hd => Or.inl (by simpa using h.1.1.2 d hd), fun d hd => Or.inl (by simpa using h.1.2 d hd)⟩
  | u :: l1, seen, t, l2, h => by
    simp only [List.cons_append, acyclicOrder, Bool.and_eq_true] at h
    obtain ⟨ha, hr⟩ := acyclicOrder_split l1 (seen ++ [u.name]) t l2 h.2
    have lift : ∀ d, d ∈ seen ++ [u.name] ∨ d ∈ names l1 → d ∈ seen ∨ d ∈ names (u :: l1) := by
      intro d hd
      simp only [List.mem_append, List.mem_singleton] at hd
      rcases hd with (h1 | h1) | h1
      · exact Or.inl h1
      · exact Or.inr (by simp [names, h1])
      · exact Or.inr (by simp only [names, List.map_cons, List.mem_cons]; exact Or.inr h1)
    exact ⟨fun d hd => lift d (ha d hd), fun d hd => lift d (hr d hd)⟩

theorem acyclicOrder_nodup :
    ∀ (l : List Step) (seen : List String), acyclicOrder seen l = true →
      (names l).Nodup ∧ ∀ x ∈ names l, x ∉ seen
  | [], _, _ => ⟨List.nodup_nil, by simp [names]⟩
  | s :: l, seen, h => by
    simp only [acyclicOrder, Bool.and_eq_true, Bool.not_eq_true'] at h
    obtain ⟨hnd, hns⟩ := acyclicOrder_nodup l (seen ++ [s.name]) h.2
    have hs : s.name ∉ seen := by simpa using h.1.1.1
    refine ⟨?_, ?_⟩
    · simp only [names, List.map_cons, List.nodup_cons]
      exact ⟨fun hm => hns s.name hm (by simp), hnd⟩
    · intro x hx
      simp only [names, List.map_cons, List.mem_cons] at hx
      rcases hx with rfl | hx
      · exact hs
      · exact fun hxs => hns x hx (by simp [hxs])

theorem acyclicOrder_of {p : Policy} (h : validateAcyclic p = true) : acyclicOrder [] p.steps = true := by
  simp only [validateAcyclic, Bool.and_eq_true] at h; exact h.2

theorem validate_of {p : Policy} (h : validateAcyclic p = true) : validate p = true := by
  simp only [validateAcyclic, Bool.and_eq_true] at h; exact h.1

theorem mem_names_of_mem {l : List Step} {t : Step} (h : t ∈ l) : t.name ∈ names l :=
  List.mem_map_of_mem h

/-- A step among the first `i` reads (by either relation) only names among
    the first `i`. -/
theorem deps_in_take {L : List Step} (hL : acyclicOrder [] L = true) (i : Nat) {t : Step}
    (ht : t ∈ L.take i) :
    (∀ d ∈ t.attestationsFrom, d ∈ names (L.take i)) ∧ (∀ d ∈ t.artifactsFrom, d ∈ names (L.take i)) := by
  obtain ⟨l1, l2, hsplit⟩ := List.append_of_mem ht
  have hL' : L = l1 ++ t :: (l2 ++ L.drop i) := by
    have e := (List.take_append_drop i L).symm; rw [hsplit] at e; simpa using e
  rw [hL'] at hL
  obtain ⟨ha, hr⟩ := acyclicOrder_split l1 [] t (l2 ++ L.drop i) hL
  have sub : ∀ d, d ∈ ([] : List String) ∨ d ∈ names l1 → d ∈ names (L.take i) := by
    intro d hd
    rcases hd with hd | hd
    · cases hd
    · rw [hsplit]; simp only [names, List.map_append, List.mem_append]; exact Or.inl hd
  exact ⟨fun d hd => sub d (ha d hd), fun d hd => sub d (hr d hd)⟩

/-- The (i+1)-th step reads only names among the first `i`. -/
theorem deps_in_take_succ {L : List Step} (hL : acyclicOrder [] L = true) (i : Nat) {t : Step}
    (ht : t ∈ L.take (i + 1)) :
    (∀ d ∈ t.attestationsFrom, d ∈ names (L.take i)) ∧ (∀ d ∈ t.artifactsFrom, d ∈ names (L.take i)) := by
  rw [List.take_succ, List.mem_append] at ht
  rcases ht with ht | ht
  · exact deps_in_take hL i ht
  · rw [Option.mem_toList] at ht
    have hi : i < L.length := by
      cases h : L[i]? with
      | none => rw [h] at ht; cases ht
      | some _ => exact (List.getElem?_eq_some_iff.mp h).1
    have ht' : t = L[i] := by rw [List.getElem?_eq_getElem hi] at ht; injection ht with ht; exact ht.symm
    have hL' : L = L.take i ++ t :: L.drop (i + 1) := by
      rw [ht', ← List.drop_eq_getElem_cons hi, List.take_append_drop]
    rw [hL'] at hL
    obtain ⟨ha, hr⟩ := acyclicOrder_split (L.take i) [] t (L.drop (i + 1)) hL
    exact ⟨fun d hd => (ha d hd).resolve_left (by simp), fun d hd => (hr d hd).resolve_left (by simp)⟩

theorem stepOf_in_take {p : Policy} (i : Nat) {n : String} {s : Step}
    (hn : n ∈ names (p.steps.take i)) (hs : stepOf p n = some s) : s ∈ p.steps.take i := by
  unfold stepOf at hs
  rw [← List.take_append_drop i p.steps, List.find?_append] at hs
  obtain ⟨x, hx, hxn⟩ := List.mem_map.mp hn
  cases hf : (p.steps.take i).find? (·.name == n) with
  | none =>
    rw [List.find?_eq_none] at hf
    exact absurd (by simp [hxn]) (hf x hx)
  | some y =>
    rw [hf] at hs
    simp only [Option.some_or] at hs
    injection hs with hs
    subst hs
    exact List.mem_of_find?_eq_some hf

theorem artClosed_take {p : Policy} (hL : acyclicOrder [] p.steps = true) (i : Nat) :
    ArtClosed p (names (p.steps.take i)) := by
  intro n s hn hs d hd
  have hs' := stepOf_in_take i (List.contains_iff_mem.mp hn) hs
  exact List.contains_iff_mem.mpr ((deps_in_take hL i hs').2 d hd)

/-! ## Phase locality -/

theorem stepsCtx_congr {s : Step} {X Y : State} (h : ∀ d ∈ s.attestationsFrom, X.get d = Y.get d) :
    stepsCtx s X = stepsCtx s Y := by
  unfold stepsCtx
  have hc : (s.attestationsFrom.all fun d => !(X.get d).isEmpty) =
      (s.attestationsFrom.all fun d => !(Y.get d).isEmpty) := by
    apply all_congr_mem; intro d hd; rw [h d hd]
  rw [hc]
  split
  · show List.map _ _ = List.map _ _
    apply List.map_congr_left
    intro d hd; rw [h d hd]
  · rfl

theorem phaseFrom_congr {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E : List Envelope}
    {α : Assign} {X Y : State} (hXY : ∀ t ∈ p.steps, ∀ d ∈ t.attestationsFrom, X.get d = Y.get d) :
    phaseFrom rego h p o E α X = phaseFrom rego h p o E α Y := by
  unfold phaseFrom
  apply List.map_congr_left
  intro t ht
  rw [stepsCtx_congr (hXY t ht)]

/-- Agreement of two phases on the first i+1 steps, from agreement of their
    sources on the first i. -/
theorem phaseFrom_agree_succ {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E : List Envelope}
    {α : Assign} (hv : validateAcyclic p = true) (i : Nat) {X Y : State}
    (hXY : Agree (names (p.steps.take i)) X Y) :
    Agree (names (p.steps.take (i + 1))) (phaseFrom rego h p o E α X) (phaseFrom rego h p o E α Y) := by
  intro n hn
  obtain ⟨t, ht, rfl⟩ := List.mem_map.mp (List.contains_iff_mem.mp hn)
  have htL : t ∈ p.steps := List.mem_of_mem_take ht
  rw [get_phaseFrom rego h o E α X (validate_of hv) htL, get_phaseFrom rego h o E α Y (validate_of hv) htL,
    stepsCtx_congr (fun d hd => hXY d (List.contains_iff_mem.mpr ((deps_in_take_succ (acyclicOrder_of hv) i ht).1 d hd)))]

/-! ## The as-built first round is a fixed point of its own phase -/

theorem get_append_of_key : ∀ {acc : State} {d : String} (l : State), d ∈ keys acc → (acc ++ l).get d = acc.get d
  | [], _, _, h => by simp [keys] at h
  | (k, v) :: acc, d, l, h => by
    by_cases hd : d = k
    · subst hd; simp only [List.cons_append]; rw [get_cons_self, get_cons_self]
    · simp only [List.cons_append]; rw [get_cons_ne _ _ hd, get_cons_ne _ _ hd]
      simp only [keys, List.map_cons, List.mem_cons] at h
      exact get_append_of_key l (h.resolve_left hd)

theorem phaseAsBuilt_selfFixed {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E : List Envelope}
    {α : Assign} (hv : validateAcyclic p = true) :
    phaseAsBuilt rego h p o E α = phaseFrom rego h p o E α (phaseAsBuilt rego h p o E α) := by
  let g : Step → State → String × List Envelope := fun s st =>
    (s.name, passedFor rego h p o E s ⟨stepsCtx s st, extCtx s α⟩)
  -- Inv pre acc: acc is pre's phase read from acc itself.
  have step : ∀ (rest pre : List Step) (acc : State),
      acc = pre.map (fun t => g t acc) →
      (∀ t ∈ pre, ∀ d ∈ t.attestationsFrom, d ∈ names pre) →
      acyclicOrder (names pre) rest = true →
      rest.foldl (fun st s => st ++ [g s st]) acc =
        (pre ++ rest).map (fun t => g t (rest.foldl (fun st s => st ++ [g s st]) acc)) := by
    intro rest
    induction rest with
    | nil => intro pre acc hinv _ _; simpa using hinv
    | cons s rest ih =>
      intro pre acc hinv hpre hord
      simp only [acyclicOrder, Bool.and_eq_true, Bool.not_eq_true', List.all_eq_true] at hord
      have hkeys : keys acc = names pre := by rw [hinv]; simp [keys, names, g]
      have hsdeps : ∀ d ∈ s.attestationsFrom, d ∈ names pre := fun d hd => by
        simpa using hord.1.1.2 d hd
      let acc' := acc ++ [g s acc]
      have same : ∀ t, (∀ d ∈ t.attestationsFrom, d ∈ names pre) → g t acc' = g t acc := by
        intro t ht
        simp only [g, acc']
        rw [stepsCtx_congr (fun d hd => get_append_of_key _ (hkeys ▸ ht d hd))]
      have hinv' : acc' = (pre ++ [s]).map (fun t => g t acc') := by
        have e1 : acc' = pre.map (fun t => g t acc) ++ [g s acc] := congrArg (· ++ [g s acc]) hinv
        calc acc' = pre.map (fun t => g t acc) ++ [g s acc] := e1
          _ = pre.map (fun t => g t acc') ++ [g s acc'] := by
            rw [same s hsdeps]
            congr 1
            apply List.map_congr_left
            intro t ht
            rw [same t (hpre t ht)]
          _ = (pre ++ [s]).map (fun t => g t acc') := by simp
      have hpre' : ∀ t ∈ pre ++ [s], ∀ d ∈ t.attestationsFrom, d ∈ names (pre ++ [s]) := by
        intro t ht d hd
        simp only [names, List.map_append, List.mem_append]
        rcases List.mem_append.mp ht with ht | ht
        · exact Or.inl (hpre t ht d hd)
        · simp only [List.mem_singleton] at ht; subst ht; exact Or.inl (hsdeps d hd)
      have hord' : acyclicOrder (names (pre ++ [s])) rest = true := by
        simpa [names] using hord.2
      simp only [List.foldl_cons]
      have := ih (pre ++ [s]) acc' hinv' hpre' hord'
      simpa using this
  have := step p.steps [] [] rfl (by simp) (by simpa [names] using acyclicOrder_of hv)
  unfold phaseAsBuilt phaseFrom
  simpa using this

/-! ## Rounds and stabilization -/

/-- The joint iteration from a starting context `Z`: round 0 prunes the phase
    read from `Z`; each later round prunes the phase read from the last. -/
def rounds (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope) (α : Assign)
    (Z : State) : Nat → State
  | 0 => prune p o (phaseFrom rego h p o E α Z)
  | k + 1 => prune p o (phaseFrom rego h p o E α (rounds rego h p o E α Z k))

section
variable {rego : Rego} {h : Hardening} {p : Policy} {o : Options} {E : List Envelope} {α : Assign}

theorem keys_rounds (Z : State) (k : Nat) : keys (rounds rego h p o E α Z k) = names p.steps := by
  cases k <;> simp only [rounds, keys_prune, keys_phaseFrom, names]

/-- The first `i` steps are stable from round `i - 1` on: each attestationsFrom
    edge costs one round, an artifactsFrom edge none. -/
theorem rounds_stable (hv : validateAcyclic p = true) (Z : State) :
    ∀ i k, i ≤ k + 1 → Agree (names (p.steps.take i)) (rounds rego h p o E α Z k) (rounds rego h p o E α Z (k + 1))
  | 0, _, _ => by intro n hn; simp [names] at hn
  | i + 1, k, hik => by
    have hsrc : Agree (names (p.steps.take i))
        (match k with | 0 => Z | k' + 1 => rounds rego h p o E α Z k') (rounds rego h p o E α Z k) := by
      cases k with
      | zero =>
        have : i = 0 := by omega
        subst this; intro n hn; simp [names] at hn
      | succ k' => exact rounds_stable hv Z i k' (by omega)
    have hph := phaseFrom_agree_succ (rego := rego) (h := h) (o := o) (E := E) (α := α) hv i hsrc
    have := prune_agree (o := o) (artClosed_take (acyclicOrder_of hv) (i + 1)) hph
    cases k with
    | zero => exact this
    | succ k' => exact this

theorem rounds_eq (hv : validateAcyclic p = true) (Z : State) (k : Nat) (hk : p.steps.length ≤ k + 1) :
    rounds rego h p o E α Z k = rounds rego h p o E α Z (k + 1) := by
  have hag := rounds_stable (rego := rego) (h := h) (o := o) (E := E) (α := α) hv Z p.steps.length k hk
  rw [List.take_length] at hag
  have hnd := (acyclicOrder_nodup p.steps [] (acyclicOrder_of hv)).1
  apply state_ext (by rw [keys_rounds, keys_rounds]) (by rw [keys_rounds]; exact hnd)
  intro n
  by_cases hn : n ∈ names p.steps
  · exact hag n (List.contains_iff_mem.mpr hn)
  · rw [get_not_key (by rw [keys_rounds]; exact hn), get_not_key (by rw [keys_rounds]; exact hn)]

/-! ## The joint fixed point is unique -/

theorem jointFixed_unique (hv : validateAcyclic p = true) {F G : State}
    (hF : JointFixed rego h p o E α F) (hG : JointFixed rego h p o E α G) : F = G := by
  have agree : ∀ i, Agree (names (p.steps.take i)) F G := by
    intro i
    induction i with
    | zero => intro n hn; simp [names] at hn
    | succ i ih =>
      have := prune_agree (o := o) (artClosed_take (acyclicOrder_of hv) (i + 1))
        (phaseFrom_agree_succ (rego := rego) (h := h) (o := o) (E := E) (α := α) hv i ih)
      rw [← hF, ← hG] at this
      exact this
  have hag := agree p.steps.length
  rw [List.take_length] at hag
  have kF : keys F = names p.steps := by rw [hF, keys_prune, keys_phaseFrom]; rfl
  have kG : keys G = names p.steps := by rw [hG, keys_prune, keys_phaseFrom]; rfl
  apply state_ext (by rw [kF, kG]) (by rw [kF]; exact (acyclicOrder_nodup p.steps [] (acyclicOrder_of hv)).1)
  intro n
  by_cases hn : n ∈ names p.steps
  · exact hag n (List.contains_iff_mem.mpr hn)
  · rw [get_not_key (by rw [kF]; exact hn), get_not_key (by rw [kG]; exact hn)]

/-! ## The loops -/

theorem ctxDeps_mem {t : Step} (ht : t ∈ p.steps) {d : String} (hd : d ∈ t.attestationsFrom) : d ∈ ctxDeps p :=
  List.mem_flatMap_of_mem ht hd

theorem fixLoop_rounds (Z : State) :
    ∀ m j, (∃ k, j ≤ k ∧ k < j + m ∧ rounds rego h p o E α Z k = rounds rego h p o E α Z (k + 1)) →
      ∃ F, fixLoop rego h p o E α m (rounds rego h p o E α Z j) = some F
  | 0, j, ⟨k, hjk, hk, _⟩ => absurd hk (by omega)
  | m + 1, j, ⟨k, hjk, hk, heq⟩ => by
    show ∃ F, (if rounds rego h p o E α Z (j + 1) == rounds rego h p o E α Z j then
        some (rounds rego h p o E α Z (j + 1)) else fixLoop rego h p o E α m (rounds rego h p o E α Z (j + 1))) = some F
    by_cases hc : (rounds rego h p o E α Z (j + 1) == rounds rego h p o E α Z j) = true
    · rw [if_pos hc]; exact ⟨_, rfl⟩
    · rw [if_neg hc]
      have hkj : k ≠ j := by
        intro e; subst e; exact hc (beq_iff_eq.mpr heq.symm)
      exact fixLoop_rounds Z m (j + 1) ⟨k, by omega, by omega, heq⟩

theorem fix9813Loop_rounds (Z : State) :
    ∀ m j, (∃ k, j ≤ k ∧ k < j + m ∧ rounds rego h p o E α Z k = rounds rego h p o E α Z (k + 1)) →
      ∃ F, fix9813Loop rego h p o E α m (some (rounds rego h p o E α Z j)) = some F ∧ JointFixed rego h p o E α F
  | 0, j, ⟨k, hjk, hk, _⟩ => absurd hk (by omega)
  | m + 1, j, ⟨k, hjk, hk, heq⟩ => by
    show ∃ F, (if (ctxDeps p).all (fun d => (rounds rego h p o E α Z j).get d == (rounds rego h p o E α Z (j + 1)).get d)
        then some (rounds rego h p o E α Z (j + 1))
        else fix9813Loop rego h p o E α m (some (rounds rego h p o E α Z (j + 1)))) = some F ∧ JointFixed rego h p o E α F
    by_cases hc : ((ctxDeps p).all fun d => (rounds rego h p o E α Z j).get d == (rounds rego h p o E α Z (j + 1)).get d) = true
    · rw [if_pos hc]
      refine ⟨_, rfl, ?_⟩
      simp only [List.all_eq_true, beq_iff_eq] at hc
      show rounds rego h p o E α Z (j + 1) = prune p o (phaseFrom rego h p o E α (rounds rego h p o E α Z (j + 1)))
      show prune p o (phaseFrom rego h p o E α (rounds rego h p o E α Z j)) = _
      rw [phaseFrom_congr (fun t ht d hd => hc d (ctxDeps_mem ht hd))]
    · rw [if_neg hc]
      have hkj : k ≠ j := by
        intro e; subst e; apply hc; simp [heq]
      exact fix9813Loop_rounds Z m (j + 1) ⟨k, by omega, by omega, heq⟩

/-! ## The bound -/

/-- **The #9813 fix converges within len(steps)+1 rounds** on every policy whose
    step list `validateAcyclic` accepts, and what it converges to is a joint
    fixed point. Not proved for an acyclic policy listed out of order. -/
theorem fix9813_converges (hv : validateAcyclic p = true) :
    ∃ F, fix9813Loop rego h p o E α (p.steps.length + 1) none = some F ∧ JointFixed rego h p o E α F := by
  have self := phaseAsBuilt_selfFixed (rego := rego) (h := h) (o := o) (E := E) (α := α) hv
  let Φ := phaseAsBuilt rego h p o E α
  have r0 : rounds rego h p o E α Φ 0 = prune p o Φ := by
    show prune p o (phaseFrom rego h p o E α Φ) = prune p o Φ
    rw [← self]
  show ∃ F, (if (ctxDeps p).all (fun d => Φ.get d == (prune p o Φ).get d) then some (prune p o Φ)
      else fix9813Loop rego h p o E α p.steps.length (some (prune p o Φ))) = some F ∧ JointFixed rego h p o E α F
  by_cases hc : ((ctxDeps p).all fun d => Φ.get d == (prune p o Φ).get d) = true
  · rw [if_pos hc]
    refine ⟨_, rfl, ?_⟩
    simp only [List.all_eq_true, beq_iff_eq] at hc
    show prune p o Φ = prune p o (phaseFrom rego h p o E α (prune p o Φ))
    rw [← phaseFrom_congr (fun t ht d hd => hc d (ctxDeps_mem ht hd)), ← self]
  · rw [if_neg hc, ← r0]
    have hlen : 0 < p.steps.length := by
      rcases hl : p.steps with _ | ⟨s, l⟩
      · exfalso; apply hc; simp [ctxDeps, hl]
      · simp
    exact fix9813Loop_rounds Φ p.steps.length 0
      ⟨p.steps.length - 1, by omega, by omega, rounds_eq hv Φ _ (by omega)⟩

/-- **...and it is the joint-fixed-point semantics.** Given enough fuel for
    `verifyFixed`, the fix and the model's fixed semantics decide alike. -/
theorem verifyFix9813_eq_verifyFixed {regoExt : RegoExt} (hv : validateAcyclic p = true)
    (hfuel : p.steps.length + 1 ≤ o.fixFuel) :
    verifyFix9813 rego regoExt h p o E = verifyFixed rego regoExt h p o E := by
  unfold verifyFix9813 verifyFixed
  congr 1
  apply any_congr_mem
  intro α _
  obtain ⟨F, hF, jF⟩ := fix9813_converges (rego := rego) (h := h) (o := o) (E := E) (α := α) hv
  obtain ⟨G, hG⟩ := fixLoop_rounds (rego := rego) (h := h) (p := p) (o := o) (E := E) (α := α) [] o.fixFuel 0
    ⟨p.steps.length, by omega, by omega, rounds_eq hv [] _ (by omega)⟩
  have hG' : fixLoop rego h p o E α o.fixFuel (prune p o (phaseFrom rego h p o E α [])) = some G := hG
  have jG := fixLoop_fixed rego h p o E α _ _ _ hG'
  rw [hF, hG', jointFixed_unique hv jF jG]

end

/-- The counterexample policy (Bound9813) passes the OLD validator, which
    checks each relation for cycles separately, and fails the NEW one. -/
theorem bound_counterexample_validators :
    validate Bound9813.pol = true ∧ validateAcyclic Bound9813.pol = false := by decide

/-- The proofs' premise is narrower than the shipped validator. `a` consumes
    `b`'s products and is listed first: the combined graph is acyclic, so
    `unionAcyclic` (and `verifyShipped`) accept the policy, but the list is not
    a topological order, so `validateAcyclic` refuses it and
    `fix9813_converges` says nothing about it. -/
def unorderedPol : Policy :=
  Fixtures.basePolicy [{ Fixtures.step "a" with artifactsFrom := ["b"] }, Fixtures.step "b"]

theorem bound_scope_gap :
    validate unorderedPol = true ∧ unionAcyclic unorderedPol = true ∧
    validateAcyclic unorderedPol = false := by decide

end CilockPolicy
