/-
  CilockPolicy.Lemmas: the structural facts every theorem leans on.
  Pruning only removes; the pruning loop reaches a fixed point inside its fuel;
  lookups into the step phase return that step's Passed set.
-/
import CilockPolicy.Verify

namespace CilockPolicy

/-! ## Filters -/

theorem filter_eq_self_of_length {α} (q : α → Bool) :
    ∀ l : List α, (l.filter q).length = l.length → l.filter q = l
  | [], _ => rfl
  | a :: l, h => by
    by_cases hq : q a = true
    · simp only [List.filter_cons, hq, ite_true, List.length_cons] at h ⊢
      rw [filter_eq_self_of_length q l (by omega)]
    · simp only [List.filter_cons, hq] at h
      have := List.length_filter_le q l
      simp at h; omega

/-! ## One pruning pass -/

/-- The pass, with the state it reads (`ref`) separated from the entries it
    rewrites (`l`), so induction over `l` is possible. -/
def passWith (p : Policy) (o : Options) (ref l : State) : State :=
  l.map fun x => (x.1, match stepOf p x.1 with
    | some s => x.2.filter (keep o ref s)
    | none => x.2)

theorem prunePass_eq (p : Policy) (o : Options) (st : State) :
    prunePass p o st = passWith p o st st := rfl

theorem lookup_passWith (p : Policy) (o : Options) (ref : State) (n : String) :
    ∀ l : State, (passWith p o ref l).lookup n =
      (l.lookup n).map fun v => match stepOf p n with
        | some s => v.filter (keep o ref s)
        | none => v
  | [] => rfl
  | ⟨k, v⟩ :: l => by
    have ih := lookup_passWith p o ref n l
    simp only [passWith] at ih
    simp only [passWith, List.map_cons]
    rw [List.lookup_cons, List.lookup_cons]
    cases hx : (n == k)
    · exact ih
    · have : n = k := beq_iff_eq.mp hx
      subst this; rfl

theorem get_passWith (p : Policy) (o : Options) (ref l : State) (n : String) :
    (passWith p o ref l).get n = match stepOf p n with
      | some s => (l.get n).filter (keep o ref s)
      | none => l.get n := by
  unfold State.get; rw [lookup_passWith]
  cases h : l.lookup n <;> cases stepOf p n <;> simp

theorem mem_passWith {p : Policy} {o : Options} {ref l : State} {n : String} {e : Envelope}
    (h : e ∈ (passWith p o ref l).get n) : e ∈ l.get n := by
  rw [get_passWith] at h
  cases hs : stepOf p n <;> simp only [hs] at h
  · exact h
  · exact (List.mem_filter.mp h).1

def entrySize (x : String × List Envelope) : Nat := x.2.length

theorem size_cons (x : String × List Envelope) (l : State) : size (x :: l) = x.2.length + size l := by
  simp [size]

theorem passWith_entry_le (p : Policy) (o : Options) (ref : State) (x : String × List Envelope) :
    (match stepOf p x.1 with | some s => x.2.filter (keep o ref s) | none => x.2).length ≤ x.2.length := by
  cases stepOf p x.1
  · exact Nat.le_refl _
  · exact List.length_filter_le _ _

theorem size_passWith_le (p : Policy) (o : Options) (ref : State) :
    ∀ l : State, size (passWith p o ref l) ≤ size l
  | [] => Nat.le_refl _
  | x :: l => by
    have h1 := passWith_entry_le p o ref x
    have h2 := size_passWith_le p o ref l
    simp only [passWith, List.map_cons] at h2 ⊢
    rw [size_cons, size_cons]
    exact Nat.add_le_add h1 h2

theorem passWith_eq_of_size (p : Policy) (o : Options) (ref : State) :
    ∀ l : State, size (passWith p o ref l) = size l → passWith p o ref l = l
  | [] => fun _ => rfl
  | x :: l => by
    intro h
    have h1 := passWith_entry_le p o ref x
    have h2 := size_passWith_le p o ref l
    simp only [passWith, List.map_cons] at h h2 ⊢
    rw [size_cons, size_cons] at h
    simp only at h
    have hx : (match stepOf p x.1 with | some s => x.2.filter (keep o ref s) | none => x.2).length
        = x.2.length := by omega
    have hl : size (passWith p o ref l) = size l := by simp only [passWith]; omega
    have ih := passWith_eq_of_size p o ref l hl
    simp only [passWith] at ih
    rw [ih]
    congr 1
    cases hs : stepOf p x.1 <;> simp only [hs] at hx ⊢
    rw [filter_eq_self_of_length _ _ hx]

/-! ## The pruning loop -/

theorem mem_pruneLoop {p : Policy} {o : Options} :
    ∀ (n : Nat) (st : State) (m : String) (e : Envelope), e ∈ (pruneLoop p o n st).get m → e ∈ st.get m
  | 0, _, _, _, h => h
  | n + 1, st, m, e, h => by
    simp only [pruneLoop] at h
    split at h
    · exact h
    · have := mem_pruneLoop n _ m e h
      rw [prunePass_eq] at this
      exact mem_passWith this

/-- Pruning only removes collections. -/
theorem mem_prune {p : Policy} {o : Options} {st : State} {m : String} {e : Envelope}
    (h : e ∈ (prune p o st).get m) : e ∈ st.get m := mem_pruneLoop _ _ _ _ h

theorem pruneLoop_fixed (p : Policy) (o : Options) :
    ∀ (n : Nat) (st : State), size st < n → prunePass p o (pruneLoop p o n st) = pruneLoop p o n st
  | 0, _, h => absurd h (Nat.not_lt_zero _)
  | n + 1, st, h => by
    simp only [pruneLoop]
    split
    · rename_i heq
      have := passWith_eq_of_size p o st st (by rw [← prunePass_eq]; exact beq_iff_eq.mp heq)
      rw [prunePass_eq]; exact this
    · rename_i hne
      apply pruneLoop_fixed
      have hle := size_passWith_le p o st st
      rw [← prunePass_eq] at hle
      have : size (prunePass p o st) ≠ size st := fun e => hne (beq_iff_eq.mpr e)
      omega

/-- The pruning result is a fixed point of one pass: its fuel (total + 1)
    always suffices, so the bound can never cut convergence short (L5). -/
theorem prune_fixed (p : Policy) (o : Options) (st : State) :
    prunePass p o (prune p o st) = prune p o st :=
  pruneLoop_fixed p o _ st (Nat.lt_succ_self _)

/-- Every survivor has, for each artifactsFrom edge, a SURVIVING upstream
    partner. -/
theorem prune_keep {p : Policy} {o : Options} {st : State} {m : String} {s : Step} {e : Envelope}
    (hs : stepOf p m = some s) (he : e ∈ (prune p o st).get m) :
    keep o (prune p o st) s e = true := by
  have hfix := prune_fixed p o st
  rw [prunePass_eq] at hfix
  have hget : (passWith p o (prune p o st) (prune p o st)).get m = (prune p o st).get m := by
    rw [hfix]
  rw [get_passWith, hs] at hget
  rw [← hget] at he
  exact (List.mem_filter.mp he).2

end CilockPolicy
