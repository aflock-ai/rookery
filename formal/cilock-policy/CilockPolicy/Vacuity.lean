/-
  CilockPolicy.Vacuity: V1 (does a statically valid policy admit an arbitrary
  signer?) and V2 (hardening monotonicity) at the functionary level.
-/
import CilockPolicy.TrustProofs

namespace CilockPolicy

/-! ## What a satisfied list constraint means -/

theorem consume_covers :
    ∀ (es vs : List String) (rest : List String), consume es vs = some rest →
      ∀ v ∈ vs, v ∈ es ∨ v ∈ rest
  | [], vs, rest, h, v, hv => by simp [consume] at h; subst h; exact Or.inr hv
  | e :: es, vs, rest, h, v, hv => by
    simp only [consume] at h
    split at h
    · by_cases hve : v = e
      · exact Or.inl (hve ▸ List.mem_cons_self)
      · have hv' : v ∈ vs.erase e := (List.mem_erase_of_ne hve).mpr hv
        rcases consume_covers es (vs.erase e) rest h v hv' with h1 | h1
        · exact Or.inl (List.mem_cons_of_mem _ h1)
        · exact Or.inr h1
    · cases h

theorem takeGlob_spec :
    ∀ (gs : List (String × Bool)) (v : String) (gs' : List (String × Bool)), takeGlob gs v = some gs' →
      (∃ g ∈ gs.map (·.1), glob (lower g) (lower v) = true) ∧ gs'.map (·.1) = gs.map (·.1)
  | [], _, _, h => by simp [takeGlob] at h
  | (g, u) :: gs, v, gs', h => by
    simp only [takeGlob] at h
    split at h
    · rename_i hc
      simp only [Bool.and_eq_true, Bool.not_eq_true'] at hc
      injection h with h; subst h
      exact ⟨⟨g, List.mem_cons_self, hc.2⟩, rfl⟩
    · cases hr : takeGlob gs v with
      | none => rw [hr] at h; cases h
      | some r =>
        rw [hr] at h; injection h with h; subst h
        obtain ⟨⟨g', hg', hm⟩, heq⟩ := takeGlob_spec gs v r hr
        exact ⟨⟨g', List.mem_cons_of_mem _ hg', hm⟩, by simp [heq]⟩

theorem assignGlobs_covers :
    ∀ (gs : List (String × Bool)) (vs : List String), assignGlobs gs vs = true →
      ∀ v ∈ vs, ∃ g ∈ gs.map (·.1), glob (lower g) (lower v) = true
  | _, [], _, _, hv => absurd hv List.not_mem_nil
  | gs, w :: vs, h, v, hv => by
    simp only [assignGlobs] at h
    split at h
    · cases h
    · rename_i gs' hg
      obtain ⟨hw, heq⟩ := takeGlob_spec gs w gs' hg
      rcases List.mem_cons.mp hv with rfl | hv'
      · exact hw
      · have := assignGlobs_covers gs' vs h v hv'
        rwa [heq] at this

/-- V1, per field. Under RejectEmptyConstraintEmptyField a list constraint is
    satisfied only by an explicit `"*"`, or by a NON-EMPTY constraint list that
    covers every non-empty certificate value (exact entry or glob). There is
    no implicit wildcard. -/
theorem listOk_nonvacuous {h : Hardening} (hE : h.emptyField = true) {cons vals : List String}
    (hok : listOk h cons vals = true) :
    cons.contains "*" = true ∨
    ((cons.filter (· != "")) ≠ [] ∧
      ∀ v ∈ vals, v ≠ "" → v ∈ cons ∨ ∃ g ∈ cons, isGlob g = true ∧ glob (lower g) (lower v) = true) := by
  unfold listOk at hok
  split at hok
  · exact Or.inl (by assumption)
  · right
    simp only at hok
    split at hok
    · simp [emptyConstraintOk, hE] at hok
    · rename_i hne
      refine ⟨by simpa using hne, ?_⟩
      intro v hv hvne
      have hv' : v ∈ vals.filter (· != "") := List.mem_filter.mpr ⟨hv, by simpa using hvne⟩
      split at hok
      · cases hok
      · rename_i rest hc
        rcases consume_covers _ _ rest hc v hv' with h1 | h1
        · exact Or.inl (List.mem_filter.mp (List.mem_filter.mp h1).1).1
        · obtain ⟨g, hg, hm⟩ := assignGlobs_covers _ _ hok v h1
          simp only [List.map_map, List.mem_map, List.mem_filter, Function.comp] at hg
          obtain ⟨g', ⟨⟨hg'1, _⟩, hg'2⟩, rfl⟩ := hg
          exact Or.inr ⟨g', hg'1, hg'2, hm⟩

/-- V1, per functionary. Under the CLI's enforce mode a credential is admitted
    only by an exact key-id pin with no certificate constraint set, or by the
    full certificate constraint: a trusted root the constraint names (or
    `"*"`), and the per-field rules of `listOk_nonvacuous`. -/
theorem fValidate_enforce {roots : List RootId} {f : Functionary} {cred : Cred}
    (hok : fValidate .enforce roots f cred = true) :
    (f.keyId ≠ "" ∧ f.keyId = cred.keyId ∧ f.cc.isSet = false) ∨
    ∃ c, cred = .cert c ∧ f.cc.roots ≠ [] ∧ ccCheck .enforce roots f.cc c = true := by
  have harm : certArm .enforce roots f cred = true →
      ∃ c, cred = .cert c ∧ f.cc.roots ≠ [] ∧ ccCheck .enforce roots f.cc c = true := by
    intro ha
    cases cred with
    | key _ => simp [certArm] at ha
    | cert c =>
      simp only [certArm, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at ha
      exact ⟨c, rfl, ha.1, ha.2⟩
  unfold fValidate at hok
  split at hok
  · rename_i hk
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at hk
    cases hset : f.cc.isSet
    · exact Or.inl ⟨hk.1, hk.2, rfl⟩
    · simp only [hset, Hardening.enforce, Bool.and_self, ite_true] at hok
      exact Or.inr (harm hok)
  · exact Or.inr (harm hok)

/-! ## V2: hardening is monotone at the functionary level -/

theorem listOk_mono {g h : Hardening} (hle : Hardening.le g h) {cons vals : List String}
    (hok : listOk h cons vals = true) : listOk g cons vals = true := by
  unfold listOk at hok ⊢
  split
  · rfl
  · rename_i hs
    simp only [hs, Bool.false_eq_true, ite_false] at hok
    simp only at hok ⊢
    split
    · rename_i he
      simp only [he, ite_true, emptyConstraintOk, Bool.and_eq_true, Bool.not_eq_true'] at hok ⊢
      refine ⟨hok.1, ?_⟩
      cases hg : g.emptyField
      · rfl
      · have := hle.2.1 hg; rw [this] at hok; cases hok.2
    · rename_i he
      simpa [he] using hok

theorem ccCheck_mono {g h : Hardening} (hle : Hardening.le g h) {roots : List RootId}
    {cc : CertConstraint} {c : Cert} (hok : ccCheck h roots cc c = true) : ccCheck g roots cc c = true := by
  simp only [ccCheck, Bool.and_eq_true] at hok ⊢
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, h9⟩ := hok
  exact ⟨⟨⟨⟨⟨⟨⟨⟨h1, listOk_mono hle h2⟩, listOk_mono hle h3⟩, listOk_mono hle h4⟩, listOk_mono hle h5⟩,
    h6⟩, h7⟩, h8⟩, h9⟩

theorem certArm_mono {g h : Hardening} (hle : Hardening.le g h) {roots : List RootId}
    {f : Functionary} {cred : Cred} (hok : certArm h roots f cred = true) : certArm g roots f cred = true := by
  cases cred with
  | key _ => simp [certArm] at hok
  | cert c =>
    simp only [certArm, Bool.and_eq_true] at hok ⊢
    exact ⟨hok.1, ccCheck_mono hle hok.2⟩

/-- V2 (functionary level): turning any hardening flag ON only removes
    admitted credentials. -/
theorem fValidate_mono {g h : Hardening} (hle : Hardening.le g h) {roots : List RootId}
    {f : Functionary} {cred : Cred} (hok : fValidate h roots f cred = true) :
    fValidate g roots f cred = true := by
  unfold fValidate at hok ⊢
  split
  · rename_i hk
    simp only [hk, ite_true] at hok
    split
    · rename_i hc
      simp only [Bool.and_eq_true] at hc
      have : h.keyIdCC = true := hle.1 hc.2
      simp only [hc.1, this, Bool.and_self, ite_true] at hok
      exact certArm_mono hle hok
    · rfl
  · rename_i hk
    simp only [hk] at hok
    exact certArm_mono hle hok

/-- V2 (triage level), for steps WITHOUT a timestamp constraint. With one it
    is false: the constraint judges the EARLIEST matched time, and a stricter
    flag can drop an old-timestamped verifier (see Counterexamples,
    `v2_timestamp_counterexample`). That direction is benign: the dropped
    verifier should not have counted. -/
theorem triage_mono {g h : Hardening} (hle : Hardening.le g h) {p : Policy} {o : Options}
    {s : Step} {e : Envelope} (hts : s.tsc = none) (hok : triage h p o s e = true) :
    triage g p o s e = true := by
  simp only [triage, hts, tscOk, Bool.and_true, Bool.and_eq_true, Bool.not_eq_true',
    List.isEmpty_eq_false_iff] at hok ⊢
  refine ⟨hok.1, ?_⟩
  obtain ⟨v, hv⟩ := List.exists_mem_of_ne_nil _ hok.2
  simp only [validFunctionaries, List.mem_filter, List.any_eq_true] at hv
  obtain ⟨hvm, f, hf, hfv⟩ := hv
  apply List.ne_nil_of_mem (a := v)
  simp only [validFunctionaries, List.mem_filter, List.any_eq_true]
  exact ⟨hvm, f, hf, fValidate_mono hle hfv⟩

end CilockPolicy
