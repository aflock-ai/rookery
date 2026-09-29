/-
  CilockPolicy.TrustProofs: what a contributing signature is, the timestamp
  constraint (V7), expiry and untrusted signers (Theorem 4), no cross-step
  reuse (Theorem 2), and the exported `policy_sound`.
-/
import CilockPolicy.Soundness

namespace CilockPolicy

/-! ## DSSE unpacking -/

theorem mem_verifiers {p : Policy} {e : Envelope} {v : Verifier} (hv : v ∈ verifiers p e) :
    ∃ sig ∈ e.sigs, sigVerifier p sig = some v := by
  simpa [verifiers] using hv

theorem sigVerifier_spec {p : Policy} {sig : Sig} {v : Verifier} (h : sigVerifier p sig = some v) :
    sig.ok = true ∧ v.cred = sig.cred ∧
    (∀ k, sig.cred = .key k → p.keys.contains k = true ∧ v.times = keyTimes p sig) ∧
    (∀ c, sig.cred = .cert c → p.tsas ≠ [] ∧ c.chainsTo.any p.roots.contains = true ∧
      v.times = certTimes p c sig ∧ v.times ≠ []) := by
  unfold sigVerifier at h
  split at h
  · rename_i k hk
    split at h
    · rename_i hc
      simp only [Bool.and_eq_true] at hc
      injection h with h; subst h
      refine ⟨hc.1, hk.symm, ?_, ?_⟩
      · intro k' hk'; rw [hk] at hk'; injection hk' with hk'; subst hk'; exact ⟨hc.2, rfl⟩
      · intro c hc'; rw [hk] at hc'; cases hc'
    · cases h
  · rename_i c hc
    split at h
    · rename_i hcond
      simp only [Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at hcond
      injection h with h; subst h
      refine ⟨hcond.1.1.1, hc.symm, ?_, ?_⟩
      · intro k hk; rw [hc] at hk; cases hk
      · intro c' hc'; rw [hc] at hc'; injection hc' with hc'; subst hc'
        exact ⟨hcond.1.1.2, hcond.1.2, rfl, hcond.2⟩
    · cases h

/-- Every time a verifier carries is a token that verified against a policy
    TSA, at a moment inside the certificate's validity window. -/
theorem mem_certTimes {p : Policy} {c : Cert} {sig : Sig} {t : Time} (h : t ∈ certTimes p c sig) :
    ∃ tok ∈ sig.tokens, tok.ok = true ∧ p.tsas.contains tok.tsa = true ∧
      c.notBefore ≤ tok.time ∧ tok.time ≤ c.notAfter ∧ tok.time = t := by
  simp only [certTimes, List.mem_map, List.mem_filter, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨tok, ⟨hm, ⟨⟨hok, hts⟩, hnb⟩, hna⟩, rfl⟩ := h
  exact ⟨tok, hm, hok, hts, hnb, hna, rfl⟩

/-- Only TSA-verified times ever reach a verdict: a verifier's times come from
    tokens of its own signature that verified against a policy TSA, never from
    a signer-claimed field (V7, second half). A certificate's are also inside
    its validity window; a raw key has none to check. -/
theorem verifier_times_tsa {p : Policy} {e : Envelope} {v : Verifier} (hv : v ∈ verifiers p e)
    {t : Time} (ht : t ∈ v.times) :
    ∃ sig ∈ e.sigs, ∃ tok ∈ sig.tokens, tok.ok = true ∧ p.tsas.contains tok.tsa = true ∧
      tok.time = t ∧ ∀ c, sig.cred = .cert c → c.notBefore ≤ tok.time ∧ tok.time ≤ c.notAfter := by
  obtain ⟨sig, hsig, hsv⟩ := mem_verifiers hv
  obtain ⟨_, _, hk, hc⟩ := sigVerifier_spec hsv
  cases hcred : sig.cred with
  | key k =>
    rw [(hk k hcred).2] at ht
    simp only [keyTimes, List.mem_map, List.mem_filter, Bool.and_eq_true] at ht
    obtain ⟨tok, ⟨htm, hok, hts⟩, rfl⟩ := ht
    exact ⟨sig, hsig, tok, htm, hok, hts, rfl, fun c hc' => by rw [hcred] at hc'; cases hc'⟩
  | cert c =>
    obtain ⟨_, _, htimes, _⟩ := hc c hcred
    rw [htimes] at ht
    obtain ⟨tok, htok, hok, hts, hnb, hna, heq⟩ := mem_certTimes ht
    refine ⟨sig, hsig, tok, htok, hok, hts, heq, fun c' hc' => ?_⟩
    rw [hcred] at hc'
    cases hc'
    exact ⟨hnb, hna⟩

/-! ## The signer behind a contributing collection -/

/-- What the verdict says about who signed collection `e` for step `s`, in
    world terms (under the Assumptions). -/
def SignerEvidence {p : Policy} {o : Options} {E : List Envelope} (A : Assumptions p o E) (h : Hardening) (s : Step)
    (e : Envelope) : Prop :=
  ∃ sig ∈ e.sigs, ∃ f ∈ s.functionaries,
    fValidate h p.roots f sig.cred = true ∧ A.signed sig.cred.keyId e.payload ∧
    (∀ k, sig.cred = .key k → p.keys.contains k = true) ∧
    (∀ c, sig.cred = .cert c → ∃ r, c.chainsTo.contains r = true ∧ p.roots.contains r = true ∧
      A.vouches r c ∧ ∃ tok ∈ sig.tokens, A.existedAt sig tok.time ∧
      c.notBefore ≤ tok.time ∧ tok.time ≤ c.notAfter ∧ tok.time ≤ o.now)

theorem triage_signer {p : Policy} {o : Options} {E : List Envelope} (A : Assumptions p o E) {h : Hardening} {s : Step}
    {e : Envelope} (he : e ∈ E) (ht : triage h p o s e = true) : SignerEvidence A h s e := by
  simp only [triage, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at ht
  obtain ⟨⟨⟨_, _⟩, hvf⟩, _⟩ := ht
  obtain ⟨v, hv⟩ := List.exists_mem_of_ne_nil _ hvf
  simp only [validFunctionaries, List.mem_filter, List.any_eq_true] at hv
  obtain ⟨hvmem, f, hf, hfv⟩ := hv
  obtain ⟨sig, hsig, hsv⟩ := mem_verifiers hvmem
  obtain ⟨hok, hcred, hk, hc⟩ := sigVerifier_spec hsv
  refine ⟨sig, hsig, f, hf, hcred ▸ hfv, A.sigUnforgeable e he sig hsig hok, fun k hk' => (hk k hk').1, ?_⟩
  intro c hc'
  obtain ⟨_, hroot, htimes, hne⟩ := hc c hc'
  simp only [List.any_eq_true] at hroot
  obtain ⟨r, hr, hpr⟩ := hroot
  obtain ⟨t, htm⟩ := List.exists_mem_of_ne_nil _ hne
  rw [htimes] at htm
  obtain ⟨tok, htok, htokok, htsa, hnb, hna, _⟩ := mem_certTimes htm
  exact ⟨r, by simpa using hr, hpr, A.caHonest e he sig hsig c hc' r (by simpa using hr) hpr,
    tok, htok, A.tsaHonest e he sig hsig tok htok htokok htsa, hnb, hna, A.tsaNotFuture e he sig hsig tok htok htokok htsa⟩

/-! ## V7: the timestamp constraint -/

/-- V7. When a step declares a timestamp constraint, a contributing collection
    has a TSA-verified time `t` from a FUNCTIONARY-MATCHED verifier; `t` is the
    earliest such time; the window bounds are exact; maxAge admits at most a
    fixed 5-minute future and an age of at most maxAge. The clock-skew option
    appears nowhere (see `triage_skew_irrelevant`). -/
theorem timestamp_sound {h : Hardening} {p : Policy} {o : Options} {s : Step} {e : Envelope}
    {c : TsConstraint} (ht : triage h p o s e = true) (hc : s.tsc = some c) :
    ∃ t, (∃ v ∈ validFunctionaries h p s.functionaries e, t ∈ v.times) ∧
      (∀ v ∈ validFunctionaries h p s.functionaries e, ∀ t' ∈ v.times, t ≤ t') ∧
      (∀ nb, c.notBefore = some nb → nb ≤ t) ∧ (∀ na, c.notAfter = some na → t ≤ na) ∧
      (∀ m, c.maxAge = some m → t ≤ o.now + maxClockSkew ∧ o.now - t ≤ m) := by
  simp only [triage, Bool.and_eq_true] at ht
  have htsc := ht.2
  simp only [tscOk, hc] at htsc
  split at htsc
  · simp at htsc
  · rename_i t hmin
    have hmem := List.min?_mem hmin
    have hle := (List.min?_eq_some_iff.mp hmin).2
    simp only [List.mem_flatMap] at hmem
    simp only [Bool.and_eq_true, Option.all_eq_true_iff_get, decide_eq_true_eq] at htsc
    refine ⟨t, hmem, fun v hv t' ht' => hle t' (List.mem_flatMap.mpr ⟨v, hv, ht'⟩), ?_, ?_, ?_⟩
    · intro nb hnb; have := htsc.1.1; simp [hnb] at this; exact this
    · intro na hna; have := htsc.1.2; simp [hna] at this; exact this
    · intro m hm; have := htsc.2; simp [hm] at this; obtain ⟨h1, h2⟩ := this; exact ⟨h1, Nat.sub_le_iff_le_add.mpr h2⟩

/-- The WithClockSkewTolerance option never reaches the per-collection checks. -/
theorem triage_skew_irrelevant (h : Hardening) (p : Policy) (o : Options) (s : Step) (e : Envelope)
    (k : Nat) : triage h p { o with skew := k } s e = triage h p o s e := rfl

/-! ## Theorem 4: expiry and untrusted signers -/

theorem expired_fails_fixed (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy)
    (o : Options) (E : List Envelope) (hexp : p.expires + o.skew < o.now) :
    verifyFixed rego regoExt h p o E = false := by
  have : decide (o.now ≤ p.expires + o.skew) = false := by simp; omega
  simp [verifyFixed, admissible, this]

theorem expired_fails_asBuilt (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy)
    (o : Options) (E : List Envelope) (hexp : p.expires + o.skew < o.now) :
    verifyAsBuilt rego regoExt h p o E = false := by
  have : decide (o.now ≤ p.expires + o.skew) = false := by simp; omega
  simp [verifyAsBuilt, admissible, this]

/-- A signature whose credential no functionary of the step admits never makes
    a collection pass triage for that step. -/
theorem untrusted_never_triaged {h : Hardening} {p : Policy} {o : Options} {s : Step} {e : Envelope}
    (hu : ∀ sig ∈ e.sigs, ∀ f ∈ s.functionaries, fValidate h p.roots f sig.cred = false) :
    triage h p o s e = false := by
  cases ht : triage h p o s e
  · rfl
  · exfalso
    simp only [triage, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at ht
    obtain ⟨v, hv⟩ := List.exists_mem_of_ne_nil _ ht.1.2
    simp only [validFunctionaries, List.mem_filter, List.any_eq_true] at hv
    obtain ⟨hvmem, f, hf, hfv⟩ := hv
    obtain ⟨sig, hsig, hsv⟩ := mem_verifiers hvmem
    obtain ⟨_, hcred, _, _⟩ := sigVerifier_spec hsv
    rw [hcred, hu sig hsig f hf] at hfv
    cases hfv

/-- ...and a key not in the policy's keys never verifies at all. -/
theorem unknown_key_no_verifier {p : Policy} {sig : Sig} {k : KeyId} (hk : sig.cred = .key k)
    (hnot : p.keys.contains k = false) : sigVerifier p sig = none := by
  simp only [sigVerifier, hk]
  have : k ∉ p.keys := by simpa using hnot
  simp [this]

/-! ## Exported: `policy_sound` -/

/-- **policy_sound.** Under the Assumptions, a passing verify (fixed
    semantics) means: the policy was admissible (not expired, validated), and
    there is a joint fixed point `F` on which EVERY step has a survivor, and
    every survivor `e` of every step `s`
    * is named for `s` and anchored on a seed digest by a signed subject,
    * carries a signature by a credential some functionary of `s` admits,
      whose key holder signed it (and, for a certificate, whose root vouched
      for it and whose TSA-proven signing time is inside the certificate's
      validity window and not after the verify clock),
    * passed every required-attestation gate with Rego reading only survivors,
    * has, for every artifactsFrom edge, a surviving upstream partner.
    The master theorem consumes this statement. -/
theorem policy_sound {rego : Rego} {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} (A : Assumptions p o E) (hpass : verifyFixed rego regoExt h p o E = true) :
    o.now ≤ p.expires + o.skew ∧ validate p = true ∧
    ∃ α F, JointFixed rego h p o E α F ∧
      (∀ s ∈ p.steps, ∃ e, e ∈ F.get s.name) ∧
      (∀ s ∈ p.steps, ∀ e ∈ F.get s.name,
        Admitted rego h p o E α F s e ∧ SignerEvidence A h s e) ∧
      (∀ x ∈ p.externals, externalOk regoExt h p o E x = true) := by
  obtain ⟨hadm, α, F, hF, hne, hall, hext⟩ := verifyFixed_spec hpass
  simp only [admissible, Bool.and_eq_true, decide_eq_true_eq] at hadm
  refine ⟨hadm.1.1, hadm.2, α, F, hF, ?_, ?_, hext⟩
  · intro s hs; exact List.exists_mem_of_ne_nil _ (hne s hs)
  · intro s hs e he
    have ha := hall s hs e he
    exact ⟨ha, triage_signer A ha.inEvidence ha.triaged⟩

/-- Theorem 2 (no cross-step reuse): a survivor of step `s` is a collection
    whose SIGNED name is `s`'s name; with unique step names it can satisfy no
    other step. -/
theorem no_cross_step {rego : Rego} {regoExt : RegoExt} {h : Hardening} {p : Policy} {o : Options}
    {E : List Envelope} (hpass : verifyFixed rego regoExt h p o E = true) :
    ∃ α F, JointFixed rego h p o E α F ∧
      ∀ s ∈ p.steps, ∀ e ∈ F.get s.name, e.payload.name = s.name := by
  obtain ⟨_, α, F, hF, _, hall, _⟩ := verifyFixed_spec hpass
  exact ⟨α, F, hF, fun s hs e he => (hall s hs e he).named⟩

end CilockPolicy
