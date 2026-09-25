/-
  DsseIntoto.Verify: DSSE (t, n)-envelope verification.

  Spec: DSSE protocol v1.0.2 §Multi-signature Verification, plus the
  signing-time profile rookery layers on it for certificate signers (#5237):
  a certificate's key is trusted for a signature only at a time some
  configured TSA verified for THAT signature, or, when no TSA is configured
  and the caller opted in, at the verifier's clock.

  As built: attestation/dsse/verify.go `Envelope.Verify`.

  Model: signatures are ideal (a key verifies a signature iff it produced it
  over exactly that message); a certificate is its key, whether its chain
  reaches a configured root, and its validity window; a TSA verifier is the
  time it vouches for (the shape of timestamp.FakeTimestamper, which the
  differential test drives). Certificate path validation and RFC 3161 are
  modeled in subtrees/rookery/formal/signing-trust.

  Result: `verify_iff_spec`. The shipped verifier accepts exactly the spec's
  valid set, and the number it reports is the number of DISTINCT trusted keys
  that verified, so one key cannot count twice toward a threshold.
-/
import DsseIntoto.Pae

namespace DsseIntoto

abbrev Key := Nat
abbrev Time := Nat

/-- An ideal signature: the key that produced it and the message it covers. -/
structure Sig where
  signer : Key
  msg : Bytes
deriving DecidableEq, Repr

def sigVerifies (k : Key) (m : Bytes) (s : Sig) : Bool := s.signer == k && s.msg == m

/-- A parsed signing certificate. -/
structure Cert where
  key : Key
  chains : Bool   -- a non-CA leaf (#9876) whose path to a configured root validates (../signing-trust)
  nb : Time
  na : Time
deriving DecidableEq, Repr

/-- Go's x509 validity check is inclusive at both ends. -/
def Cert.validAt (c : Cert) (t : Time) : Bool := c.chains && c.nb ≤ t && t ≤ c.na

/-- One entry of `signatures`. `keyid` is carried and never read. -/
structure EnvSig where
  keyid : Nat
  sig : Sig
  cert : Option Cert
  timestamps : List Time
deriving DecidableEq, Repr

structure Envelope where
  payloadType : Bytes
  payload : Bytes
  sigs : List EnvSig
deriving DecidableEq, Repr

structure Opts where
  verifiers : List Key   -- raw public-key verifiers, each with parseable key material
  threshold : Int
  tsas : List Time       -- TSA verifiers: each verifies the token naming its time
  fallback : Bool        -- VerifyWithCurrentTimeFallback
  now : Time
deriving DecidableEq, Repr

def tsaVerify (T tok : Time) : Option Time := if tok = T then some T else none

/-! ### Spec -/

/-- A time at which the profile trusts a certificate for this signature. -/
def TrustedTime (o : Opts) (s : EnvSig) (t : Time) : Prop :=
  (o.tsas ≠ [] ∧ ∃ tok ∈ s.timestamps, ∃ T ∈ o.tsas, tsaVerify T tok = some t) ∨
  (o.tsas = [] ∧ o.fallback = true ∧ t = o.now)

/-- Key `k` is a trusted public key and signature `s` passes verification
    against it over message `m`. -/
-- spec: DSSE protocol §Multi-signature Verification "Verify SIGNATURE against PAE(UTF8(PAYLOAD_TYPE), SERIALIZED_BODY). Skip over if the verification fails. Add the accepted public key to the set ACCEPTED_KEYS."
-- spec: DSSE protocol §Signature Definition "KEYID ... MUST NOT be used for security decisions"
def TrustedFor (o : Opts) (m : Bytes) (s : EnvSig) (k : Key) : Prop :=
  sigVerifies k m s.sig = true ∧
  (k ∈ o.verifiers ∨ ∃ c, s.cert = some c ∧ c.key = k ∧ ∃ t, TrustedTime o s t ∧ c.validAt t = true)

def Accepted (o : Opts) (e : Envelope) (k : Key) : Prop :=
  ∃ s ∈ e.sigs, TrustedFor o (pae e.payloadType e.payload) s k

/-- The envelope is valid: at least t of the unique trusted keys accepted it. -/
-- spec: DSSE protocol §Multi-signature Verification "A (t, n)-ENVELOPE is valid if the enclosed signatures pass the verification against at least t of n unique trusted public keys where t is application-specific."
-- spec: DSSE protocol §Multi-signature Verification "Reject if the unique keys in ACCEPTED_KEYS is less than t."
def SpecValid (o : Opts) (e : Envelope) : Prop :=
  1 ≤ o.threshold ∧ ∃ ks : List Key, ks.Nodup ∧ (∀ k, k ∈ ks ↔ Accepted o e k) ∧ o.threshold ≤ ks.length

/-! ### As built -/

/-- `verifiedKeyIDs[id] = struct{}{}`: a set insert, keyed by the public key. -/
def ins (k : Key) (acc : List Key) : List Key := if k ∈ acc then acc else acc ++ [k]

/-- The key a certificate signature contributes, if it passes. -/
-- cite: attestation/dsse/verify.go:203-204 sha256:77839f1e0c0abea4
-- cite: attestation/dsse/verify.go:237-244 sha256:ec0b2f2eaf2dfcb9
-- cite: attestation/dsse/verify.go:263-265 sha256:2985c933b7a484e6
-- cite: attestation/dsse/verify.go:295-313 sha256:da8a333a5ce2f1b0
-- cite: attestation/dsse/verify.go:331-337 sha256:600eebabb9690009
-- cite: attestation/dsse/verify.go:383-392 sha256:faca2b53e5069c9b
-- cite: attestation/cryptoutil/x509.go:65-93 sha256:fe28db1e674c959d
def certPasses (o : Opts) (m : Bytes) (s : EnvSig) : Option Key :=
  match s.cert with
  | none => none
  | some c =>
    if o.tsas = [] then
      if o.fallback && c.validAt o.now && sigVerifies c.key m s.sig then some c.key else none
    else
      if o.tsas.any (fun T => s.timestamps.any (fun tok =>
          match tsaVerify T tok with
          | some t => c.validAt t && sigVerifies c.key m s.sig
          | none => false)) then some c.key else none

/-- The raw verifier loop, run for every signature whatever the cert path did. -/
-- cite: attestation/dsse/verify.go:354-366 sha256:d734c1f0bfba150e
def rawStep (o : Opts) (m : Bytes) (acc : List Key) (s : EnvSig) : List Key :=
  o.verifiers.foldl (fun acc k => if sigVerifies k m s.sig then ins k acc else acc) acc

def sigStep (o : Opts) (m : Bytes) (acc : List Key) (s : EnvSig) : List Key :=
  let acc := match certPasses o m s with
    | some k => ins k acc
    | none => acc
  rawStep o m acc s

-- cite: attestation/dsse/verify.go:164-167 sha256:99797e46b3dc3fca
def verifiedIds (o : Opts) (e : Envelope) : List Key :=
  e.sigs.foldl (sigStep o (preauthEncode e.payloadType e.payload)) []

inductive Verdict where
  | invalidThreshold
  | noSignatures
  | noMatching
  | thresholdNotMet (n : Nat)
  | ok (n : Nat)
deriving DecidableEq, Repr

-- cite: attestation/dsse/verify.go:157-159 sha256:4bafdf7fb04492b9
-- cite: attestation/dsse/verify.go:369-380 sha256:9a4befc24a4f8d60
def verify (o : Opts) (e : Envelope) : Verdict :=
  if o.threshold ≤ 0 then .invalidThreshold
  else if e.sigs = [] then .noSignatures
  else
    let n := (verifiedIds o e).length
    if n = 0 then .noMatching
    else if (n : Int) < o.threshold then .thresholdNotMet n
    else .ok n

/-! ### Proofs -/

theorem mem_ins (x k : Key) (acc : List Key) : x ∈ ins k acc ↔ x = k ∨ x ∈ acc := by
  unfold ins
  by_cases h : k ∈ acc
  · simp only [h, ↓reduceIte]
    constructor
    · intro hx; exact Or.inr hx
    · intro hx; cases hx with
      | inl hx => subst hx; exact h
      | inr hx => exact hx
  · simp only [h, ↓reduceIte, List.mem_append, List.mem_singleton]
    constructor
    · intro hx; cases hx with
      | inl hx => exact Or.inr hx
      | inr hx => exact Or.inl hx
    · intro hx; cases hx with
      | inl hx => exact Or.inr hx
      | inr hx => exact Or.inl hx

theorem nodup_ins (k : Key) (acc : List Key) (h : acc.Nodup) : (ins k acc).Nodup := by
  unfold ins
  by_cases hk : k ∈ acc
  · simp only [hk, ↓reduceIte]; exact h
  · simp only [hk, ↓reduceIte]
    rw [List.nodup_append]
    refine ⟨h, by simp, ?_⟩
    intro a ha b hb hab
    simp at hb; subst hb; subst hab; exact hk ha

theorem mem_condFold (p : Key → Bool) (l acc : List Key) (x : Key) :
    x ∈ l.foldl (fun acc k => if p k then ins k acc else acc) acc ↔ x ∈ acc ∨ (x ∈ l ∧ p x = true) := by
  induction l generalizing acc with
  | nil => simp
  | cons y ys ih =>
    simp only [List.foldl_cons]
    rw [ih]
    by_cases hy : p y = true
    · simp only [hy, ↓reduceIte, mem_ins, List.mem_cons]
      constructor
      · intro h
        rcases h with (h | h) | ⟨h1, h2⟩
        · exact Or.inr ⟨Or.inl h, by subst h; exact hy⟩
        · exact Or.inl h
        · exact Or.inr ⟨Or.inr h1, h2⟩
      · intro h
        rcases h with h | ⟨h1 | h1, h2⟩
        · exact Or.inl (Or.inr h)
        · exact Or.inl (Or.inl h1)
        · exact Or.inr ⟨h1, h2⟩
    · have hy' : p y = false := by simpa using hy
      simp only [hy', Bool.false_eq_true, ↓reduceIte, List.mem_cons]
      constructor
      · intro h
        rcases h with h | ⟨h1, h2⟩
        · exact Or.inl h
        · exact Or.inr ⟨Or.inr h1, h2⟩
      · intro h
        rcases h with h | ⟨h1 | h1, h2⟩
        · exact Or.inl h
        · subst h1; rw [hy'] at h2; exact absurd h2 (by simp)
        · exact Or.inr ⟨h1, h2⟩

theorem nodup_condFold (p : Key → Bool) (l acc : List Key) (h : acc.Nodup) :
    (l.foldl (fun acc k => if p k then ins k acc else acc) acc).Nodup := by
  induction l generalizing acc with
  | nil => simpa using h
  | cons y ys ih =>
    simp only [List.foldl_cons]
    apply ih
    by_cases hy : p y = true
    · simp only [hy, ↓reduceIte]; exact nodup_ins y acc h
    · have hy' : p y = false := by simpa using hy
      simp only [hy', Bool.false_eq_true, ↓reduceIte]; exact h

theorem mem_sigStep (o : Opts) (m : Bytes) (acc : List Key) (s : EnvSig) (x : Key) :
    x ∈ sigStep o m acc s ↔ x ∈ acc ∨ certPasses o m s = some x ∨ (x ∈ o.verifiers ∧ sigVerifies x m s.sig = true) := by
  unfold sigStep rawStep
  rw [mem_condFold]
  cases hc : certPasses o m s with
  | none => simp
  | some k =>
    simp only [mem_ins, Option.some.injEq]
    constructor
    · intro h
      rcases h with (h | h) | h
      · exact Or.inr (Or.inl h.symm)
      · exact Or.inl h
      · exact Or.inr (Or.inr h)
    · intro h
      rcases h with h | h | h
      · exact Or.inl (Or.inr h)
      · exact Or.inl (Or.inl h.symm)
      · exact Or.inr h

theorem nodup_sigStep (o : Opts) (m : Bytes) (acc : List Key) (s : EnvSig) (h : acc.Nodup) :
    (sigStep o m acc s).Nodup := by
  unfold sigStep rawStep
  apply nodup_condFold
  cases certPasses o m s with
  | none => exact h
  | some k => exact nodup_ins k acc h

theorem mem_sigsFold (o : Opts) (m : Bytes) (sigs : List EnvSig) (acc : List Key) (x : Key) :
    x ∈ sigs.foldl (sigStep o m) acc ↔ x ∈ acc ∨ ∃ s ∈ sigs,
      certPasses o m s = some x ∨ (x ∈ o.verifiers ∧ sigVerifies x m s.sig = true) := by
  induction sigs generalizing acc with
  | nil => simp
  | cons s ss ih =>
    simp only [List.foldl_cons]
    rw [ih, mem_sigStep]
    constructor
    · intro h
      rcases h with (h | h | h) | ⟨s', hs', h'⟩
      · exact Or.inl h
      · exact Or.inr ⟨s, by simp, Or.inl h⟩
      · exact Or.inr ⟨s, by simp, Or.inr h⟩
      · exact Or.inr ⟨s', by simp [hs'], h'⟩
    · intro h
      rcases h with h | ⟨s', hs', h'⟩
      · exact Or.inl (Or.inl h)
      · simp at hs'
        rcases hs' with hs' | hs'
        · subst hs'
          rcases h' with h' | h'
          · exact Or.inl (Or.inr (Or.inl h'))
          · exact Or.inl (Or.inr (Or.inr h'))
        · exact Or.inr ⟨s', hs', h'⟩

theorem nodup_verifiedIds (o : Opts) (e : Envelope) : (verifiedIds o e).Nodup := by
  unfold verifiedIds
  have : ∀ (sigs : List EnvSig) (acc : List Key), acc.Nodup →
      (sigs.foldl (sigStep o (preauthEncode e.payloadType e.payload)) acc).Nodup := by
    intro sigs
    induction sigs with
    | nil => intro acc h; simpa using h
    | cons s ss ih => intro acc h; simp only [List.foldl_cons]; exact ih _ (nodup_sigStep _ _ _ _ h)
  exact this e.sigs [] List.nodup_nil

/-- The certificate branch passes exactly when the profile trusts the
    certificate's key at some trusted time AND the key verifies. -/
theorem certPasses_iff (o : Opts) (m : Bytes) (s : EnvSig) (k : Key) :
    certPasses o m s = some k ↔ sigVerifies k m s.sig = true ∧
      ∃ c, s.cert = some c ∧ c.key = k ∧ ∃ t, TrustedTime o s t ∧ c.validAt t = true := by
  unfold certPasses
  cases hc : s.cert with
  | none => simp
  | some c =>
    simp only [Option.some.injEq, exists_eq_left']
    by_cases ht : o.tsas = []
    · simp only [ht, ↓reduceIte]
      constructor
      · intro h
        by_cases hb : (o.fallback && c.validAt o.now && sigVerifies c.key m s.sig) = true
        · simp only [hb, ↓reduceIte, Option.some.injEq] at h
          subst h
          simp only [Bool.and_eq_true] at hb
          obtain ⟨⟨hf, hva⟩, hv⟩ := hb
          exact ⟨hv, rfl, o.now, Or.inr ⟨ht, hf, rfl⟩, hva⟩
        · simp only [hb, Bool.false_eq_true, ↓reduceIte] at h
          simp at h
      · rintro ⟨hv, rfl, t, htt, hva⟩
        rcases htt with ⟨hne, _⟩ | ⟨_, hf, rfl⟩
        · exact absurd ht hne
        · have hb : (o.fallback && c.validAt o.now && sigVerifies c.key m s.sig) = true := by
            simp only [Bool.and_eq_true]; exact ⟨⟨hf, hva⟩, hv⟩
          simp only [hb, ↓reduceIte]
    · simp only [ht, ↓reduceIte]
      constructor
      · intro h
        by_cases hb : (o.tsas.any (fun T => s.timestamps.any (fun tok =>
            match tsaVerify T tok with
            | some t => c.validAt t && sigVerifies c.key m s.sig
            | none => false))) = true
        · simp only [hb, ↓reduceIte, Option.some.injEq] at h
          subst h
          simp only [List.any_eq_true] at hb
          obtain ⟨T, hT, tok, htok, hm⟩ := hb
          by_cases he : tok = T
          · subst he
            simp only [tsaVerify, ↓reduceIte, Bool.and_eq_true] at hm
            exact ⟨hm.2, rfl, tok, Or.inl ⟨ht, tok, htok, tok, hT, by simp [tsaVerify]⟩, hm.1⟩
          · simp [tsaVerify, he] at hm
        · simp only [hb, Bool.false_eq_true, ↓reduceIte] at h
          simp at h
      · rintro ⟨hv, rfl, t, htt, hva⟩
        rcases htt with ⟨_, tok, htok, T, hT, hm⟩ | ⟨hnil, _⟩
        · have hb : (o.tsas.any (fun T => s.timestamps.any (fun tok =>
              match tsaVerify T tok with
              | some t => c.validAt t && sigVerifies c.key m s.sig
              | none => false))) = true := by
            simp only [List.any_eq_true]
            refine ⟨T, hT, tok, htok, ?_⟩
            rw [hm]; simp [hva, hv]
          simp only [hb, ↓reduceIte]
        · exact absurd hnil ht

theorem mem_verifiedIds (o : Opts) (e : Envelope) (k : Key) :
    k ∈ verifiedIds o e ↔ Accepted o e k := by
  unfold verifiedIds Accepted
  rw [mem_sigsFold, preauthEncode_eq]
  simp only [List.not_mem_nil, false_or]
  constructor
  · rintro ⟨s, hs, h⟩
    refine ⟨s, hs, ?_⟩
    rcases h with h | ⟨hk, hv⟩
    · have := (certPasses_iff o _ s k).mp h
      exact ⟨this.1, Or.inr this.2⟩
    · exact ⟨hv, Or.inl hk⟩
  · rintro ⟨s, hs, hv, h⟩
    refine ⟨s, hs, ?_⟩
    rcases h with hk | hc
    · exact Or.inr ⟨hk, hv⟩
    · exact Or.inl ((certPasses_iff o _ s k).mpr ⟨hv, hc⟩)

/-- Two duplicate-free lists with the same members have the same length. -/
theorem length_eq_of_same_members {l₁ l₂ : List Key} (d₁ : l₁.Nodup) (d₂ : l₂.Nodup)
    (h : ∀ k, k ∈ l₁ ↔ k ∈ l₂) : l₁.length = l₂.length :=
  ((List.perm_ext_iff_of_nodup d₁ d₂).mpr h).length_eq

/-- The verifier accepts exactly the spec's valid set, and the count it
    reports is the number of distinct accepted keys. -/
theorem verify_iff_spec (o : Opts) (e : Envelope) :
    (∃ n, verify o e = .ok n) ↔ SpecValid o e := by
  unfold verify SpecValid
  constructor
  · rintro ⟨n, hn⟩
    by_cases h0 : o.threshold ≤ 0
    · simp [h0] at hn
    · by_cases hs : e.sigs = []
      · simp [h0, hs] at hn
      · simp only [h0, hs, ↓reduceIte] at hn
        by_cases hz : (verifiedIds o e).length = 0
        · simp [hz] at hn
        · simp only [hz, ↓reduceIte] at hn
          by_cases hlt : ((verifiedIds o e).length : Int) < o.threshold
          · simp [hlt] at hn
          · refine ⟨by omega, verifiedIds o e, nodup_verifiedIds o e, mem_verifiedIds o e, by omega⟩
  · rintro ⟨h1, ks, hnd, hmem, hle⟩
    have hlen : ks.length = (verifiedIds o e).length :=
      length_eq_of_same_members hnd (nodup_verifiedIds o e)
        (fun k => by rw [hmem, mem_verifiedIds])
    have h0 : ¬ o.threshold ≤ 0 := by omega
    have hs : e.sigs ≠ [] := by
      intro hs
      have hpos : 0 < ks.length := by omega
      obtain ⟨k, hk⟩ : ∃ k, k ∈ ks := by
        cases ks with
        | nil => simp at hpos
        | cons k _ => exact ⟨k, by simp⟩
      obtain ⟨s, hsm, _⟩ := (hmem k).mp hk
      rw [hs] at hsm; simp at hsm
    have hz : ¬ (verifiedIds o e).length = 0 := by omega
    have hlt : ¬ ((verifiedIds o e).length : Int) < o.threshold := by omega
    exact ⟨(verifiedIds o e).length, by simp [h0, hs, hz, hlt]⟩

/-- A duplicated signature, or the same key presented as both a raw verifier
    and a certificate, never counts twice. -/
theorem verify_counts_distinct (o : Opts) (e : Envelope) (n : Nat) (h : verify o e = .ok n) :
    ∃ ks : List Key, ks.Nodup ∧ (∀ k, k ∈ ks ↔ Accepted o e k) ∧ ks.length = n := by
  refine ⟨verifiedIds o e, nodup_verifiedIds o e, mem_verifiedIds o e, ?_⟩
  unfold verify at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · simp only at h
      split at h
      · simp at h
      · split at h
        · simp at h
        · simp at h; exact h

/-- KEYID is never read: rewriting every keyid leaves the verdict unchanged. -/
theorem verify_ignores_keyid (o : Opts) (e : Envelope) (f : Nat → Nat) :
    verify o { e with sigs := e.sigs.map (fun s => { s with keyid := f s.keyid }) } = verify o e := by
  unfold verify verifiedIds
  simp only [List.map_eq_nil_iff]
  have : ∀ (sigs : List EnvSig) (acc : List Key),
      (sigs.map (fun s => { s with keyid := f s.keyid })).foldl
        (sigStep o (preauthEncode e.payloadType e.payload)) acc =
      sigs.foldl (sigStep o (preauthEncode e.payloadType e.payload)) acc := by
    intro sigs
    induction sigs with
    | nil => intro acc; rfl
    | cons s ss ih => intro acc; simp only [List.map_cons, List.foldl_cons]; rw [ih]; rfl
  rw [this]

end DsseIntoto
