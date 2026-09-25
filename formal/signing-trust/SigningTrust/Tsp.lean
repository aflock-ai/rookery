/-
  SigningTrust.Tsp: RFC 3161 time-stamp token verification (with the RFC 5816
  ESSCertIDv2 update), and how dsse/verify.go uses the verified time.

  As built: attestation/timestamp/tsp.go `TSPVerifier.Verify`, which reads the
  token through digitorus/timestamp and digitorus/pkcs7. Neither library reads
  the ESS signing-certificate attributes (id-aa-signingCertificate
  1.2.840.113549.1.9.16.2.12, id-aa-signingCertificateV2 ...2.47): they are
  written by `timestamp.generateSignedData` and never checked on the way back.

  Model: a token is its message-imprint algorithm and whether the imprint
  matches the signed data, whether the CMS signature verifies, the TSTInfo
  genTime, the optional PKCS#9 signingTime, the signer certificate and its
  root, and which ESS attribute it carries. The signer chain is validated by
  the same Go path semantics as SigningTrust.X509, for timeStamping.
-/
import SigningTrust.X509

namespace SigningTrust

inductive Alg where
  | sha1 | sha256 | sha384 | sha512
deriving DecidableEq, Repr

/-- The ESS attribute a token carries, and whether it names the signer. -/
inductive Ess where
  | none          -- neither attribute
  | v2            -- SigningCertificateV2, certHash and issuerSerial match the signer
  | v2BadHash     -- SigningCertificateV2 naming another certificate
  | v2BadSerial   -- right certHash, issuerSerial naming another serial
  | v1            -- SigningCertificate (SHA-1 ESSCertID) matching the signer
  | v1BadHash
deriving DecidableEq, Repr

structure Token where
  alg : Alg
  imprintOk : Bool
  sigOk : Bool
  genTime : Time             -- 0: the zero time
  signingTime : Option Time
  leaf : Cert                -- the signer certificate the token embeds
  root : Cert                -- its issuer
  ess : Ess
deriving DecidableEq, Repr

def Alg.sha2 : Alg → Bool
  | .sha1 => false
  | _ => true

/-- Go's `x509.VerifyOptions.CurrentTime`: the zero time means "now". -/
def eff (cur now : Time) : Time := if cur = 0 then now else cur

def Token.soleTimeStamping (tok : Token) : Bool := tok.leaf.eku == .timeStamping

def Token.signingTimeOk (tok : Token) : Bool :=
  match tok.signingTime with
  | none => true
  | some s => tok.leaf.validAt s

def tsaChain (anchors : List Nat) (tok : Token) (t : Time) : Bool :=
  match choosePath anchors tok.leaf [tok.root] with
  | none => false
  | some p => goVerify p t .timeStamping

/-- `TSPVerifier.Verify` before the signer-keyUsage and ESS fixes (#9917):
    the time it returns, or a refusal. The checks it names are still the
    code's; the fixed verifiers below add theirs in front of it. -/
def tspVerify (anchors : List Nat) (tok : Token) (now : Time) : Option Time :=
  if !tok.alg.sha2 then none
  else if !tok.imprintOk then none
  else if !tok.soleTimeStamping then none
  else if tok.genTime = 0 then none
  else if tok.signingTimeOk && tok.sigOk && tsaChain anchors tok (eff tok.genTime now) then some tok.genTime
  else none

def Ess.identifiesSigner : Ess → Bool
  | .v2 | .v1 => true
  | _ => false

/-- As it must be: the ESS attribute must name the signer, and the signer's
    keyUsage, when present, must permit signing. -/
def tspVerifyReq (anchors : List Nat) (tok : Token) (now : Time) : Option Time :=
  if tok.ess.identifiesSigner && tok.leaf.kuSigns then tspVerify anchors tok now else none

/-- As built now: the signer keyUsage fix, without the ESS fix. -/
-- cite: attestation/timestamp/tsp.go:240-268 sha256:e8c158c268bc68cd
-- cite: attestation/timestamp/tsp.go:289-314 sha256:9c14caae8846cf2d
-- cite: attestation/timestamp/tsp.go:336-359 sha256:03d2f29ca3058550
-- cite: attestation/timestamp/tsp.go:362-384 sha256:9c0e7cd843e8b125
-- cite: attestation/cryptoutil/x509_keyusage.go:27-54 sha256:8c93d0ffdb62bcf4
def tspVerifyKU (anchors : List Nat) (tok : Token) (now : Time) : Option Time :=
  if tok.leaf.kuSigns then tspVerify anchors tok now else none

/-! ### Spec -/

-- spec: RFC 3161 §2.4.2 "messageImprint ... The hash algorithm indicated in the hashAlgorithm field SHOULD be a known hash algorithm (one-way and collision resistant)."
-- spec: RFC 3161 §2.3 "The TSA MUST sign each time-stamp message with a key reserved specifically for that purpose. ... the corresponding certificate MUST contain only one instance of the extended key usage field extension ... with KeyPurposeID having value: id-kp-timeStamping."
-- spec: RFC 3161 §2.4.1 "The ESS SigningCertificate attribute MUST be included ... in order to identify the certificate of the TSA"
-- spec: RFC 5816 §2.2.1 "the ESSCertIDv2 ... [or] ESSCertID ... MUST identify the TSA's signing certificate"
-- spec: RFC 3161 §2.4.2 "genTime is the time at which the time-stamp token has been created by the TSA."
-- spec: RFC 5280 §4.2.1.3 digitalSignature / nonRepudiation (contentCommitment) for a key that verifies signatures
-- spec: profile (#5747 TS4): the TSA chain is valid at genTime, and so is any PKCS#9 signingTime
def tspSpec (anchors : List Nat) (tok : Token) : Prop :=
  tok.alg.sha2 = true ∧ tok.imprintOk = true ∧ tok.sigOk = true ∧ tok.soleTimeStamping = true ∧
  tok.ess.identifiesSigner = true ∧ tok.leaf.kuSigns = true ∧ tok.genTime ≠ 0 ∧
  tok.signingTimeOk = true ∧ tsaChain anchors tok tok.genTime = true

/-! ### Proofs -/

theorem eff_ne_zero (g now : Time) (h : g ≠ 0) : eff g now = g := by
  unfold eff; simp [h]

/-- The verified time is the token's genTime. -/
theorem tspVerify_returns_genTime (A : List Nat) (tok : Token) (now g : Time)
    (h : tspVerify A tok now = some g) : g = tok.genTime ∧ g ≠ 0 := by
  unfold tspVerify at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  rename_i hz
  split at h
  · simp at h; exact ⟨h.symm, by rw [← h]; exact hz⟩
  · simp at h

/-- Wall-clock time never decides a token: the chain is built at genTime, and
    the zero genTime (which Go would read as "now") is refused first. -/
theorem tspVerify_now_irrelevant (A : List Nat) (tok : Token) (now now' : Time) :
    tspVerify A tok now = tspVerify A tok now' := by
  unfold tspVerify
  by_cases hz : tok.genTime = 0
  · simp [hz]
  · simp [hz, eff_ne_zero]

theorem tspVerifyReq_now_irrelevant (A : List Nat) (tok : Token) (now now' : Time) :
    tspVerifyReq A tok now = tspVerifyReq A tok now' := by
  unfold tspVerifyReq; rw [tspVerify_now_irrelevant A tok now now']

/-- The fixed verifier accepts exactly the spec's tokens, and returns genTime. -/
theorem tspVerifyReq_iff (A : List Nat) (tok : Token) (now : Time) :
    tspVerifyReq A tok now = some tok.genTime ↔ tspSpec A tok := by
  unfold tspVerifyReq tspVerify tspSpec
  by_cases hz : tok.genTime = 0
  · simp [hz]
  · simp only [eff_ne_zero _ _ hz]
    cases h1 : tok.ess.identifiesSigner <;> cases h2 : tok.leaf.kuSigns <;> cases h3 : tok.alg.sha2 <;>
      cases h4 : tok.imprintOk <;> cases h5 : tok.soleTimeStamping <;> cases h6 : tok.signingTimeOk <;>
      cases h7 : tok.sigOk <;> cases h8 : tsaChain A tok tok.genTime <;> simp [hz]

/-- How dsse/verify.go uses a token: the signing certificate's path is
    checked at the time the TSA verified. -/
-- cite: attestation/dsse/verify.go:295-313 sha256:da8a333a5ce2f1b0
-- cite: attestation/dsse/verify.go:383-392 sha256:faca2b53e5069c9b
def dsseCertOk (tsaAnchors : List Nat) (tok : Token) (signer : Path) (now : Time) : Bool :=
  match tspVerify tsaAnchors tok now with
  | none => false
  | some g => x509Verify signer (eff g now)

/-- Verify time IS the timestamp time: a timestamped certificate signature's
    verdict does not depend on the verifier's clock at all. -/
theorem dsseCertOk_now_irrelevant (A : List Nat) (tok : Token) (signer : Path) (now now' : Time) :
    dsseCertOk A tok signer now = dsseCertOk A tok signer now' := by
  unfold dsseCertOk
  rw [tspVerify_now_irrelevant A tok now now']
  cases h : tspVerify A tok now' with
  | none => rfl
  | some g =>
    have := (tspVerify_returns_genTime A tok now' g h).2
    simp only [eff_ne_zero _ _ this]

theorem dsseCertOk_at_genTime (A : List Nat) (tok : Token) (signer : Path) (now : Time)
    (h : dsseCertOk A tok signer now = true) : x509Verify signer tok.genTime = true := by
  unfold dsseCertOk at h
  cases hv : tspVerify A tok now with
  | none => rw [hv] at h; simp at h
  | some g =>
    rw [hv] at h
    obtain ⟨hg, hz⟩ := tspVerify_returns_genTime A tok now g hv
    simp only at h
    rw [eff_ne_zero _ _ hz] at h
    rw [← hg]; exact h

/-! ### TSA re-issue (#9843) -/

theorem choosePath_pair (A : List Nat) (leaf root : Cert) :
    choosePath A leaf [root] =
      if leaf.id ∈ A then some ⟨leaf, [], none⟩
      else if root.id ∈ A then some ⟨leaf, [], some root⟩ else none := by
  unfold choosePath choosePath.go
  by_cases h1 : leaf.id ∈ A
  · simp [h1]
  · by_cases h2 : root.id ∈ A
    · simp [h1, h2]
    · simp [h1, h2, choosePath.go]

/-- A re-issued TSA certificate (same key, new window) changes nothing for a
    token already minted: the token carries its own certificate and is
    judged at its own genTime. Any later trust configuration that still
    anchors the TSA's ROOT keeps accepting it, at any wall-clock time, and
    whether or not the configuration also names the old or the new leaf. -/
theorem reissue_keeps_verifying (A A' : List Nat) (tok : Token) (now now' g : Time)
    (hroot : tok.root.id ∈ A) (hleaf : tok.leaf.id ∉ A) (hroot' : tok.root.id ∈ A')
    (h : tspVerify A tok now = some g) : tspVerify A' tok now' = some g := by
  rw [tspVerify_now_irrelevant A' tok now' now]
  unfold tspVerify tsaChain at *
  rw [choosePath_pair] at *
  simp only [hleaf, hroot, ↓reduceIte] at h
  by_cases hl' : tok.leaf.id ∈ A'
  · simp only [hl', ↓reduceIte]
    revert h
    simp only [goVerify, Path.issuers, Option.toList, List.all_cons, List.all_nil,
      List.nil_append, List.append_nil, List.zipIdx_cons, List.zipIdx_nil]
    repeat' split
    all_goals grind
  · simp only [hl', hroot', ↓reduceIte]; exact h

end SigningTrust
