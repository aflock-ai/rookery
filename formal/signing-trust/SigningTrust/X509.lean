/-
  SigningTrust.X509: the RFC 5280 path-validation subset a DSSE signing
  certificate must pass, and what the shipped verifier checks.

  Spec: RFC 5280 §6.1 (basic path validation) restricted to what rookery
  relies on, plus the signing profile rookery layers on it: a signing leaf is
  an end-entity certificate for code signing (the Fulcio / CA/B code-signing
  profile; RFC 5280 is silent on a CA signing data directly, #9842) whose
  keyUsage, when present, asserts digitalSignature (RFC 5280 §4.2.1.3).

  As built: attestation/cryptoutil/x509.go `X509Verifier.Verify`, which is
  `checkNotCA` (#9876) followed by Go's `x509.Certificate.Verify` with
  KeyUsages = [codeSigning]. The Go semantics modeled here are those of
  go1.26.6 crypto/x509 (outside this repository, so not hash-cited):
  `isValid` (verify.go:443-510) checks unhandled critical extensions, the
  validity window at CurrentTime (inclusive), cA on intermediates, and
  pathLen on every issuer; `CheckSignatureFrom` (x509.go:928-941) requires
  every issuer, the anchor included, to be a v3 CA whose keyUsage (when
  present) asserts keyCertSign; `checkChainForKeyUsage` (verify.go:981-1030)
  requires every certificate in the chain that lists EKUs to permit the
  requested purpose. Go ignores the LEAF's keyUsage bits entirely
  (verify.go:478-494, the "KeyUsage status flags are ignored" comment).

  A path is the chain Go builds: the leaf, the intermediates, and the first
  certificate from the trusted pool (the anchor). A leaf that is itself in
  the pool is its own anchor (`anchor = none`).
-/
namespace SigningTrust

abbrev Time := Nat

/-- The extendedKeyUsage extension: absent, or the purposes it lists. -/
inductive EKU where
  | none | codeSigning | timeStamping | serverAuth | any | codeAndServer | tsAndServer
deriving DecidableEq, Repr

inductive Purpose where
  | codeSigning | timeStamping
deriving DecidableEq, Repr

/-- Does the extension permit the purpose? An absent extension does. -/
-- spec: RFC 5280 §4.2.1.12 "If the extension is present, then the certificate MUST only be used for one of the purposes indicated."
def EKU.permits : EKU → Purpose → Bool
  | .none, _ => true
  | .any, _ => true
  | .codeSigning, p => p == .codeSigning
  | .timeStamping, p => p == .timeStamping
  | .serverAuth, _ => false
  | .codeAndServer, p => p == .codeSigning
  | .tsAndServer, p => p == .timeStamping

/-- A present keyUsage extension. A value with no modeled bit set asserts
    some other bit (keyEncipherment), as a real extension must. -/
structure KU where
  digitalSignature : Bool
  contentCommitment : Bool
  keyCertSign : Bool
deriving DecidableEq, Repr

structure Cert where
  id : Nat
  bc : Bool                 -- basicConstraints present
  ca : Bool                 -- its cA boolean
  pathLen : Option Nat      -- pathLenConstraint (only meaningful with bc)
  ku : Option KU            -- none: no keyUsage extension
  eku : EKU
  nb : Time
  na : Time
  crit : Bool               -- carries a critical extension nobody recognizes
deriving DecidableEq, Repr

def Cert.isCA (c : Cert) : Bool := c.bc && c.ca
def Cert.validAt (c : Cert) (t : Time) : Bool := decide (c.nb ≤ t) && decide (t ≤ c.na)
def Cert.kuCertSign (c : Cert) : Bool := match c.ku with | none => true | some k => k.keyCertSign
/-- A non-CA certificate asserting keyCertSign is misissued. -/
-- spec: RFC 5280 §4.2.1.9 "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension MUST also be asserted."
def Cert.noCAUsage (c : Cert) : Bool := match c.ku with | none => true | some k => !k.keyCertSign || c.isCA
/-- A DSSE signing leaf's keyUsage permits signing: digitalSignature, and no CA usage. -/
def Cert.kuDigSig (c : Cert) : Bool :=
  c.noCAUsage && match c.ku with | none => true | some k => k.digitalSignature
/-- A TSA signer's keyUsage permits signing: digitalSignature or contentCommitment, and no CA usage. -/
def Cert.kuSigns (c : Cert) : Bool :=
  c.noCAUsage && match c.ku with | none => true | some k => k.digitalSignature || k.contentCommitment
/-- pathLenConstraint `p` of a certificate with `below` intermediates under it. -/
def Cert.plOk (c : Cert) (below : Nat) : Bool :=
  match c.bc, c.pathLen with
  | true, some p => decide (below ≤ p)
  | _, _ => true

structure Path where
  leaf : Cert
  cas : List Cert           -- intermediates, leaf side first
  anchor : Option Cert      -- none: the leaf itself is in the trusted pool
deriving DecidableEq, Repr

def Path.issuers (p : Path) : List Cert := p.cas ++ p.anchor.toList

/-- The path Go builds from a linear chain: cut at the first certificate
    that is in the trusted pool. -/
def choosePath (anchors : List Nat) (leaf : Cert) (rest : List Cert) : Option Path :=
  if leaf.id ∈ anchors then some ⟨leaf, [], none⟩ else go [] rest
where
  go (acc : List Cert) : List Cert → Option Path
    | [] => none
    | c :: cs => if c.id ∈ anchors then some ⟨leaf, acc, some c⟩ else go (acc ++ [c]) cs

/-! ### As built -/

/-- Go's `x509.Certificate.Verify` on a built path. -/
def goVerify (p : Path) (t : Time) (purpose : Purpose) : Bool :=
  (p.leaf :: p.issuers).all (fun c => !c.crit && c.validAt t) &&
  (p.issuers.zipIdx.all (fun (c, j) => c.isCA && c.kuCertSign && c.plOk j)) &&
  (p.leaf :: p.issuers).all (fun c => c.eku.permits purpose)

/-- `X509Verifier.Verify` before the keyUsage fix (#9917): refuse a CA leaf
    (#9876), then Go's chain check for codeSigning. The signature itself is
    a separate, ideal check. Kept to state what the fix changed. -/
def x509Verify (p : Path) (t : Time) : Bool :=
  !p.leaf.isCA && goVerify p t .codeSigning

/-- `X509Verifier.Verify` as built now: also refuse a leaf whose keyUsage
    does not assert digitalSignature or asserts a CA usage. -/
-- cite: attestation/cryptoutil/x509.go:58-72 sha256:d9d3f0fd484ca053
-- cite: attestation/cryptoutil/x509.go:74-95 sha256:03ba16c6e338f72a
-- cite: attestation/cryptoutil/x509_keyusage.go:27-54 sha256:8c93d0ffdb62bcf4
def x509VerifyReq (p : Path) (t : Time) : Bool :=
  x509Verify p t && p.leaf.kuDigSig

/-! ### Spec -/

/-- RFC 5280 §6.1 over the certificates of the path (the anchor excluded:
    it is trust-anchor input, not a path certificate), plus the signing
    profile on the leaf. -/
-- spec: RFC 5280 §6.1.3 (a)(2) "The certificate validity period includes the current time."
-- spec: RFC 5280 §6.1.4 (k) "verify that the certificate is a CA certificate (as specified in a basicConstraints extension or as verified out-of-band)."
-- spec: RFC 5280 §6.1.4 (l) "If the certificate was not self-issued, verify that max_path_length is greater than zero and decrement max_path_length by 1."
-- spec: RFC 5280 §6.1.4 (m) "If pathLenConstraint is present in the certificate and is less than max_path_length, set max_path_length to the value of pathLenConstraint."
-- spec: RFC 5280 §6.1.4 (n) "If a key usage extension is present, verify that the keyCertSign bit is set."
-- spec: RFC 5280 §6.1.4 (o) "Recognize and process any other critical extension present in the certificate."
-- spec: RFC 5280 §4.2 "A certificate-using system MUST reject the certificate if it encounters a critical extension it does not recognize"
-- spec: RFC 5280 §4.2.1.12 extKeyUsage "id-kp-codeSigning ... Signing of downloadable executable code"
-- spec: RFC 5280 §4.2.1.3 "The digitalSignature bit is asserted when the subject public key is used for verifying digital signatures, other than signatures on certificates (bit 5) and CRLs (bit 6)"
-- spec: #9842 signing profile: a CA certificate is never a signing leaf (Fulcio issues end-entity code-signing leaves; RFC 5280 is silent)
def specPath (p : Path) (t : Time) : Bool :=
  (p.leaf :: p.cas).all (fun c => !c.crit && c.validAt t) &&
  (p.cas.zipIdx.all (fun (c, j) => c.isCA && c.kuCertSign && c.plOk j)) &&
  p.leaf.eku.permits .codeSigning &&
  !p.leaf.isCA && p.leaf.kuDigSig

/-- What Go additionally demands of the anchor. RFC 5280 takes the anchor as
    input and checks none of this; Go refuses more. -/
def anchorStrict (p : Path) (t : Time) : Bool :=
  match p.anchor with
  | none => true
  | some a => !a.crit && a.validAt t && a.isCA && a.kuCertSign && a.plOk p.cas.length

/-- Go's EKU nesting: every CA that lists EKUs must list the purpose too.
    RFC 5280 does not define EKU on CA certificates; Go refuses more. -/
def nestedEku (p : Path) (purpose : Purpose) : Bool := p.issuers.all (fun c => c.eku.permits purpose)

/-! ### Proofs -/

theorem zipIdx_append_single (l : List Cert) (a : Cert) :
    (l ++ [a]).zipIdx = l.zipIdx ++ [(a, l.length)] := by
  simp [List.zipIdx_append]

/-- The fixed verifier is exactly the RFC 5280 subset with the signing
    profile, plus Go's two conservative extras (anchor checks and EKU
    nesting), which only ever refuse more. -/
theorem x509VerifyReq_iff (p : Path) (t : Time) :
    x509VerifyReq p t = (specPath p t && anchorStrict p t && nestedEku p .codeSigning) := by
  cases p with
  | mk leaf cas anchor =>
    cases anchor with
    | none =>
      simp only [x509VerifyReq, x509Verify, goVerify, specPath, anchorStrict, nestedEku, Path.issuers,
        Option.toList, List.append_nil, List.all_cons]
      cases leaf.isCA <;> cases leaf.kuDigSig <;> cases leaf.crit <;> cases leaf.validAt t <;>
        cases leaf.eku.permits .codeSigning <;> simp [Bool.and_comm]
    | some a =>
      simp only [x509VerifyReq, x509Verify, goVerify, specPath, anchorStrict, nestedEku, Path.issuers,
        Option.toList, List.all_cons, List.all_append, zipIdx_append_single, List.all_nil]
      rw [Bool.eq_iff_iff]
      simp only [Bool.and_eq_true]
      grind

/-- #9842 holds as built: no path whose leaf is a CA verifies. -/
theorem x509Verify_never_ca_leaf (p : Path) (t : Time) (h : x509Verify p t = true) : p.leaf.isCA = false := by
  unfold x509Verify at h
  simp only [Bool.and_eq_true, Bool.not_eq_true'] at h
  exact h.1

theorem x509VerifyReq_never_ca_leaf (p : Path) (t : Time) (h : x509VerifyReq p t = true) : p.leaf.isCA = false := by
  unfold x509VerifyReq at h
  simp only [Bool.and_eq_true] at h
  exact x509Verify_never_ca_leaf p t h.1

theorem x509VerifyReq_leaf_signs (p : Path) (t : Time) (h : x509VerifyReq p t = true) : p.leaf.kuDigSig = true := by
  unfold x509VerifyReq at h
  simp only [Bool.and_eq_true] at h
  exact h.2

end SigningTrust
