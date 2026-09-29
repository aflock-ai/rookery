/-
  CilockPolicy.TrustCounterexamples: where the trust statements, read
  literally, fail. Each is a concrete trace decided by the kernel.
-/
import CilockPolicy.Vacuity
import CilockPolicy.Fixtures

namespace CilockPolicy.TrustCounterexamples
open CilockPolicy CilockPolicy.Fixtures

/-- cilock's static validator for a root functionary, ERRORS only
    (`validate.go`, `validate.go`): certConstraint.roots
    non-empty, each "*" or a defined root, commonname non-empty. Empty
    dns/emails/orgs and a "*" uri are WARNINGS (`validate.go`).
    -- cite: cilock/internal/policy/validate.go:381-397 sha256:b8293de6b6b8a1fb8fb3058f13a99632b79379739cf375426c25535136e856ee
    -- cite: cilock/internal/policy/validate.go:544-547 sha256:7d9a638a378c6623e04a81cb8c3ed7d7c5f8362ba1e020f0a62f470a7eb781d5
    -- cite: cilock/internal/policy/validate.go:548-568 sha256:6737b4462419ec08a498ce5405e52a226235bd4d05183b4262786d2d711fabd7
    -/
def staticRootValid (definedRoots : List RootId) (f : Functionary) : Bool :=
  f.type == "root" && !f.cc.roots.isEmpty &&
  f.cc.roots.all (fun r => r == "*" || definedRoots.contains r) && f.cc.cn != ""

/-- A Fulcio-like certificate with an attacker's own identity, chaining to the
    policy root `fulcio`. -/
def attackerCert : Cert :=
  { keyId := "attacker-key", cn := "", dns := [], emails := ["mallory@example.com"], orgs := [],
    uris := ["https://github.com/mallory/evil/.github/workflows/x.yml@refs/heads/main"],
    exts := [("Issuer", "https://token.actions.githubusercontent.com")], policyOids := [],
    chainsTo := ["fulcio"], notBefore := 0, notAfter := 100 }

/-- Every identity field "*". -/
def starCC (cn : String) : CertConstraint :=
  { cn := cn
    dns := ["*"]
    emails := ["*"]
    orgs := ["*"]
    uris := ["*"]
    roots := ["fulcio"] }

def allStar : Functionary := { type := "root", cc := starCC "*" }

/-- V1, literally stated, is FALSE: a functionary the static validator accepts
    admits an arbitrary identity from the root, even with every hardening flag
    on. The only defence is the policy author's constraints; `listOk_nonvacuous`
    proves there is no IMPLICIT wildcard, so "*" must be written. -/
theorem v1_all_star_admits_anyone :
    staticRootValid ["fulcio"] allStar = true ∧
    fValidate .enforce ["fulcio"] allStar (.cert attackerCert) = true := by decide

/-- R3_181 (RejectEmptyConstraintEmptyField). Constraint lists left empty: the
    validator only warns. With the flag OFF (the library default for any
    embedder that never calls SetHardening) a cert with no SANs is admitted;
    ON (the cilock CLI default) refuses. -/
def emptyLists : Functionary := { type := "root", cc := { cn := "*", roots := ["fulcio"] } }
def bareCert : Cert := { attackerCert with emails := [], uris := [] }

theorem r3_181_off_admits : fValidate .warn ["fulcio"] emptyLists (.cert bareCert) = true := by decide
theorem r3_181_on_refuses : fValidate .enforce ["fulcio"] emptyLists (.cert bareCert) = false := by decide
theorem r3_181_static_valid : staticRootValid ["fulcio"] emptyLists = true := by decide

/-- R3_184 (EnforceCertConstraintOnKeyIDMatch). A functionary pinning key `kx`
    AND a certificate identity: with the flag OFF the identity is ignored on
    a key-id match (`step.go`). The holder of `kx` can sign under any
    certificate identity.
    -- cite: attestation/policy/step.go:568-580 sha256:81402839fa0c7643af7f7f9c1cd089da8bd0a86c993149f01c2d1b0e95c92cf3
    -/
def pinned : Functionary := { type := "publickey", keyId := "kx", cc := starCC "build-bot" }
def otherIdentity : Cert := { attackerCert with keyId := "kx", cn := "somebody-else" }

theorem r3_184_off_admits : fValidate .warn ["fulcio"] pinned (.cert otherIdentity) = true := by decide
theorem r3_184_on_refuses : fValidate .enforce ["fulcio"] pinned (.cert otherIdentity) = false := by
  decide

/-! ## V2 fails at triage level with a timestamp constraint -/

def certA : Cert := { bareCert with keyId := "a", cn := "a" }
def certB : Cert := { attackerCert with keyId := "b", cn := "b" }
/-- `fA` leaves its lists empty (admitted only with the flag OFF); `fB` is complete. -/
def fA : Functionary := { type := "root", cc := { cn := "a", roots := ["fulcio"] } }
def fB : Functionary := { type := "root", cc := starCC "b" }
def tsPol : Policy := { expires := 1000, roots := ["fulcio"], tsas := ["tsa"], keys := [], steps := [] }
def tsStep : Step :=
  { name := "s"
    functionaries := [fA, fB]
    atts := [⟨attT, 0⟩]
    tsc := some { notBefore := some 40 } }
/-- Two signatures: certA stamped at 30 (old), certB stamped at 50. -/
def twoSigs : Envelope :=
  env "e" (coll "s") [⟨.cert certA, true, [⟨"tsa", true, 30⟩]⟩, ⟨.cert certB, true, [⟨"tsa", true, 50⟩]⟩]

theorem v2_timestamp_counterexample :
    triage .warn tsPol opts tsStep twoSigs = false ∧ triage .enforce tsPol opts tsStep twoSigs = true := by
  decide

/-! ## Evidence timestamps are not compared with the policy's expiry -/

/-- The engine compares expiry with the VERIFY clock only (`policy.go`).
    A TSA time after `expires` is accepted while the clock is before it; the
    soundness theorem needs `TsaNotFuture` to rule this out.
    -- cite: attestation/policy/policy.go:678-680 sha256:7759d749f16c04962d08059b1d7e97ad861c39ce2af3c99b30e54e280139a8a3
    -/
def lateCert : Cert := { certB with notAfter := 5000 }
def latePol : Policy :=
  { expires := 1000, roots := ["fulcio"], tsas := ["tsa"], keys := [], steps := [step' ] }
where step' : Step := { name := "build", functionaries := [fB], atts := [⟨attT, 0⟩] }
def lateEnv : Envelope := env "late" (coll "build") [⟨.cert lateCert, true, [⟨"tsa", true, 2000⟩]⟩]

theorem timestamp_after_expiry_passes :
    verifyFixed rego regoExt .enforce latePol opts [lateEnv] = true ∧ opts.now ≤ latePol.expires := by
  decide

end CilockPolicy.TrustCounterexamples
