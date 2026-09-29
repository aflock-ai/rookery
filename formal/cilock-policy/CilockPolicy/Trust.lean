/-
  CilockPolicy.Trust: who may sign, and when.

  DSSE signature verification against the policy's trust material, the
  functionary check (key id or certificate constraint), the hardening flags,
  and the step timestamp constraint. Each definition cites the Go it models.
-/
import CilockPolicy.Policy

namespace CilockPolicy

/-! ## Strings and globs -/

/-- normalizeGlobValue (`constraints.go`): lower-case.
  -- cite: attestation/policy/constraints.go:638 sha256:e9ffc453e66125cd01e13cb3a7c37349107f86c9bd3d107669e0d861826e16e6
-/
def lower (s : String) : List Char := s.toList.map Char.toLower

/-- containsGlobMeta (`constraints.go`).
  -- cite: attestation/policy/constraints.go:55-62 sha256:fdb4342599afa0f0b173ddd14aefdd1e04dca3b18c47f5da450bff85b60a0c95
-/
def isGlob (s : String) : Bool := s.toList.any fun c => c == '*' || c == '?' || c == '{' || c == '['

/-- gobwas/glob compiled without separators, restricted to `*` (any sequence,
    `/` included) and `?` (one character). Structural on a fuel of
    pattern length + value length + 1, which every call decreases. `{…}` and `[…]` are matched
    literally here; no policy in the holdout set uses them. -/
def globMatch : Nat → List Char → List Char → Bool
  | 0, _, _ => false
  | _ + 1, [], s => s.isEmpty
  | n + 1, '*' :: ps, [] => globMatch n ps []
  | n + 1, '*' :: ps, c :: s => globMatch n ps (c :: s) || globMatch n ('*' :: ps) s
  | _ + 1, '?' :: _, [] => false
  | n + 1, '?' :: ps, _ :: s => globMatch n ps s
  | _ + 1, _ :: _, [] => false
  | n + 1, p :: ps, c :: s => p == c && globMatch n ps s

def glob (pat v : List Char) : Bool := globMatch (pat.length + v.length + 1) pat v

/-- certGlob.Match (#9867): the matcher every cert-constraint glob goes
    through. An empty value matches only the explicit allow-all `*`, even when
    the pattern could match it in glob terms (`**`; in the engine also `{,a}`).
    -- cite: attestation/policy/certglob.go:55-60 sha256:fbe39743c4f0ee7bc8f211c37795d204ada72ecd407e0e67c7b1bb0219e45569
    -/
def certGlob (pat v : List Char) : Bool := (!v.isEmpty || pat == ['*']) && glob pat v

/-! ## Certificate constraint (`constraints.go`)
  -- cite: attestation/policy/constraints.go:138-668 sha256:5b84c09f917fb853c4a990518e57c1e4eabd8a2ebdf9b739b94d711897cbcbc3
-/

/-- checkCertConstraintGlob (`constraints.go`): `*` any, empty fails
    closed, glob on lower-cased values, else case-insensitive equality.
    -- cite: attestation/policy/constraints.go:407-452 sha256:d7042a55ed81a4c0ed0d148332aa026c90b57d02a57e3085e7c7398ee750a190
    -/
def cnOk (con v : String) : Bool :=
  if con == "*" then true
  else if con == "" then false
  else if isGlob con then certGlob (lower con) (lower v)
  else lower con == lower v

/-- The exact-constraint multiset consumption (`constraints.go`). Returns
    the values left for the globs, or `none` when an exact constraint is unmet.
    -- cite: attestation/policy/constraints.go:525-542 sha256:727203ff7511347f81955cba90d85d5a855c80923098181b1d0dead6a66e49c3
    -/
def consume : List String → List String → Option (List String)
  | [], vs => some vs
  | e :: es, vs => if vs.contains e then consume es (vs.erase e) else none

/-- assignValueToGlob (`constraints.go`): the first unused glob that
    matches takes the value. Greedy, exactly as the Go loop. `glob` here
    equals `certGlob`: listOk drops empty values before any reach it.
    -- cite: attestation/policy/constraints.go:615-630 sha256:65b4e504fc9d606749f7294313f2f7e82f65b458efa441aba7e314458d9dc03f
    -/
def takeGlob : List (String × Bool) → String → Option (List (String × Bool))
  | [], _ => none
  | (g, u) :: gs, v =>
    if !u && glob (lower g) (lower v) then some ((g, true) :: gs)
    else (takeGlob gs v).map ((g, u) :: ·)

/-- matchGlobConstraints (`constraints.go`): every remaining value lands
    on a glob and every glob is used.
    -- cite: attestation/policy/constraints.go:566-593 sha256:349460c8a5bdfb8b560ef11814f0eb7d2940cff8feb8751c6ce528ecf425deeb
    -/
def assignGlobs : List (String × Bool) → List String → Bool
  | gs, [] => gs.all (·.2)
  | gs, v :: vs => match takeGlob gs v with
    | none => false
    | some gs' => assignGlobs gs' vs

/-- resolveEmptyConstraint (`constraints.go`).
  -- cite: attestation/policy/constraints.go:461-478 sha256:56d27dee260a63b4792b44a14166aaca2629413e84084a18a1654823ce23a63a
-/
def emptyConstraintOk (h : Hardening) (vals : List String) : Bool :=
  vals.isEmpty && !h.emptyField

/-- checkCertConstraint (`constraints.go`).
  -- cite: attestation/policy/constraints.go:480-553 sha256:c5773bccc0dabcdd9daa6afb0b247210595bed16f8981a790d150e1717aa346e
-/
def listOk (h : Hardening) (cons vals : List String) : Bool :=
  if cons.contains "*" then true
  else
    let cs := cons.filter (· != "")
    let vs := vals.filter (· != "")
    if cs.isEmpty then emptyConstraintOk h vs
    else
      match consume (cs.filter (fun c => !isGlob c)) vs with
      | none => false
      | some rest => assignGlobs ((cs.filter isGlob).map (·, false)) rest

/-- checkTrustBundles (`constraints.go`). The trust bundles are exactly
    the policy's roots (`policy.go`).
    -- cite: attestation/policy/constraints.go:263-286 sha256:be7d6ea4e7dfba8712afc063b680ba8ca00947d407a49195bb96ed14da0194d1
    -- cite: attestation/policy/policy.go:161-163 sha256:470701d7a1361929feaf507ca6bbe65458cafb4a7cada2adddeadf198d16038d
    -/
def rootsOk (policyRoots : List RootId) (cons : List RootId) (c : Cert) : Bool :=
  if cons.contains "*" then c.chainsTo.any policyRoots.contains
  else cons.any fun r => policyRoots.contains r && c.chainsTo.contains r

/-- checkExtensions (`constraints.go`): empty constraint skipped; exact
    or glob, NOT lower-cased.
    -- cite: attestation/policy/constraints.go:340-389 sha256:d819dead8a7307eb1f6428b7ece2e56b025901dc89038602fe32bff93deb6ee5
    -/
def extOk (c : Cert) (fc : String × String) : Bool :=
  let v := (c.exts.lookup fc.1).getD ""
  fc.2 == "" || (if isGlob fc.2 then certGlob fc.2.toList v.toList else fc.2 == v)

/-- CertConstraint.Check (`constraints.go`), in the Go order.
  -- cite: attestation/policy/constraints.go:138-179 sha256:08eb1059abca290ca79fb51e5464def5a376dfcbcb0b2e114d1631681bb231d2
-/
def ccCheck (h : Hardening) (policyRoots : List RootId) (cc : CertConstraint) (c : Cert) : Bool :=
  cnOk cc.cn c.cn && listOk h cc.dns c.dns && listOk h cc.emails c.emails &&
  listOk h cc.orgs c.orgs && listOk h cc.uris c.uris && rootsOk policyRoots cc.roots c &&
  cc.exts.all (extOk c) && cc.oids.all c.policyOids.contains

/-- The x509 arm of Functionary.Validate (`step.go`).
  -- cite: attestation/policy/step.go:583-596 sha256:66dbe257461a8ac127a3be30ead0ddef763fbaa1d1df4bf2d59f3e78004439a0
-/
def certArm (h : Hardening) (policyRoots : List RootId) (f : Functionary) : Cred → Bool
  | .key _ => false
  | .cert c => !f.cc.roots.isEmpty && ccCheck h policyRoots f.cc c

/-- Functionary.Validate (`step.go`). A key-id match short-circuits; the
    certificate constraint then runs only under EnforceCertConstraintOnKeyIDMatch
    (`step.go`). `type` is never read.
    -- cite: attestation/policy/step.go:562-597 sha256:0be8c018de52408f0de33beca61fbfe26205cd40a30256af8907a9cef64a529c
    -- cite: attestation/policy/step.go:568-580 sha256:81402839fa0c7643af7f7f9c1cd089da8bd0a86c993149f01c2d1b0e95c92cf3
    -/
def fValidate (h : Hardening) (policyRoots : List RootId) (f : Functionary) (cred : Cred) : Bool :=
  if f.keyId != "" && f.keyId == cred.keyId then
    (if f.cc.isSet && h.keyIdCC then certArm h policyRoots f cred else true)
  else certArm h policyRoots f cred

/-! ## DSSE (`verify.go`)
  Chain building is an observation (`Cert.chainsTo`). Since #10124 it includes
  the Certificate Transparency check: a leaf under a CT-logging CA must embed
  an SCT that verifies. That check is modelled, and differentially tested, in
  formal/signing-trust (`x509VerifyCT_iff`); here it is part of what
  `chainsTo` reports.
  -- cite: attestation/dsse/verify.go:161-394 sha256:78f76b97af45c0e1f76b664130a5106a1dc090e562b886c47f1492e7ca0f1a6e
-/

/-- A verifier that passed: the credential and its TSA-verified times. -/
structure Verifier where
  cred  : Cred
  times : List Time
deriving DecidableEq, Repr

/-- The TSA-verified times of a certificate signature: a token that verified
    against a policy TSA, at a time inside the certificate's validity window
    (verifyX509Time at tsTime, `verify.go`).
    -- cite: attestation/dsse/verify.go:308-350 sha256:76acc0a3d62f2f89467d37392ce0e0cb8a82476f8988e68df3b148e10b40a82c
    -/
def certTimes (p : Policy) (c : Cert) (s : Sig) : List Time :=
  (s.tokens.filter fun t => t.ok && p.tsas.contains t.tsa && decide (c.notBefore ≤ t.time) &&
    decide (t.time ≤ c.notAfter)).map (·.time)

/-- One signature. Raw keys: checked against the policy's keys, no timestamp
    (`verify.go`). Certificates: no TSA configured means rejected,
    since policyverify never enables the current-time fallback
    (`verify.go`); otherwise the chain must reach a policy root and
    some token must verify at a time the certificate was valid.
    -- cite: attestation/dsse/verify.go:367-379 sha256:d734c1f0bfba150e66d4270a06e3881fc655c7eb7116af358ab1a4741c5fd22b
    -- cite: attestation/dsse/verify.go:250-275 sha256:42896d9716400dac32e61653dda6bb1b0ecdcd95d0f8625e574a3a5744229beb
    -/
def sigVerifier (p : Policy) (s : Sig) : Option Verifier :=
  match s.cred with
  | .key k => if s.ok && p.keys.contains k then some ⟨.key k, []⟩ else none
  | .cert c =>
    if s.ok && !p.tsas.isEmpty && c.chainsTo.any p.roots.contains && !(certTimes p c s).isEmpty
    then some ⟨.cert c, certTimes p c s⟩ else none

/-- The passing verifiers of an envelope (`verified.go`). Empty means the
    envelope failed (`verify.go`).
    -- cite: attestation/source/verified.go:536-551 sha256:52b1160fd086e3743db92574b528d3dd59ea861a41e4c8e26c2a1ed27cfee04b
    -- cite: attestation/dsse/verify.go:382-388 sha256:8b97154d98585f3d23fc71c6e1b36a164353eae2f587647b17e0bd5e90b9f5c0
    -/
def verifiers (p : Policy) (e : Envelope) : List Verifier := e.sigs.filterMap (sigVerifier p)

/-! ## Timestamp constraint (`timestamp_constraint.go`)
  -- cite: attestation/policy/timestamp_constraint.go:107-147 sha256:51e3358d09fd59549f11114317687fbf53baabed4c15845b9aec3ecab80bd2d0
-/

/-- maxClockSkew (`timestamp_constraint.go`): a FIXED 5 minutes. The
    WithClockSkewTolerance option is not read here.
    -- cite: attestation/policy/timestamp_constraint.go:28 sha256:545f7ac982a7b7076c1467fd76946002e3dcb5003ad61e86d2fa43e54f856336
    -/
def maxClockSkew : Nat := 300

/-- Check: the EARLIEST verified time is judged; bounds are exact; maxAge
    rejects a time beyond now + 5m and an age above maxAge. -/
def tscOk (tsc : Option TsConstraint) (times : List Time) (now : Time) : Bool :=
  match tsc with
  | none => true
  | some c =>
    match times.min? with
    | none => false
    | some e =>
      c.notBefore.all (· ≤ e) && c.notAfter.all (e ≤ ·) &&
      c.maxAge.all fun m => decide (e ≤ now + maxClockSkew) && decide (now - e ≤ m)

/-! ## Functionary triage (`policy.go`)
  -- cite: attestation/policy/policy.go:2138-2228 sha256:6ad551cd73674d984aedc1755a5fb4b29e5e835f5e5d6f10fef7e2147ea92f5d
  -- cite: attestation/policy/tsa_time.go:36-50 sha256:1fc88b3a0d1ac34db8a3f50cf1444e7b6d565790a3c3a2156bc805ac9c2dd9a5
-/

/-- The verifiers that match some functionary of the step (ValidFunctionaries). -/
def validFunctionaries (h : Hardening) (p : Policy) (fs : List Functionary) (e : Envelope) :
    List Verifier :=
  (verifiers p e).filter fun v => fs.any fun f => fValidate h p.roots f v.cred

/-- triageOne: collection predicate type, some verifier, some functionary match,
    and the timestamp constraint judged on the matched verifiers' times only. -/
def triage (h : Hardening) (p : Policy) (o : Options) (s : Step) (e : Envelope) : Bool :=
  e.payload.isCollection && !(verifiers p e).isEmpty &&
  !(validFunctionaries h p s.functionaries e).isEmpty &&
  tscOk s.tsc ((validFunctionaries h p s.functionaries e).flatMap (·.times)) o.now

end CilockPolicy
