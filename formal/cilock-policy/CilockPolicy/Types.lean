/-
  CilockPolicy.Types: the shared vocabulary.

  Digest, signer identity (key / certificate), subject, signature and timestamp
  live here and nowhere else, so a later common library (the cilock master
  theorem, formal/cilock) can replace them by refinement. Nothing in this file
  decides trust: cryptographic and third-party facts are hypotheses in
  `CilockPolicy.Assumptions`, never definitions.

  Every field is the part of the Go value that a verification decision reads.
  Citations are to subtrees/rookery at origin/main d023787f95.
-/
namespace CilockPolicy

/-- Seconds. Go's time.Time, abstracted to a natural number. -/
abbrev Time := Nat
/-- cryptoutil.Verifier.KeyID(). For a raw key it is the policy key id; for an
    X.509 verifier it is the id of the certificate's public key. -/
abbrev KeyId := String
/-- An id in the policy's `roots` / `timestampauthorities` maps. -/
abbrev RootId := String

/-- One (algorithm, value) entry of a signed subject or a DigestSet. -/
structure Digest where
  alg   : String
  value : String
deriving DecidableEq, Repr

/-- An in-toto subject: name plus one digest (a multi-digest subject is several). -/
structure Subject where
  name   : String
  digest : Digest
deriving DecidableEq, Repr

/-- A DigestSet (cryptoutil/digestset.go): algorithm name -> value. -/
abbrev DigestSet := List (String × String)

/-- The X.509 leaf as the constraint check reads it (`constraints.go`).
    `chainsTo` abstracts chain building: the policy roots this leaf verifies to
    (cryptoutil.X509Verifier.BelongsToRoot).
    -- cite: attestation/policy/constraints.go:145-190 sha256:183fc0354ea2bb41336c83080f215dee10de7b5cca93bdd396a9309d59ad34ee
    -/
structure Cert where
  keyId      : KeyId
  cn         : String
  dns        : List String
  emails     : List String
  orgs       : List String
  uris       : List String
  /-- Fulcio extension field name -> value (certificate.Extensions). -/
  exts       : List (String × String)
  policyOids : List String
  chainsTo   : List RootId
  notBefore  : Time
  notAfter   : Time
  /-- The decoded value of every occurrence of the platform Fulcio's
      assurance extension (OID 1.3.6.1.4.1.57264.1.100), in order. An
      occurrence that is not one UTF8String is recorded as a value no level
      parses from. -/
  acr        : List String := []
deriving DecidableEq, Repr

/-- An RFC 3161 token attached to one signature. `ok` is the TSA signature
    check over the DSSE signature bytes (timestamp.Verifier.Verify); `tsa` is the
    policy TSA root that check succeeded against. -/
structure TsToken where
  tsa  : RootId
  ok   : Bool
  time : Time
deriving DecidableEq, Repr

/-- The credential a DSSE signature presents: a raw key or a certificate. -/
inductive Cred where
  | key  (k : KeyId)
  | cert (c : Cert)
deriving DecidableEq, Repr

def Cred.keyId : Cred → KeyId
  | .key k  => k
  | .cert c => c.keyId

/-- One DSSE signature. `ok` is the signature check over PAE(payload) with the
    presented credential (`verify.go`, `verify.go`).
    -- cite: attestation/dsse/verify.go:322 sha256:a0a7dd9f9396524294eabc0736a9de050a854f65d6f98b727556cf3869a34ffe
    -- cite: attestation/dsse/verify.go:372 sha256:df1add63d18d6582fe33e436f9eec490dd9e4b98a47ae69497b428ab74dad56e
    -/
structure Sig where
  cred   : Cred
  ok     : Bool
  tokens : List TsToken
deriving DecidableEq, Repr

/-- One attestor inside a collection. `body` is an opaque content id: Rego and
    AI are modelled as opaque predicates over it. `commitHash` is the git
    attestor's `commithash` (`commit_binding.go`).
    -- cite: attestation/policy/commit_binding.go:170-202 sha256:fb78a0013d65e921a57ac9385e81db0f7d84f7626ef098c85ee36faeb57543ee
    -/
structure Attestor where
  type       : String
  body       : Nat
  commitHash : Option String
deriving DecidableEq, Repr

/-- The signed collection predicate (attestation.Collection) plus the facts the
    engine reads off its statement. -/
structure Collection where
  name           : String
  /-- predicateType is the collection type (`policy.go`).
  -- cite: attestation/policy/policy.go:2223 sha256:40966cb8a742b836ec622532156befb4a32d4ed1debbb886daf32272a004bafe
  -/
  isCollection   : Bool
  predicateType  : String
  subjects       : List Subject
  /-- The statement carries a hardened git attestation (SubjectMatchScope). -/
  hardenedGit    : Bool
  attestors      : List Attestor
  materials      : List (String × DigestSet)
  products       : List (String × DigestSet)
  /-- VerifyInlineLeaves succeeds (leaves fold to the signed root). -/
  leavesOk       : Bool
  /-- HasInlineMaterials: the empty material set is a signed commitment. -/
  inlineMaterials : Bool
  /-- Relationship edges (BackRefs). Recorded, never followed (`policy.go`).
  -- cite: attestation/policy/policy.go:977-982 sha256:02729af599c32c78c149bc44223b5c85ab327eaf880015995a092724246ced22
  -/
  backRefs       : List Digest
deriving DecidableEq, Repr

/-- A DSSE envelope as a source returns it. `ref` is source-provided
    (a file path or an Archivista gitoid), not signed. -/
structure Envelope where
  ref     : String
  payload : Collection
  sigs    : List Sig
deriving DecidableEq, Repr

end CilockPolicy
