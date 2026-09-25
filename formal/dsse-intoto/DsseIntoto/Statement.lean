/-
  DsseIntoto.Statement: the in-toto Statement layer, what cilock emits into
  it, and what a verifier hands the application out of it.

  Spec: in-toto Attestation Framework v1 (in-toto/attestation spec/v1:
  statement.md, resource_descriptor.md, digest_set.md, envelope.md) and the
  DSSE protocol v1.0.2 / envelope v1.0.2 parsing rules.

  As built:
  * attestation/intoto/statement.go   `NewStatement`, the one constructor
  * attestation/source/source.go      `EnvelopeToCollectionEnvelope`
  * attestation/source/verified.go    `VerifiedSource.SearchByPredicateType`
  * attestation/dsse/dsse.go          `Envelope` / `Signature` JSON decoding

  The model works at the level the spec does: which fields are set, which
  JSON kind a value is, which base64 alphabet a string is in. It does not
  parse JSON; the differential test does that against the real code.
-/
namespace DsseIntoto

/-! ### Statement -/

/-- The JSON kind of a value. -/
inductive JKind where
  | object | array | string | number | bool | null
deriving DecidableEq, Repr

structure Subject where
  name : String
  digest : List (String × String)
deriving DecidableEq, Repr

structure Statement where
  ty : String
  subject : List Subject
  predicateType : String
  predicate : JKind
deriving DecidableEq, Repr

def statementV1 : String := "https://in-toto.io/Statement/v1"
def statementV01 : String := "https://in-toto.io/Statement/v0.1"
def intotoPayloadType : String := "application/vnd.in-toto+json"

-- spec: in-toto statement.md §Fields "`predicate` _object, optional_ ... Unset is treated the same as set-but-empty."
def predicateOk : JKind → Bool
  | .object => true
  | .null => true
  | _ => false

/-- Every clause of the v1 Statement spec except the `_type` string. -/
-- spec: in-toto statement.md §Fields "`subject` _array of ResourceDescriptor objects, required_ ... Each element MUST have `digest` set."
-- spec: in-toto statement.md §Fields "`predicateType` _string (TypeURI), required_"
-- spec: in-toto digest_set.md §Fields "Set of one or more cryptographic digests"
def ConformsV1Body (s : Statement) : Prop :=
  (∀ sub ∈ s.subject, sub.digest ≠ []) ∧ s.predicateType ≠ "" ∧ predicateOk s.predicate = true

-- spec: in-toto statement.md §Fields "`_type` ... Always `https://in-toto.io/Statement/v1` for this version of the spec."
def ConformsV1 (s : Statement) : Prop := s.ty = statementV1 ∧ ConformsV1Body s

inductive MkErr where
  | invalidJson | emptyPredicateType | predicateNotObject | subjectWithoutDigest
deriving DecidableEq, Repr

/-- Lexicographic order on code points, which is Go's byte order on UTF-8. -/
def charsLt : List Char → List Char → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a.toNat < b.toNat then true else if a.toNat = b.toNat then charsLt as bs else false

def strLt (a b : String) : Bool := charsLt a.toList b.toList

def insertByName (p : String × List (String × String)) :
    List (String × List (String × String)) → List (String × List (String × String))
  | [] => [p]
  | q :: qs => if strLt q.1 p.1 then q :: insertByName p qs else p :: q :: qs

/-- Subjects are emitted sorted by name (`sort.Strings`). -/
def sortSubjects (subs : List (String × List (String × String))) : List Subject :=
  (subs.foldr insertByName []).map (fun p => ⟨p.1, p.2⟩)

theorem mem_insertByName (p x : String × List (String × String)) (l : List (String × List (String × String))) :
    x ∈ insertByName p l ↔ x = p ∨ x ∈ l := by
  induction l with
  | nil => simp [insertByName]
  | cons q qs ih =>
    unfold insertByName
    split
    · simp only [List.mem_cons, ih]
      constructor
      · rintro (h | h | h)
        · exact Or.inr (Or.inl h)
        · exact Or.inl h
        · exact Or.inr (Or.inr h)
      · rintro (h | h | h)
        · exact Or.inr (Or.inl h)
        · exact Or.inl h
        · exact Or.inr (Or.inr h)
    · simp

theorem mem_foldr_insert (x : String × List (String × String)) (l : List (String × List (String × String))) :
    x ∈ l.foldr insertByName [] ↔ x ∈ l := by
  induction l with
  | nil => simp
  | cons q qs ih => simp only [List.foldr_cons, mem_insertByName, ih, List.mem_cons]

/-- `intoto.NewStatement` as built. `pred = none` is predicate bytes that are
    not valid JSON; the only input it refuses. -/
-- cite: attestation/intoto/statement.go:25-28 sha256:71f553ef51eef1ba
-- cite: attestation/intoto/statement.go:42-52 sha256:d527dcd632b4abc6
-- cite: attestation/intoto/statement.go:57-73 sha256:574c359571940f63
-- cite: attestation/intoto/statement.go:76-88 sha256:cb7a2678df3b4656
def newStatement (predType : String) (pred : Option JKind)
    (subs : List (String × List (String × String))) : Except MkErr Statement :=
  match pred with
  | none => .error .invalidJson
  | some k => .ok ⟨statementV01, sortSubjects subs, predType, k⟩

/-- `NewStatement` as it must be: refuse what the v1 body forbids. The type
    string stays the caller's concern (#9827 moved cilock to v1 through
    `NewStatementV1`; #9841 tracks the platform-signed emitters). -/
def newStatementReq (ty predType : String) (pred : Option JKind)
    (subs : List (String × List (String × String))) : Except MkErr Statement :=
  match pred with
  | none => .error .invalidJson
  | some k =>
    if predType = "" then .error .emptyPredicateType
    else if k ≠ .object then .error .predicateNotObject
    else if subs.any (fun p => p.2.isEmpty) then .error .subjectWithoutDigest
    else .ok ⟨ty, sortSubjects subs, predType, k⟩

theorem mem_sortSubjects (subs : List (String × List (String × String))) (s : Subject)
    (h : s ∈ sortSubjects subs) : (s.name, s.digest) ∈ subs := by
  unfold sortSubjects at h
  simp only [List.mem_map] at h
  obtain ⟨p, hp, rfl⟩ := h
  exact (mem_foldr_insert p subs).mp hp

/-- Whatever the fixed constructor emits meets every body clause of the v1
    spec, and meets the whole v1 spec when asked for the v1 type. -/
theorem newStatementReq_conforms (ty predType : String) (pred : Option JKind)
    (subs : List (String × List (String × String))) (s : Statement)
    (h : newStatementReq ty predType pred subs = .ok s) : ConformsV1Body s ∧ (ty = statementV1 → ConformsV1 s) := by
  unfold newStatementReq at h
  cases pred with
  | none => simp at h
  | some k =>
    simp only at h
    by_cases hp : predType = ""
    · simp [hp] at h
    · by_cases hk : k ≠ .object
      · simp [hp, hk] at h
      · by_cases hs : subs.any (fun p => p.2.isEmpty) = true
        · simp [hp, hk, hs] at h
        · simp only [hp, hk, hs, ↓reduceIte, Bool.false_eq_true, Except.ok.injEq] at h
          subst h
          have hk' : k = .object := by simpa using hk
          have body : ConformsV1Body ⟨ty, sortSubjects subs, predType, k⟩ := by
            refine ⟨?_, hp, by simp [hk', predicateOk]⟩
            intro sub hsub hnil
            have hm := mem_sortSubjects subs sub hsub
            apply hs
            simp only [List.any_eq_true]
            exact ⟨(sub.name, sub.digest), hm, by simp [hnil]⟩
          exact ⟨body, fun hty => ⟨hty, body⟩⟩

/-! ### What a verifier hands the application -/

/-- What an envelope's payload bytes decode to, when they decode at all. -/
structure Decoded where
  ty : String
  predicateType : String
  collection : Bool      -- the predicate decodes as an attestation Collection
deriving DecidableEq, Repr

structure RawEnv where
  payloadType : String
  payload : Option Decoded   -- `none`: empty, or not a JSON statement
deriving DecidableEq, Repr

-- spec: in-toto envelope.md §Fields "`payloadType` MUST be set to `application/vnd.in-toto.<predicate>+json` or to `application/vnd.in-toto+json`."
-- spec: DSSE protocol §Protocol "Reject if PAYLOAD_TYPE is not a supported type."
def supportedPayloadType (t : String) : Bool :=
  let c := t.toList
  let pre := "application/vnd.in-toto.".toList
  let suf := "+json".toList
  t == intotoPayloadType ||
  -- the predicate segment is case-sensitive and non-empty
  (pre.isPrefixOf c && suf.reverse.isPrefixOf c.reverse && decide (pre.length + suf.length < c.length))

/-- A statement type a verifier reads: v1, or the legacy v0.1 that deployed
    emitters still sign (#9841). -/
-- spec: in-toto statement.md §Fields "`_type` _string (TypeURI), required_ Identifier for the schema of the Statement."
def knownStatementType (t : String) : Bool := t == statementV1 || t == statementV01

/-- The spec's reading of a verified envelope as an in-toto statement. -/
-- spec: in-toto envelope.md §Fields "`payload` MUST be a base64-encoded JSON Statement."
-- spec: DSSE protocol §Protocol "Parse SERIALIZED_BODY according to PAYLOAD_TYPE. Reject if the parsing fails."
def SpecReads (e : RawEnv) (d : Decoded) : Prop :=
  supportedPayloadType e.payloadType = true ∧ e.payload = some d ∧ knownStatementType d.ty = true

/-- `EnvelopeToCollectionEnvelope` as built. -/
-- cite: attestation/source/source.go:157-182 sha256:c05ceee181a9c414
def toCollection (e : RawEnv) : Option Decoded :=
  match e.payload with
  | none => none
  | some d => if d.predicateType = "" then none else if d.collection then some d else none

/-- The same, as it must be. -/
def toCollectionReq (e : RawEnv) : Option Decoded :=
  if supportedPayloadType e.payloadType = false then none
  else match e.payload with
    | none => none
    | some d =>
      if knownStatementType d.ty = false then none
      else if d.predicateType = "" then none
      else if d.collection then some d else none

theorem toCollectionReq_reads (e : RawEnv) (d : Decoded) (h : toCollectionReq e = some d) : SpecReads e d := by
  unfold toCollectionReq at h
  by_cases hp : supportedPayloadType e.payloadType = false
  · simp [hp] at h
  · simp only [hp] at h
    cases hd : e.payload with
    | none => simp [hd] at h
    | some d' =>
      simp only [hd] at h
      by_cases hk : knownStatementType d'.ty = false
      · simp [hk] at h
      · simp only [hk] at h
        by_cases he : d'.predicateType = ""
        · simp [he] at h
        · by_cases hc : d'.collection = true
          · simp [he, hc] at h
            subst h
            exact ⟨by simpa using hp, hd, by simpa using hk⟩
          · simp [he, hc] at h

/-- An external (bare-predicate) statement: what the source decoded, next to
    what the verified payload bytes actually say, and the predicate types the
    verifier searched for. -/
structure External where
  env : RawEnv
  sourceStmt : Decoded     -- `StatementEnvelope.Statement` as the source filled it
  requested : List String  -- the `predicateTypes` passed to SearchByPredicateType
deriving DecidableEq, Repr

/-- `VerifiedSource.SearchByPredicateType` as built, for an envelope whose
    signatures verified: the signed payload must decode far enough to show a
    subject matching the request, and then it hands on the source's own
    decode. Nothing binds the signed predicateType to `requested`. -/
-- cite: attestation/source/verified.go:46-70 sha256:d4955b29f8b91f0a
-- cite: attestation/source/verified.go:608-652 sha256:5ef62c1b381c6854
def externalRead (x : External) : Option Decoded :=
  match x.env.payload with
  | none => none
  | some _ => some x.sourceStmt

/-- As it must be: decode the verified bytes, typed as in-toto, of a
    requested predicate type. -/
def externalReadReq (x : External) : Option Decoded :=
  if supportedPayloadType x.env.payloadType = false then none
  else match x.env.payload with
    | none => none
    | some d =>
      if knownStatementType d.ty = false then none
      else if x.requested.contains d.predicateType then some d else none

/-- What the application receives is the verified bytes read as the spec
    reads them, and it is evidence of the type the verifier asked for (the
    policy's external names one predicate type and binds only that). -/
-- spec: DSSE protocol §Protocol "Implementations MUST ensure that the same SERIALIZED_BODY that is verified is the same sent to the application layer."
-- spec: in-toto envelope.md §Fields "Consumer SHOULD only rely on the `predicateType` field in the Statement layer." / "To obtain predicate information that is authenticated, consumers MUST parse the Envelope's `payload`, and verify it against its `signatures`."
def SameBytes (x : External) (d : Decoded) : Prop := SpecReads x.env d ∧ d.predicateType ∈ x.requested

theorem externalReadReq_sameBytes (x : External) (d : Decoded) (h : externalReadReq x = some d) :
    SameBytes x d := by
  unfold externalReadReq at h
  by_cases hp : supportedPayloadType x.env.payloadType = false
  · simp [hp] at h
  · simp only [hp] at h
    cases hd : x.env.payload with
    | none => simp [hd] at h
    | some d' =>
      simp only [hd] at h
      by_cases hk : knownStatementType d'.ty = false
      · simp [hk] at h
      · by_cases hr : x.requested.contains d'.predicateType = true
        · simp only [hk, hr, Bool.true_eq_false, ↓reduceIte, Option.some.injEq] at h
          subst h
          exact ⟨⟨by simpa using hp, hd, by simpa using hk⟩, by simpa using hr⟩
        · have hr' : x.requested.contains d'.predicateType = false := by simpa using hr
          simp only [hk, hr', Bool.true_eq_false, Bool.false_eq_true, ↓reduceIte] at h
          exact absurd h (by simp)

/-! ### Envelope JSON decoding -/

/-- Which RFC 4648 alphabet a base64 field is written in. `both`: no index
    62/63 character, so it reads the same in either. -/
inductive B64 where
  | both | stdOnly | urlOnly | invalid
deriving DecidableEq, Repr

structure EnvJson where
  hasPayload : Bool
  hasPayloadType : Bool
  hasSignatures : Bool
  payload : B64
  sigs : List (Bool × B64)     -- (the `sig` key is present, its alphabet)
deriving DecidableEq, Repr

def b64Std : B64 → Bool
  | .both | .stdOnly => true
  | _ => false

def b64Either : B64 → Bool
  | .both | .stdOnly | .urlOnly => true
  | .invalid => false

-- spec: DSSE envelope.md §Parsing rules "The following fields are REQUIRED and MUST be set, even if empty: `payload`, `payloadType`, `signature`, `signature.sig`."
-- spec: DSSE protocol §Protocol "Either standard or URL-safe base64 encodings are allowed. Signers may use either, and verifiers **MUST** accept either."
def SpecDecodes (j : EnvJson) : Prop :=
  j.hasPayload = true ∧ j.hasPayloadType = true ∧ j.hasSignatures = true ∧
  b64Either j.payload = true ∧ ∀ s ∈ j.sigs, s.1 = true ∧ b64Either s.2 = true

/-- `encoding/json` into `dsse.Envelope` as built: a missing key decodes to
    the zero value; a `[]byte` field decodes with the standard alphabet only. -/
-- cite: attestation/dsse/dsse.go:208-229 sha256:124ced99c6c60f7e
def decodes (j : EnvJson) : Bool :=
  (!j.hasPayload || b64Std j.payload) && j.sigs.all (fun s => !s.1 || b64Std s.2)

def decodesReq (j : EnvJson) : Bool :=
  j.hasPayload && j.hasPayloadType && j.hasSignatures && b64Either j.payload &&
    j.sigs.all (fun s => s.1 && b64Either s.2)

theorem decodesReq_iff (j : EnvJson) : decodesReq j = true ↔ SpecDecodes j := by
  unfold decodesReq SpecDecodes
  simp only [Bool.and_eq_true, List.all_eq_true]
  constructor
  · rintro ⟨⟨⟨⟨hp, ht⟩, hs⟩, hb⟩, hsig⟩
    exact ⟨hp, ht, hs, hb, fun s hs' => by simpa using hsig s hs'⟩
  · rintro ⟨hp, ht, hs, hb, hsig⟩
    exact ⟨⟨⟨⟨hp, ht⟩, hs⟩, hb⟩, fun s hs' => by simpa using hsig s hs'⟩

end DsseIntoto
