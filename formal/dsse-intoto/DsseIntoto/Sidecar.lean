/-
  DsseIntoto.Sidecar: what cilock admits as a sidecar next to a bundle, and
  the base64 alphabet equivalence the DSSE parsing rules rely on.

  Sidecar acceptance (#10165). `cilock policy from-bundles` and `cilock verify`
  discover companion envelopes next to a bundle. #10165 routes every candidate
  through one decoder, `decodeSidecarEnvelope`
  (cilock/cli/policy_from_bundles.go on that branch): `json.Unmarshal` into
  `dsse.Envelope` (the DSSE parsing rules, modelled here as `decodesReq`),
  then a non-empty payload, at least one signature, and a payload that is an
  in-toto statement naming a non-empty `predicateType`. Before #10165 the
  discovery walk used its own struct and the standard alphabet only, while the
  manifest index used `dsse.Envelope`, so the two could disagree about one
  file. `sidecarAccepts` is the one decoder; `sidecarAccepts_iff` says exactly
  what it admits. The Go side of these vectors lands with #10165
  (cilock/cli/formal_sidecar_differential_test.go).

  Alphabet equivalence. DSSE protocol: "Either standard or URL-safe base64
  encodings are allowed ... verifiers MUST accept either."
  `decodeBase64Field` (attestation/dsse/envelope_json.go:95-110) tries the
  standard alphabet, then the URL-safe one. `either_reads_url_as_std` proves
  that reading a character through either alphabet gives the URL-safe
  spelling of any standard-alphabet encoding the same sextet sequence as the
  standard spelling, so both decode to the same bytes; the `alphabet` vectors
  hold `decodeBase64Field` to that on real byte strings.
-/
import DsseIntoto.Statement

namespace DsseIntoto

/-! ### Sidecar acceptance -/

/-- The decoded payload, by what `decodeSidecarEnvelope` can read from it. -/
inductive SidecarPayload where
  | empty                 -- zero bytes
  | notJson               -- not JSON at all
  | noPredicateType       -- a JSON object without `predicateType`
  | emptyPredicateType    -- `"predicateType": ""`
  | nonStringPredicateType -- `"predicateType": 5`
  | nullJson              -- the JSON literal null
  | statement             -- an object with a non-empty string `predicateType`
deriving DecidableEq, Repr

structure SidecarJson where
  env : EnvJson
  payload : SidecarPayload
deriving DecidableEq, Repr

def payloadNonEmpty : SidecarPayload → Bool
  | .empty => false
  | _ => true

/-- A payload is an in-toto statement naming a predicate type. -/
def namesPredicateType : SidecarPayload → Bool
  | .statement => true
  | _ => false

-- spec: DSSE envelope.md §Parsing rules "The following fields are REQUIRED and MUST be set, even if empty: `payload`, `payloadType`, `signature`, `signature.sig`."
-- spec: in-toto statement.md "predicateType ... REQUIRED"
def sidecarAccepts (s : SidecarJson) : Bool :=
  decodesReq s.env && payloadNonEmpty s.payload && !s.env.sigs.isEmpty && namesPredicateType s.payload

/-- Exactly what cilock admits as a sidecar: the envelope meets the DSSE
    parsing rules, and its payload is non-empty, it carries at least one
    signature, and the payload is a statement naming a predicate type. -/
theorem sidecarAccepts_iff (s : SidecarJson) :
    sidecarAccepts s = true ↔
      SpecDecodes s.env ∧ payloadNonEmpty s.payload = true ∧ s.env.sigs ≠ [] ∧
        namesPredicateType s.payload = true := by
  rw [← decodesReq_iff]
  unfold sidecarAccepts
  cases h : s.env.sigs <;> simp [Bool.and_eq_true, and_assoc]

/-- An accepted sidecar decodes under the DSSE rules and carries a signature
    and a named predicate type: the direction a caller relies on. -/
theorem sidecar_accepted_is_signed_statement (s : SidecarJson) (h : sidecarAccepts s = true) :
    SpecDecodes s.env ∧ s.env.sigs ≠ [] ∧ s.payload = .statement := by
  obtain ⟨hd, _, hs, hp⟩ := (sidecarAccepts_iff s).mp h
  refine ⟨hd, hs, ?_⟩
  cases hq : s.payload <;> simp_all [namesPredicateType]

/-- A URL-safe sidecar is accepted whenever its standard-alphabet twin is:
    the alphabet of the payload or a signature never decides acceptance. -/
theorem sidecar_url_safe_accepted (s : SidecarJson)
    (h : s.env.payload = .stdOnly) :
    sidecarAccepts { s with env := { s.env with payload := .urlOnly } } = sidecarAccepts s := by
  simp [sidecarAccepts, decodesReq, h, b64Either]

/-! ### Base64: either alphabet reads the URL-safe spelling as the standard one -/

def stdAlphabet : List Char :=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toList

def urlAlphabet : List Char :=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toList

def stdChar (n : Nat) : Char := stdAlphabet.getD (n % 64) 'A'
def urlChar (n : Nat) : Char := urlAlphabet.getD (n % 64) 'A'

/-- RFC 4648 §4 padded encoding over an alphabet. -/
def encodeWith (ch : Nat → Char) : List Nat → List Char
  | a :: b :: c :: rest =>
      [ch (a / 4), ch ((a % 4) * 16 + b / 16), ch ((b % 16) * 4 + c / 64), ch (c % 64)] ++ encodeWith ch rest
  | [a, b] => [ch (a / 4), ch ((a % 4) * 16 + b / 16), ch ((b % 16) * 4), '=']
  | [a] => [ch (a / 4), ch ((a % 4) * 16), '=', '=']
  | [] => []

def encodeStd : List Nat → List Char := encodeWith stdChar
def encodeUrl : List Nat → List Char := encodeWith urlChar

/-- The URL-safe alphabet differs from the standard one at 62 and 63 only. -/
def toUrl (c : Char) : Char :=
  if c = '+' then '-' else if c = '/' then '_' else c

def indexIn (alpha : List Char) (c : Char) : Option Nat := alpha.idxOf? c

/-- A character's sextet under `decodeBase64Field`: the standard alphabet
    first, then the URL-safe one. -/
def eitherIndex (c : Char) : Option Nat :=
  (indexIn stdAlphabet c).or (indexIn urlAlphabet c)

theorem urlAlphabet_eq : urlAlphabet = stdAlphabet.map toUrl := by decide

theorem urlChar_eq (n : Nat) : urlChar n = toUrl (stdChar n) := by
  unfold urlChar stdChar
  rw [urlAlphabet_eq, List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases (stdAlphabet[n % 64]?) with
  | none => decide
  | some x => rfl

theorem encodeUrl_eq (bs : List Nat) : encodeUrl bs = (encodeStd bs).map toUrl := by
  unfold encodeUrl encodeStd
  induction bs using encodeWith.induct with
  | case1 a b c rest ih => simp [encodeWith, urlChar_eq, ih]
  | case2 a b => simp [encodeWith, urlChar_eq, toUrl]
  | case3 a => simp [encodeWith, urlChar_eq, toUrl]
  | case4 => rfl

theorem eitherIndex_toUrl (c : Char) : eitherIndex (toUrl c) = eitherIndex c := by
  unfold toUrl
  by_cases h1 : c = '+'
  · subst h1; decide
  · by_cases h2 : c = '/'
    · subst h2; decide
    · simp [h1, h2]

/-- Reading the URL-safe spelling of any byte string through either alphabet
    gives the standard spelling's sextets and padding, position by position,
    so the two decode to the same bytes. -/
theorem either_reads_url_as_std (bs : List Nat) :
    (encodeUrl bs).map eitherIndex = (encodeStd bs).map eitherIndex := by
  rw [encodeUrl_eq, List.map_map]
  exact List.map_congr_left (fun c _ => eitherIndex_toUrl c)

end DsseIntoto
