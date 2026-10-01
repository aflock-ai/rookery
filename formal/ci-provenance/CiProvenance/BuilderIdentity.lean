import Lean.Data.Json

/-!
# SLSA builder.id against the signer's Fulcio Build Signer URI (#9827)

`checkSLSAProvenance` (attestation/policy/slsa_builder.go) runs on every
collection attestation (step gate) and every external candidate. Any type name
that is the pre-#9827 spelling `https://slsa.dev/provenance/v1.0` is refused
by name (Cole, 2026-09-29: no deprecation window). For SLSA provenance v1, a
`runDetails.builder.id` that names a CI
workflow identity (it contains `/.github/workflows/`, compared in lower case)
must equal the Fulcio Build Signer URI (OID 1.3.6.1.4.1.57264.1.9) of one of
the signers that satisfied the policy's functionaries. The provenance body is
written by whoever ran the attestor; only the certificate extension is
stamped by the CA from the CI platform's own OIDC token.

This is the verify-time half of `SlsaL3Workflow.builder_id_without_extension`:
there a verifier that compares builder.id without the certificate extension is
refuted; here the engine's check is modelled and bound to the Go by
`TestFormalDifferentialSLSABuilderIdentity` (attestation/policy).

-- cite: attestation/policy/slsa_builder.go:86-207 sha256:5fedaa9d9b10aa09963cba72d4b997fdc916da70aa4099d80a6f072bbfc82cc7

Modelling boundaries (stated in the README): lower-casing is ASCII, so a
builder.id whose only claim to the workflow path is a non-ASCII rune Go folds
to ASCII (the Kelvin sign) is outside the differential. The body is read by
exact key, as Rego reads `input.runDetails.builder.id`, and an object on that
path that also spells the key in another case is refused as ambiguous: Go's
struct decode would match it case-insensitively and keep the last match, so
the check and the policy would read different ids (Codex #10633 round 1). A
key repeated in its exact spelling is refused by the Go too, but `Json.parse`
keeps one of the two, so exact repeats are outside the differential.
-/

namespace CiProvenance.BuilderIdentity

open Lean (Json)

def specType : String := "https://slsa.dev/provenance/v1"
def legacyType : String := "https://slsa.dev/provenance/v1.0"

/-- The builder check applies when any name the attestation is known by is
SLSA provenance v1. The legacy spelling has no alias. -/
def isProvenance (types : List String) : Bool := types.any fun t => t == specType

/-- Any name the attestation is known by is the pre-#9827 spelling. -/
def isLegacy (types : List String) : Bool := types.any fun t => t == legacyType

def lowerAscii (s : String) : String := s.map Char.toLower

def containsSub (s sub : String) : Bool := go s.toList
where
  go : List Char → Bool
    | [] => sub.toList.isEmpty
    | c :: cs => sub.toList.isPrefixOf (c :: cs) || go cs

/-- builderIDClaimsWorkflowIdentity. -/
def claimsWorkflow (id : String) : Bool := containsSub (lowerAscii id) "/.github/workflows/"

/-- What decoding `{runDetails: {builder: {id}}}` into the Go struct yields. -/
inductive Builder where
  | absent            -- runDetails or builder absent or null: the check passes
  | malformed         -- a non-object runDetails/builder, a non-string id, a non-object body
  | ambiguous         -- a key on the path also spelled in another case
  | id (s : String)   -- the id ("" when absent or null)
  deriving Repr, DecidableEq

/-- Why the check refuses, or `none` when it admits. `signers` are the Build
Signer URIs of the verifiers that satisfied the functionaries ("" for one with
no such extension or no certificate). The legacy type is refused first, by
name, whatever the body or signers. -/
inductive Refusal where
  | legacyType
  | malformed
  | ambiguousKey
  | unbacked
  deriving Repr, DecidableEq

def refusal (types : List String) (b : Builder) (signers : List String) : Option Refusal :=
  if isLegacy types then some .legacyType
  else if !isProvenance types then none
  else match b with
    | .absent => none
    | .malformed => some .malformed
    | .ambiguous => some .ambiguousKey
    | .id s => if !claimsWorkflow s || signers.contains s then none else some .unbacked

def ok (types : List String) (b : Builder) (signers : List String) : Bool :=
  (refusal types b signers).isNone

def Refusal.name : Refusal → String
  | .legacyType => "legacy-type"
  | .malformed => "malformed"
  | .ambiguousKey => "ambiguous-key"
  | .unbacked => "unbacked"

/-! ## Decoding, by exact key, refusing case variants -/

def keyMatches (field k : String) : Bool := lowerAscii field == lowerAscii k

/-- One key of the builder.id path in one object. -/
inductive Member where
  | absent
  | ambiguous
  | val (j : Json)

/-- The exact key's value, or `ambiguous` when any other key equals it up to
case. -/
def member (kvs : List (String × Json)) (field : String) : Member :=
  if kvs.any (fun (k, _) => keyMatches field k && k != field) then .ambiguous
  else match kvs.find? (fun (k, _) => k == field) with
    | some (_, v) => .val v
    | none => .absent

def objFields : Json → Option (List (String × Json))
  | .obj kvs => some (kvs.toList.map fun ⟨k, v⟩ => (k, v))
  | _ => none

def decode (body : Json) : Builder :=
  match objFields body with
  | none => .malformed
  | some top =>
    match member top "runDetails" with
    | .ambiguous => .ambiguous
    | .absent | .val .null => .absent
    | .val rd =>
      match objFields rd with
      | none => .malformed
      | some rdf =>
        match member rdf "builder" with
        | .ambiguous => .ambiguous
        | .absent | .val .null => .absent
        | .val b =>
          match objFields b with
          | none => .malformed
          | some bf =>
            match member bf "id" with
            | .ambiguous => .ambiguous
            | .absent | .val .null => .id ""
            | .val (.str s) => .id s
            | .val _ => .malformed

/-! ## Results -/

/-- **non_provenance_passes**: the check never touches another predicate
type. -/
theorem non_provenance_passes (types : List String) (b : Builder) (sig : List String)
    (h1 : isLegacy types = false) (h2 : isProvenance types = false) : ok types b sig = true := by
  simp [ok, refusal, h1, h2]

/-- **legacy_refused**: provenance known by the pre-#9827 type is refused, by
name, whatever its body and signers. -/
theorem legacy_refused (types : List String) (b : Builder) (sig : List String)
    (h : isLegacy types = true) : refusal types b sig = some .legacyType := by
  simp [refusal, h]

/-- **legacy_never_admitted**: in particular it is never admitted. -/
theorem legacy_never_admitted (b : Builder) (sig : List String) : ok [legacyType] b sig = false := by
  simp [ok, refusal, isLegacy]

/-- **claim_is_backed**: an admitted provenance body whose builder.id claims a
workflow identity names exactly a satisfying signer's Build Signer URI. -/
theorem claim_is_backed (types : List String) (s : String) (sig : List String)
    (hp : isProvenance types = true) (hc : claimsWorkflow s = true) (h : ok types (.id s) sig = true) :
    s ∈ sig := by
  unfold ok refusal at h
  cases hl : isLegacy types <;> simp_all

/-- **malformed_refused**: spec-typed provenance whose builder cannot be
decoded is refused. -/
theorem malformed_refused (types : List String) (sig : List String)
    (hl : isLegacy types = false) (hp : isProvenance types = true) :
    refusal types .malformed sig = some .malformed := by
  simp [refusal, hl, hp]

/-- **ambiguous_refused**: spec-typed provenance that spells a key on the
builder.id path in two cases is refused, whatever its signers. -/
theorem ambiguous_refused (types : List String) (sig : List String)
    (hl : isLegacy types = false) (hp : isProvenance types = true) :
    refusal types .ambiguous sig = some .ambiguousKey := by
  simp [refusal, hl, hp]

/-- **no_signer_no_claim**: with no satisfying signer, no workflow-identity
claim is admitted. -/
theorem no_signer_no_claim (types : List String) (s : String)
    (hp : isProvenance types = true) (hc : claimsWorkflow s = true) :
    ok types (.id s) [] = false := by
  unfold ok refusal
  cases hl : isLegacy types <;> simp_all

end CiProvenance.BuilderIdentity
