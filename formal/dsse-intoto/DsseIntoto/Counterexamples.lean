/-
  DsseIntoto.Counterexamples: where the code at the pinned commit departed
  from the spec. Each is a closed term the kernel checks; each names the
  issue that carries the fix. `ce_type_v01` still holds of the code as built.
  The others were fixed by #10058, #10060 and #10057: each is now a theorem
  named for what the code does with that trace, stated against the as-built
  (`...Built` / `...Req`) definition, and it still carries the original
  counterexample, against the uncited pre-fix definition, as a conjunct.
-/
import DsseIntoto.Statement

namespace DsseIntoto

def objStmt : Statement := ⟨statementV01, [⟨"a", [("sha256", "ab")]⟩], "https://example.com/p/v1", .object⟩

/-- `NewStatement` signs the v0.1 `_type`, as built now (after #10058) as
    before. Known: #9827 (cilock collections move to v1 through
    `NewStatementV1`, #9879) and #9841 (platform-signed receipts and VSAs,
    held on v0.1 until every deployed verifier reads v1). -/
theorem ce_type_v01 :
    newStatementBuilt "https://example.com/p/v1" (some .object) [("a", [("sha256", "ab")])] = .ok objStmt ∧
      ¬ ConformsV1 objStmt := by
  refine ⟨by rfl, ?_⟩
  intro h; exact absurd h.1 (by decide)

/-- An empty predicateType is refused (#10058). Before #10058 it was signed
    (formerly `ce_empty_predicateType`: the second and third conjuncts). -/
theorem empty_predicateType_refused :
    newStatementBuilt "" (some .object) [] = .error .emptyPredicateType ∧
      newStatement "" (some .object) [] = .ok ⟨statementV01, [], "", .object⟩ ∧
      ¬ ConformsV1Body ⟨statementV01, [], "", .object⟩ := by
  refine ⟨by rfl, by rfl, ?_⟩
  intro h; exact h.2.1 rfl

/-- A predicate that is not a JSON object is refused (#10058). Before #10058
    it was signed (formerly `ce_predicate_array`). -/
theorem predicate_array_refused :
    newStatementBuilt "p" (some .array) [] = .error .predicateNotObject ∧
      newStatement "p" (some .array) [] = .ok ⟨statementV01, [], "p", .array⟩ ∧
      ¬ ConformsV1Body ⟨statementV01, [], "p", .array⟩ := by
  refine ⟨by rfl, by rfl, ?_⟩
  intro h; exact absurd h.2.2 (by decide)

/-- A subject with no digest is refused (#10058). Before #10058 it was
    signed (formerly `ce_subject_without_digest`). -/
theorem subject_without_digest_refused :
    newStatementBuilt "p" (some .object) [("a", [])] = .error .subjectWithoutDigest ∧
      newStatement "p" (some .object) [("a", [])] = .ok ⟨statementV01, [⟨"a", []⟩], "p", .object⟩ ∧
      ¬ ConformsV1Body ⟨statementV01, [⟨"a", []⟩], "p", .object⟩ := by
  refine ⟨by rfl, by rfl, ?_⟩
  intro h; exact h.1 ⟨"a", []⟩ (by simp) rfl

/-- A foreign payload type and a foreign `_type` are refused (#10060).
    Before #10060 they were read as an in-toto collection, the payload-type
    confusion DSSE's authenticated payloadType exists to stop (formerly
    `ce_foreign_payload_type`). -/
def foreignEnv : RawEnv :=
  ⟨"application/vnd.aflock.policy+json", some ⟨"https://example.com/NotAStatement", "https://aflock.ai/attestation-collection/v0.1", true⟩⟩

theorem foreign_payload_type_refused :
    toCollectionReq foreignEnv = none ∧
      toCollection foreignEnv = foreignEnv.payload ∧ ∀ d, ¬ SpecReads foreignEnv d := by
  refine ⟨by decide, by rfl, ?_⟩
  intro d h; exact absurd h.1 (by decide)

/-- A source whose decode differs from the signed bytes no longer decides
    what the policy reads (#10060): the verified bytes are decoded, they name
    a predicate type nobody asked for, and the candidate is refused. Before
    #10060 the source's decode was handed on (formerly
    `ce_external_not_from_verified_bytes`). -/
def swapped : External :=
  ⟨⟨intotoPayloadType, some ⟨statementV1, "https://slsa.dev/provenance/v1", false⟩⟩,
   ⟨statementV1, "https://slsa.dev/verification_summary/v1", false⟩,
   ["https://slsa.dev/verification_summary/v1"]⟩

theorem external_source_decode_not_handed_on :
    externalReadReq swapped = none ∧
      externalRead swapped = some swapped.sourceStmt ∧ ¬ SameBytes swapped swapped.sourceStmt := by
  refine ⟨by decide, rfl, ?_⟩
  intro h
  have := h.1.2.1
  simp [swapped] at this

/-- A signed statement of a predicate type the verifier did not search for
    is refused (#10060). Before #10060 even an honest source's statement was
    accepted for an external it is not evidence of (formerly
    `ce_external_unrequested_type`). -/
def unrequested : External :=
  ⟨⟨intotoPayloadType, some ⟨statementV1, "https://slsa.dev/provenance/v1", false⟩⟩,
   ⟨statementV1, "https://slsa.dev/provenance/v1", false⟩,
   ["https://slsa.dev/verification_summary/v1"]⟩

theorem external_unrequested_type_refused :
    externalReadReq unrequested = none ∧
      externalRead unrequested = some unrequested.sourceStmt ∧
      ¬ SameBytes unrequested unrequested.sourceStmt := by
  refine ⟨by decide, rfl, ?_⟩
  intro h
  have := h.2
  simp [unrequested] at this

/-- A URL-safe envelope, which the spec says a verifier MUST accept, is
    accepted (#10057). Before #10057 it was refused (formerly
    `ce_url_safe_refused`). -/
def urlSafe : EnvJson := ⟨true, true, true, .urlOnly, [(true, .urlOnly)]⟩

theorem url_safe_accepted :
    decodesReq urlSafe = true ∧ SpecDecodes urlSafe ∧ decodes urlSafe = false := by
  refine ⟨by decide, (decodesReq_iff urlSafe).mp (by decide), by decide⟩

/-- An envelope missing every REQUIRED field is refused (#10057). Before
    #10057 it decoded (formerly `ce_missing_fields_decode`). -/
def bare : EnvJson := ⟨false, false, true, .invalid, [(false, .invalid)]⟩

theorem missing_fields_refused :
    decodesReq bare = false ∧ decodes bare = true ∧ ¬ SpecDecodes bare := by
  refine ⟨by decide, by rfl, ?_⟩
  intro h; exact absurd h.1 (by decide)

end DsseIntoto
