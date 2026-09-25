/-
  DsseIntoto.Counterexamples: where the code at the pinned commit departs
  from the spec. Each is a closed term the kernel checks with `decide`; each
  names the issue that carries the fix.
-/
import DsseIntoto.Statement

namespace DsseIntoto

def objStmt : Statement := ⟨statementV01, [⟨"a", [("sha256", "ab")]⟩], "https://example.com/p/v1", .object⟩

/-- `NewStatement` signs the v0.1 `_type`. Known: #9827 (cilock collections
    move to v1 through `NewStatementV1`, #9879) and #9841 (platform-signed
    receipts and VSAs, held on v0.1 until every deployed verifier reads v1). -/
theorem ce_type_v01 :
    newStatement "https://example.com/p/v1" (some .object) [("a", [("sha256", "ab")])] = .ok objStmt ∧
      ¬ ConformsV1 objStmt := by
  refine ⟨by rfl, ?_⟩
  intro h; exact absurd h.1 (by decide)

/-- An empty predicateType is signed. -/
theorem ce_empty_predicateType :
    newStatement "" (some .object) [] = .ok ⟨statementV01, [], "", .object⟩ ∧
      ¬ ConformsV1Body ⟨statementV01, [], "", .object⟩ := by
  refine ⟨by rfl, ?_⟩
  intro h; exact h.2.1 rfl

/-- A predicate that is not a JSON object is signed. -/
theorem ce_predicate_array :
    newStatement "p" (some .array) [] = .ok ⟨statementV01, [], "p", .array⟩ ∧
      ¬ ConformsV1Body ⟨statementV01, [], "p", .array⟩ := by
  refine ⟨by rfl, ?_⟩
  intro h; exact absurd h.2.2 (by decide)

/-- A subject with no digest is signed. -/
theorem ce_subject_without_digest :
    newStatement "p" (some .object) [("a", [])] = .ok ⟨statementV01, [⟨"a", []⟩], "p", .object⟩ ∧
      ¬ ConformsV1Body ⟨statementV01, [⟨"a", []⟩], "p", .object⟩ := by
  refine ⟨by rfl, ?_⟩
  intro h; exact h.1 ⟨"a", []⟩ (by simp) rfl

/-- A foreign payload type and a foreign `_type` are read as an in-toto
    collection: the payload-type confusion DSSE's authenticated payloadType
    exists to stop. -/
def foreignEnv : RawEnv :=
  ⟨"application/vnd.aflock.policy+json", some ⟨"https://example.com/NotAStatement", "https://aflock.ai/attestation-collection/v0.1", true⟩⟩

theorem ce_foreign_payload_type :
    toCollection foreignEnv = foreignEnv.payload ∧ ∀ d, ¬ SpecReads foreignEnv d := by
  refine ⟨by rfl, ?_⟩
  intro d h; exact absurd h.1 (by decide)

/-- The statement handed on for an external attestation is the source's, not
    the verified bytes': a source that decodes differently from what was
    signed changes what the policy reads. -/
def swapped : External :=
  ⟨⟨intotoPayloadType, some ⟨statementV1, "https://slsa.dev/provenance/v1", false⟩⟩,
   ⟨statementV1, "https://slsa.dev/verification_summary/v1", false⟩,
   ["https://slsa.dev/verification_summary/v1"]⟩

theorem ce_external_not_from_verified_bytes :
    externalRead swapped = some swapped.sourceStmt ∧ ¬ SameBytes swapped swapped.sourceStmt := by
  refine ⟨rfl, ?_⟩
  intro h
  have := h.1.2.1
  simp [swapped] at this

/-- Even an honest source's statement is accepted for an external it is not
    evidence of: nothing binds the signed predicateType to the search. -/
def unrequested : External :=
  ⟨⟨intotoPayloadType, some ⟨statementV1, "https://slsa.dev/provenance/v1", false⟩⟩,
   ⟨statementV1, "https://slsa.dev/provenance/v1", false⟩,
   ["https://slsa.dev/verification_summary/v1"]⟩

theorem ce_external_unrequested_type :
    externalRead unrequested = some unrequested.sourceStmt ∧ ¬ SameBytes unrequested unrequested.sourceStmt := by
  refine ⟨rfl, ?_⟩
  intro h
  have := h.2
  simp [unrequested] at this

/-- A URL-safe envelope, which the spec says a verifier MUST accept, is
    refused. -/
def urlSafe : EnvJson := ⟨true, true, true, .urlOnly, [(true, .urlOnly)]⟩

theorem ce_url_safe_refused : SpecDecodes urlSafe ∧ decodes urlSafe = false := by
  refine ⟨(decodesReq_iff urlSafe).mp (by decide), by decide⟩

/-- An envelope missing every REQUIRED field decodes. -/
def bare : EnvJson := ⟨false, false, true, .invalid, [(false, .invalid)]⟩

theorem ce_missing_fields_decode : decodes bare = true ∧ ¬ SpecDecodes bare := by
  refine ⟨by rfl, ?_⟩
  intro h; exact absurd h.1 (by decide)

end DsseIntoto
