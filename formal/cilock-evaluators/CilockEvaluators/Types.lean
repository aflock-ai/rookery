/-
  CilockEvaluators.Types: the shared vocabulary.

  Everything a later composed proof has to agree on lives in this one file:
  digests, subjects, policy digests, verifier identities, timestamps and the
  evaluator verdict. They are deliberately thin wrappers so a common library
  can replace this file by refinement without touching any proof: no proof
  here looks inside a `Digest` or a `VerifierIdentity`, it only compares them.
-/

namespace CilockEvaluators

/-- A content digest (for example the sha256 of exact bytes). Opaque here. -/
structure Digest where
  val : String
  deriving DecidableEq, Repr

-- cite: plugins/attestors/policyverify/policyverify.go:390-390 sha256:02839719c4e110bd96207a38909ffa2888e7722a322a8371f623ce1e38378b65
/-- The digest of the exact decoded policy DSSE payload bytes
(`policyverify.go`, `cryptoutil.CalculateDigestSetFromBytes(policyEnvelope.Payload, …)`). -/
abbrev PolicyDigest := Digest

/-- An artifact subject, named by digest. -/
structure Subject where
  digest : Digest
  deriving DecidableEq, Repr

/-- The identity that signed an envelope, as established by DSSE signature
verification plus a functionary match. It is never a field a signer writes
into its own payload. -/
structure VerifierIdentity where
  id : String
  deriving DecidableEq, Repr

/-- Seconds since the epoch. -/
abbrev Timestamp := Nat

-- cite: attestation/policy/ai_jev.go:35-45 sha256:fa89c682b1b70931f3ec4609129ace3190a81aaa4ca9640609dda9f266197b8a
-- cite: attestation/policy/policy.go:683-706 sha256:a8588ac8fed5e41bd25bde0f7b6072643a83fc775baec4aa51eb402ac7230d2c
/-- The outcome of one evaluator run.

* `pass`    : the evaluator affirmatively admitted the input.
* `deny`    : a completed negative finding (Rego deny, AI answered FAIL).
* `error`   : no verdict (parse/compile/eval error, timeout, malformed reply).
* `refused` : an AI provider produced no completed verdict
              (`ErrAIEvaluationRefused`, `ai_jev.go`). Kept apart from
              `error` because the verifier aggregates it differently
              (`policy.go`, `refusedAIResults`).

Fail-closed means: every constructor except `pass` rejects. -/
inductive Verdict where
  | pass
  | deny
  | error
  | refused
  deriving DecidableEq, Repr

/-- The only value that admits. -/
def Verdict.passes : Verdict → Bool
  | .pass => true
  | _ => false

theorem Verdict.passes_iff (v : Verdict) : v.passes = true ↔ v = .pass := by
  cases v <;> simp [Verdict.passes]

end CilockEvaluators
