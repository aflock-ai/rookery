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
-- cite: attestation/policy/policy.go:759-788 sha256:cfee072d06f1ff6ddf0165b79bb2d570d5a311aadd37c14c29a8bb7bfb4800cf
-- cite: attestation/policy/regorefusal.go:19-44 sha256:51cefd7488b8b398e3a4d26166e15aa0eb3e9e548ff4e0cf5d65584b9f573a96
/-- The outcome of one evaluator run.

* `pass`    : the evaluator affirmatively admitted the input.
* `deny`    : a completed negative finding (Rego deny, AI answered FAIL).
* `error`   : no verdict (parse/compile/eval error, malformed reply).
* `refused` : no completed verdict because the evaluator refused to answer:
              an AI refusal (`ErrAIEvaluationRefused`, `ai_jev.go`) or a
              Rego evaluation that ran out of its deadline
              (`ErrRegoEvaluationRefused`, `regorefusal.go`, #9872). Kept
              apart from `error` because the verifier aggregates it
              differently (`policy.go`, `refusedAIResults`).

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
