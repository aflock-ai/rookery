-- cite: plugins/attestors/policyverify/policyverify.go:229-423 sha256:da4f17ffccbef061
-- cite: attestation/workflow/verify.go:326-352 sha256:a33f012b394cf59baaf640fb52e376b443f142dd03229b4e5b1e897f5fcd0244
-- cite: plugins/attestors/vsa/vsa.go:37-37 sha256:ea4b5f26d671802f212f2452002bcb25afa9797036154c0f16af56a2abc26f6f
-- cite: plugins/attestors/vsa/vsa.go:106-118 sha256:7945715445a34d85a477d13ab7fd9f0380f93322dc1a8ca1a5c62feaf2bff81f
/-
  CilockEvaluators.Vsa: Verification Summary Attestations.

  Emission: `policyverify.Attest` + `verificationSummaryFromResults`
  (plugins/attestors/policyverify/policyverify.go), surfaced by
  `workflow.Verify` (attestation/workflow/verify.go).

  Consumption: a downstream policy reads a VSA as an external attestation
  (predicate https://slsa.dev/verification_summary/v1, typed factory
  plugins/attestors/vsa/vsa.go). The typed factory decodes the
  predicate and checks nothing. Acceptance is the external-envelope gate of
  Gate.lean: signature, subject binding, functionary, the consumer's own Rego
  and AI policies. What a consumer learns about the upstream policy, result
  and time therefore depends on what its Rego checks. `ExactPolicyRego` below
  names that obligation.
-/
import CilockEvaluators.Gate

namespace CilockEvaluators.Vsa

open CilockEvaluators

inductive Result where
  | passed
  | failed
  deriving DecidableEq, Repr

-- cite: plugins/attestors/vsa/vsa.go:70-76 sha256:038d66464d69c9becc571e44b6db2068aab57824951a204e685fc9ab5e425a7f
-- cite: plugins/attestors/policyverify/policyverify.go:187-200 sha256:5f642ecb06bd65592bd29d065808ababc86bcc05b9f3d9ab6e50743ee805144c
/-- The predicate (attestation/slsa/verificationsummary.go; vsa.go) plus the
statement subjects (policyverify.go). -/
structure Vsa where
  subjects : List Subject
  policyUri : String
  policyDigest : PolicyDigest
  verifierId : String
  timeVerified : Timestamp
  inputs : List Digest
  result : Result
  deriving DecidableEq, Repr

/-- One upstream `cilock verify` as `policyverify.Attest` sees it. -/
structure Run where
  /-- The exact decoded DSSE payload bytes of the policy. -/
  policyPayload : String
  policyUri : String
  -- cite: plugins/attestors/policyverify/policyverify.go:223-225 sha256:c230b8950d74bf5783bd434f704317ee37284315367b906a68407c99177c937a
  /-- `policysig.VerifyPolicySignature` (policyverify.go). -/
  policySigOk : Bool
  -- cite: plugins/attestors/policyverify/policyverify.go:231-235 sha256:a524815bd4f3ac2bc1929a3fee8fe8d5d1c2e45b12153d6b18fa6c4cd6e0b0ce
  /-- `policy.DecodePolicyEnvelope` (policyverify.go). -/
  decodeOk : Bool
  seeds : List Subject
  outcome : Gate.VerifyOutcome
  now : Timestamp
  passedInputs : List Digest
  rejectedInputs : List Digest
  deriving DecidableEq, Repr

-- cite: plugins/attestors/policyverify/policyverify.go:223-235 sha256:abcc70a2863fac22524181ed79e94f76e7fff149c29fa316b2b55108f2911946
-- cite: plugins/attestors/policyverify/policyverify.go:299-308 sha256:bf3a0030348d8741f6be2781a75a0bead271fb58807c79f2e4956192bb0320a3
-- cite: plugins/attestors/policyverify/policyverify.go:395-398 sha256:6eb71cb8138ef3a45489c5b202f940a7db63391745ee1f3272531c5fb557a2db
-- cite: plugins/attestors/policyverify/policyverify.go:390-390 sha256:02839719c4e110bd96207a38909ffa2888e7722a322a8371f623ce1e38378b65
-- cite: plugins/attestors/policyverify/policyverify.go:401-403 sha256:f5d8b93d8f8bf66baf5b25836316dcd560aad5eb3ec940f8d4eb1f7802492c8b
-- cite: plugins/attestors/policyverify/policyverify.go:362-388 sha256:92a13498dd9b9d65b66f2f0af09ab4e837a490041d8ac95ef16a3c6fd9328f23
-- cite: plugins/attestors/policyverify/policyverify.go:187-200 sha256:5f642ecb06bd65592bd29d065808ababc86bcc05b9f3d9ab6e50743ee805144c
/-- `Attest` + `verificationSummaryFromResults`. `hash` is the digest function
over exact bytes.
* policy signature or decode failure: no VSA (policyverify.go);
* `Verify` returned an error (including an AI refusal): no VSA (policyverify.go);
* otherwise a VSA whose result is PASSED iff accepted (policyverify.go),
  whose policy digest is the digest of the exact payload (policyverify.go),
  whose verifier id is the constant "aflock" (policyverify.go),
  whose inputs are the passed collections plus, on failure, the rejected ones
  (policyverify.go), and whose subjects are the seeds plus the policy
  subject (policyverify.go). -/
def emit (hash : String → Digest) (r : Run) : Option Vsa :=
  if !r.policySigOk || !r.decodeOk then none
  else match r.outcome with
    | .failed _ => none
    | .accepted b => some
      { subjects := r.seeds ++ [⟨hash r.policyPayload⟩]
        policyUri := r.policyUri
        policyDigest := hash r.policyPayload
        verifierId := "aflock"
        timeVerified := r.now
        inputs := r.passedInputs ++ (if b then [] else r.rejectedInputs)
        result := if b then .passed else .failed }

theorem emit_refusal_none (hash : String → Digest) (r : Run) (b : Bool)
    (h : r.outcome = .failed b) : emit hash r = none := by
  unfold emit; split
  · rfl
  · rw [h]

/-- What an emitted VSA says about its run. -/
theorem emit_sound (hash : String → Digest) (r : Run) (v : Vsa) (h : emit hash r = some v) :
    r.policySigOk = true ∧ r.decodeOk = true ∧ v.policyDigest = hash r.policyPayload ∧
      v.timeVerified = r.now ∧ v.verifierId = "aflock" ∧
      (∀ s ∈ r.seeds, s ∈ v.subjects) ∧
      (v.result = .passed ↔ r.outcome = .accepted true) ∧
      (v.result = .failed ↔ r.outcome = .accepted false) := by
  unfold emit at h
  split at h
  · simp at h
  · rename_i hok
    simp only [Bool.or_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, not_or] at hok
    obtain ⟨hs, hd⟩ := hok
    have hs' : r.policySigOk = true := by simpa using hs
    have hd' : r.decodeOk = true := by simpa using hd
    split at h
    · simp at h
    · rename_i b hout
      simp only [Option.some.injEq] at h
      subst h
      refine ⟨hs', hd', rfl, rfl, rfl, fun s hs => by simp [hs], ?_, ?_⟩ <;>
        cases b <;> simp [hout]

/-! ## Consumption -/

-- cite: attestation/policy/policy.go:1807-1807 sha256:a66860576a2118541df86481df475f9f83f3a31cc93666bfcc6fd6cba3e4cc33
/-- A candidate VSA envelope in a downstream verify. `sigOk`: its DSSE
signature verified against the downstream policy's roots/keys, naming
`signer` (source/verified.go; policy.go). -/
structure Candidate where
  vsa : Vsa
  signer : VerifierIdentity
  sigOk : Bool
  deriving DecidableEq, Repr

-- cite: attestation/policy/policy.go:1807-1818 sha256:f100b55459c88dd720341e0520bbfce7ea9953388dbc3c2b1340ff49ff4c60f0
/-- The consumer's view of a candidate as a `Gate.Envelope`: signature errors
and subject-unbound both surface as envelope errors (policy.go);
no commit binding and no declared `commitSubject`, so `commitUnbound` is
false; the consumer's Rego over the predicate; its AI policies (none, for the
VSA gates modelled here). -/
def toEnvelope (allowed : VerifierIdentity → Bool) (requested : Subject) (consumer : Vsa → Verdict)
    (c : Candidate) : Gate.Envelope :=
  { sigErrors := !(c.sigOk && c.vsa.subjects.contains requested)
    subjectUnbound := !c.vsa.subjects.contains requested
    commitUnbound := false
    signerAllowed := allowed c.signer
    hasAttestor := true
    regoV := consumer c.vsa
    aiV := .pass }

/-- The downstream external gate accepts this VSA. -/
def accepts (allowed : VerifierIdentity → Bool) (requested : Subject) (consumer : Vsa → Verdict)
    (c : Candidate) : Prop :=
  Gate.envGate (toEnvelope allowed requested consumer c) = .passed

/-- The engine's own guarantees, whatever the consumer's Rego: a verified
signature, the requested subject among the signed subjects, an allowed
signer, and a passing consumer Rego. Nothing about the VSA's result, policy
digest or time is checked by the engine itself. -/
theorem accepts_iff (allowed : VerifierIdentity → Bool) (requested : Subject)
    (consumer : Vsa → Verdict) (c : Candidate) :
    accepts allowed requested consumer c ↔
      c.sigOk = true ∧ requested ∈ c.vsa.subjects ∧ allowed c.signer = true ∧
        consumer c.vsa = .pass := by
  unfold accepts
  rw [Gate.envGate_passed_iff]
  simp only [toEnvelope, Bool.not_eq_false', Bool.and_eq_true, List.contains_iff_mem, and_true,
    true_and]
  constructor
  · intro ⟨⟨h1, h2⟩, h3, h4⟩; exact ⟨h1, h2, h3, h4⟩
  · intro ⟨h1, h2, h3, h4⟩; exact ⟨⟨h1, h2⟩, h3, h4⟩

/-- Which identity produced which VSA body. Abstract: a relation on the world. -/
structure World where
  produced : VerifierIdentity → Vsa → Prop

/-- The trust assumptions, named and separate from every definition.

* `unforgeable`: a verified DSSE signature (Fulcio chain + TSA, or a pinned
  key) means `signer` produced exactly these bytes.
* `honestVerifier`: an identity the consumer allows signs only VSAs that
  `emit` produced from a real run of this verifier. This is where a consumer
  trusts the upstream verifier binary; nothing checks it cryptographically.
* `digestInjective`: collision resistance of the digest over exact bytes.

AI provider honesty is NOT assumed anywhere: the AI side is modelled as
fail-closed on every answer shape (Ai.lean), and `Ai.Contract`, once a
premise about the in-process provider code, is now enforced by
`EvaluateAIPolicyWithProvider` for any provider (`Ai.checked_contract`). -/
structure Assumptions (hash : String → Digest) (W : World) (allowed : VerifierIdentity → Bool) : Prop where
  unforgeable : ∀ c : Candidate, c.sigOk = true → W.produced c.signer c.vsa
  honestVerifier : ∀ id v, allowed id = true → W.produced id v → ∃ r, emit hash r = some v
  digestInjective : ∀ p q, hash p = hash q → p = q

/-- The consumer's Rego admits a VSA only when it reports PASSED, names
exactly the expected policy digest, and was produced inside the freshness
window ending at the consumer's `now`. -/
def ExactPolicyRego (consumer : Vsa → Verdict) (expected : PolicyDigest) (now window : Timestamp) : Prop :=
  ∀ v, consumer v = .pass →
    v.result = .passed ∧ v.policyDigest = expected ∧ v.timeVerified ≤ now ∧ now ≤ v.timeVerified + window

/-- **vsa_exact_policy_sound.** Under the assumptions, and for a consumer whose
Rego checks exact policy, result and freshness, an accepted VSA is about the
requested subject, was signed by an allowed verifier, reports PASSED, names
the byte-identical expected policy digest, and is fresh. -/
theorem vsa_exact_policy_sound (hash : String → Digest) (W : World)
    (allowed : VerifierIdentity → Bool) (A : Assumptions hash W allowed)
    (consumer : Vsa → Verdict) (expected : PolicyDigest) (now window : Timestamp)
    (hrego : ExactPolicyRego consumer expected now window)
    (requested : Subject) (c : Candidate) (h : accepts allowed requested consumer c) :
    requested ∈ c.vsa.subjects ∧ allowed c.signer = true ∧ W.produced c.signer c.vsa ∧
      c.vsa.result = .passed ∧ c.vsa.policyDigest = expected ∧
      c.vsa.timeVerified ≤ now ∧ now ≤ c.vsa.timeVerified + window := by
  obtain ⟨hsig, hsub, hal, hcons⟩ := (accepts_iff allowed requested consumer c).1 h
  obtain ⟨hres, hdig, ht1, ht2⟩ := hrego c.vsa hcons
  exact ⟨hsub, hal, A.unforgeable c hsig, hres, hdig, ht1, ht2⟩

/-- **E7, non-amplification.** Under the same premises an accepted VSA stands
for a real upstream run that ACCEPTED, under a policy whose exact payload has
the expected digest (so, by collision resistance, the byte-identical policy),
about the requested subject (as a seed, or as the policy subject itself). No
FAILED verdict and no other policy's verdict can stand in for it. -/
theorem vsa_non_amplification (hash : String → Digest) (W : World)
    (allowed : VerifierIdentity → Bool) (A : Assumptions hash W allowed)
    (consumer : Vsa → Verdict) (expected : PolicyDigest) (now window : Timestamp)
    (hrego : ExactPolicyRego consumer expected now window)
    (requested : Subject) (c : Candidate) (h : accepts allowed requested consumer c) :
    ∃ r : Run, emit hash r = some c.vsa ∧ r.outcome = .accepted true ∧ r.policySigOk = true ∧
      hash r.policyPayload = expected ∧
      (∀ p, hash p = expected → p = r.policyPayload) ∧
      (requested ∈ r.seeds ∨ requested = ⟨hash r.policyPayload⟩) := by
  obtain ⟨hsub, hal, hprod, hres, hdig, _, _⟩ :=
    vsa_exact_policy_sound hash W allowed A consumer expected now window hrego requested c h
  obtain ⟨r, hr⟩ := A.honestVerifier c.signer c.vsa hal hprod
  obtain ⟨hsig, _, hpd, _, _, _, hpass, _⟩ := emit_sound hash r c.vsa hr
  have hpayload : hash r.policyPayload = expected := by rw [← hpd, hdig]
  refine ⟨r, hr, hpass.1 hres, hsig, hpayload, fun p hp => A.digestInjective p _ (hp.trans hpayload.symm), ?_⟩
  -- the subjects of an emitted VSA are the seeds plus the policy subject
  unfold emit at hr
  split at hr
  · simp at hr
  · split at hr
    · simp at hr
    · simp only [Option.some.injEq] at hr
      rw [← hr] at hsub
      simp only [List.mem_append, List.mem_singleton] at hsub
      exact hsub

-- cite: plugins/attestors/policyverify/policyverify.go:198-198 sha256:807db86f672dff48c839b71ac0bcac20cfcf711c3c6be53f4fd014f58839b4d6
/-- The policy subject: every VSA of a policy names that policy's digest as a
subject (policyverify.go), so a verify seeded with a POLICY digest binds
to every VSA of that policy, whatever artifact it was about. -/
theorem policy_subject_matches_every_artifact (hash : String → Digest) (r₁ r₂ : Run) (v₁ v₂ : Vsa)
    (h₁ : emit hash r₁ = some v₁) (h₂ : emit hash r₂ = some v₂)
    (hp : r₁.policyPayload = r₂.policyPayload) :
    (⟨hash r₁.policyPayload⟩ : Subject) ∈ v₁.subjects ∧ (⟨hash r₁.policyPayload⟩ : Subject) ∈ v₂.subjects := by
  constructor
  · unfold emit at h₁; split at h₁
    · simp at h₁
    · split at h₁
      · simp at h₁
      · simp only [Option.some.injEq] at h₁; rw [← h₁]; simp
  · unfold emit at h₂; split at h₂
    · simp at h₂
    · split at h₂
      · simp at h₂
      · simp only [Option.some.injEq] at h₂; rw [← h₂, hp]; simp

end CilockEvaluators.Vsa
