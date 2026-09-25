-- cite: attestation/policy/step.go:849-988 sha256:a18742f78af1678e05cc6b218b3a93e8d24d8bca30c5cc514a2ac80ddcbcf8f3
-- cite: attestation/policy/policy.go:1573-1681 sha256:1b79f611b8a198919d34cddb46fdeb31c9ca217d1679accd96d00228dc1f69fa
-- cite: attestation/policy/policy.go:1690-1720 sha256:5794395b282f761bdc2c31ed4c80b90f125ea247f1e2b69464af9f8c8b6e7f3a
-- cite: attestation/policy/step.go:491-496 sha256:351b4b76ec382062d9d27820da19248c21615a0b0b689b0a5cca2805348efffc
-- cite: attestation/policy/policy.go:584-706 sha256:dc2019e56013693292e074dcf46a13383fb1202cec8a9cd346f41b682db4d1a1
/-
  CilockEvaluators.Gate: how evaluator verdicts combine.

  * the per-collection step gate `gateOneContext` (step.go);
  * the per-envelope external gate (policy.go) and the external
    result (policy.go, step.go);
  * the verdict aggregation of `VerifyWithExternals` (policy.go).

  Trust and linking (functionaries, signatures, subject search, cross-step
  artifact linking) are NOT modelled here: they belong to the cilock-policy
  model. They enter as inputs: a collection handed to the gate has already
  passed functionary validation, and a step's `analyze`/`hasPassed` bits are
  whatever trust + linking + this gate produced.
-/
import CilockEvaluators.Rego
import CilockEvaluators.Ai

namespace CilockEvaluators.Gate

open CilockEvaluators

-- cite: attestation/policy/step.go:891-913 sha256:66913ac0d392989382e998f0ca3390faefb130f1601e42332f77822160e33316
/-- One attestor inside a collection. `type` is its attestation type URI
(the legacy-alias lookup of step.go is abstracted away: `type` is
already the matched URI). -/
structure Attestor where
  ref : Nat
  type : String
  deriving DecidableEq, Repr

-- cite: attestation/policy/step.go:878-883 sha256:324819cb96f168941ea7d83daabc3d4763e6ffef6233447119460c4a998a3b43
/-- A functionary-authorised collection as the gate receives it. `errors` is
`collection.Errors` non-empty (step.go). -/
structure Collection where
  name : String
  errors : Bool
  attestors : List Attestor
  deriving DecidableEq, Repr

-- cite: attestation/policy/step.go:238-242 sha256:e5a7ca0bacf2e8bc2d6cdb93e579d2eacd4b25db87bf0283aadde46f3de646ca
/-- One required attestation of a step (`Attestation`, step.go). -/
structure Expected where
  type : String
  rego : List Rego.Module
  ai : List Ai.AiPolicy
  deriving DecidableEq, Repr

structure Step where
  name : String
  expected : List Expected
  deriving DecidableEq, Repr

/-- The two evaluators as functions of (attestor, expectation). In the running
system they are `Rego.eval` and `Ai.gate`; here they are parameters so the
combinator theorems hold for ANY evaluator, and the instantiated theorem
below plugs the real ones in. -/
structure Evaluators where
  rego : Attestor → Expected → Verdict
  ai : Attestor → Expected → Verdict

-- cite: attestation/policy/step.go:885-897 sha256:82035c8327f1d340396c631341ff570b17f9286c99646996a9cc47ba625f1229
/-- Every attestor of the expected type; ALL of them, not the last one
(step.go, "G (#5747)"). -/
def attestorsOf (c : Collection) (t : String) : List Attestor :=
  c.attestors.filter (fun a => a.type == t)

-- cite: attestation/policy/step.go:922-929 sha256:72f155f4a6c7cb2f3bc45a844f2e2ce37a2e98b79bb85bcc2c07d26d21f0fe3c
/-- Verdicts produced for one attestor. AI runs only when Rego passed: a
deterministic rejection is not disclosed to a provider (step.go). -/
def attestorVerdicts (ev : Evaluators) (a : Attestor) (e : Expected) : List Verdict :=
  match ev.rego a e with
  | .pass => [.pass, ev.ai a e]
  | v => [v]

inductive Outcome where
  | wrongName
  | passed
  /-- `refused`: some reason is an AI refusal (`ErrAIEvaluationRefused`). -/
  | rejected (refused : Bool)
  deriving DecidableEq, Repr

/-- Every verdict for this attestor passes. -/
def attPass (ev : Evaluators) (a : Attestor) (e : Expected) : Bool :=
  (attestorVerdicts ev a e).all Verdict.passes

def attestorOk (ev : Evaluators) (c : Collection) (e : Expected) : Bool :=
  !(attestorsOf c e.type).isEmpty && (attestorsOf c e.type).all (fun a => attPass ev a e)

def anyRefused (ev : Evaluators) (c : Collection) (s : Step) : Bool :=
  s.expected.any (fun e => (attestorsOf c e.type).any
    (fun a => (attestorVerdicts ev a e).any (fun v => v == .refused)))

-- cite: attestation/policy/step.go:849-988 sha256:a18742f78af1678e05cc6b218b3a93e8d24d8bca30c5cc514a2ac80ddcbcf8f3
-- cite: attestation/policy/step.go:855-858 sha256:2e634f1aa948679a297ead28197c9e38d1f45a71bc5784800b0b355fde847122
-- cite: attestation/policy/step.go:868-876 sha256:89df68265d5e72f6745d75a94e8a3cf7832c739989594eb18f5ca7b84f31c08d
-- cite: attestation/policy/step.go:878-883 sha256:324819cb96f168941ea7d83daabc3d4763e6ffef6233447119460c4a998a3b43
-- cite: attestation/policy/step.go:906-914 sha256:5b1c9fe372bf6b19bdc15ca4eec5bb76c8b202999b85531065ff93a166476120
-- cite: attestation/policy/step.go:919-957 sha256:f6e1f71385979482dfc5e4f16a968b20d1457d735bcb2f1243c005d5ab7a525f
/-- `gateOneContext` (step.go):
* exact step-name match, else skipped (step.go);
* no required attestations: rejected (F9, step.go);
* collection errors: rejected (step.go);
* a required type with no attestor: rejected (step.go);
* every attestor of every required type must pass Rego and AI (step.go). -/
def gate (ev : Evaluators) (s : Step) (c : Collection) : Outcome :=
  if c.name != s.name then .wrongName
  else if !s.expected.isEmpty && !c.errors && s.expected.all (attestorOk ev c) then .passed
  else .rejected (anyRefused ev c s)

theorem attestorVerdicts_pass (ev : Evaluators) (a : Attestor) (e : Expected) :
    attPass ev a e = true ↔ ev.rego a e = .pass ∧ ev.ai a e = .pass := by
  unfold attPass attestorVerdicts
  cases h : ev.rego a e <;> cases h2 : ev.ai a e <;> simp [Verdict.passes]

/-- E2, exact as-built combinator: a collection passes the step gate iff it is
named for the step, the step requires something, the collection carries no
verification errors, every required type is present, and EVERY attestor of
EVERY required type passes EVERY Rego module and EVERY AI policy. -/
theorem gate_passed_iff (ev : Evaluators) (s : Step) (c : Collection) :
    gate ev s c = .passed ↔
      c.name = s.name ∧ s.expected ≠ [] ∧ c.errors = false ∧
        ∀ e ∈ s.expected, attestorsOf c e.type ≠ [] ∧
          ∀ a ∈ attestorsOf c e.type, ev.rego a e = .pass ∧ ev.ai a e = .pass := by
  unfold gate
  by_cases hn : c.name = s.name
  · simp only [hn, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, true_and]
    by_cases hok : (!s.expected.isEmpty && !c.errors && s.expected.all (attestorOk ev c)) = true
    · simp only [hok, ↓reduceIte, true_iff]
      simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, List.isEmpty_eq_false_iff,
        List.all_eq_true] at hok
      obtain ⟨⟨hne, herr⟩, hall⟩ := hok
      refine ⟨hne, herr, fun e he => ?_⟩
      have := hall e he
      simp only [attestorOk, Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true,
        List.isEmpty_eq_false_iff, List.all_eq_true, attestorVerdicts_pass] at this
      exact this
    · simp only [hok, Bool.false_eq_true, ↓reduceIte, reduceCtorEq, false_iff]
      intro ⟨hne, herr, hall⟩
      apply hok
      simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, List.isEmpty_eq_false_iff,
        List.all_eq_true]
      refine ⟨⟨hne, herr⟩, fun e he => ?_⟩
      simp only [attestorOk, Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true,
        List.isEmpty_eq_false_iff, List.all_eq_true, attestorVerdicts_pass]
      exact hall e he
  · have : (c.name != s.name) = true := by simpa using hn
    simp only [this, ↓reduceIte, reduceCtorEq, false_iff]
    intro ⟨h, _⟩
    exact hn h

/-- E1 lifted to the gate: any non-pass verdict from any evaluator on any
attestor of a required type rejects the collection. -/
theorem gate_fail_closed (ev : Evaluators) (s : Step) (c : Collection)
    (e : Expected) (he : e ∈ s.expected) (a : Attestor) (ha : a ∈ attestorsOf c e.type)
    (hbad : ev.rego a e ≠ .pass ∨ ev.ai a e ≠ .pass) : gate ev s c ≠ .passed := by
  intro h
  obtain ⟨_, _, _, hall⟩ := (gate_passed_iff ev s c).1 h
  obtain ⟨hr, hai⟩ := (hall e he).2 a ha
  rcases hbad with hb | hb
  · exact hb hr
  · exact hb hai

-- cite: attestation/policy/step.go:885-897 sha256:82035c8327f1d340396c631341ff570b17f9286c99646996a9cc47ba625f1229
-- cite: attestation/policy/step.go:917-921 sha256:918c758b7eaa53c475ca2177541850489a24e0dc6b33a6f7e8f1d59380f1dcda
/-- No last-writer-wins: a passing duplicate cannot shadow a failing attestor
of the same type (step.go). -/
theorem no_shadowing (ev : Evaluators) (s : Step) (c : Collection) (e : Expected)
    (he : e ∈ s.expected) (good bad : Attestor)
    (hbad : bad ∈ attestorsOf c e.type) (_hgood : good ∈ attestorsOf c e.type)
    (_hg : ev.rego good e = .pass ∧ ev.ai good e = .pass) (hb : ev.rego bad e ≠ .pass) :
    gate ev s c ≠ .passed :=
  gate_fail_closed ev s c e he bad hbad (Or.inl hb)

-- cite: attestation/policy/policy.go:1545-1720 sha256:c644a9688eeb9e49835662fd765db0e6ff5ad14891aff4b47a6d8d5449f08e15
/-! ## External attestations (policy.go) -/

/-- One candidate envelope for an external, as the external gate sees it. -/
structure Envelope where
  -- cite: attestation/policy/policy.go:1579-1579 sha256:a66860576a2118541df86481df475f9f83f3a31cc93666bfcc6fd6cba3e4cc33
  /-- The source reported envelope errors and no verifier (policy.go). -/
  sigErrors : Bool
  -- cite: attestation/policy/policy.go:1579-1590 sha256:f100b55459c88dd720341e0520bbfce7ea9953388dbc3c2b1340ff49ff4c60f0
  /-- Those errors say the signed subjects do not name the requested
  subject (`ErrExternalSubjectNotRequested`, policy.go). -/
  subjectUnbound : Bool
  -- cite: attestation/policy/policy.go:1598-1605 sha256:0388008112c7147138a6b85c5c6f053958a1caf288ec3136b9513174b4d03a01
  /-- A commit binding is set and this envelope is not bound to it (policy.go). -/
  commitUnbound : Bool
  -- cite: attestation/policy/policy.go:1607-1629 sha256:3d7451637b78f22c6030209644d05f5fbc032ec6864f6d72a1fb2a1b58fdba14
  /-- Some verifier matched some functionary (policy.go). -/
  signerAllowed : Bool
  hasAttestor : Bool
  regoV : Verdict
  aiV : Verdict
  deriving DecidableEq, Repr

inductive EnvOutcome where
  | unbound
  | rejected (refused : Bool)
  | passed
  deriving DecidableEq, Repr

def envGate (e : Envelope) : EnvOutcome :=
  if e.sigErrors then (if e.subjectUnbound then .unbound else .rejected false)
  else if e.commitUnbound then .unbound
  else if !e.signerAllowed then .rejected false
  else if !e.hasAttestor then .rejected false
  else if e.regoV != .pass then .rejected false
  else if e.aiV != .pass then .rejected (e.aiV == .refused)
  else .passed

theorem envGate_passed_iff (e : Envelope) :
    envGate e = .passed ↔
      e.sigErrors = false ∧ e.commitUnbound = false ∧ e.signerAllowed = true ∧
        e.hasAttestor = true ∧ e.regoV = .pass ∧ e.aiV = .pass := by
  unfold envGate
  cases e.sigErrors <;> cases e.commitUnbound <;> cases e.signerAllowed <;> cases e.hasAttestor <;>
    simp <;> (try split) <;> simp_all <;> (try split) <;> simp_all

-- cite: attestation/policy/policy.go:1686-1720 sha256:05d4dee43d5f3e206825b5479a8776c448139abafdb33decae8644514cc50583
-- cite: attestation/policy/step.go:491-496 sha256:351b4b76ec382062d9d27820da19248c21615a0b0b689b0a5cca2805348efffc
/-- What one external yields (policy.go, step.go). -/
inductive ExtOutcome where
  /-- required and nothing bound was found: `ErrMissingExternalAttestation`. -/
  | missing
  /-- required, candidates found, all rejected: `ErrExternalAttestationRejected`. -/
  | allRejected
  /-- optional and nothing bound was found. -/
  | skipped
  /-- a result; `refusedOnly` marks no pass and some AI refusal. -/
  | result (passed : Bool) (refusedOnly : Bool)
  deriving DecidableEq, Repr

def isPassed : EnvOutcome → Bool
  | .passed => true
  | _ => false

def isRejected : EnvOutcome → Bool
  | .rejected _ => true
  | _ => false

def isRefusedRej : EnvOutcome → Bool
  | .rejected true => true
  | _ => false

def external (required : Bool) (envs : List Envelope) : ExtOutcome :=
  let outs := envs.map envGate
  let anyPass := outs.any isPassed
  let anyRej := outs.any isRejected
  if !anyPass && !anyRej then (if required then .missing else .skipped)
  else if !anyPass && required then .allRejected
  else .result anyPass (!anyPass && outs.any isRefusedRej)

/-- An external contributes a pass only through an envelope that passed the
envelope gate, that is, one whose signer was allowed and whose Rego and AI
evaluators both passed. -/
theorem external_pass_has_witness (required : Bool) (envs : List Envelope) (r : Bool)
    (h : external required envs = .result true r) :
    ∃ e ∈ envs, envGate e = .passed := by
  unfold external at h
  simp only at h
  split at h
  · split at h <;> simp at h
  · split at h
    · simp at h
    · simp only [ExtOutcome.result.injEq] at h
      obtain ⟨hp, _⟩ := h
      simp only [List.any_eq_true, List.mem_map] at hp
      obtain ⟨o, ⟨e, he, heo⟩, ho⟩ := hp
      refine ⟨e, he, ?_⟩
      rw [heo]
      cases o <;> simp_all [isPassed]

-- cite: attestation/policy/policy.go:584-706 sha256:dc2019e56013693292e074dcf46a13383fb1202cec8a9cd346f41b682db4d1a1
/-! ## Aggregation (`VerifyWithExternals`, policy.go) -/

/-- A step's result as the aggregation reads it. `analyze` is
`StepResult.Analyze()`; `hasPassed` is `HasPassed()`; `refusal` says some
rejected collection's reason is an AI refusal. These come from the trust +
linking model and from `gate` above. -/
structure StepSummary where
  analyze : Bool
  hasPassed : Bool
  refusal : Bool
  deriving DecidableEq, Repr

/-- The verify outcome.
* `accepted b`: `Verify` returned `(b, _, nil)`, a completed verdict;
* `failed refusal`: `Verify` returned an error (`refusal`: the error is an
  `ErrAIEvaluationRefused`). -/
inductive VerifyOutcome where
  | accepted (pass : Bool)
  | failed (refusal : Bool)
  deriving DecidableEq, Repr

def isExtErr : ExtOutcome → Bool
  | .missing | .allRejected => true
  | _ => false

def extAnalyze : ExtOutcome → Bool
  | .skipped => true
  | .result p _ => p
  | _ => false

def extVerified : ExtOutcome → Bool
  | .skipped => false
  | _ => true

def extRefused : ExtOutcome → Bool
  | .result false true => true
  | _ => false

-- cite: attestation/policy/policy.go:585-617 sha256:27f001d6875f02cd73cb841431156637b283c92056cad3d25d59d510ea8650a3
/-- `policyOk` covers everything before evaluation: options, expiry,
`Validate`, `checkStepAbout`, trust bundles (policy.go). -/
def verify (policyOk : Bool) (steps : List StepSummary) (exts : List ExtOutcome) : VerifyOutcome :=
  if !policyOk then .failed false
  -- cite: attestation/policy/policy.go:627-633 sha256:7b1b49f34a123318a43cca7eb3be5635269f821434f706cafbf4c1ca7bc6113f
  else if exts.any isExtErr then .failed false                                   -- policy.go
  else if steps.any (fun s => !s.hasPassed && s.refusal) || exts.any extRefused
    -- cite: attestation/policy/policy.go:646-648 sha256:933f639fffb9e3fe1432919165b72b194ac14b5f681f816c01cd4f471a7e76ed
    -- cite: attestation/policy/policy.go:683-706 sha256:a8588ac8fed5e41bd25bde0f7b6072643a83fc775baec4aa51eb402ac7230d2c
    then .failed true                                                            -- policy.go
  else .accepted (steps.all StepSummary.analyze && exts.all extAnalyze &&
      -- cite: attestation/policy/policy.go:657-676 sha256:693fa1ad33c7238fb5ebc6a4cd223d39c6f35f4fadab72b083a34c3a52778283
      (!steps.isEmpty || exts.any extVerified))                                  -- policy.go

-- cite: attestation/policy/policy.go:657-676 sha256:693fa1ad33c7238fb5ebc6a4cd223d39c6f35f4fadab72b083a34c3a52778283
/-- A completed passing verdict needs every step to analyze true, every
external to analyze true, and at least one real obligation (no vacuous pass,
GHSA-rgp5-33mp-jhfm, policy.go). -/
theorem verify_accepts_iff (policyOk : Bool) (steps : List StepSummary) (exts : List ExtOutcome) :
    verify policyOk steps exts = .accepted true ↔
      policyOk = true ∧ (∀ x ∈ exts, isExtErr x = false) ∧
        (∀ s ∈ steps, ¬ (s.hasPassed = false ∧ s.refusal = true)) ∧ (∀ x ∈ exts, extRefused x = false) ∧
        (∀ s ∈ steps, s.analyze = true) ∧ (∀ x ∈ exts, extAnalyze x = true) ∧
        (steps ≠ [] ∨ ∃ x ∈ exts, extVerified x = true) := by
  unfold verify
  cases hp : policyOk <;> simp only [Bool.not_false, Bool.not_true, Bool.false_eq_true, ↓reduceIte,
    reduceCtorEq, false_and, true_and, false_iff, not_false_eq_true]
  by_cases h1 : exts.any isExtErr = true
  · simp only [h1, ↓reduceIte, reduceCtorEq, false_iff, not_and]
    intro hn
    simp only [List.any_eq_true] at h1
    obtain ⟨x, hx, hxe⟩ := h1
    rw [hn x hx] at hxe; cases hxe
  · simp only [h1, Bool.false_eq_true, ↓reduceIte]
    have h1' : ∀ x ∈ exts, isExtErr x = false := by
      intro x hx; simp only [List.any_eq_true, not_exists, not_and, Bool.not_eq_true] at h1; exact h1 x hx
    by_cases h2 : (steps.any (fun s => !s.hasPassed && s.refusal) || exts.any extRefused) = true
    · simp only [h2, ↓reduceIte, reduceCtorEq, false_iff, not_and]
      intro _ hs hx
      simp only [Bool.or_eq_true, List.any_eq_true, Bool.and_eq_true, Bool.not_eq_eq_eq_not,
        Bool.not_true] at h2
      rcases h2 with ⟨s, hs', hsp, hsr⟩ | ⟨x, hx', hxr⟩
      · exact (hs s hs' hsp hsr).elim
      · rw [hx x hx'] at hxr; cases hxr
    · simp only [h2, Bool.false_eq_true, ↓reduceIte, VerifyOutcome.accepted.injEq]
      simp only [Bool.or_eq_true, List.any_eq_true, Bool.and_eq_true, Bool.not_eq_eq_eq_not,
        Bool.not_true, not_or, not_exists, not_and, Bool.not_eq_true] at h2
      obtain ⟨h2a, h2b⟩ := h2
      simp only [Bool.and_eq_true, List.all_eq_true, Bool.or_eq_true, Bool.not_eq_eq_eq_not,
        Bool.not_true, List.isEmpty_eq_false_iff, List.any_eq_true]
      constructor
      · intro ⟨⟨ha, hb⟩, hc⟩
        refine ⟨h1', fun s hs ⟨hsp, hsr⟩ => ?_, h2b, ha, hb, hc⟩
        have := h2a s hs hsp; rw [hsr] at this; cases this
      · intro ⟨_, _, _, ha, hb, hc⟩
        exact ⟨⟨ha, hb⟩, hc⟩

/-- A refusal never becomes a completed verdict, pass or fail. -/
theorem refusal_is_not_a_verdict (policyOk : Bool) (steps : List StepSummary) (exts : List ExtOutcome)
    (s : StepSummary) (hs : s ∈ steps) (hnp : s.hasPassed = false) (hr : s.refusal = true)
    (hext : ∀ x ∈ exts, isExtErr x = false) (hpol : policyOk = true) :
    verify policyOk steps exts = .failed true := by
  unfold verify
  have h1 : exts.any isExtErr = false := by
    simp only [List.any_eq_false]; intro x hx; simp [hext x hx]
  have h2 : (steps.any (fun s => !s.hasPassed && s.refusal) || exts.any extRefused) = true := by
    simp only [Bool.or_eq_true, List.any_eq_true]
    exact Or.inl ⟨s, hs, by simp [hnp, hr]⟩
  simp [hpol, h1, h2]

/-! ## The instantiated statement: the real evaluators plugged in -/

/-- The evaluators are the modelled ones: Rego is `Rego.eval` over the
attestation's modules under some OPA run, AI is `Ai.gate` over the
attestation's AI policies under some provider outcome that satisfies the
provider contract (discharged for both in-tree providers by
`Ai.ollama_contract` and `Ai.jev_contract`). -/
structure RealEvaluators (ev : Evaluators) : Prop where
  rego : ∀ a e, ∃ rd run, ev.rego a e = Rego.eval rd e.rego run ∧
    (ev.rego a e = .pass → e.rego = [] ∨ ∀ m ∈ e.rego, run.deny m.pkg = .collection 0)
  ai : ∀ a e, ∃ out, Ai.Contract e.ai out ∧ ev.ai a e = Ai.gate e.ai out ∧
    (ev.ai a e = .pass → e.ai = [] ∨ (out.rs.length = e.ai.length ∧ ∀ r ∈ out.rs, r.status = "PASS"))

/-- Build `RealEvaluators` from the model functions. -/
theorem realEvaluators_of (ev : Evaluators)
    (hr : ∀ a e, ∃ rd run, ev.rego a e = Rego.eval rd e.rego run)
    (ha : ∀ a e, ∃ out, Ai.Contract e.ai out ∧ ev.ai a e = Ai.gate e.ai out) :
    RealEvaluators ev where
  rego a e := by
    obtain ⟨rd, run, h⟩ := hr a e
    refine ⟨rd, run, h, fun hp => ?_⟩
    rw [h] at hp
    rcases (Rego.eval_pass_iff rd e.rego run).1 hp with h' | ⟨_, _, _, h'⟩
    · exact Or.inl h'
    · exact Or.inr h'
  ai a e := by
    obtain ⟨out, hc, h⟩ := ha a e
    refine ⟨out, hc, h, fun hp => ?_⟩
    rw [h] at hp
    exact Ai.gate_pass_all_pass e.ai out hc hp

/-- **evaluators_fail_closed.** A collection passes the step gate only if, for
every required attestation and every attestor of its type, every Rego module
yielded an empty `deny` and every AI policy was answered with a literal
`PASS`, one per policy. No error, timeout, undefined `deny`, malformed reply,
provider outage, refusal or unparseable typed answer can produce a pass. -/
theorem evaluators_fail_closed (ev : Evaluators) (hreal : RealEvaluators ev)
    (s : Step) (c : Collection) (h : gate ev s c = .passed) :
    c.name = s.name ∧ s.expected ≠ [] ∧ c.errors = false ∧
      ∀ e ∈ s.expected, attestorsOf c e.type ≠ [] ∧ ∀ a ∈ attestorsOf c e.type,
        ev.rego a e = .pass ∧ ev.ai a e = .pass ∧
        (e.rego = [] ∨ ∃ rd run, ev.rego a e = Rego.eval rd e.rego run ∧
          ∀ m ∈ e.rego, run.deny m.pkg = .collection 0) ∧
        (e.ai = [] ∨ ∃ out, ev.ai a e = Ai.gate e.ai out ∧
          out.rs.length = e.ai.length ∧ ∀ r ∈ out.rs, r.status = "PASS") := by
  obtain ⟨hn, hne, herr, hall⟩ := (gate_passed_iff ev s c).1 h
  refine ⟨hn, hne, herr, fun e he => ⟨(hall e he).1, fun a ha => ?_⟩⟩
  obtain ⟨hr, hai⟩ := (hall e he).2 a ha
  refine ⟨hr, hai, ?_, ?_⟩
  · obtain ⟨rd, run, hev, himp⟩ := hreal.rego a e
    rcases himp hr with h' | h'
    · exact Or.inl h'
    · exact Or.inr ⟨rd, run, hev, h'⟩
  · obtain ⟨out, _, hev, himp⟩ := hreal.ai a e
    rcases himp hai with h' | h'
    · exact Or.inl h'
    · exact Or.inr ⟨out, hev, h'⟩

end CilockEvaluators.Gate
