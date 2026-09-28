-- cite: attestation/policy/step.go:900-1046 sha256:e4d08a4b43a4fc90595cff8e2f12d822928d5feb7b84e53278ef6481851a73d8
-- cite: attestation/policy/policy.go:1801-1923 sha256:2222517c484f8a32f45267cd7e946ad5ee6975ad98675f97543fcd1471cab371
-- cite: attestation/policy/policy.go:1930-1971 sha256:48e5293f2cc102e1f9594652dfb2ae9ecdea6e7fdbe38e652c6aebe2cdc85bf9
-- cite: attestation/policy/step.go:536-541 sha256:351b4b76ec382062d9d27820da19248c21615a0b0b689b0a5cca2805348efffc
-- cite: attestation/policy/policy.go:664-788 sha256:6ccc053d2d2728df1af6732cf03ae543d5b447cae59fa992ebea02ddba01fbc9
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

-- cite: attestation/policy/step.go:936-958 sha256:66913ac0d392989382e998f0ca3390faefb130f1601e42332f77822160e33316
/-- One attestor inside a collection. `type` is its attestation type URI
(the legacy-alias lookup of step.go is abstracted away: `type` is
already the matched URI). -/
structure Attestor where
  ref : Nat
  type : String
  deriving DecidableEq, Repr

-- cite: attestation/policy/step.go:923-928 sha256:324819cb96f168941ea7d83daabc3d4763e6ffef6233447119460c4a998a3b43
/-- A functionary-authorised collection as the gate receives it. `errors` is
`collection.Errors` non-empty (step.go). -/
structure Collection where
  name : String
  errors : Bool
  attestors : List Attestor
  deriving DecidableEq, Repr

-- cite: attestation/policy/step.go:283-287 sha256:e5a7ca0bacf2e8bc2d6cdb93e579d2eacd4b25db87bf0283aadde46f3de646ca
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

-- cite: attestation/policy/step.go:930-942 sha256:82035c8327f1d340396c631341ff570b17f9286c99646996a9cc47ba625f1229
/-- Every attestor of the expected type; ALL of them, not the last one
(step.go, "G (#5747)"). -/
def attestorsOf (c : Collection) (t : String) : List Attestor :=
  c.attestors.filter (fun a => a.type == t)

-- cite: attestation/policy/step.go:967-974 sha256:72f155f4a6c7cb2f3bc45a844f2e2ce37a2e98b79bb85bcc2c07d26d21f0fe3c
/-- Verdicts produced for one attestor. AI runs only when Rego passed: a
deterministic rejection is not disclosed to a provider (step.go). -/
def attestorVerdicts (ev : Evaluators) (a : Attestor) (e : Expected) : List Verdict :=
  match ev.rego a e with
  | .pass => [.pass, ev.ai a e]
  | v => [v]

inductive Outcome where
  | wrongName
  | passed
  /-- `refused`: some reason is an evaluation refusal, AI or Rego
  (`evaluationRefusal`, regorefusal.go). -/
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

-- cite: attestation/policy/step.go:900-1046 sha256:e4d08a4b43a4fc90595cff8e2f12d822928d5feb7b84e53278ef6481851a73d8
-- cite: attestation/policy/regorefusal.go:32-44 sha256:93d80ba472d31d6108b51b5208b745b9172ce7a943358feca21eed76028dd87f
-- cite: attestation/policy/step.go:900-903 sha256:2e634f1aa948679a297ead28197c9e38d1f45a71bc5784800b0b355fde847122
-- cite: attestation/policy/step.go:913-921 sha256:89df68265d5e72f6745d75a94e8a3cf7832c739989594eb18f5ca7b84f31c08d
-- cite: attestation/policy/step.go:923-928 sha256:324819cb96f168941ea7d83daabc3d4763e6ffef6233447119460c4a998a3b43
-- cite: attestation/policy/step.go:951-959 sha256:5b1c9fe372bf6b19bdc15ca4eec5bb76c8b202999b85531065ff93a166476120
-- cite: attestation/policy/step.go:943-1010 sha256:6690ab89e22425a46a274f5773f623ea0956548765d746036ec917830bc138a1
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

-- cite: attestation/policy/step.go:930-942 sha256:82035c8327f1d340396c631341ff570b17f9286c99646996a9cc47ba625f1229
-- cite: attestation/policy/step.go:962-966 sha256:918c758b7eaa53c475ca2177541850489a24e0dc6b33a6f7e8f1d59380f1dcda
/-- No last-writer-wins: a passing duplicate cannot shadow a failing attestor
of the same type (step.go). -/
theorem no_shadowing (ev : Evaluators) (s : Step) (c : Collection) (e : Expected)
    (he : e ∈ s.expected) (good bad : Attestor)
    (hbad : bad ∈ attestorsOf c e.type) (_hgood : good ∈ attestorsOf c e.type)
    (_hg : ev.rego good e = .pass ∧ ev.ai good e = .pass) (hb : ev.rego bad e ≠ .pass) :
    gate ev s c ≠ .passed :=
  gate_fail_closed ev s c e he bad hbad (Or.inl hb)

-- cite: attestation/policy/policy.go:1766-1977 sha256:4e901ec5e89f4e6dc98a4bf73fafda2f56328f95c2749d07d380c80cf315b09f
/-! ## External attestations (policy.go) -/

/-- One candidate envelope for an external, as the external gate sees it. -/
structure Envelope where
  -- cite: attestation/policy/policy.go:1807-1807 sha256:a66860576a2118541df86481df475f9f83f3a31cc93666bfcc6fd6cba3e4cc33
  /-- The source reported envelope errors and no verifier (policy.go). -/
  sigErrors : Bool
  -- cite: attestation/policy/policy.go:1807-1818 sha256:f100b55459c88dd720341e0520bbfce7ea9953388dbc3c2b1340ff49ff4c60f0
  /-- Those errors say the signed subjects do not name the requested
  subject (`ErrExternalSubjectNotRequested`, policy.go). -/
  subjectUnbound : Bool
  -- cite: attestation/policy/policy.go:1820-1845 sha256:5d0c386d102568a6e4015a47a487a115b455350b07ac33251b0e060a3cbf0526
  /-- The envelope is not about this external's commit: some external of its
  predicate type declares a `commitSubject` and the signed payload does not
  match THIS external's declaration (`MatchExternalSubjects`), or a commit
  binding is set and the envelope is not bound to it. Both checks run in
  that order, right after the signature check, and both make the candidate
  unbound (policy.go). -/
  commitUnbound : Bool
  -- cite: attestation/policy/policy.go:1849-1871 sha256:3d7451637b78f22c6030209644d05f5fbc032ec6864f6d72a1fb2a1b58fdba14
  /-- Some verifier matched some functionary (policy.go). -/
  signerAllowed : Bool
  hasAttestor : Bool
  regoV : Verdict
  aiV : Verdict
  deriving DecidableEq, Repr

inductive EnvOutcome where
  | unbound
  /-- `refused`: the rejection reason is an evaluation refusal, AI or Rego
  (`evaluationRefusal`, regorefusal.go), which `refusedAIResults` reports
  (policy.go). -/
  | rejected (refused : Bool)
  | passed
  deriving DecidableEq, Repr

def envGate (e : Envelope) : EnvOutcome :=
  if e.sigErrors then (if e.subjectUnbound then .unbound else .rejected false)
  else if e.commitUnbound then .unbound
  else if !e.signerAllowed then .rejected false
  else if !e.hasAttestor then .rejected false
  else if e.regoV != .pass then .rejected (e.regoV == .refused)
  else if e.aiV != .pass then .rejected (e.aiV == .refused)
  else .passed

theorem envGate_passed_iff (e : Envelope) :
    envGate e = .passed ↔
      e.sigErrors = false ∧ e.commitUnbound = false ∧ e.signerAllowed = true ∧
        e.hasAttestor = true ∧ e.regoV = .pass ∧ e.aiV = .pass := by
  unfold envGate
  cases e.sigErrors <;> cases e.commitUnbound <;> cases e.signerAllowed <;> cases e.hasAttestor <;>
    simp <;> (try split) <;> simp_all <;> (try split) <;> simp_all

/-- A Rego evaluation of an external that ran out of its deadline is a
refused rejection, not a completed one: the reason is an
`ErrRegoEvaluationRefused`, which `refusedAIResults` reports (policy.go,
regorefusal.go, #9872). -/
theorem env_rego_deadline_refuses (e : Envelope) (hs : e.sigErrors = false)
    (hc : e.commitUnbound = false) (ha : e.signerAllowed = true) (hat : e.hasAttestor = true)
    (hr : e.regoV = .refused) : envGate e = .rejected true := by
  simp [envGate, hs, hc, ha, hat, hr]

-- cite: attestation/policy/policy.go:1925-1971 sha256:1e6932d747251682ee2597d3e8eedbf3681482b57fab66b900550f42af858ab4
-- cite: attestation/policy/step.go:536-541 sha256:351b4b76ec382062d9d27820da19248c21615a0b0b689b0a5cca2805348efffc
/-- What one external yields (policy.go, step.go). -/
inductive ExtOutcome where
  /-- required and nothing bound was found: `ErrMissingExternalAttestation`. -/
  | missing
  /-- required, candidates found, all rejected: `ErrExternalAttestationRejected`. -/
  | allRejected
  /-- optional and nothing bound was found. -/
  | skipped
  /-- a result; `refusedOnly` marks no pass and some evaluation refusal. -/
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

-- cite: attestation/policy/policy.go:664-788 sha256:6ccc053d2d2728df1af6732cf03ae543d5b447cae59fa992ebea02ddba01fbc9
/-! ## Aggregation (`VerifyWithExternals`, policy.go) -/

/-- A step's result as the aggregation reads it. `analyze` is
`StepResult.Analyze()`; `hasPassed` is `HasPassed()`; `refusal` says some
rejected collection's reason is an evaluation refusal, an AI refusal or a
Rego deadline (`evaluationRefusal`, regorefusal.go, #9872). These come from
the trust + linking model and from `gate` above. -/
structure StepSummary where
  analyze : Bool
  hasPassed : Bool
  refusal : Bool
  deriving DecidableEq, Repr

/-- The verify outcome.
* `accepted b`: `Verify` returned `(b, _, nil)`, a completed verdict;
* `failed refusal`: `Verify` returned an error (`refusal`: the error is an
  `ErrAIEvaluationRefused` or an `ErrRegoEvaluationRefused`). -/
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

-- cite: attestation/policy/policy.go:665-697 sha256:27f001d6875f02cd73cb841431156637b283c92056cad3d25d59d510ea8650a3
/-- `policyOk` covers everything before evaluation: options, expiry,
`Validate`, `checkStepAbout`, trust bundles (policy.go). -/
def verify (policyOk : Bool) (steps : List StepSummary) (exts : List ExtOutcome) : VerifyOutcome :=
  if !policyOk then .failed false
  -- cite: attestation/policy/policy.go:707-713 sha256:7b1b49f34a123318a43cca7eb3be5635269f821434f706cafbf4c1ca7bc6113f
  else if exts.any isExtErr then .failed false                                   -- policy.go
  else if steps.any (fun s => !s.hasPassed && s.refusal) || exts.any extRefused
    -- cite: attestation/policy/policy.go:726-728 sha256:933f639fffb9e3fe1432919165b72b194ac14b5f681f816c01cd4f471a7e76ed
    -- cite: attestation/policy/policy.go:759-788 sha256:cfee072d06f1ff6ddf0165b79bb2d570d5a311aadd37c14c29a8bb7bfb4800cf
    -- cite: attestation/policy/regorefusal.go:32-44 sha256:93d80ba472d31d6108b51b5208b745b9172ce7a943358feca21eed76028dd87f
    then .failed true                                                            -- policy.go
  else .accepted (steps.all StepSummary.analyze && exts.all extAnalyze &&
      -- cite: attestation/policy/policy.go:737-756 sha256:693fa1ad33c7238fb5ebc6a4cd223d39c6f35f4fadab72b083a34c3a52778283
      (!steps.isEmpty || exts.any extVerified))                                  -- policy.go

-- cite: attestation/policy/policy.go:737-756 sha256:693fa1ad33c7238fb5ebc6a4cd223d39c6f35f4fadab72b083a34c3a52778283
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

/-- An optional external whose only candidate's Rego ran out of its deadline
makes the verify a refusal, not a completed FAILED verdict: `refusedAIResults`
returns the `ErrRegoEvaluationRefused` (policy.go, #9872). -/
theorem optional_external_rego_deadline_is_refusal :
    let env : Envelope := ⟨false, false, false, true, true, .refused, .pass⟩
    verify true [] [external false [env]] = .failed true := by
  decide

/-! ## The instantiated statement: the real evaluators plugged in -/

/-- The evaluators are the modelled ones: Rego is `Rego.eval` over the
attestation's modules under some OPA run, AI is `Ai.gate` over the
attestation's AI policies under some provider outcome. No premise on the
provider: `EvaluateAIPolicyWithProvider` enforces the provider contract
itself (`Ai.checked_contract`, #9873). -/
structure RealEvaluators (ev : Evaluators) : Prop where
  rego : ∀ a e, ∃ rd run, ev.rego a e = Rego.eval rd e.rego run ∧
    (ev.rego a e = .pass → e.rego = [] ∨ ∀ m ∈ e.rego, run.deny m.pkg = .collection 0)
  ai : ∀ a e, ∃ out, ev.ai a e = Ai.gate e.ai out ∧
    (ev.ai a e = .pass → e.ai = [] ∨ (out.rs.length = e.ai.length ∧ ∀ r ∈ out.rs, r.status = "PASS"))

/-- Build `RealEvaluators` from the model functions. -/
theorem realEvaluators_of (ev : Evaluators)
    (hr : ∀ a e, ∃ rd run, ev.rego a e = Rego.eval rd e.rego run)
    (ha : ∀ a e, ∃ out, ev.ai a e = Ai.gate e.ai out) :
    RealEvaluators ev where
  rego a e := by
    obtain ⟨rd, run, h⟩ := hr a e
    refine ⟨rd, run, h, fun hp => ?_⟩
    rw [h] at hp
    rcases (Rego.eval_pass_iff rd e.rego run).1 hp with h' | ⟨_, _, _, _, h', _⟩
    · exact Or.inl h'
    · exact Or.inr h'
  ai a e := by
    obtain ⟨out, h⟩ := ha a e
    refine ⟨out, h, fun hp => ?_⟩
    rw [h] at hp
    rcases Ai.gate_pass_all_pass e.ai out hp with h' | ⟨hl, hs, _⟩
    · exact Or.inl h'
    · exact Or.inr ⟨hl, hs⟩

/-- **evaluators_fail_closed.** A collection passes the step gate only if, for
every required attestation and every attestor of its type, every Rego module
yielded an empty `deny` and every AI policy was answered with a literal
`PASS`, one per policy. No error, timeout, undefined `deny`, missing-field
admit, unread `allow`, malformed reply, provider outage, refusal, answer from
another model or unparseable typed answer can produce a pass. -/
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
  · obtain ⟨out, hev, himp⟩ := hreal.ai a e
    rcases himp hai with h' | h'
    · exact Or.inl h'
    · exact Or.inr ⟨out, hev, h'⟩

end CilockEvaluators.Gate
