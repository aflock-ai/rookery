-- cite: attestation/policy/step.go:975-1008 sha256:4a82bc8ba27e36910bf5d1f993c9c14cb617eef4f12bfa663965a4b21e53306a
-- cite: attestation/policy/ai.go:185-258 sha256:db02941e59cd22748f299c2103aa1dadbd3f00d4d1e85aa6c33086e3ca5c08e7
-- cite: attestation/policy/policy.go:1886-1919 sha256:141e115a6200a205ec3a9a4a7166a32bc1b17c1a61c5cfbbbbd81be63de056d3
-- cite: attestation/policy/ai_validate.go:176-187 sha256:392afbf6e077d0574a273d2fbc2893ef290ea0e724e7c64ccf3def0e2c93b428
-- cite: attestation/policy/ai_validate.go:164-167 sha256:447e8d7f26779c15fb53befd274c89c3cdd67ff177d6e7617dc4233c128cb16e
-- cite: attestation/policy/ai_jev.go:381-383 sha256:45be6524a4eee9715468946f5aadc435d43515c91229543ecf23b2fcd24fd4b3
-- cite: attestation/policy/ai_jev.go:471-473 sha256:2fc4e630d5beab7962fd0845f1a28cead7cfad985fdd19b2036fe79345a6f27f
/-
  CilockEvaluators.Ai: AI policies (attestation/policy/ai.go, ai_validate.go,
  ai_decode.go, ai_jev.go, ai_jev_projection.go), the checks
  `EvaluateAIPolicyWithProvider` holds every provider to (ai.go: one answer
  per policy, status exactly PASS or FAIL, answered by the policy's own
  model), and the way the step gate turns the result into pass/fail
  (step.go, policy.go).

  Numbers: Go uses float64. After validation every bound and every answer is
  finite and inside a closed range (ai_validate.go;
  ai_jev.go), and comparisons are the ordinary `<=`/`>=`, so
  the model uses fixed-point integers (`unit` = 1.0). The boundary behaviour
  (inclusive comparisons) is what matters and is modelled exactly; rounding
  of decimal literals into binary floats is not.
-/
import CilockEvaluators.Types

namespace CilockEvaluators.Ai

open CilockEvaluators

/-- Fixed-point stand-in for a finite float64; `unit` is 1.0. -/
abbrev Num := Int

/-- 1.0 at ten decimal places. -/
def unit : Num := 10000000000

-- cite: attestation/policy/ai_jev.go:33-33 sha256:0496969b682e2fdcfa170af78df66ef16be98b68b31765bf9704edcbbf1d3822
/-- A model name as the Jev provider classifies it: `jev-X.Y.Z` is pinned
(`jevPinnedModel`, ai_jev.go); anything else, including a bare alias such as
`jev`, is not. The empty name is `other ""`. -/
inductive ModelName where
  | pinned (major minor patch : Nat)
  | other (s : String)
  deriving DecidableEq, Repr

def ModelName.isPinned : ModelName → Bool
  | .pinned .. => true
  | .other _ => false

-- cite: attestation/policy/step.go:224-280 sha256:2d9a13e243a3d230b979ad187bf5b1280daea488c66073ccd1d0d9a504bfe27d
/-- The typed-decision body (step.go). Instructions and criteria are
not modelled; their emptiness checks only add refusals. -/
inductive Decision where
  | yesNo (minP maxP : Option Num)
  | choice (options allow deny : List String) (minConf : Option Num)
  | score (levels : Nat) (minS maxS : Option Num)
  deriving DecidableEq, Repr

-- cite: attestation/policy/step.go:208-222 sha256:a12c36482dcf11d53827b9095ab7f45e7422abcee02011ae9b4c106d9891c803
/-- `AiPolicy` (step.go). `prompt` and `decision` are both present in
the Go struct; validation requires exactly one. -/
structure AiPolicy where
  name : String
  model : ModelName
  prompt : String
  decision : Option Decision
  deriving DecidableEq, Repr

def inRange (lo hi : Num) : Option Num → Bool
  | none => true
  | some v => decide (lo ≤ v) && decide (v ≤ hi)

def leOpt : Option Num → Option Num → Bool
  | some a, some b => decide (a ≤ b)
  | _, _ => true

-- cite: attestation/policy/ai_validate.go:61-174 sha256:74e0e65dd9760dc195db85d6bc0b71cce839d2f771550075e83cef481afbb720
/-- `AiDecision.validate` (ai_validate.go). -/
def Decision.valid : Decision → Bool
  | .yesNo mn mx =>
    (mn.isSome || mx.isSome) && inRange 0 unit mn && inRange 0 unit mx && leOpt mn mx
  | .choice opts al dn mc =>
    !opts.isEmpty && (!al.isEmpty || !dn.isEmpty || mc.isSome) &&
      al.all opts.contains && dn.all opts.contains && inRange 0 unit mc
  | .score lv mn mx =>
    lv != 0 && (mn.isSome || mx.isSome) &&
      inRange 0 ((lv - 1 : Nat) * unit) mn && inRange 0 ((lv - 1 : Nat) * unit) mx && leOpt mn mx

-- cite: attestation/policy/ai_validate.go:35-57 sha256:33f09609749fb049c680db6db9cc23c914a39c363476f0843a96d04c7f764de5
/-- `AiPolicy.Validate` (ai_validate.go). -/
def AiPolicy.valid (p : AiPolicy) : Bool :=
  p.name != "" && p.model != .other "" &&
    match p.prompt != "", p.decision with
    | true, none => true
    | false, some d => d.valid
    | _, _ => false

-- cite: attestation/policy/ai_validate.go:206-218 sha256:dd636a7d2e7d19bd7ea2ae81d40af8e2208f13b51f8928df5dab63b4e78807fa
/-- `validateAiPolicySet` (ai_validate.go): each valid, names unique. -/
def validSet : List AiPolicy → Bool
  | [] => true
  | p :: ps => p.valid && !(ps.any (fun q => q.name == p.name)) && validSet ps

-- cite: attestation/policy/ai.go:72-79 sha256:e53717fe99c24d1a2971f74c96fe523e5200bae91db76cffcbbb59422caa9c7b
/-- A typed answer after parsing (`AiAnswer`, ai.go). -/
inductive Answer where
  | yesNo (p : Num)
  | choice (c : String) (conf : Num)
  | score (s : Num)
  deriving DecidableEq, Repr

-- cite: attestation/policy/ai_jev.go:516-528 sha256:45a49fc8ee1b69f717aec1a4acb64b66691ced08340214e24481ae9220504cff
/-- `decideJevAnswer` (ai_jev.go). Inclusive on every bound. -/
def decideAnswer : Decision → Answer → Bool
  | .yesNo mn mx, .yesNo p => leOpt mn (some p) && leOpt (some p) mx
  | .choice _ al dn mc, .choice c conf =>
    (al.isEmpty || al.contains c) && !dn.contains c && leOpt mc (some conf)
  | .score _ mn mx, .score s => leOpt mn (some s) && leOpt (some s) mx
  | _, _ => false

-- cite: attestation/policy/ai.go:60-65 sha256:98f542026e9d3c4fb8e3d329c507304166179e3a20c97939cec5f0929b73bbad
/-- One `AiResponse` (ai.go). -/
structure Response where
  status : String
  reason : String
  model : ModelName
  answer : Option Answer
  deriving DecidableEq, Repr

def Response.empty : Response := ⟨"", "", .other "", none⟩

/-- How a provider error classifies downstream. `refusal` is
`ErrAIEvaluationRefused`; `denied` is a completed FAIL returned with an error;
`other` is any other error. -/
inductive ErrKind where
  | refusal
  | denied
  | other
  deriving DecidableEq, Repr

/-- What `EvaluateAIPolicyWithProvider` returns: `([]AiResponse, error)`. -/
structure Outcome where
  rs : List Response
  err : Option ErrKind
  deriving DecidableEq, Repr

-- cite: attestation/policy/ai.go:237-258 sha256:ec6fe684a211cce927dfb1881a2fbffee4c01828ec5a1aa88b6253e334118177
/-- `checkAiResponseSchema` then `pinResolvedModel` for one answer (ai.go):
a status other than exactly `PASS`/`FAIL` is an ordinary error; an answer
whose recorded model is empty or is not the policy's model is a refusal
(`model_mismatch`, #9871). -/
def respCheck (p : AiPolicy) (r : Response) : Option ErrKind :=
  if r.status != "PASS" && r.status != "FAIL" then some .other
  else if r.model == .other "" || r.model != p.model then some .refusal
  else none

/-- The first failing check, in policy order (ai.go). -/
def firstErr : List (AiPolicy × Response) → Option ErrKind
  | [] => none
  | (p, r) :: rest =>
    match respCheck p r with
    | some k => some k
    | none => firstErr rest

-- cite: attestation/policy/ai.go:211-235 sha256:a262d736d351aef709e5c956de738733ceb7664cbf2990586976ba287ecc0d11
-- cite: attestation/policy/ai.go:185-209 sha256:25eebc694dafaaa5d4f7e04993d4891f589600e09ae43fbb9e5a79cc9fcdf335
/-- What `EvaluateAIPolicyWithProvider` makes of a provider's `(responses,
error)` (`evaluateAiBatch`, ai.go): a provider error is returned as is; a
response count other than one per policy is an error; otherwise the first
answer that fails `respCheck` decides. The non-batch loop runs the same
`respCheck` per answer inside `ExecuteAiPolicyWithProvider` (ai.go); see
`ollama` below. -/
def checked (pols : List AiPolicy) (out : Outcome) : Outcome :=
  match out.err with
  | some _ => out
  | none =>
    if out.rs.length != pols.length then ⟨out.rs, some .other⟩
    else ⟨out.rs, firstErr (pols.zip out.rs)⟩

-- cite: attestation/policy/ai.go:125-160 sha256:6e5f5e41abaff02ce2e2f43a270573f6880b835ec3f6bb2d73d2faa8670435b5
-- cite: attestation/policy/step.go:975-1008 sha256:4a82bc8ba27e36910bf5d1f993c9c14cb617eef4f12bfa663965a4b21e53306a
-- cite: attestation/policy/policy.go:1886-1919 sha256:141e115a6200a205ec3a9a4a7166a32bc1b17c1a61c5cfbbbbd81be63de056d3
-- cite: attestation/policy/ai.go:128-130 sha256:35238ce2c72621baa8719b56b25575d0ce1e52e3c423e1569961c83ebbde7bad
-- cite: attestation/policy/ai.go:132-134 sha256:e66e602b851109d805e1aadba90ada8bcf3fef0c38a734f8adc02e8008e6503f
-- cite: attestation/policy/step.go:976-979 sha256:bcea2270ab37fdbeedce0db5603b97fa9ad9459a06f3cd622a638d24f54d7578
-- cite: attestation/policy/step.go:986-989 sha256:21db4e5d5f096d80bdfffbb1ac140aadfaf09d6ed1213f185ac3a45d45e7772f
-- cite: attestation/policy/policy.go:1898-1898 sha256:b5df317369278e4c97d65388cf629257780d657c6c30beb90869014422f1f73c
/-- The gate: `EvaluateAIPolicyWithProvider` (ai.go) over a provider's raw
outcome `out`, as consumed by the step gate (step.go) and the external gate
(policy.go).

* no policies: pass (ai.go);
* invalid set: error before any provider call (ai.go);
* the provider's outcome goes through `checked` (ai.go);
* any error left after that: rejected (step.go);
* otherwise: rejected iff some response is not exactly `"PASS"` (step.go,
  #9820). The external gate rejects on `== "FAIL"` (policy.go); after
  `checked` every status is `PASS` or `FAIL`, so the two agree
  (`checked_contract`). -/
def gate (pols : List AiPolicy) (out : Outcome) : Verdict :=
  if pols.isEmpty then .pass
  else if !validSet pols then .error
  else match (checked pols out).err with
    | some .refusal => .refused
    | some .denied => .deny
    | some .other => .error
    | none => if (checked pols out).rs.any (fun r => r.status != "PASS") then .deny else .pass

/-! ## The checks on their own -/

theorem checked_rs (pols : List AiPolicy) (out : Outcome) : (checked pols out).rs = out.rs := by
  unfold checked
  split
  · rfl
  · split <;> rfl

theorem checked_err_some (pols : List AiPolicy) (out : Outcome) (k : ErrKind)
    (h : out.err = some k) : (checked pols out).err = some k := by
  simp [checked, h]

theorem respCheck_none (p : AiPolicy) (r : Response) (h : respCheck p r = none) :
    (r.status = "PASS" ∨ r.status = "FAIL") ∧ r.model = p.model := by
  unfold respCheck at h
  by_cases hs : (r.status != "PASS" && r.status != "FAIL") = true
  · simp [hs] at h
  · simp only [hs, Bool.false_eq_true, ↓reduceIte] at h
    by_cases hm : (r.model == .other "" || r.model != p.model) = true
    · simp [hm] at h
    · simp only [Bool.or_eq_true, bne_iff_ne, ne_eq, beq_iff_eq, not_or, Decidable.not_not] at hm
      simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, not_and, Decidable.not_not] at hs
      refine ⟨?_, hm.2⟩
      by_cases hp : r.status = "PASS"
      · exact Or.inl hp
      · exact Or.inr (hs hp)

theorem firstErr_none (l : List (AiPolicy × Response)) (h : firstErr l = none) :
    ∀ x ∈ l, respCheck x.1 x.2 = none := by
  induction l with
  | nil => intro x hx; cases hx
  | cons y ys ih =>
    obtain ⟨p, r⟩ := y
    simp only [firstErr] at h
    cases hc : respCheck p r with
    | some k => rw [hc] at h; cases h
    | none =>
      rw [hc] at h
      intro x hx
      simp only [List.mem_cons] at hx
      rcases hx with hx | hx
      · subst hx; exact hc
      · exact ih h x hx

theorem mem_zip_right {α β : Type} (ps : List α) (rs : List β) (hl : rs.length = ps.length)
    (r : β) (hr : r ∈ rs) : ∃ p, (p, r) ∈ ps.zip rs := by
  induction ps generalizing rs with
  | nil => cases rs with
    | nil => cases hr
    | cons _ _ => simp at hl
  | cons p ps ih =>
    cases rs with
    | nil => cases hr
    | cons r' rs =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hl
      simp only [List.mem_cons] at hr
      rcases hr with hr | hr
      · subst hr; exact ⟨p, by simp⟩
      · obtain ⟨q, hq⟩ := ih rs hl hr
        exact ⟨q, by simp [hq]⟩

/-- What a clean `checked` outcome guarantees, whatever the provider did:
the provider returned no error, one response per policy, and each response
passed `respCheck`. -/
theorem checked_none (pols : List AiPolicy) (out : Outcome) (h : (checked pols out).err = none) :
    out.err = none ∧ out.rs.length = pols.length ∧ ∀ x ∈ pols.zip out.rs, respCheck x.1 x.2 = none := by
  unfold checked at h
  split at h
  · rename_i k hk; rw [hk] at h; cases h
  · rename_i hn
    split at h
    · cases h
    · rename_i hl
      refine ⟨hn, by simpa using hl, firstErr_none _ h⟩

/-! ## The gate on its own -/

/-- What a gate pass says about the provider's outcome, with no assumption on
the provider. -/
theorem gate_pass_iff (pols : List AiPolicy) (out : Outcome) :
    gate pols out = .pass ↔
      pols = [] ∨ (validSet pols = true ∧ (checked pols out).err = none ∧ ∀ r ∈ out.rs, r.status = "PASS") := by
  unfold gate
  rw [checked_rs]
  cases pols with
  | nil => simp
  | cons p ps =>
    simp only [List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte, reduceCtorEq, false_or]
    cases hv : validSet (p :: ps) with
    | false => simp
    | true =>
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte, true_and]
      cases he : (checked (p :: ps) out).err with
      | some k => cases k <;> simp
      | none =>
        simp only [List.any_eq_true, bne_iff_ne, ne_eq, true_and]
        by_cases h : ∃ x ∈ out.rs, ¬ x.status = "PASS"
        · simp only [h, ↓reduceIte, reduceCtorEq, false_iff]
          intro hall
          obtain ⟨x, hx, hs⟩ := h
          exact hs (hall x hx)
        · simp only [h, ↓reduceIte, true_iff]
          intro r hr
          by_cases hs : r.status = "PASS"
          · exact hs
          · exact absurd ⟨r, hr, hs⟩ h

/-- Every provider error rejects: refusal, completed FAIL, anything else. -/
theorem provider_error_rejects (pols : List AiPolicy) (out : Outcome) (k : ErrKind)
    (hne : pols ≠ []) (he : out.err = some k) : gate pols out ≠ .pass := by
  intro h
  rcases (gate_pass_iff pols out).1 h with h | ⟨_, h, _⟩
  · exact hne h
  · rw [checked_err_some pols out k he] at h; cases h

/-- A malformed policy set rejects before any provider call. -/
theorem invalid_set_rejects (pols : List AiPolicy) (out : Outcome)
    (hne : pols ≠ []) (hv : validSet pols = false) : gate pols out ≠ .pass := by
  intro h
  rcases (gate_pass_iff pols out).1 h with h | ⟨h, _, _⟩
  · exact hne h
  · rw [hv] at h; cases h

/-- The provider contract: on a nil error, one response per policy, each
`PASS` or `FAIL`. Until #9873 it was a premise about the provider code;
`EvaluateAIPolicyWithProvider` now enforces it (`checked_contract`), and
`ollama_contract` and `jev_contract` show the two in-tree providers honour
it on their own. -/
def Contract (pols : List AiPolicy) (out : Outcome) : Prop :=
  out.err = none →
    out.rs.length = pols.length ∧ ∀ r ∈ out.rs, r.status = "PASS" ∨ r.status = "FAIL"

/-- The checks establish the contract for ANY provider (ai.go, #9873). -/
theorem checked_contract (pols : List AiPolicy) (out : Outcome) : Contract pols (checked pols out) := by
  intro h
  obtain ⟨_, hl, hx⟩ := checked_none pols out h
  rw [checked_rs]
  refine ⟨hl, fun r hr => ?_⟩
  obtain ⟨p, hp⟩ := mem_zip_right pols out.rs hl r hr
  exact (respCheck_none p r (hx (p, r) hp)).1

/-- E1/E2 for AI, with no premise on the provider: a gate pass means one
`PASS` per policy, each answered by that policy's own model (E5). -/
theorem gate_pass_all_pass (pols : List AiPolicy) (out : Outcome) (h : gate pols out = .pass) :
    pols = [] ∨ (out.rs.length = pols.length ∧ (∀ r ∈ out.rs, r.status = "PASS") ∧
      ∀ x ∈ pols.zip out.rs, x.2.model = x.1.model) := by
  rcases (gate_pass_iff pols out).1 h with h | ⟨_, he, hp⟩
  · exact Or.inl h
  · obtain ⟨_, hl, hx⟩ := checked_none pols out he
    exact Or.inr ⟨hl, hp, fun x hmem => (respCheck_none x.1 x.2 (hx x hmem)).2⟩

-- cite: attestation/policy/ai.go:260-388 sha256:141b38532424a8781deaf3e64613efefa40c2fcfcdae1682948cf7a387a7bb3f
/-! ## The generative provider (`ollamaProvider`, ai.go) -/

-- cite: attestation/policy/ai.go:353-377 sha256:1fe08b12cdd4fa103ad90da9cae68621f8327985d4ba32aa8e970e9511a981d1
/-- What the remote Ollama-compatible server sends back, abstracted:
a transport failure (including a body that is not a JSON envelope), or an
envelope whose `response` field decodes to a status (`none`: it does not
decode, ai.go) and whose `model` member names `served`, the model that
answered (`.other ""` when absent). -/
inductive GenReply where
  | transport
  | body (status : Option String) (reason : String) (served : ModelName)
  deriving DecidableEq, Repr

-- cite: attestation/policy/ai.go:284-290 sha256:ddc78bac1f94ab75536ba2c87db748a2fe1bdaa8a79147b8cf0f3b71f3444837
/-- `ollamaProvider.Evaluate` + `parseOllamaGenerateResponse` for one policy.
`urlOk` abstracts `serverURL != ""` and `validateAIServerURL` (ai.go). -/
def ollamaOne (urlOk : Bool) (p : AiPolicy) (reply : GenReply) : Response × Option ErrKind :=
  -- cite: attestation/policy/ai.go:275-277 sha256:ae6976c4d86442367b4a20d4451c9516c0e6af6d537ec346780aa2e53454277b
  if p.decision.isSome then (.empty, some .other)                 -- ai.go
  -- cite: attestation/policy/ai.go:284-290 sha256:ddc78bac1f94ab75536ba2c87db748a2fe1bdaa8a79147b8cf0f3b71f3444837
  else if !urlOk then (.empty, some .other)                       -- ai.go
  -- cite: attestation/policy/ai.go:308-311 sha256:e89cf8ec9495bee30c408b5b52bab3f3ea1ef19aaba7c3e258c84915b93c8b4e
  else if p.model = .other "" then (.empty, some .other)          -- ai.go
  else match reply with
    -- cite: attestation/policy/ai.go:336-345 sha256:d425045aedf34ceabc50e4b19a2e035c1cc8aa33f9ed37e47340e4219a44bcca
    | .transport => (.empty, some .other)                         -- ai.go
    | .body st rsn served =>
      -- cite: attestation/policy/ai.go:363-368 sha256:22df572aa734b4cadd4f0efae6ed62de0abd211f995a25041abcd1437004c23e
      -- The server's model is checked BEFORE the answer is read (#9871).
      if served != p.model then (.empty, some .refusal)          -- ai.go
      else match st with
      -- cite: attestation/policy/ai.go:370-373 sha256:15c54a51c269be0a974d40011b44e61c81c036f41c4361dcdfaeae2eed5e5069
      | none => (.empty, some .other)                             -- ai.go
      | some st =>
        -- cite: attestation/policy/ai.go:375-377 sha256:9c7dff8882289da3222bec34990ddb5d2832acb35d9b9bf773f10115000a7f91
        if st != "PASS" && st != "FAIL" then (.empty, some .other)  -- ai.go
        else
          -- cite: attestation/policy/ai.go:379-381 sha256:a7685da59aa3febacb300f6ee4b19cbef2c0803de26e5aa12999c191f0176483
          -- Model is the server's resolved model, already equal to the policy's.
          let r : Response := ⟨st, rsn, served, none⟩
          -- cite: attestation/policy/ai.go:383-387 sha256:e6c77a0a4a1f1f7eb8a2a5e0a41b26289dc264d0dff522676a5a80135f9ad781
          if st == "FAIL" then (r, some .denied) else (r, none)   -- ai.go

-- cite: attestation/policy/ai.go:198-208 sha256:fd2a23e9efb483cb472e768d584c8dab4a1c3396841929fcc8cd75cf2d96de4d
/-- `ExecuteAiPolicyWithProvider` (ai.go): a provider error is returned as is;
a nil-error answer still goes through `respCheck`. -/
def execOne (urlOk : Bool) (p : AiPolicy) (reply : GenReply) : Response × Option ErrKind :=
  match ollamaOne urlOk p reply with
  | (resp, some k) => (resp, some k)
  | (resp, none) => (resp, respCheck p resp)

-- cite: attestation/policy/ai.go:145-159 sha256:4e51baf6828bde9126ea469405ab653be4a79691c3f6c2a8f8da927ed9b82275
/-- The non-batch loop of `EvaluateAIPolicyWithProvider` (ai.go):
append each result, stop at the first error. -/
def ollama (urlOk : Bool) : List (AiPolicy × GenReply) → Outcome
  | [] => ⟨[], none⟩
  | (p, r) :: rest =>
    match execOne urlOk p r with
    | (resp, some k) => ⟨[resp], some k⟩
    | (resp, none) =>
      let o := ollama urlOk rest
      ⟨resp :: o.rs, o.err⟩

theorem ollamaOne_ok_pass (urlOk : Bool) (p : AiPolicy) (r : GenReply) (resp : Response)
    (h : ollamaOne urlOk p r = (resp, none)) : resp.status = "PASS" := by
  unfold ollamaOne at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  cases r with
  | transport => simp at h
  | body st rsn m =>
    simp only at h
    split at h
    · simp at h
    cases st with
    | none => simp at h
    | some s =>
      simp only at h
      by_cases hp : s = "PASS"
      · subst hp
        simp at h
        subst h
        rfl
      · by_cases hf : s = "FAIL"
        · subst hf; simp at h
        · simp [hp, hf] at h

theorem execOne_ok_pass (urlOk : Bool) (p : AiPolicy) (r : GenReply) (resp : Response)
    (h : execOne urlOk p r = (resp, none)) : resp.status = "PASS" := by
  unfold execOne at h
  cases h1 : ollamaOne urlOk p r with
  | mk r' k =>
    rw [h1] at h
    cases k with
    | some k => simp at h
    | none =>
      simp only [Prod.mk.injEq] at h
      obtain ⟨rfl, _⟩ := h
      exact ollamaOne_ok_pass urlOk p r r' h1

/-- The generative provider honours the contract, so its gate pass means
every question was answered literally `PASS`. -/
theorem ollama_contract (urlOk : Bool) (items : List (AiPolicy × GenReply)) :
    Contract (items.map Prod.fst) (ollama urlOk items) := by
  induction items with
  | nil => intro _; simp [ollama]
  | cons it rest ih =>
    obtain ⟨p, r⟩ := it
    intro he
    simp only [ollama] at he ⊢
    cases h1 : execOne urlOk p r with
    | mk resp k =>
      cases k with
      | some k => simp [h1] at he
      | none =>
        simp only [h1] at he ⊢
        obtain ⟨hl, hs⟩ := ih he
        refine ⟨by simp [hl], ?_⟩
        intro x hx
        simp only [List.mem_cons] at hx
        rcases hx with hx | hx
        · subst hx; exact Or.inl (execOne_ok_pass urlOk p r _ h1)
        · exact hs x hx

/-! ## The typed provider (`jevProvider`, ai_jev.go) -/

-- cite: attestation/policy/ai_jev.go:270-291 sha256:7b7783f31bf24a4c60b5d199ff226bba474b398d3223b8c8a4a38aebf2eb58ba
-- cite: attestation/policy/ai_jev.go:296-306 sha256:57561fbb48e1e1b42c416482e14031aca1513c5f4c2c816deddea21933c93316
-- cite: attestation/policy/ai_jev.go:289-313 sha256:05f670c14d2bfaeb5a520cbd2ff6c1ff22e3d2ce3eca9d096378da41d0aa9c0f
-- cite: attestation/policy/ai_jev.go:385-426 sha256:c04256890db38085fa7f269bd9b1afe4522ecb975e390b388391362dc17fea0a
/-- The remote reply to one question, abstracted to what the client decides on:
* `transport`: cancelled, timed out, unavailable, unreadable (ai_jev.go);
* `http c`: any non-200 (ai_jev.go);
* `malformed`: invalid or duplicate-member JSON, oversize (ai_jev.go);
* `envelope resolved ans`: a well-formed envelope; `resolved` is its `model`
  member (`none` when absent), `ans` this question's answer (`none` when
  missing; `some none` when it does not parse, ai_jev.go). -/
inductive JevReply where
  | transport
  | http (code : Nat)
  | malformed
  | envelope (resolved : Option ModelName) (ans : Option (Option Answer))
  deriving DecidableEq, Repr

-- cite: attestation/policy/ai_jev.go:398-421 sha256:2a5f826c4c510de0325a02ea8ec634a17c38a218f51595de1b594d43f16529b7
-- cite: attestation/policy/ai_jev.go:452-496 sha256:e78739a6830e93931705aa1b2431226bd93a6c91eda58a6908eacea0fe3ba4b3
/-- The per-kind shape checks of `parseJevAnswer` that the model keeps: the
answer kind matches the question, a choice names a defined option, a score is
inside the ladder, a probability inside [0, 1] (ai_jev.go). -/
def wellFormed : Decision → Answer → Bool
  | .yesNo .., .yesNo p => decide (0 ≤ p) && decide (p ≤ unit)
  | .choice opts .., .choice c conf => opts.contains c && decide (0 ≤ conf) && decide (conf ≤ unit)
  | .score lv .., .score s => decide (0 ≤ s) && decide (s ≤ (lv - 1 : Nat) * unit)
  | _, _ => false

-- cite: attestation/policy/ai_jev.go:224-231 sha256:934b8557f3d662605c6e227bfe069bc5d49efbb4d55c962bba3b029164093202
/-- Question shapes the Jev provider refuses although `Validate` accepts them:
a score ladder of fewer than two levels (`invalid_score_levels`,
ai_jev.go). Found by the differential test, not by reading. The
criteria and instruction checks of `makeJevQuestion` are not modelled. -/
def Decision.jevRejects : Decision → Bool
  | .score lv _ _ => decide (lv < 2)
  | _ => false

-- cite: attestation/policy/ai_jev.go:529-532 sha256:62d621706713cdf522d16718414379ceac222c06acb7daf7aad13ff7c9c73f7c
/-- The constant reasons of a completed typed verdict (ai_jev.go). -/
def passReason : String := "typed decision assertions satisfied"
def failReason : String := "typed decision assertions not satisfied"

-- cite: attestation/policy/ai_jev.go:116-134 sha256:77486b438c8bc389872978cfaeb814fb1794edca8a97bc35293f4b007951cb4f
-- cite: attestation/policy/ai_jev.go:243-257 sha256:4e4d490b3edef7af95815a2a749fa26326457e15bbd7555fd1c63a305a3a3a3e
/-- One question through the Jev path. `keyOk` / `endpointOk` are the preflight
credential and endpoint checks (ai_jev.go). -/
def jevOne (keyOk endpointOk : Bool) (p : AiPolicy) (reply : JevReply) : Response × Option ErrKind :=
  -- cite: attestation/policy/ai_jev.go:116-134 sha256:77486b438c8bc389872978cfaeb814fb1794edca8a97bc35293f4b007951cb4f
  if !keyOk || !endpointOk || !p.valid then (.empty, some .refusal)   -- ai_jev.go
  -- cite: attestation/policy/ai_jev.go:172-174 sha256:8541a81d36f2bbc89ef3b4b0ee8064f14f87e1b6bd2ca0600de10c7e3562d3f0
  else if !p.model.isPinned then (.empty, some .refusal)              -- ai_jev.go
  else match p.decision with
    -- cite: attestation/policy/ai_jev.go:205-207 sha256:cfe3d12146f9ed54b2891c596c31c89da6f5664a446a349d3331539cf1e31757
    | none => (.empty, some .refusal)                                  -- ai_jev.go
    | some d =>
      -- cite: attestation/policy/ai_jev.go:224-231 sha256:934b8557f3d662605c6e227bfe069bc5d49efbb4d55c962bba3b029164093202
      if d.jevRejects then (.empty, some .refusal)                     -- ai_jev.go
      else match reply with
      | .transport | .http _ | .malformed => (.empty, some .refusal)
      | .envelope resolved ans =>
        -- cite: attestation/policy/ai_jev.go:314-317 sha256:62eb9a6738dbd4baa449a72c5b4db36fbdbe1b944ca04449f78d7bd752043359
        if resolved != some p.model then (.empty, some .refusal)       -- ai_jev.go
        else match ans with
          -- cite: attestation/policy/ai_jev.go:149-160 sha256:209fe415e249fae94b1e35b3ce7c7c302ff46de46a6f9ffd036cbc811a9d9e4d
          -- cite: attestation/policy/ai_jev.go:388-390 sha256:af081dedcdd02aa5dbf7ace754f8fceadfa4715e9f23fece79428c4dbb5241d5
          | none | some none => (.empty, some .refusal)                -- ai_jev.go
          | some (some a) =>
            if !wellFormed d a then (.empty, some .refusal)
            else if decideAnswer d a then (⟨"PASS", passReason, p.model, some a⟩, none)
            else (⟨"FAIL", failReason, p.model, some a⟩, none)

def isRefusal : Option ErrKind → Bool
  | some .refusal => true
  | _ => false

-- cite: attestation/policy/ai_jev.go:75-114 sha256:898fc038306fec6d684db424b045f375e0f8fa5853d2684aeb767f38d945c1ee
-- cite: attestation/policy/ai_jev.go:167-202 sha256:ff325ef3adf5fb6a340e37ffd98f360bc3b808b495867e687906a2887c28df23
-- cite: attestation/policy/ai_jev.go:191-191 sha256:37aa2d290aad8fe0cdc19689d1201a19e349b59c37b29a200deec9332b049de7
/-- `jevProvider.EvaluateBatch` (ai_jev.go): any refusal returns NO
responses and the refusal; else all responses, with `ErrPolicyDenied` when
any is `FAIL`. (Grouping by model and state, ai_jev.go, only batches
requests; each group's model is the policy's own model because it is part of
the group key, ai_jev.go.) -/
def jev (keyOk endpointOk : Bool) (items : List (AiPolicy × JevReply)) : Outcome :=
  let results := items.map (fun it => jevOne keyOk endpointOk it.1 it.2)
  if results.any (fun x => isRefusal x.2) then ⟨[], some .refusal⟩
  else
    let rs := results.map Prod.fst
    if rs.any (fun r => r.status == "FAIL") then ⟨rs, some .denied⟩ else ⟨rs, none⟩

/-- Every Jev result is a refusal, or a completed `PASS`/`FAIL` with no error. -/
theorem jevOne_shape (keyOk endpointOk : Bool) (p : AiPolicy) (reply : JevReply)
    (x : Response × Option ErrKind) (hx : jevOne keyOk endpointOk p reply = x) :
    x.2 = some .refusal ∨ (x.2 = none ∧ (x.1.status = "PASS" ∨ x.1.status = "FAIL")) := by
  unfold jevOne at hx
  repeat' split at hx
  all_goals (subst hx; simp)

/-- The typed provider honours the contract. -/
theorem jev_contract (keyOk endpointOk : Bool) (items : List (AiPolicy × JevReply)) :
    Contract (items.map Prod.fst) (jev keyOk endpointOk items) := by
  intro he
  simp only [jev] at he ⊢
  split at he
  · simp at he
  · rename_i hr
    split at he
    · simp at he
    · rename_i hf
      rw [if_neg hr, if_neg hf]
      refine ⟨by simp, ?_⟩
      intro r hmem
      simp only [List.mem_map] at hmem
      obtain ⟨x, ⟨it, hit, hx⟩, hrx⟩ := hmem
      have hnr : isRefusal x.2 = false := by
        cases h : isRefusal x.2
        · rfl
        · exact absurd (List.any_eq_true.2 ⟨x, List.mem_map.2 ⟨it, hit, hx⟩, h⟩) hr
      rcases jevOne_shape keyOk endpointOk it.1 it.2 x hx with h | ⟨_, h⟩
      · rw [h] at hnr; simp [isRefusal] at hnr
      · rw [← hrx]; exact h

/-- A completed typed verdict for one question: exactly the decision function
of (decision, answer). No reason text, no model prose, no other input. -/
theorem jevOne_verdict (keyOk endpointOk : Bool) (p : AiPolicy) (d : Decision) (a : Answer)
    (hk : keyOk = true) (he : endpointOk = true) (hv : p.valid = true)
    (hpin : p.model.isPinned = true) (hd : p.decision = some d) (hj : d.jevRejects = false)
    (hw : wellFormed d a = true) :
    jevOne keyOk endpointOk p (.envelope (some p.model) (some (some a))) =
      (⟨if decideAnswer d a then "PASS" else "FAIL",
        if decideAnswer d a then passReason else failReason, p.model, some a⟩, none) := by
  unfold jevOne
  simp only [hk, he, hv, Bool.not_true, Bool.or_self, Bool.false_eq_true, ↓reduceIte, hpin, hd,
    bne_self_eq_false, hw, hj]
  cases decideAnswer d a <;> simp

/-- E5 (Jev path): a policy that passes was answered by EXACTLY the model it
names. A reply resolved to any other model (an alias resolving to a newer
build included) is a refusal. -/
theorem jev_model_pinned (keyOk endpointOk : Bool) (p : AiPolicy) (reply : JevReply)
    (resp : Response) (h : jevOne keyOk endpointOk p reply = (resp, none)) :
    p.model.isPinned = true ∧ resp.model = p.model ∧
      ∃ ans, reply = .envelope (some p.model) ans := by
  unfold jevOne at h
  split at h; · simp at h
  split at h; · simp at h
  rename_i hpin
  have hpin' : p.model.isPinned = true := by simpa using hpin
  split at h; · simp at h
  split at h; · simp at h
  split at h
  · simp at h
  · simp at h
  · simp at h
  · rename_i resolved ans
    split at h; · simp at h
    rename_i hres
    have hres' : resolved = some p.model := by simpa using hres
    refine ⟨hpin', ?_, ans, by rw [hres']⟩
    split at h
    · simp at h
    · simp at h
    · split at h; · simp at h
      split at h
      · simp only [Prod.mk.injEq] at h; rw [← h.1]
      · simp only [Prod.mk.injEq] at h; rw [← h.1]

/-- Every non-answer on the Jev path is a refusal, never a pass and never a
completed FAIL (the six reply classes of TestJevProviderContractRefusalsAreNotFindings). -/
theorem jev_failures_refuse (keyOk endpointOk : Bool) (p : AiPolicy) (reply : JevReply)
    (h : reply = .transport ∨ (∃ c, reply = .http c) ∨ reply = .malformed ∨
      (∃ m, m ≠ some p.model ∧ ∃ a, reply = .envelope m a) ∨
      reply = .envelope (some p.model) none ∨ reply = .envelope (some p.model) (some none)) :
    (jevOne keyOk endpointOk p reply).2 = some .refusal := by
  unfold jevOne
  split; · rfl
  split; · rfl
  split; · rfl
  split; · rfl
  rcases h with h | ⟨c, h⟩ | h | ⟨m, hm, a, h⟩ | h | h <;> subst h <;> simp_all

/-! ## E4: boundaries, decided as the code decides them -/

theorem leOpt_self (t : Num) : leOpt (some t) (some t) = true := by
  simp [leOpt]

theorem leOpt_none_l (b : Option Num) : leOpt none b = true := by
  cases b <;> rfl

theorem leOpt_none_r (a : Option Num) : leOpt a none = true := by
  cases a <;> rfl

-- cite: attestation/policy/ai_jev.go:521-521 sha256:cc1773627aa928f168aefdcebfd57faac284606ef82c148e9ad3ac275a097d22
/-- `minProbability`: an answer exactly AT the minimum passes (`>=`, ai_jev.go). -/
theorem yesNo_min_inclusive (t : Num) (mx : Option Num) (hmx : leOpt (some t) mx = true) :
    decideAnswer (.yesNo (some t) mx) (.yesNo t) = true := by
  simp only [decideAnswer, leOpt_self, hmx, Bool.and_self]

/-- `maxProbability`: an answer exactly AT the maximum passes (`<=`). -/
theorem yesNo_max_inclusive (t : Num) (mn : Option Num) (hmn : leOpt mn (some t) = true) :
    decideAnswer (.yesNo mn (some t)) (.yesNo t) = true := by
  simp only [decideAnswer, leOpt_self, hmn, Bool.and_self]

-- cite: attestation/policy/ai_jev.go:524-524 sha256:27d24d2660883d2f9bab3ae7df34c27eed7653cab7b99dee63ae0f418691b068
/-- `minConfidence`: AT the minimum passes (ai_jev.go). -/
theorem choice_minConf_inclusive (opts al dn : List String) (c : String) (t : Num)
    (hal : (al.isEmpty || al.contains c) = true) (hdn : dn.contains c = false) :
    decideAnswer (.choice opts al dn (some t)) (.choice c t) = true := by
  simp only [decideAnswer, hal, hdn, leOpt_self, Bool.not_false, Bool.and_self]

-- cite: attestation/policy/ai_jev.go:527-527 sha256:fb75ce8e71ab1040d27f81393685a416ff0d6130ec6a0de60881b343cace7c17
/-- `minScore` / `maxScore`: AT either bound passes (ai_jev.go). -/
theorem score_bounds_inclusive (lv : Nat) (t : Num) :
    decideAnswer (.score lv (some t) (some t)) (.score t) = true := by
  simp only [decideAnswer, leOpt_self, Bool.and_self]

/-- `deny` wins over `allow` when an option is in both. -/
theorem choice_deny_wins (opts : List String) (c : String) (mc : Option Num) (conf : Num) :
    decideAnswer (.choice opts [c] [c] mc) (.choice c conf) = false := by
  simp [decideAnswer]


/-! ## E5 on the generative path: refuted as built, fixed by #9871 -/

-- cite: attestation/policy/ai.go:363-368 sha256:22df572aa734b4cadd4f0efae6ed62de0abd211f995a25041abcd1437004c23e
-- cite: attestation/policy/ai.go:249-258 sha256:201046ed20aff9fa38c12516b3904c557ab21832f80cc8a1da96eaac92c8ea70
/-- A generative answer from a server that ran another model is REFUSED, and
the gate refuses with it (ai.go).

As built at the first version of this model (testifysec/judge#9820) the same
trace PASSED, recorded against the policy's model
(`generative_model_not_verified`, refuted as built); fixed by #9871. -/
theorem generative_other_model_refused :
    let p : AiPolicy := ⟨"review", .other "llama3:8b", "is this safe?", none⟩
    let served := ModelName.other "some-other-model"
    let out := ollama true [(p, .body (some "PASS") "ok" served)]
    out = ⟨[.empty], some .refusal⟩ ∧ gate [p] out = .refused := by
  decide

/-- E5 on the generative path: a completed generative answer was produced by
exactly the policy's model, as the server itself reported it (ai.go). -/
theorem generative_model_pinned (urlOk : Bool) (p : AiPolicy) (reply : GenReply) (resp : Response)
    (h : execOne urlOk p reply = (resp, none)) :
    resp.model = p.model ∧ ∃ st rsn, reply = .body (some st) rsn p.model := by
  unfold execOne at h
  cases h1 : ollamaOne urlOk p reply with
  | mk r k =>
    rw [h1] at h
    cases k with
    | some k => simp at h
    | none =>
      simp only [Prod.mk.injEq] at h
      obtain ⟨hr, hc⟩ := h
      subst hr
      refine ⟨(respCheck_none p r hc).2, ?_⟩
      unfold ollamaOne at h1
      split at h1; · simp at h1
      split at h1; · simp at h1
      split at h1; · simp at h1
      cases reply with
      | transport => simp at h1
      | body st rsn m =>
        simp only at h1
        split at h1
        · simp at h1
        · rename_i hm
          have hm' : m = p.model := by simpa using hm
          cases st with
          | none => simp at h1
          | some s => exact ⟨s, rsn, by rw [hm']⟩

/-- On the generative path the verdict IS model text: the server's own
`status` string decides, so E4 holds only for typed decisions. -/
theorem generative_status_is_model_output (p : AiPolicy) (st rsn : String)
    (hd : p.decision = none) (hm : p.model ≠ .other "") (hst : st = "PASS") :
    ollamaOne true p (.body (some st) rsn p.model) = (⟨"PASS", rsn, p.model, none⟩, none) := by
  subst hst
  simp [ollamaOne, hd, hm]

-- cite: attestation/policy/ai.go:271-277 sha256:9005840d1d62da40e6e2b2921f5253b3d512679423dd5adcef4dc2a9473d8efa
/-- A decision policy on the default provider is refused, not skipped
(ai.go). -/
theorem decision_without_provider_rejects (p : AiPolicy) (d : Decision) (r : GenReply) (u : Bool)
    (hd : p.decision = some d) : (ollamaOne u p r).2 = some .other := by
  simp [ollamaOne, hd]

end CilockEvaluators.Ai
