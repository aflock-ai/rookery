-- cite: attestation/policy/step.go:930-955 sha256:97598156781efbb660f695af698b697563d26c089a6f6122458b000a417a935d
-- cite: attestation/policy/policy.go:1644-1677 sha256:141e115a6200a205ec3a9a4a7166a32bc1b17c1a61c5cfbbbbd81be63de056d3
-- cite: attestation/policy/ai_validate.go:176-187 sha256:392afbf6e077d0574a273d2fbc2893ef290ea0e724e7c64ccf3def0e2c93b428
-- cite: attestation/policy/ai_validate.go:164-167 sha256:447e8d7f26779c15fb53befd274c89c3cdd67ff177d6e7617dc4233c128cb16e
-- cite: attestation/policy/ai_jev.go:381-383 sha256:45be6524a4eee9715468946f5aadc435d43515c91229543ecf23b2fcd24fd4b3
-- cite: attestation/policy/ai_jev.go:471-473 sha256:2fc4e630d5beab7962fd0845f1a28cead7cfad985fdd19b2036fe79345a6f27f
/-
  CilockEvaluators.Ai: AI policies (attestation/policy/ai.go, ai_validate.go,
  ai_decode.go, ai_jev.go, ai_jev_projection.go) and the way the step gate
  turns a provider's answer into pass/fail (step.go,
  policy.go).

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

-- cite: attestation/policy/step.go:179-235 sha256:2d9a13e243a3d230b979ad187bf5b1280daea488c66073ccd1d0d9a504bfe27d
/-- The typed-decision body (step.go). Instructions and criteria are
not modelled; their emptiness checks only add refusals. -/
inductive Decision where
  | yesNo (minP maxP : Option Num)
  | choice (options allow deny : List String) (minConf : Option Num)
  | score (levels : Nat) (minS maxS : Option Num)
  deriving DecidableEq, Repr

-- cite: attestation/policy/step.go:163-177 sha256:a12c36482dcf11d53827b9095ab7f45e7422abcee02011ae9b4c106d9891c803
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

-- cite: attestation/policy/ai.go:127-160 sha256:aaddbdf45763b968c4fdcd7d6d346ec3be3931af7de448dc814d396a04276cd9
-- cite: attestation/policy/step.go:930-955 sha256:97598156781efbb660f695af698b697563d26c089a6f6122458b000a417a935d
-- cite: attestation/policy/policy.go:1644-1677 sha256:141e115a6200a205ec3a9a4a7166a32bc1b17c1a61c5cfbbbbd81be63de056d3
-- cite: attestation/policy/ai.go:128-130 sha256:35238ce2c72621baa8719b56b25575d0ce1e52e3c423e1569961c83ebbde7bad
-- cite: attestation/policy/ai.go:132-134 sha256:e66e602b851109d805e1aadba90ada8bcf3fef0c38a734f8adc02e8008e6503f
-- cite: attestation/policy/step.go:931-934 sha256:bcea2270ab37fdbeedce0db5603b97fa9ad9459a06f3cd622a638d24f54d7578
-- cite: attestation/policy/step.go:941-941 sha256:faf86499b43ebfca580c98101f39f7bd075e889c49c9ad488f36c4661ea90cb7
-- cite: attestation/policy/policy.go:1656-1656 sha256:b5df317369278e4c97d65388cf629257780d657c6c30beb90869014422f1f73c
/-- The gate: `EvaluateAIPolicyWithProvider` (ai.go) as consumed by the
step gate (step.go) and the external gate (policy.go).

* no policies: pass (ai.go);
* invalid set: error before any provider call (ai.go);
* any provider error: rejected (step.go);
* otherwise: rejected iff some response has status exactly `"FAIL"`
  (step.go, policy.go). -/
def gate (pols : List AiPolicy) (out : Outcome) : Verdict :=
  if pols.isEmpty then .pass
  else if !validSet pols then .error
  else match out.err with
    | some .refusal => .refused
    | some .denied => .deny
    | some .other => .error
    | none => if out.rs.any (fun r => r.status == "FAIL") then .deny else .pass

/-! ## The gate on its own -/

/-- What a gate pass says about the provider's outcome, with no assumption on
the provider. -/
theorem gate_pass_iff (pols : List AiPolicy) (out : Outcome) :
    gate pols out = .pass ↔
      pols = [] ∨ (validSet pols = true ∧ out.err = none ∧ ∀ r ∈ out.rs, r.status ≠ "FAIL") := by
  unfold gate
  cases pols with
  | nil => simp
  | cons p ps =>
    simp only [List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte, reduceCtorEq, false_or]
    cases hv : validSet (p :: ps) with
    | false => simp
    | true =>
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte, true_and]
      cases he : out.err with
      | some k => cases k <;> simp
      | none =>
        simp only [List.any_eq_true, beq_iff_eq, true_and]
        by_cases h : ∃ x ∈ out.rs, x.status = "FAIL"
        · simp only [h, ↓reduceIte, reduceCtorEq, false_iff]
          intro hall
          obtain ⟨x, hx, hs⟩ := h
          exact hall x hx hs
        · simp only [h, ↓reduceIte, true_iff]
          intro r hr hs
          exact h ⟨r, hr, hs⟩

/-- Every provider error rejects: refusal, completed FAIL, anything else. -/
theorem provider_error_rejects (pols : List AiPolicy) (out : Outcome) (k : ErrKind)
    (hne : pols ≠ []) (he : out.err = some k) : gate pols out ≠ .pass := by
  intro h
  rcases (gate_pass_iff pols out).1 h with h | ⟨_, h, _⟩
  · exact hne h
  · rw [he] at h; cases h

/-- A malformed policy set rejects before any provider call. -/
theorem invalid_set_rejects (pols : List AiPolicy) (out : Outcome)
    (hne : pols ≠ []) (hv : validSet pols = false) : gate pols out ≠ .pass := by
  intro h
  rcases (gate_pass_iff pols out).1 h with h | ⟨h, _, _⟩
  · exact hne h
  · rw [hv] at h; cases h

/-- The provider contract: on a nil error, one response per policy, each
`PASS` or `FAIL`. A premise about the in-process provider code, stated as a
hypothesis and never built into `gate`; `ollama_contract` and `jev_contract`
discharge it for the two providers in this package. -/
def Contract (pols : List AiPolicy) (out : Outcome) : Prop :=
  out.err = none →
    out.rs.length = pols.length ∧ ∀ r ∈ out.rs, r.status = "PASS" ∨ r.status = "FAIL"

/-- E1/E2 for AI under the contract: a gate pass means one `PASS` per policy. -/
theorem gate_pass_all_pass (pols : List AiPolicy) (out : Outcome)
    (hc : Contract pols out) (h : gate pols out = .pass) :
    pols = [] ∨ (out.rs.length = pols.length ∧ ∀ r ∈ out.rs, r.status = "PASS") := by
  rcases (gate_pass_iff pols out).1 h with h | ⟨_, he, hnf⟩
  · exact Or.inl h
  · obtain ⟨hl, hs⟩ := hc he
    refine Or.inr ⟨hl, fun r hr => ?_⟩
    rcases hs r hr with h | h
    · exact h
    · exact absurd h (hnf r hr)

-- cite: attestation/policy/ai.go:205-321 sha256:596562b3262f05dd6198bcd5be6719c8fc4b5d8d9d9919820e1d636a07747b83
/-! ## The generative provider (`ollamaProvider`, ai.go) -/

-- cite: attestation/policy/ai.go:299-306 sha256:0284dabd8426d708333958d5b40e33596d4085690c7f48d7924d574b016a18f2
/-- What the remote Ollama-compatible server sends back, abstracted:
a transport failure, or a body whose `response` field decodes to a status
(`none`: it does not decode, ai.go). `served` is the model the server
actually ran; nothing in the client can see it. -/
inductive GenReply where
  | transport
  | body (status : Option String) (reason : String) (served : ModelName)
  deriving DecidableEq, Repr

-- cite: attestation/policy/ai.go:225-231 sha256:ddc78bac1f94ab75536ba2c87db748a2fe1bdaa8a79147b8cf0f3b71f3444837
/-- `ollamaProvider.Evaluate` + `parseOllamaGenerateResponse` for one policy.
`urlOk` abstracts `serverURL != ""` and `validateAIServerURL` (ai.go). -/
def ollamaOne (urlOk : Bool) (p : AiPolicy) (reply : GenReply) : Response × Option ErrKind :=
  -- cite: attestation/policy/ai.go:216-218 sha256:ae6976c4d86442367b4a20d4451c9516c0e6af6d537ec346780aa2e53454277b
  if p.decision.isSome then (.empty, some .other)                 -- ai.go
  -- cite: attestation/policy/ai.go:225-231 sha256:ddc78bac1f94ab75536ba2c87db748a2fe1bdaa8a79147b8cf0f3b71f3444837
  else if !urlOk then (.empty, some .other)                       -- ai.go
  -- cite: attestation/policy/ai.go:249-252 sha256:e89cf8ec9495bee30c408b5b52bab3f3ea1ef19aaba7c3e258c84915b93c8b4e
  else if p.model = .other "" then (.empty, some .other)          -- ai.go
  else match reply with
    -- cite: attestation/policy/ai.go:277-286 sha256:d425045aedf34ceabc50e4b19a2e035c1cc8aa33f9ed37e47340e4219a44bcca
    | .transport => (.empty, some .other)                         -- ai.go
    -- cite: attestation/policy/ai.go:299-306 sha256:0284dabd8426d708333958d5b40e33596d4085690c7f48d7924d574b016a18f2
    | .body none _ _ => (.empty, some .other)                     -- ai.go
    | .body (some st) rsn _ =>
      -- cite: attestation/policy/ai.go:308-310 sha256:9c7dff8882289da3222bec34990ddb5d2832acb35d9b9bf773f10115000a7f91
      if st != "PASS" && st != "FAIL" then (.empty, some .other)  -- ai.go
      else
        -- cite: attestation/policy/ai.go:312-314 sha256:1188c9846e79c7259e11cf8f49221255c64e2a9c4ad5326f6b94f7ee13acf748
        -- Model is the POLICY's model, never the server's (ai.go).
        let r : Response := ⟨st, rsn, p.model, none⟩
        -- cite: attestation/policy/ai.go:316-320 sha256:e6c77a0a4a1f1f7eb8a2a5e0a41b26289dc264d0dff522676a5a80135f9ad781
        if st == "FAIL" then (r, some .denied) else (r, none)     -- ai.go

-- cite: attestation/policy/ai.go:145-159 sha256:4e51baf6828bde9126ea469405ab653be4a79691c3f6c2a8f8da927ed9b82275
/-- The non-batch loop of `EvaluateAIPolicyWithProvider` (ai.go):
append each result, stop at the first error. -/
def ollama (urlOk : Bool) : List (AiPolicy × GenReply) → Outcome
  | [] => ⟨[], none⟩
  | (p, r) :: rest =>
    match ollamaOne urlOk p r with
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
    cases st with
    | none => simp at h
    | some s =>
      by_cases hp : s = "PASS"
      · subst hp
        simp only [Prod.mk.injEq] at h
        simp at h
        rw [← h]
      · by_cases hf : s = "FAIL"
        · subst hf; simp at h
        · simp [hp, hf] at h

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
    cases h1 : ollamaOne urlOk p r with
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
        · subst hx; exact Or.inl (ollamaOne_ok_pass urlOk p r _ h1)
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


/-! ## E5 on the generative path: REFUTED -/

-- cite: attestation/policy/ai.go:312-314 sha256:1188c9846e79c7259e11cf8f49221255c64e2a9c4ad5326f6b94f7ee13acf748
/-- The generative verdict records the POLICY's model and never learns which
model the server ran: a server that served another model still yields `PASS`
recorded against the named one (ai.go). -/
-- Tracked: testifysec/judge#9820
theorem generative_model_not_verified :
    let p : AiPolicy := ⟨"review", .other "llama3:8b", "is this safe?", none⟩
    let served := ModelName.other "some-other-model"
    let out := ollama true [(p, .body (some "PASS") "ok" served)]
    gate [p] out = .pass ∧ out.rs = [⟨"PASS", "ok", .other "llama3:8b", none⟩] ∧
      served ≠ p.model := by
  decide

/-- On the generative path the verdict IS model text: the server's own
`status` string decides, so E4 holds only for typed decisions. -/
theorem generative_status_is_model_output (p : AiPolicy) (st rsn : String) (m : ModelName)
    (hd : p.decision = none) (hm : p.model ≠ .other "") (hst : st = "PASS") :
    ollamaOne true p (.body (some st) rsn m) = (⟨"PASS", rsn, p.model, none⟩, none) := by
  subst hst
  simp [ollamaOne, hd, hm]

-- cite: attestation/policy/ai.go:212-218 sha256:9005840d1d62da40e6e2b2921f5253b3d512679423dd5adcef4dc2a9473d8efa
/-- A decision policy on the default provider is refused, not skipped
(ai.go). -/
theorem decision_without_provider_rejects (p : AiPolicy) (d : Decision) (r : GenReply) (u : Bool)
    (hd : p.decision = some d) : (ollamaOne u p r).2 = some .other := by
  simp [ollamaOne, hd]

end CilockEvaluators.Ai
