-- cite: attestation/policy/ai_decision_provider_test.go:118-118 sha256:4a77c5e8cc95bb8913bda79604faf94550244bfce7b43b88bb899d73a30f8461
-- cite: attestation/policy/ai_decision_provider_test.go:156-156 sha256:302c7b2da419a2d0e17151ec175fca808ff5b42a021e4d1185682171bd4dd6d7
-- cite: attestation/policy/policy_external_test.go:561-561 sha256:f28a5f40ed63d99bde260d0b04a15ba81db583ceb23a2444b833dd60427f0553
-- cite: attestation/policy/failclosed_rego_d_test.go:34-34 sha256:8b2597fd8ceabb8030a4ba11879b1bf2f87ecdc23e904f6913a528c779c72ef5
/-
  CilockEvaluators.Holdout: predictions for four real fixtures chosen BEFORE
  the model was written, and never used to tune it. Each theorem states what
  the model predicts; the Go test named alongside asserts what the code does.
  README.md records the run of those tests.

  H1  TestJevProviderContractThresholdsAreLocal   (ai_decision_provider_test.go)
  H2  TestJevProviderContractRefusalsAreNotFindings (ai_decision_provider_test.go)
  H3  TestExternal_09_TwoExternalsSamePredicateDifferentRego (policy_external_test.go)
  H4  TestRed_D_NonStringDenyMustFailClosed        (failclosed_rego_d_test.go)
-/
import CilockEvaluators.Vsa

namespace CilockEvaluators.Holdout

open CilockEvaluators Ai

/-- The fixture's policy: one yes/no question on a pinned `jev-1.13.0`. -/
def pol (mn mx : Option Num) : AiPolicy :=
  ⟨"review-injection", .pinned 1 13 0, "", some (.yesNo mn mx)⟩

def reply (p : Num) : JevReply := .envelope (some (.pinned 1 13 0)) (some (some (.yesNo p)))

/-- Status of the single response, or "" when there is none. -/
def status1 (o : Outcome) : String :=
  match o.rs with
  | r :: _ => r.status
  | [] => ""

/-- H1: the six threshold cases (0.2 max for the first four, 0.8 min for the
last two), in fixed point with ten decimals. The test expects
pass, fail, fail, pass, pass, fail; a pass has no error, a fail has an error
AND a FAIL response. -/
theorem h1_thresholds :
    let mx := some (2000000000 : Num)
    let mn := some (8000000000 : Num)
    let run := fun (m : Option Num) (M : Option Num) (p : Num) => jev true true [(pol m M, reply p)]
    (status1 (run none mx 2000000000), (run none mx 2000000000).err) = ("PASS", none) ∧
    (status1 (run none mx 2000000001), (run none mx 2000000001).err) = ("FAIL", some .denied) ∧
    (status1 (run none mx 9900000000), (run none mx 9900000000).err) = ("FAIL", some .denied) ∧
    (status1 (run none mx 0), (run none mx 0).err) = ("PASS", none) ∧
    (status1 (run mn none 8000000000), (run mn none 8000000000).err) = ("PASS", none) ∧
    (status1 (run mn none 7999999999), (run mn none 7999999999).err) = ("FAIL", some .denied) := by
  decide

/-- H2: every refusal class in the fixture yields NO response and a refusal,
never a PASS and never a completed FAIL. -/
theorem h2_refusals :
    let p := pol none (some 2000000000)
    let refused := fun (r : JevReply) => jev true true [(p, r)] = ⟨[], some .refusal⟩
    refused (.http 400) ∧ refused (.http 401) ∧ refused (.http 429) ∧ refused (.http 500) ∧
    refused .malformed ∧                                                  -- invalid JSON, duplicate member
    refused (.envelope (some (.pinned 1 13 0)) none) ∧                    -- missing / wrong question
    refused (.envelope (some (.pinned 1 13 0)) (some none)) ∧             -- null / missing / string / NaN / overflow
    refused (reply (-100000000)) ∧                                        -- negative probability
    refused (reply 10100000000) ∧                                         -- probability above one
    refused (.envelope (some (.pinned 1 13 0)) (some (some (.choice "pass" unit)))) ∧  -- wrong answer type
    refused (.envelope (some (.other "jev-other")) (some (some (.yesNo 100000000)))) ∧ -- model mismatch
    refused (.envelope none (some (some (.yesNo 100000000)))) := by       -- missing resolved model
  decide

/-- H3: one SLSA envelope; a required external whose Rego accepts and an
optional external whose Rego always denies. The test expects `pass = false`
with NO error. -/
theorem h3_optional_rejected_external_fails :
    let env := fun (v : Verdict) => (⟨false, false, false, true, true, v, .pass⟩ : Gate.Envelope)
    let accept := Gate.external true [env .pass]
    let deny := Gate.external false [env .deny]
    Gate.verify true [] [accept, deny] = .accepted false := by
  decide

-- cite: attestation/policy/rego.go:232-233 sha256:8652ff077745e11f2003b1666ef3c4c0c42d5ff4e3db04531c39cb35eae5ae44
/-- H4: `deny[x] { x := 42 }`: a one-element set with a non-string member.
The test expects an error; the model predicts `deny`, which the Go code
returns as `ErrPolicyDenied` (rego.go). -/
theorem h4_nonstring_deny :
    let m : Rego.Module := ⟨"nonstring", "redgate_nonstring_deny", true, false⟩
    Rego.eval false [m] ⟨false, false, fun _ => .collection 1, fun _ => none, .clean⟩ = .deny := by
  decide

end CilockEvaluators.Holdout
