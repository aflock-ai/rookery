/-
  CilockPolicy.NonVacuity: `policy_sound` is not vacuous for certificate
  policies. A policy with a Fulcio-like root and a TSA, evidence signed by a
  certificate and stamped by that TSA, a passing verify, and the Assumptions
  bundle holding on that evidence, all at once.
-/
import CilockPolicy.TrustCounterexamples
import CilockPolicy.TrustProofs

namespace CilockPolicy.NonVacuity
open CilockPolicy CilockPolicy.Fixtures CilockPolicy.TrustCounterexamples

/-- `certB` (functionary `fB`), stamped by the policy TSA at 5: inside the
    certificate's window [0, 100] and before the clock (10). -/
def goodEnv : Envelope := env "good" (coll "build") [⟨.cert certB, true, [⟨"tsa", true, 5⟩]⟩]

/-- The same policy `timestamp_after_expiry_passes` uses: a root, a TSA. -/
theorem certificate_policy_passes :
    latePol.tsas ≠ [] ∧ verifyFixed rego regoExt .enforce latePol opts [goodEnv] = true := by
  decide

/-- The bundle holds on that evidence. The world predicates are taken as
    true; the point is that no hypothesis contradicts the configured TSA, which
    the previous, unscoped `tsaNotFuture` did. -/
def goodAssumptions : Assumptions latePol opts [goodEnv] where
  signed _ _ := True
  existedAt _ _ := True
  vouches _ _ := True
  sigUnforgeable _ _ _ _ _ := trivial
  tsaHonest _ _ _ _ _ _ _ _ := trivial
  tsaNotFuture := by decide
  caHonest _ _ _ _ _ _ _ _ _ := trivial

/-- Why the hypotheses range over the evidence: stated over every
    constructible signature, TsaNotFuture is false for any policy with a TSA
    (build a token one tick after the clock), so a bundle carrying it could
    never be built and `policy_sound` would hold vacuously. -/
theorem unscoped_tsaNotFuture_refuted :
    ¬ ∀ (s : Sig) (t : TsToken), t ∈ s.tokens → t.ok = true →
      latePol.tsas.contains t.tsa = true → t.time ≤ opts.now := fun h =>
  absurd (h ⟨.key "k", true, [⟨"tsa", true, 11⟩]⟩ ⟨"tsa", true, 11⟩ (by simp) rfl (by decide))
    (by decide)

/-- `policy_sound`'s hypotheses are jointly satisfiable for a certificate
    policy with a TSA, so its conclusion is not vacuously true there. -/
theorem assumptions_inhabited :
    ∃ E, latePol.tsas ≠ [] ∧ verifyFixed rego regoExt .enforce latePol opts E = true ∧
      Nonempty (Assumptions latePol opts E) :=
  ⟨[goodEnv], certificate_policy_passes.1, certificate_policy_passes.2, ⟨goodAssumptions⟩⟩

end CilockPolicy.NonVacuity
