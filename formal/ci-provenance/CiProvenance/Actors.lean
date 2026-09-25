import CiProvenance.AlpsProofs
import CiProvenance.Slsa

/-!
# Actors: what each can observe, forge or withhold

A table over the ALPS deployment model. "Forge" means: make an item a
verifier accepts say something other than what happened. The rows for the
adversary are not asserted, they are tied to `emit` by the theorems below.
-/

namespace CiProvenance

inductive Actor where
  /-- The CI runner / hosted build platform. -/
  | ciRunner
  /-- The model harness and the agent it runs: the ALPS adversary. -/
  | harness
  /-- A tenant build step CI/lock wraps: the SLSA L3 adversary. -/
  | buildStep
  /-- CI/lock running in the agent's uid. -/
  | cilock
  /-- The designed daemon, outside the agent's uid. -/
  | cilockd
  /-- The keyless CA (and the OIDC issuer behind it). -/
  | signer
  | tsa
  /-- The repository host. -/
  | repo
  deriving DecidableEq, Repr

inductive Item where
  | attribution | execution | products | principal | time | boundary | isolation
  deriving DecidableEq, Repr

structure Powers where
  observes  : List Item
  forges    : List Item
  withholds : Bool
  deriving Repr

def powers (d : Deployment) (tb : TrustBase) (b : BuildSetup) : Actor → Powers
  | .harness =>
    { observes := [.attribution, .execution, .products],
      forges := [.attribution] ++ (if executionTrusted d tb then [] else [.execution]) ++
        (if productsTrusted d tb then [] else [.products]) ++ (if agentHoldsKey d then [.boundary] else []),
      withholds := true }
  | .buildStep =>
    { observes := [.execution, .products],
      forges := if stepsForgeProvenance b then [.products] else [],
      withholds := true }
  | .ciRunner =>
    -- The hosted platform runs the job: it is trusted for everything in it.
    { observes := [.execution, .products, .principal], forges := [.execution, .products], withholds := true }
  | .cilock =>
    -- Honest binary; in the agent's uid it is substitutable, which is the harness row.
    { observes := [.attribution, .execution, .products], forges := [], withholds := true }
  | .cilockd =>
    { observes := [.execution, .products],
      forges := if d.daemon && !tb.daemon then [.execution, .isolation] else [],
      withholds := true }
  | .signer =>
    { observes := [.principal], forges := if tb.fulcio then [] else [.principal, .boundary, .isolation], withholds := true }
  | .tsa =>
    { observes := [.time], forges := if tb.tsa then [] else [.time], withholds := true }
  | .repo =>
    { observes := [], forges := [], withholds := true }

/-- The harness row is exact for execution: it lists `execution` iff some
adversary can make the accepted execution record differ from what ran. -/
theorem harness_forges_execution_iff (d : Deployment) (tb : TrustBase) (b : BuildSetup) (t : Facts) :
    Item.execution ∈ (powers d tb b .harness).forges ↔
      ∃ adv : Adversary, (emit d tb adv t).execution ≠ t.execution := by
  rw [execution_forgeable_iff]
  cases hx : executionTrusted d tb <;> cases hp : productsTrusted d tb <;>
    cases hk : agentHoldsKey d <;> simp [powers, hx, hp, hk]

theorem harness_forges_products_iff (d : Deployment) (tb : TrustBase) (b : BuildSetup) (t : Facts) :
    Item.products ∈ (powers d tb b .harness).forges ↔
      ∃ adv : Adversary, (emit d tb adv t).products ≠ t.products := by
  rw [products_forgeable_iff]
  cases hx : executionTrusted d tb <;> cases hp : productsTrusted d tb <;>
    cases hk : agentHoldsKey d <;> simp [powers, hx, hp, hk]

/-- The harness forges attribution in every deployment. -/
theorem harness_always_forges_attribution (d : Deployment) (tb : TrustBase) (b : BuildSetup) :
    Item.attribution ∈ (powers d tb b .harness).forges := by
  simp [powers]

/-- Every actor can withhold, and withholding yields Unknown, never a level. -/
theorem every_actor_withholds (d : Deployment) (tb : TrustBase) (b : BuildSetup) (a : Actor) :
    (powers d tb b a).withholds = true := by
  cases a <;> rfl

/-- CI/lock in CI today: a build step forges provenance subjects. -/
theorem buildStep_forges_in_job (d : Deployment) (tb : TrustBase) :
    Item.products ∈ (powers d tb cilockInJob .buildStep).forges := by
  simp [powers, stepsForgeProvenance, cilockInJob]

end CiProvenance
