/-!
# SLSA Build levels for provenance CI/lock produces in CI

SLSA 1.2 Build: L1 provenance exists; L2 provenance is authentic, generated
and signed by a hosted build platform; L3 provenance is unforgeable by the
tenant's build steps (signing material unavailable to them) and runs are
isolated. The repository's own posture document states the same split and
leaves L2 and L3 to a separate assessment:
-- see (monorepo, outside this tree): docs/slsa-posture.md:22-26

In CI, CI/lock signs keyless with the job's ambient OIDC identity, read from
the job environment in-process:
-- cite: cilock/internal/auth/workflow.go:26-29 sha256:ef9c2193fb3f22e14fb91086a17b4e60928e54b9551895c942b0d65805416b5f
-- cite: plugins/signers/fulcio/fulcio.go:262-275 sha256:3b9b18568ac0719a0db3bc52e3e2f8f2f9756818d2da1bd982c917b67ccaac14
and runs the tenant's build step as a child with no `Env` set, so the child
inherits that environment, token-request credential included:
-- cite: plugins/attestors/commandrun/commandrun.go:2577-2578 sha256:7e44ad486ef3ea87e769e144d2133f9624838d1a0ab8325427c5a3c420c75e46
Protecting the in-memory signing key does not change that: the build step
does not need CI/lock's key when it can mint its own leaf for the same identity.
-- cite: cilock/internal/keyguard/keyguard.go:7-13 sha256:6775c1d82f440150c325efd8cbe1d84f2331bda53dbad0ea26bac416af4eff95
-/

namespace CiProvenance

inductive Slsa where
  | none | l1 | l2 | l3
  deriving DecidableEq, Repr

def Slsa.rank : Slsa → Nat
  | .none => 0
  | .l1 => 1
  | .l2 => 2
  | .l3 => 3

def Slsa.atLeast (a b : Slsa) : Bool := decide (b.rank ≤ a.rank)

def Slsa.name : Slsa → String
  | .none => "none"
  | .l1 => "L1"
  | .l2 => "L2"
  | .l3 => "L3"

/-- How the build is really set up. -/
structure BuildSetup where
  /-- `-a slsa` selected: typed SLSA provenance is produced. -/
  provenance        : Bool
  /-- Hosted CI runner, not a tenant-operated host. -/
  hosted            : Bool
  /-- Keyless leaf for the workflow's own OIDC identity. -/
  workflowSigner    : Bool
  tsa               : Bool
  ephemeral         : Bool
  /-- A tenant build step can obtain the same OIDC identity the signer uses. -/
  stepsMintIdentity : Bool
  /-- Provenance is generated and signed under a builder identity no tenant
  step can obtain (a control-plane or isolated signing job). -/
  separateSigner    : Bool
  deriving DecidableEq, Repr

structure SlsaTrust where
  /-- CA and OIDC issuer bind a leaf only to the identity they authenticated. -/
  fulcio   : Bool
  tsa      : Bool
  /-- The hosted platform's own claims (hosted, ephemeral) are honest. -/
  platform : Bool
  deriving DecidableEq, Repr

def SlsaTrust.honest : SlsaTrust := ⟨true, true, true⟩

/-- What a verifier reads from a provenance envelope and its leaf. -/
structure ProvEvidence where
  present              : Bool
  /-- Leaf names the workflow identity on a hosted runner. -/
  hostedWorkflowSigner : Bool
  /-- Leaf names a trusted builder identity distinct from the tenant workflow. -/
  trustedBuilderSigner : Bool
  timestamped          : Bool
  ephemeralRunner      : Bool
  subjects             : List (String × String)
  deriving DecidableEq, Repr

/-- The verifier SLSA 1.2 asks for. L3 needs a signer the build steps cannot
become. -/
def deriveSlsa (p : ProvEvidence) : Slsa :=
  if !p.present then .none
  else if !(p.hostedWorkflowSigner && p.timestamped) then .l1
  else if !(p.trustedBuilderSigner && p.ephemeralRunner) then .l2
  else .l3

/-- The shortcut: a workflow-bound leaf on an ephemeral hosted runner is L3.
This is the reasoning of the published "SLSA Level 3 in 75 minutes" post:
-- cite: site/blog/2026-06-08-slsa-level-3-in-75-minutes/index.md:33-33 sha256:5e87e8540f0131d5c0523e9ef510dbc9bf21ade083dd7736196f0103342e1d0e
-/
def deriveSlsaNaive (p : ProvEvidence) : Slsa :=
  if !p.present then .none
  else if !(p.hostedWorkflowSigner && p.timestamped) then .l1
  else if !p.ephemeralRunner then .l2
  else .l3

/-- The tenant's build steps, the SLSA L3 adversary. -/
structure Steps where
  forge : Bool
  claim : List (String × String)
  deriving DecidableEq, Repr

/-- The steps can sign provenance as the builder. -/
def stepsForgeProvenance (b : BuildSetup) : Bool :=
  !b.separateSigner && (b.stepsMintIdentity || !b.hosted)

def emitProv (b : BuildSetup) (tb : SlsaTrust) (s : Steps) (built : List (String × String)) : ProvEvidence where
  present              := b.provenance || (s.forge && stepsForgeProvenance b)
  hostedWorkflowSigner := (b.hosted && b.workflowSigner) || (s.forge && !tb.fulcio)
  trustedBuilderSigner := b.separateSigner || (s.forge && !tb.fulcio)
  timestamped          := b.tsa || (s.forge && !tb.tsa)
  ephemeralRunner      := (b.hosted && b.ephemeral) || (s.forge && !tb.platform)
  subjects             := if s.forge && stepsForgeProvenance b then s.claim else built

/-- CI/lock with `-a slsa` inside a GitHub-hosted job with `id-token: write`:
what the code does today. -/
def cilockInJob : BuildSetup :=
  { provenance := true, hosted := true, workflowSigner := true, tsa := true, ephemeral := true,
    stepsMintIdentity := true, separateSigner := false }

/-- A laptop run with a local key. -/
def localRun : BuildSetup :=
  { provenance := true, hosted := false, workflowSigner := false, tsa := true, ephemeral := false,
    stepsMintIdentity := true, separateSigner := false }

/-- Provenance signed by a builder identity no tenant step can obtain. -/
def isolatedBuilder : BuildSetup :=
  { cilockInJob with separateSigner := true }

theorem deriveSlsa_l2 (p : ProvEvidence) :
    (deriveSlsa p).atLeast .l2 = (p.present && p.hostedWorkflowSigner && p.timestamped) := by
  obtain ⟨pr, hw, tbs, ts, eph, sub⟩ := p
  cases pr <;> cases hw <;> cases tbs <;> cases ts <;> cases eph <;> rfl

theorem deriveSlsa_l3 (p : ProvEvidence) :
    (deriveSlsa p = .l3) =
      (p.present = true ∧ p.hostedWorkflowSigner = true ∧ p.timestamped = true ∧
        p.trustedBuilderSigner = true ∧ p.ephemeralRunner = true) := by
  obtain ⟨pr, hw, tbs, ts, eph, sub⟩ := p
  cases pr <;> cases hw <;> cases tbs <;> cases ts <;> cases eph <;> simp [deriveSlsa]

/-- L1: provenance exists. Nothing about who wrote it. -/
theorem slsa_l1 (b : BuildSetup) (tb : SlsaTrust) (s : Steps) (built : List (String × String))
    (h : (deriveSlsa (emitProv b tb s built)).atLeast .l1 = true) :
    (emitProv b tb s built).present = true := by
  revert h
  simp only [deriveSlsa]
  cases hp : (emitProv b tb s built).present <;> simp [Slsa.atLeast, Slsa.rank]

/-- L2: with an honest CA, a derived L2 means the provenance was signed by
the hosted platform's workflow identity. Forgery by anyone outside that job
is excluded; forgery by the job's own steps is not. -/
theorem slsa_l2 (b : BuildSetup) (tb : SlsaTrust) (s : Steps) (built : List (String × String))
    (hf : tb.fulcio = true) (ht : tb.tsa = true)
    (h : (deriveSlsa (emitProv b tb s built)).atLeast .l2 = true) :
    b.hosted = true ∧ b.workflowSigner = true ∧
      ((emitProv b tb s built).subjects = built ∨ stepsForgeProvenance b = true) := by
  rw [deriveSlsa_l2] at h
  simp [emitProv, hf, ht] at h
  obtain ⟨⟨_, hh, hw⟩, _⟩ := h
  refine ⟨hh, hw, ?_⟩
  by_cases hfp : stepsForgeProvenance b = true
  · exact Or.inr hfp
  · left; simp [emitProv, hfp]

/-- L3: with an honest CA and platform, a derived L3 means a separate signer
and subjects equal to what was built: unforgeable by the build steps. -/
theorem slsa_l3 (b : BuildSetup) (tb : SlsaTrust) (s : Steps) (built : List (String × String))
    (hf : tb.fulcio = true) (hp : tb.platform = true)
    (h : deriveSlsa (emitProv b tb s built) = .l3) :
    b.separateSigner = true ∧ (emitProv b tb s built).subjects = built := by
  rw [deriveSlsa_l3] at h
  simp [emitProv, hf, hp] at h
  obtain ⟨_, _, _, hsep, _⟩ := h
  refine ⟨hsep, ?_⟩
  simp [emitProv, stepsForgeProvenance, hsep]

/-- What the code does in CI is exactly SLSA L2 under the strict verifier,
whatever the build steps do. -/
theorem cilockInJob_is_l2 (s : Steps) (built : List (String × String)) :
    deriveSlsa (emitProv cilockInJob SlsaTrust.honest s built) = .l2 := by
  obtain ⟨f, c⟩ := s
  cases f <;> rfl

/-- The isolated-builder shape reaches L3 and binds subjects. -/
theorem isolatedBuilder_is_l3 (s : Steps) (built : List (String × String)) :
    deriveSlsa (emitProv isolatedBuilder SlsaTrust.honest s built) = .l3 ∧
      (emitProv isolatedBuilder SlsaTrust.honest s built).subjects = built := by
  obtain ⟨f, c⟩ := s
  cases f <;> exact ⟨rfl, rfl⟩

/-- A laptop run with a local key is L1 at most. -/
theorem localRun_is_l1 (s : Steps) (built : List (String × String)) :
    (deriveSlsa (emitProv localRun SlsaTrust.honest s built)).atLeast .l2 = false := by
  obtain ⟨f, c⟩ := s
  cases f <;> rfl

/-- A build step that mints its own leaf and signs provenance for an artifact
it did not build. -/
def forger : Steps := { forge := true, claim := [("file:release.tar.gz", "sha256:attacker")] }

/-- Counterexample to the L3 claim: under the shortcut verifier, provenance a
build step forged with the job's own OIDC identity is L3, every signer honest,
and names an artifact that was never built. Filed as issue #9822. -/
theorem naive_l3_accepts_step_forgery :
    deriveSlsaNaive (emitProv cilockInJob SlsaTrust.honest forger []) = .l3 ∧
      (emitProv cilockInJob SlsaTrust.honest forger []).subjects ≠ [] := by
  refine ⟨rfl, ?_⟩
  simp [emitProv, forger, cilockInJob, stepsForgeProvenance]

end CiProvenance
