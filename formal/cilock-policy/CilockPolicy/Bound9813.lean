/-
  CilockPolicy.Bound9813: the round bound of the testifysec/judge#9813 fix
  (commit 1c49f05539, attestation/policy/policy.go verifySteps).

  The fix repeats step verification and artifact pruning. Round 1 builds each
  attestationsFrom context from the live results, as before; every later round
  builds it from the previous round's survivors. It stops when every context
  equals what survived, and refuses (ErrAttestationsFromNotConverged) after
  len(steps)+1 rounds.

  Result: when attestationsFrom ∪ artifactsFrom has a cycle (which a validator
  checking each relation separately accepts), a policy that settles on PASS can
  need more rounds than the bound, and is refused. Confirmed against the engine
  with the fix applied: the Go analogue of the trace below PASSES for m ≤ 2 and
  is refused "after 3 rounds" for m ≥ 3. #9860 therefore shipped the fix with
  `unionAcyclic`, which refuses such a policy up front. BoundProof.lean proves
  the bound for step lists in topological order (`fix9813_converges`); an
  acyclic policy listed out of order is not covered (`bound_scope_gap`).
-/
import CilockPolicy.Fixtures

namespace CilockPolicy

/-- The dependency names a policy's Rego contexts read. -/
def ctxDeps (p : Policy) : List String := p.steps.flatMap (·.attestationsFrom)

/-- The fix's loop. `prev = none` is round 1 (context from the live, pre-pruning
    results: the as-built phase); otherwise the context is `prev`, the previous
    round's survivors. `used d` is the set the context showed for `d`. -/
def fix9813Loop (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) : Nat → Option State → Option State
  | 0, _ => none
  | n + 1, prev =>
    let phase := match prev with
      | none => phaseAsBuilt rego h p o E α
      | some st => phaseFrom rego h p o E α st
    let used : State := match prev with
      | none => phase
      | some st => st
    let F := prune p o phase
    if (ctxDeps p).all (fun d => used.get d == F.get d) then some F
    else fix9813Loop rego h p o E α n (some F)

/-- The fix's verify: refused (false) when the loop has not converged within
    len(steps)+1 rounds. -/
def verifyFix9813 (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options)
    (E : List Envelope) : Bool :=
  admissible p o &&
  (assignments regoExt h p o E).any fun α =>
    match fix9813Loop rego h p o E α (p.steps.length + 1) none with
    | some F => verdictOn regoExt h p o E F
    | none => false

/-- Kahn's algorithm over attestationsFrom ∪ artifactsFrom: a step is ready
    once every dependency that names a policy step is done. A dependency on a
    name that is not a step has no outgoing edges in the engine's DFS, so it
    cannot close a cycle. -/
def unionAcyclicAux (names : List String) : Nat → List String → List Step → Bool
  | _, _, [] => true
  | 0, _, _ => false
  | n + 1, done, pending =>
    let ready := pending.filter fun s =>
      (s.attestationsFrom ++ s.artifactsFrom).all fun d => !names.contains d || done.contains d
    if ready.isEmpty then false
    else unionAcyclicAux names n (done ++ ready.map (·.name))
      (pending.filter fun s => !ready.any (·.name == s.name))

/-- The validator #9860 shipped with the fix: the combined
    attestationsFrom ∪ artifactsFrom graph has no cycle, or the policy is
    refused before any evidence is read.
    -- cite: attestation/policy/policy.go:517-576 sha256:ca5c15317a583acf447f40503769b9c42ea07629ba1b97dca184a43a5ff03f64
    -- cite: attestation/policy/policy.go:587-598 sha256:60b550df0f0bca5541de37f0e8a89a5f3157aeb3585f982f41dc90a99d7e3cc5
    -/
def unionAcyclic (p : Policy) : Bool :=
  unionAcyclicAux (p.steps.map (·.name)) p.steps.length [] p.steps

/-- The engine as shipped by #9860: the union-acyclicity validator, then the
    round-bounded fix. -/
def verifyShipped (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options)
    (E : List Envelope) : Bool :=
  unionAcyclic p && verifyFix9813 rego regoExt h p o E

namespace Bound9813
open Fixtures

/-- b_i passes iff i = 0 or some `a` collection in input.steps carries the
    marker for i+1. Deterministic. -/
def chainRego : Rego := fun g a ctx =>
  g == 0 || a.body == 0 ||
    ctx.steps.any fun d => d.1 == "a" && d.2.any fun c => c.attestors.any fun x => x.type == "mark" && x.body == a.body + 1

def aStep : Step := { step "a" with artifactsFrom := ["b"] }
def bStep : Step := { step "b" 1 with attestationsFrom := ["a"] }
/-- `a` consumes `b`'s products; `b`'s Rego reads `a`. The combined graph has
    the cycle a → b → a; each relation alone is acyclic. -/
def pol : Policy := basePolicy [aStep, bStep]

def path (i : Nat) : String := ["x0", "x1", "x2", "x3", "x4"].getD i "x"
def dig (i : Nat) : String := ["d0", "d1", "d2", "d3", "d4"].getD i "d"

def aEnv (i : Nat) : Envelope :=
  env (path i) { coll "a" [⟨"mark", i, none⟩] [(path i, [("sha256", dig i)])] with
    attestors := [⟨attT, i, none⟩, ⟨"mark", i, none⟩] }
def bEnv (i : Nat) : Envelope :=
  env (dig i) { coll "b" [] [] [(path i, [("sha256", dig i)])] with attestors := [⟨attT, i, none⟩] }

def evidence (m : Nat) : List Envelope := (List.range (m + 1)).flatMap fun i => [aEnv i, bEnv i]

/-- m = 2 converges inside the bound and passes. -/
theorem m2_passes : verifyFix9813 chainRego regoExt .enforce pol opts (evidence 2) = true := by decide

/-- m = 3: the fix refuses after len(steps)+1 = 3 rounds... -/
theorem m3_refused : verifyFix9813 chainRego regoExt .enforce pol opts (evidence 3) = false := by decide

/-- ...although the same iteration, given more rounds, settles on a PASS: the
    policy converges, it just needs m+1 rounds. -/
theorem m3_converges_later :
    (fix9813Loop chainRego .enforce pol opts (evidence 3) [] 8 none).isSome = true ∧
    verifyFixed chainRego regoExt .enforce pol opts (evidence 3) = true := by decide

end Bound9813
end CilockPolicy
