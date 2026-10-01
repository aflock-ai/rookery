/-!
# GitLab tiers: graceful degradation without failing open

The contract of docs/design/gitlab-api-attestors.md section 2.7 for the
gitlab-review and gitlab-project-config attestors (designed, not built):

- the attestor detects the GitLab plan once;
- a tier-gated read that answers "this tier lacks it" is recorded as
  `unavailable` ONLY when the feature is above the detected plan;
- any other failure (auth, network, malformed, or "missing" at a plan that
  should have it) fails the attestor loudly;
- a policy requirement over a field is met only by an observed value that
  meets it; `unavailable` never satisfies one, and a policy that requires
  nothing is unaffected.

`collect` is the model of the attestor's per-field decision and `satisfied`
the model of the shipped rego helper. The Go differential test lands with
the attestors; `Eval.lean` already answers `{"fn":"tier", ..}` cases.
-/

namespace CilockCi

inductive Plan where
  | free | premium | ultimate
deriving Repr, DecidableEq

def Plan.rank : Plan → Nat
  | .free => 0
  | .premium => 1
  | .ultimate => 2

/-- What GitLab answered for one tier-gated read. -/
inductive TierAnswer where
  /-- 2xx with a well-formed value (a count, or 0/1 for a flag) -/
  | ok (v : Nat)
  /-- the answer a lower tier gives: REST 404 route missing, GraphQL `undefinedField` -/
  | tierMissing
  /-- 401, 403, 5xx, network, malformed body -/
  | failure
deriving Repr, DecidableEq

structure Unavailable where
  detected : Plan
  needs : Plan
deriving Repr, DecidableEq

inductive Field where
  | observed (v : Nat)
  | unavailable (r : Unavailable)
deriving Repr, DecidableEq

inductive CollectError where
  /-- the read failed, or said "missing" at a plan that has the feature -/
  | loud
deriving Repr, DecidableEq

/-- The attestor's decision for one field. -/
def collect (detected needs : Plan) (a : TierAnswer) : Except CollectError Field :=
  match a with
  | .ok v => .ok (.observed v)
  | .tierMissing => if needs.rank > detected.rank then .ok (.unavailable ⟨detected, needs⟩) else .error .loud
  | .failure => .error .loud

/-- A policy requirement over one field. -/
inductive Req where
  | none
  | atLeast (n : Nat)
deriving Repr, DecidableEq

/-- The rego helper: observed and meets it, or not satisfied. -/
def satisfied (f : Field) : Req → Bool
  | .none => true
  | .atLeast n => match f with
    | .observed v => decide (n ≤ v)
    | .unavailable _ => false

/-- `unavailable` never satisfies a requirement. -/
theorem unavailable_never_satisfies (u : Unavailable) (r : Req) (h : r ≠ .none) :
    satisfied (.unavailable u) r = false := by
  cases r with
  | none => exact absurd rfl h
  | atLeast n => rfl

/-- A policy that requires nothing is unaffected by the tier. -/
theorem no_requirement_unaffected (f : Field) : satisfied f .none = true := rfl

/-- Nothing is disguised as `unavailable`: only a "tier lacks it" answer for
a feature above the detected plan becomes one. -/
theorem unavailable_only_above_plan (detected needs : Plan) (a : TierAnswer) (u : Unavailable)
    (h : collect detected needs a = .ok (.unavailable u)) :
    a = .tierMissing ∧ needs.rank > detected.rank := by
  cases a with
  | ok v => simp [collect] at h
  | tierMissing =>
    simp only [collect] at h
    split at h
    · exact ⟨rfl, by assumption⟩
    · simp at h
  | failure => simp [collect] at h

/-- Real errors stay loud: a failed read is never a field. -/
theorem failure_is_loud (detected needs : Plan) : collect detected needs .failure = .error .loud := rfl

/-- A "missing" answer at a plan that has the feature is loud, not unavailable. -/
theorem missing_at_plan_is_loud (detected needs : Plan) (h : needs.rank ≤ detected.rank) :
    collect detected needs .tierMissing = .error .loud := by
  simp only [collect]
  split
  · omega
  · rfl

end CilockCi
