/-!
# gitlab-review: an approval counts only for the exact sha it approved

Cole, 2026-09-29: approvals bind to the EXACT sha; an approval given on any
other sha does not count, and there is no patch-id opt-in
(docs/design/gitlab-api-attestors.md, sections 3.3 and 10).

GitLab records no sha per approval, so it is derived from the merge
request's diff versions: an approval binds to the head of the newest version
created strictly before it. A tie with a version's creation time, a time
within `skew` of one, an approval older than every version, or two versions
created at the same newest instant with different heads bind to nothing.

`boundHead`, `counts`, `countFor` are the model of
attestation/gitlabreview (binding.go); its differential test runs both.
-/

namespace CilockCi.Review

structure Version where
  head : String
  createdAt : Nat
deriving Repr, DecidableEq

structure Approval where
  user : Nat
  approvedAt : Nat
deriving Repr, DecidableEq

/-- `|a - b| ≤ skew`, over naturals. -/
def near (skew a b : Nat) : Bool := decide (a ≤ b + skew) && decide (b ≤ a + skew)

/-- The newest creation time among `vs`, if any. -/
def newest : List Version → Option Nat
  | [] => none
  | v :: vs => match newest vs with
    | none => some v.createdAt
    | some m => some (max v.createdAt m)

/-- The head this approval binds to, or none. -/
def boundHead (skew : Nat) (vs : List Version) (t : Nat) : Option String :=
  if vs.any (fun v => near skew t v.createdAt) then none else
  let before := vs.filter (fun v => decide (v.createdAt < t))
  match newest before with
  | none => none
  | some m =>
    match (before.filter (·.createdAt == m)).map (·.head) with
    | [] => none
    | h :: hs => if hs.all (· == h) then some h else none

/-- Counted for head `h` of an MR merged at `mergedAt`. -/
def counts (skew : Nat) (vs : List Version) (mergedAt : Nat) (h : String) (a : Approval) : Bool :=
  boundHead skew vs a.approvedAt == some h && decide (a.approvedAt ≤ mergedAt)

/-- Distinct approvers with a counted approval, the author excluded when given. -/
def countFor (skew : Nat) (vs : List Version) (as : List Approval) (mergedAt : Nat) (h : String)
    (author : Option Nat) : Nat :=
  (((as.filter (counts skew vs mergedAt h)).map (·.user)).eraseDups.filter (fun u => some u != author)).length

theorem counts_only_bound_sha (skew : Nat) (vs : List Version) (mergedAt : Nat) (h : String) (a : Approval)
    (hc : counts skew vs mergedAt h a = true) : boundHead skew vs a.approvedAt = some h := by
  simp only [counts, Bool.and_eq_true, beq_iff_eq] at hc
  exact hc.1

/-- An approval bound to any other sha never counts: the exact-sha ruling. -/
theorem other_sha_not_counted (skew : Nat) (vs : List Version) (mergedAt : Nat) (h p : String) (a : Approval)
    (hb : boundHead skew vs a.approvedAt = some p) (hne : p ≠ h) : counts skew vs mergedAt h a = false := by
  simp [counts, hb, hne]

theorem late_approval_not_counted (skew : Nat) (vs : List Version) (mergedAt : Nat) (h : String) (a : Approval)
    (hl : mergedAt < a.approvedAt) : counts skew vs mergedAt h a = false := by
  simp only [counts, Bool.and_eq_false_iff]
  right
  simp
  omega

/-- The ruling's test: the parent `p` was pushed at 10, the head `h` at 20;
an approval at 15 was given on the parent, and does not count for the head
(nor does it with a 60-unit clock guard, which refuses it outright). -/
theorem parent_sha_approval_fails :
    countFor 0 [⟨"p", 10⟩, ⟨"h", 20⟩] [⟨7, 15⟩] 100 "h" none = 0 ∧
    countFor 0 [⟨"p", 10⟩, ⟨"h", 20⟩] [⟨7, 15⟩] 100 "p" none = 1 ∧
    countFor 0 [⟨"p", 10⟩, ⟨"h", 20⟩] [⟨7, 25⟩] 100 "h" none = 1 := by
  decide

/-- A tie with a version's creation time binds to nothing. -/
theorem tie_unbound (skew : Nat) (vs : List Version) (v : Version) (hv : v ∈ vs) :
    boundHead skew vs v.createdAt = none := by
  have : vs.any (fun w => near skew v.createdAt w.createdAt) = true := by
    rw [List.any_eq_true]
    exact ⟨v, hv, by simp [near]⟩
  simp [boundHead, this]

end CilockCi.Review
