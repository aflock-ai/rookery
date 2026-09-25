/-!
# The alps-evidence ancestry verdict

The one Go decision the ALPS 0.1 producer makes: what the walk of cilock's
process ancestry concluded. It is computed only from what the walk observed:
-- cite: plugins/attestors/alps-evidence/verdict.go:81-89 sha256:593a3cc392121e3f50e06125699eb3bc8a532759fb7e59866e82fbced93c9b15
and every field it reports is graded by how it was learned, never promoted:
-- cite: plugins/attestors/alps-evidence/predicate.go:132-151 sha256:994d4a7c53abeb79e5a988afe4740602f01eb4f2992218e86f29183151e29c14
The self-description forgery threat is explicitly not mitigated:
-- see (monorepo, outside this tree): docs/design/alps-attribution-containment-tracks.md:127-127

`verdict` is the function the differential test runs against the Go.
-/

namespace CiProvenance

inductive Status where
  | detected | notDetected | incomplete | unavailable
  deriving DecidableEq, Repr

def Status.wire : Status → String
  | .detected => "detected"
  | .notDetected => "not-detected"
  | .incomplete => "incomplete"
  | .unavailable => "unavailable"

/-- `walkCoverage`: what the walk observed. -/
structure Coverage where
  unexamined : List String
  stopped    : String
  matched    : Bool
  unbound    : String
  deriving DecidableEq, Repr

/-- The walk examined every ancestor it passed and reached a root or a match. -/
def Coverage.complete (c : Coverage) : Bool :=
  c.stopped == "" && c.unexamined.isEmpty && c.unbound == ""

def verdict (c : Coverage) : Status :=
  if c.stopped != "" || !c.unexamined.isEmpty || c.unbound != "" then .incomplete
  else if c.matched then .detected
  else .notDetected

theorem complete_iff (c : Coverage) :
    c.complete = !(c.stopped != "" || !c.unexamined.isEmpty || c.unbound != "") := by
  unfold Coverage.complete
  simp only [bne]
  cases (c.stopped == "") <;> cases c.unexamined.isEmpty <;> cases (c.unbound == "") <;> rfl

/-- A positive verdict (either one) needs a complete walk. -/
theorem positive_verdict_needs_complete_walk (c : Coverage)
    (h : verdict c = .detected ∨ verdict c = .notDetected) : c.complete = true := by
  rw [complete_iff]
  unfold verdict at h
  split at h
  · simp at h
  · simpa using (by assumption : ¬((c.stopped != "" || !c.unexamined.isEmpty || c.unbound != "") = true))

theorem detected_iff (c : Coverage) : verdict c = .detected ↔ c.complete = true ∧ c.matched = true := by
  constructor
  · intro h
    refine ⟨positive_verdict_needs_complete_walk c (Or.inl h), ?_⟩
    unfold verdict at h
    split at h
    · simp at h
    · split at h
      · assumption
      · simp at h
  · intro ⟨hc, hm⟩
    rw [complete_iff] at hc
    unfold verdict
    split
    · rename_i hcond
      simp [hcond] at hc
    · simp_all

/-- The walk never reports `unavailable`: that status is set only where the
platform refused the walk, outside this function. -/
theorem verdict_never_unavailable (c : Coverage) : verdict c ≠ .unavailable := by
  unfold verdict
  split
  · simp
  · split <;> simp

end CiProvenance
