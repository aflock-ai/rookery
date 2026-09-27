/-
  SemgrepAttestor.Summary: what the signed summary may say about a report.

  The attestor records facts and never a pass/fail verdict (design doc §3.7);
  the policy decides. What the summary must not do is overstate a scan:
    * scanComplete is true only when errors[] is empty, whatever level each
      entry was logged at (a timed-out file is `warn` but lost coverage);
    * bySeverity counts LIVE findings only, so a waived (is_ignored) finding
      never counts, and live + ignored = total;
    * every subject comes from a live finding: a waived finding is never
      indexable as a live one, and a file subject exists only for a file whose
      content digest cilock recorded (never a name hash).
-/
namespace SemgrepAttestor

inductive Sev where
  | critical
  | high
  | medium
  | low
  | info
  | unknown
  deriving DecidableEq, Repr

structure Finding where
  id : Nat
  sev : Sev
  ignored : Bool
  /-- the recorded material digest of the finding's file, if cilock saw it -/
  fileDigest : Option Nat
  deriving DecidableEq, Repr

def live (f : Finding) : Bool := !f.ignored

/-- scanComplete: no errors[] entry at any level. -/
def scanComplete (errors : List α) : Bool := errors.isEmpty

theorem scanComplete_iff (errors : List α) : scanComplete errors = true ↔ errors = [] := by
  unfold scanComplete
  cases errors <;> simp

/-- The count in one severity bucket: live findings of that severity. -/
def bucket (fs : List Finding) (s : Sev) : Nat := fs.countP (fun f => live f && f.sev == s)

def ignoredCount (fs : List Finding) : Nat := fs.countP (fun f => f.ignored)

def liveCount (fs : List Finding) : Nat := fs.countP live

def bucketTotal (fs : List Finding) : Nat :=
  bucket fs .critical + bucket fs .high + bucket fs .medium +
  bucket fs .low + bucket fs .info + bucket fs .unknown

/-- The six buckets partition exactly the live findings. -/
theorem bucketTotal_eq_live (fs : List Finding) : bucketTotal fs = liveCount fs := by
  induction fs with
  | nil => rfl
  | cons f fs ih =>
    unfold bucketTotal bucket liveCount at *
    simp only [List.countP_cons]
    cases hf : f.ignored <;> cases hs : f.sev <;> simp_all [live] <;> omega

/-- live + ignored = total: no finding is dropped from the roll-up. -/
theorem live_add_ignored (fs : List Finding) : liveCount fs + ignoredCount fs = fs.length := by
  induction fs with
  | nil => rfl
  | cons f fs ih =>
    unfold liveCount ignoredCount at *
    simp only [List.countP_cons, List.length_cons]
    cases hf : f.ignored <;> simp_all [live] <;> omega

inductive Subject where
  | finding (id : Nat)
  | file (digest : Nat)
  deriving DecidableEq, Repr

/-- The subjects the attestor mints (rule subjects carry no evidence of their
    own and are omitted). -/
def subjects (fs : List Finding) : List Subject :=
  fs.flatMap fun f =>
    if f.ignored then []
    else Subject.finding f.id :: (match f.fileDigest with
      | some d => [Subject.file d]
      | none => [])

/-- Every finding subject names a live finding. -/
theorem finding_subject_live {fs : List Finding} {i : Nat}
    (h : Subject.finding i ∈ subjects fs) : ∃ f ∈ fs, f.ignored = false ∧ f.id = i := by
  unfold subjects at h
  rw [List.mem_flatMap] at h
  obtain ⟨f, hf, hs⟩ := h
  cases hi : f.ignored
  · refine ⟨f, hf, hi, ?_⟩
    simp only [hi, Bool.false_eq_true, ite_false, List.mem_cons] at hs
    rcases hs with hs | hs
    · cases hs; rfl
    · cases hd : f.fileDigest <;> simp [hd] at hs
  · simp [hi] at hs

/-- Every file subject carries a digest cilock recorded for a live finding's
    file; a file cilock did not observe gets no subject. -/
theorem file_subject_recorded {fs : List Finding} {d : Nat}
    (h : Subject.file d ∈ subjects fs) :
    ∃ f ∈ fs, f.ignored = false ∧ f.fileDigest = some d := by
  unfold subjects at h
  rw [List.mem_flatMap] at h
  obtain ⟨f, hf, hs⟩ := h
  cases hi : f.ignored
  · refine ⟨f, hf, hi, ?_⟩
    simp only [hi, Bool.false_eq_true, ite_false, List.mem_cons] at hs
    rcases hs with hs | hs
    · cases hs
    · cases hd : f.fileDigest <;> simp_all
  · simp [hi] at hs

end SemgrepAttestor
