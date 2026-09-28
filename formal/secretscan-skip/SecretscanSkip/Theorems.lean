/-
  SecretscanSkip.Theorems: what a skip implies about the file itself.
-/
import SecretscanSkip.Model

namespace SecretscanSkip

/-- A skip needs git's positive answer about a path inside the working tree,
    reached with no symlink anywhere along it. -/
theorem skip_proven (f : Facts) (h : skip f = true) :
    f.inside = true ∧ f.gitReady = true ∧ f.resolves = true ∧
      f.parentSymlink = false ∧ f.finalSymlink = false ∧ f.underGitlink = false ∧
      f.nestedRepo = false ∧ f.spelledTracked = false := by
  cases f
  simp_all [skip, provenUntracked, realMatches]

/-- The headline: a skipped file is untracked as ITSELF, not merely under the
    name it was reached by. No staged or committed file is ever skipped. -/
theorem skip_implies_untracked (f : Facts) (wf : WellFormed f) (h : skip f = true) :
    f.tracked = false := by
  obtain ⟨_, _, _, hp, hfin, hg, hn, hs⟩ := skip_proven f h
  rw [← wf hp hfin hg hn]
  exact hs

/-- The contrapositive, as the property a reviewer checks: tracked files are
    always scanned. -/
theorem tracked_never_skipped (f : Facts) (wf : WellFormed f) (ht : f.tracked = true) :
    skip f = false := by
  cases hs : skip f
  · rfl
  · have := skip_implies_untracked f wf hs
    rw [ht] at this
    exact absurd this (by decide)

/-- A skipped file is cilock's own output: its own stream by identity, or a
    discovered (not recorded) envelope whose surrounding text is clean. -/
theorem skip_implies_own (f : Facts) (h : skip f = true) :
    f.isStream = true ∨
      (f.recordedProduct = false ∧ f.treeScope = false ∧ f.envelope = true ∧
        f.residualDirty = false) := by
  cases f with
  | mk inside gitReady parentSymlink finalSymlink resolves tracked spelledTracked isStream
      envelope residualDirty underGitlink recordedProduct treeScope nestedRepo =>
    cases isStream <;> cases recordedProduct <;> cases treeScope <;> cases envelope <;>
      cases residualDirty <;> simp_all [skip, ownStream, envelopeRoute]

/-- A path at or under a submodule gitlink is never skipped: the parent's
    index names only the gitlink, so it cannot prove the file untracked. -/
theorem gitlink_never_skipped (f : Facts) (h : f.underGitlink = true) : skip f = false := by
  cases f
  simp_all [skip, provenUntracked]

/-- A product the wrapped command recorded is skipped only by stream
    identity: cilock's redirected output still reaches the stream skip, but an
    envelope-shaped product is always scanned. -/
theorem recorded_product_skipped_only_by_stream (f : Facts) (hr : f.recordedProduct = true)
    (h : skip f = true) : f.isStream = true := by
  rcases skip_implies_own f h with hs | ⟨hr', _, _⟩
  · exact hs
  · rw [hr] at hr'; exact absurd hr' (by decide)

/-- A nested repository that is not a submodule owns its files; the outer
    index cannot prove one untracked, so it is scanned. -/
theorem nested_repo_never_skipped (f : Facts) (h : f.nestedRepo = true) : skip f = false := by
  cases f
  simp_all [skip, provenUntracked]

/-- Under a tree (or products) scope, only stream identity skips a file: an
    envelope found there is scanned. -/
theorem tree_scope_skipped_only_by_stream (f : Facts) (ht : f.treeScope = true)
    (h : skip f = true) : f.isStream = true := by
  rcases skip_implies_own f h with hs | ⟨_, ht', _⟩
  · exact hs
  · rw [ht] at ht'; exact absurd ht' (by decide)

/-- The contrapositive: a recorded product that is not this process's stream
    is always scanned, envelope or not. -/
theorem recorded_non_stream_scanned (f : Facts) (hr : f.recordedProduct = true)
    (hs : f.isStream = false) : skip f = false := by
  cases h : skip f
  · rfl
  · have := recorded_product_skipped_only_by_stream f hr h
    rw [hs] at this; exact absurd this (by decide)

/-- Any symlink along the path, the last component included, means a scan. -/
theorem symlink_never_skipped (f : Facts) (h : f.parentSymlink = true ∨ f.finalSymlink = true) :
    skip f = false := by
  cases f
  rcases h with h | h <;> simp_all [skip, provenUntracked, realMatches]

/-- In particular a symlink whose target is this process's stream is not the
    stream, and is scanned. -/
theorem symlink_to_stream_never_skipped (f : Facts) (h : f.finalSymlink = true) :
    skip f = false :=
  symlink_never_skipped f (Or.inr h)

/-- Outside a git work tree with a born HEAD, nothing is proven untracked. -/
theorem no_git_never_skipped (f : Facts) (h : f.gitReady = false) : skip f = false := by
  cases f
  simp_all [skip, provenUntracked]

/-- A path that is not inside the working directory is scanned. -/
theorem outside_never_skipped (f : Facts) (h : f.inside = false) : skip f = false := by
  cases f
  simp_all [skip, provenUntracked]

/-- A finding in the text beside an envelope makes the whole file scanned,
    unless the file is the stream itself. -/
theorem dirty_residual_scanned (f : Facts) (hs : f.isStream = false) (hd : f.residualDirty = true) :
    skip f = false := by
  cases f
  simp_all [skip, ownStream]

/-- Content that is neither the stream nor an envelope is never skipped,
    whatever its name. -/
theorem not_own_never_skipped (f : Facts) (hs : f.isStream = false) (he : f.envelope = false) :
    skip f = false := by
  cases f
  simp_all [skip, ownStream]

/-- The whole decision, as one equation. -/
theorem skip_iff (f : Facts) :
    skip f = true ↔
      (f.inside = true ∧ f.gitReady = true ∧ f.resolves = true ∧
        f.parentSymlink = false ∧ f.finalSymlink = false ∧ f.underGitlink = false ∧
        f.nestedRepo = false ∧ f.spelledTracked = false ∧
        (f.isStream = true ∨
          (f.recordedProduct = false ∧ f.treeScope = false ∧ f.envelope = true ∧
            f.residualDirty = false))) := by
  constructor
  · intro h
    obtain ⟨hi, hg, hr, hp, hf, hl, hn, hs⟩ := skip_proven f h
    exact ⟨hi, hg, hr, hp, hf, hl, hn, hs, skip_implies_own f h⟩
  · rintro ⟨hi, hg, hr, hp, hf, hl, hn, hs, hst | ⟨hrp, ht, he, hd⟩⟩
    · simp [skip, provenUntracked, realMatches, ownStream, hi, hg, hr, hp, hf, hl, hn, hs, hst]
    · simp [skip, provenUntracked, realMatches, envelopeRoute, hi, hg, hr, hp, hf, hl, hn, hs,
        hrp, ht, he, hd]

/-! ## Refutations of the earlier rules -/

/-- Round 2's finding on #10174: `alias -> tracked-dir`, product
    `alias/report.log`, which is the tracked `tracked-dir/report.log` this
    process writes its stream to. git has no entry named `alias/report.log`. -/
def parentSymlinkTrackedStream : Facts :=
  { inside := true, gitReady := true, parentSymlink := true, finalSymlink := false,
    resolves := true, tracked := true, spelledTracked := false, isStream := true,
    envelope := false, residualDirty := false }

theorem parentSymlinkTrackedStream_wf : WellFormed parentSymlinkTrackedStream := by
  intro h; cases h

/-- The round-1 rule skipped a tracked file. -/
theorem round1_skipped_tracked :
    skipRound1 parentSymlinkTrackedStream = true ∧ parentSymlinkTrackedStream.tracked = true := by
  decide

/-- The current rule scans it. -/
theorem current_scans_parent_symlink : skip parentSymlinkTrackedStream = false := by decide

/-- The first version's finding: an untracked link `out/link.log` whose target
    is the tracked file this process writes its stream to. -/
def finalSymlinkTrackedStream : Facts :=
  { inside := true, gitReady := true, parentSymlink := false, finalSymlink := true,
    resolves := true, tracked := true, spelledTracked := false, isStream := true,
    envelope := false, residualDirty := false }

theorem finalSymlinkTrackedStream_wf : WellFormed finalSymlinkTrackedStream := by
  intro _ h; cases h

/-- `os.Stat` followed the link, so the first version skipped a tracked file. -/
theorem round0_skipped_tracked :
    skipRound0 finalSymlinkTrackedStream = true ∧ finalSymlinkTrackedStream.tracked = true := by
  decide

/-- Round 1 (`os.Lstat`) already scanned that one; round 1 fell to the parent
    case above. -/
theorem round1_scans_final_symlink : skipRound1 finalSymlinkTrackedStream = false := by decide

theorem current_scans_final_symlink : skip finalSymlinkTrackedStream = false := by decide

/-- Codex round 3: a file inside a submodule, committed there, that this
    process writes its stream to. The parent's index lists only the gitlink,
    so the spelled path looks untracked to the parent. -/
def gitlinkTrackedStream : Facts :=
  { inside := true, gitReady := true, parentSymlink := false, finalSymlink := false,
    resolves := true, tracked := true, spelledTracked := false, isStream := true,
    envelope := false, residualDirty := false, underGitlink := true }

theorem gitlinkTrackedStream_wf : WellFormed gitlinkTrackedStream := by
  intro _ _ h; cases h

/-- The round-2 rule skipped a tracked file inside a submodule. -/
theorem round2_skipped_gitlink_tracked :
    skipRound2 gitlinkTrackedStream = true ∧ gitlinkTrackedStream.tracked = true := by
  decide

theorem current_scans_gitlink : skip gitlinkTrackedStream = false := by decide

/-- Codex round 3: a product the wrapped command recorded that parses as a
    signed collection envelope, with a secret inside the envelope's payload.
    The residual scan sees only text OUTSIDE the envelope, so it is clean; the
    secret is in bytes the envelope skip never reads. It is the step's output,
    not cilock's. -/
def recordedEnvelopeProduct : Facts :=
  { inside := true, gitReady := true, parentSymlink := false, finalSymlink := false,
    resolves := true, tracked := false, spelledTracked := false, isStream := false,
    envelope := true, residualDirty := false, recordedProduct := true }

/-- The round-2 rule skipped it, so a step could hide a secret from the scan
    by wrapping its own output in an envelope shape. -/
theorem round2_skipped_recorded_product : skipRound2 recordedEnvelopeProduct = true := by decide

theorem current_scans_recorded_product : skip recordedEnvelopeProduct = false := by decide

/-- cilock's own redirected stream, recorded as a product: round 3 must still
    skip it, or #10174 is undone. -/
def recordedOwnStream : Facts :=
  { inside := true, gitReady := true, parentSymlink := false, finalSymlink := false,
    resolves := true, tracked := false, spelledTracked := false, isStream := true,
    envelope := false, residualDirty := false, recordedProduct := true }

theorem current_skips_recorded_own_stream : skip recordedOwnStream = true := by decide

/-- Codex round 3: a file committed in a nested repository (not a submodule)
    that this process writes its stream to. The outer index never lists it. -/
def nestedRepoTrackedStream : Facts :=
  { inside := true, gitReady := true, parentSymlink := false, finalSymlink := false,
    resolves := true, tracked := true, spelledTracked := false, isStream := true,
    envelope := false, residualDirty := false, nestedRepo := true }

theorem nestedRepoTrackedStream_wf : WellFormed nestedRepoTrackedStream := by
  intro _ _ _ h; cases h

theorem round2_skipped_nested_repo_tracked :
    skipRound2 nestedRepoTrackedStream = true ∧ nestedRepoTrackedStream.tracked = true := by
  decide

theorem current_scans_nested_repo : skip nestedRepoTrackedStream = false := by decide

/-- Codex round 3: an untracked envelope with a secret in its payload, found by
    a tree-scope walk, which reads the working tree on purpose. -/
def treeScopeEnvelope : Facts :=
  { inside := true, gitReady := true, parentSymlink := false, finalSymlink := false,
    resolves := true, tracked := false, spelledTracked := false, isStream := false,
    envelope := true, residualDirty := false, treeScope := true }

theorem round2_skipped_tree_scope_envelope : skipRound2 treeScopeEnvelope = true := by decide

theorem current_scans_tree_scope_envelope : skip treeScopeEnvelope = false := by decide

theorem round2_breaks_untracked :
    ¬ (∀ f, WellFormed f → skipRound2 f = true → f.tracked = false) := by
  intro h
  have := h gitlinkTrackedStream gitlinkTrackedStream_wf round2_skipped_gitlink_tracked.1
  exact absurd this (by decide)

/-- The earlier rules broke exactly the headline theorem. -/
theorem round1_breaks_untracked :
    ¬ (∀ f, WellFormed f → skipRound1 f = true → f.tracked = false) := by
  intro h
  have := h parentSymlinkTrackedStream parentSymlinkTrackedStream_wf round1_skipped_tracked.1
  exact absurd this (by decide)

theorem round0_breaks_untracked :
    ¬ (∀ f, WellFormed f → skipRound0 f = true → f.tracked = false) := by
  intro h
  have := h finalSymlinkTrackedStream finalSymlinkTrackedStream_wf round0_skipped_tracked.1
  exact absurd this (by decide)

end SecretscanSkip
