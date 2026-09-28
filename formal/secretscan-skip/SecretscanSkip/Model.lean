/-
  SecretscanSkip.Model: the secretscan own-output skip, as cilock implements
  it (plugins/attestors/secretscan/own_output.go on #10174/#10175).

  A scan of the working tree may skip a file that is cilock's own output: the
  file this process writes its stdout or stderr to (#10174), or a signed
  attestation-collection envelope from another run (#10175). The security
  argument is that such a file is skipped only when git proves no commit in
  the push, and no commit `git commit` would make now, carries it.

  `Facts` is GROUND TRUTH about one path, stated from outside the program:
  what the file really is and what git really says about the file itself.
  `skip` is the Go decision, written over the observables the Go code reads
  (`lstat`, `os.SameFile`, `filepath.EvalSymlinks`, `git ls-files`/`ls-tree`
  of the spelled path), each derived from the ground truth by the same
  relation the operating system and git impose. The theorems then say what a
  skip implies about the ground truth.
-/

namespace SecretscanSkip

/-- Ground truth about one candidate path `rel` under the working directory. -/
structure Facts where
  /-- `rel` is non-empty, relative, and does not climb out (`..`). -/
  inside : Bool
  /-- The working directory is in a git work tree whose HEAD is born, so
      `git ls-files --cached` and `git ls-tree HEAD` both answer. -/
  gitReady : Bool
  /-- Some component of `rel` other than the last is a symlink. -/
  parentSymlink : Bool
  /-- The last component of `rel` is a symlink. -/
  finalSymlink : Bool
  /-- The path resolves (every symlink along it has a target). -/
  resolves : Bool
  /-- The REAL file (after resolving every symlink) is in the index or in
      HEAD's tree: staged, committed, or both. -/
  tracked : Bool
  /-- The spelled name `rel` is in the index or in HEAD's tree. Equal to
      `tracked` when no component is a symlink (see `WellFormed`). -/
  spelledTracked : Bool
  /-- The real file is the same file (device and inode) as a regular file
      this process writes its stdout or stderr to. -/
  isStream : Bool
  /-- The bytes read through `rel` are, or contain on a line of their own, a
      signed DSSE envelope over an attestation collection. -/
  envelope : Bool
  /-- The text outside the envelope holds a secret finding, or scanning it
      failed. -/
  residualDirty : Bool
  /-- The path is at or under a submodule gitlink: the parent repository's
      index and HEAD list only the gitlink, never the files inside it, so the
      parent's answer about the spelled path says nothing about the file. -/
  underGitlink : Bool := false
  /-- The candidate is a product the wrapped command recorded, rather than a
      file that diff-scope untracked discovery found. cilock's redirected
      stdout/stderr reaches the scanner this way, so the stream skip (an
      identity proof) still applies; the envelope skip (a shape guess) does
      not. -/
  recordedProduct : Bool := false
  /-- The attestor's scope is not a diff scope (`tree`, or the default
      products scope). A tree scope reads the working tree on purpose, so an
      envelope found there is scanned. -/
  treeScope : Bool := false
  /-- The file belongs to a nested repository that is not a submodule: git,
      asked from the file's own directory, names another toplevel. The outer
      index says nothing about it. -/
  nestedRepo : Bool := false
  deriving Repr, DecidableEq

/-- The one relation the file system imposes between the spelled name and the
    real file: with no symlink along the path and no submodule boundary above
    it, they are the same name in the same repository, so git answers the same
    for both. -/
def WellFormed (f : Facts) : Prop :=
  f.parentSymlink = false → f.finalSymlink = false → f.underGitlink = false →
    f.nestedRepo = false → f.spelledTracked = f.tracked

/-! ## The Go decision, over its observables -/

/-- `isOwnStream`: `os.Lstat(abs)` is a regular file (so the last component is
    not a symlink) and `os.SameFile` matches a regular stdout/stderr. -/
def ownStream (f : Facts) : Bool :=
  f.resolves && !f.finalSymlink && f.isStream

/-- `realPathMismatch(...) == ""`: `EvalSymlinks(wd/rel)` succeeds and equals
    `EvalSymlinks(wd)/rel`, which holds exactly when no component of `rel` is a
    symlink. -/
def realMatches (f : Facts) : Bool :=
  f.resolves && !f.parentSymlink && !f.finalSymlink

/-- `provenUntracked`: inside, git answered, the real-path check passed, the
    path is not at or under a submodule gitlink, and the spelled path is in
    neither the index nor HEAD. -/
def provenUntracked (f : Facts) : Bool :=
  f.inside && f.gitReady && realMatches f && !f.spelledTracked && !f.underGitlink &&
    !f.nestedRepo

/-- `ownOutputReason`'s route test for the envelope: only the diff scope's
    working-tree walk. -/
def envelopeRoute (f : Facts) : Bool :=
  !f.recordedProduct && !f.treeScope

/-- `skipAsOwnOutput`: a proven-untracked path and a reason. The stream
    reason (identity) applies to any candidate; the envelope reason (shape)
    applies only to a file untracked discovery found, never to a recorded
    product, and needs a clean residual. -/
def skip (f : Facts) : Bool :=
  provenUntracked f &&
    (ownStream f || (envelopeRoute f && f.envelope && !f.residualDirty))

/-! ## Earlier rules, kept for the refutations -/

/-- Round 2 of #10174/#10175 (heads 3b04d70fe0 / 8e59cd8082): the real-path
    check, but no gitlink check and no restriction to discovered files. -/
def skipRound2 (f : Facts) : Bool :=
  (f.inside && f.gitReady && realMatches f && !f.spelledTracked) &&
    (ownStream f || (f.envelope && !f.residualDirty))

/-- Round 1 of #10174: the stream check used `os.Lstat` (the last component
    only) and git was asked about the spelled path with no real-path check. -/
def skipRound1 (f : Facts) : Bool :=
  (f.inside && f.gitReady && !f.spelledTracked) &&
    ((f.resolves && !f.finalSymlink && f.isStream) || (f.envelope && !f.residualDirty))

/-- The first version of #10174: the stream check used `os.Stat`, which
    follows a final symlink to its target. -/
def skipRound0 (f : Facts) : Bool :=
  (f.inside && f.gitReady && !f.spelledTracked) &&
    ((f.resolves && f.isStream) || (f.envelope && !f.residualDirty))

end SecretscanSkip
