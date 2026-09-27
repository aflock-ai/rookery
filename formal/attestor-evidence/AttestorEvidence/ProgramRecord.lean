/-
  AttestorEvidence.ProgramRecord: the commandrun program record (#9683, P1a of
  docs/design/command-program-pinning.md) may claim a digest only for the file
  the operating system opens, and may claim "not set-id" only when absence was
  established.

  1. Windows path. syscall.StartProcess makes argv0 absolute against Dir with
     `joinExeDirAndFName` (go1.26 syscall/exec_windows.go) before CreateProcess
     opens it. `windowsJoinExeDir` (program_exec_target.go) mirrors it, and the
     record measures its result. `joinExe` below is that rule. The rule it
     replaced concatenated Dir and argv0 whenever `filepath.IsAbs` was false,
     which is also false for a rooted `\tools\t.exe` and a drive-relative
     `D:t.exe`; `oldConcat_measures_a_decoy` is the counterexample.

     GetFullPathNameW is modelled only where the rule depends on it: a
     drive-relative name on another drive resolves against that drive's own
     current directory (`driveCwd`). Elsewhere the joined names are already
     absolute and are taken as given.

  2. Set-id (program_platform_linux.go, `programFileFacts` and
     `fileCapabilityOf`). A setuid/setgid mode bit is set-id. Otherwise only a
     descriptor read of `security.capability` that answers ENODATA or
     EOPNOTSUPP establishes "not set-id"; every other outcome is unknown.

  3. Binding. P1a never claims an execution binding: every record is
     `unverified`, and a rewrite of the exec target after the record was taken
     names why.
-/
import AttestorEvidence.Text

namespace AttestorEvidence.Program

open AttestorEvidence

def isSlash (c : Char) : Bool := c = '\\' || c = '/'

def upper (c : Char) : Char :=
  if 'a' ≤ c ∧ c ≤ 'z' then Char.ofNat (c.toNat - 32) else c

inductive Resolved where
  | name (p : Text)
  | refused
  deriving DecidableEq, Repr

/-- `joinExeDirAndFName` with `dir` already made absolute (`normalizeDir`):
    `dir` is refused when it is a UNC path or has no volume. -/
def joinExe (driveCwd : Char → Text) (dir p : Text) : Resolved :=
  let dirOk : Bool := match dir with
    | a :: b :: _ => !(isSlash a && isSlash b) && b = ':'
    | _ => false
  match p with
  | [] => .refused
  | a :: b :: c :: rest =>
    if isSlash a && isSlash b then .name p                       -- \\server\share\path
    else if b = ':' then
      if isSlash c then .name p                                  -- C:\path
      else if !dirOk then .refused
      else match dir with
        | d :: _ =>
          if upper a = upper d then .name (dir ++ ['\\'] ++ c :: rest)  -- same drive
          else .name ([a, ':'] ++ driveCwd a ++ ['\\'] ++ c :: rest)    -- that drive's cwd
        | [] => .refused
    else if !dirOk then .refused
    else if isSlash a then .name (dir.take 2 ++ p)               -- rooted: dir's volume
    else .name (dir ++ ['\\'] ++ p)
  | [a, b] =>
    if b = ':' then .refused                                     -- bare "C:"
    else if !dirOk then .refused
    else if isSlash a then .name (dir.take 2 ++ p)
    else .name (dir ++ ['\\'] ++ p)
  | [a] =>
    if !dirOk then .refused
    else if isSlash a then .name (dir.take 2 ++ p)
    else .name (dir ++ ['\\'] ++ p)

/-- The rule #9683 replaced: concatenate unless `filepath.IsAbs`, which on
    Windows needs a volume and a separator (`C:\...`) or a UNC prefix. -/
def windowsIsAbs (p : Text) : Bool :=
  match p with
  | a :: b :: c :: _ => (isSlash a && isSlash b) || (b = ':' && isSlash c)
  | _ => false

def oldConcat (dir p : Text) : Text :=
  if windowsIsAbs p then p else dir ++ ['\\'] ++ p

/-- A rooted name takes dir's volume and never lies under dir. -/
theorem rooted_takes_dir_volume (driveCwd : Char → Text) (d : Char) (dirRest : Text)
    (a b c : Char) (rest : Text) (ha : isSlash a = true) (hb : isSlash b = false)
    (hbc : b ≠ ':') (hd : isSlash d = false) :
    joinExe driveCwd (d :: ':' :: dirRest) (a :: b :: c :: rest) =
      .name ([d, ':'] ++ a :: b :: c :: rest) := by
  simp [joinExe, ha, hb, hbc, hd]

/-- An absolute name with a volume is opened as given, whatever Dir is. -/
theorem absolute_unchanged (driveCwd : Char → Text) (dir : Text) (v s : Char) (rest : Text)
    (hs : isSlash s = true) :
    joinExe driveCwd dir (v :: ':' :: s :: rest) = .name (v :: ':' :: s :: rest) := by
  by_cases hv : isSlash v = true
  · simp [joinExe, hv, hs]
  · simp [joinExe, hs, hv]

def dirW : Text := "C:\\work".toList
def rootedP : Text := "\\tools\\t.exe".toList

/-- Counterexample for the replaced rule: CreateProcess opens C:\tools\t.exe,
    the old record measured C:\work\tools\t.exe, a file an attacker can plant
    under the working directory. -/
theorem oldConcat_measures_a_decoy :
    joinExe (fun _ => []) dirW rootedP = .name "C:\\tools\\t.exe".toList ∧
    oldConcat dirW rootedP = "C:\\work\\\\tools\\t.exe".toList := by
  decide

/-! ### Set-id -/

inductive Xattr where
  | present | enodata | eopnotsupp | otherErr
  deriving DecidableEq, Repr

/-- `programFileFacts` + `fileCapabilityOf`: `none` is unknown. -/
def setIdOf (modeSetId hasFd : Bool) (x : Xattr) : Option Bool :=
  if modeSetId then some true
  else if !hasFd then none
  else match x with
    | .present => some true
    | .enodata => some false
    | .eopnotsupp => some false
    | .otherErr => none

/-- "Not set-id" is claimed only when the descriptor was asked and absence was
    established; an unreadable attribute is never a permissive answer. -/
theorem not_setid_needs_established_absence {m f : Bool} {x : Xattr}
    (h : setIdOf m f x = some false) :
    m = false ∧ f = true ∧ (x = .enodata ∨ x = .eopnotsupp) := by
  cases m <;> cases f <;> cases x <;> simp_all [setIdOf]

theorem read_error_is_unknown (m : Bool) : setIdOf false true .otherErr = none ∧
    setIdOf m false .enodata ≠ some false := by
  cases m <;> simp [setIdOf]

/-! ### Binding -/

inductive Binding where
  | verified | unverified
  deriving DecidableEq, Repr

/-- P1a: the record never claims an execution binding. -/
def bindingOf (_recordedTarget _execTarget : Text) : Binding := .unverified

theorem record_never_verified (r e : Text) : bindingOf r e ≠ .verified := by
  simp [bindingOf]

end AttestorEvidence.Program
