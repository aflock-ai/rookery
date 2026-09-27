/-
  AttestorEvidence.Vectors: decide-checked rows. `lake exe attestor-evidence-eval`
  prints each row as one JSON line; each code PR's `// formal:differential`
  Go test runs the same inputs through the Go function and compares.
-/
import AttestorEvidence.SbomBackref
import AttestorEvidence.ProgramRecord
import AttestorEvidence.ScriptCapture

namespace AttestorEvidence.Vectors

open AttestorEvidence

def hex64 : String := "3b2b8e1f9a0c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"

/-! ### SBOM: (type, version, expected digest) with no purl digest -/

def sbomRows : List (String × String × Option String) :=
  [ ("container", "sha256:" ++ hex64, some hex64)
  , ("library",   "sha256:" ++ hex64, none)
  , ("",          "sha256:" ++ hex64, none)
  , ("container", "sha256:abc", none)
  , ("container", "sha256:3B2B8E1F9A0C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6", none)
  , ("container", "sha256:gb2b8e1f9a0c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6", none)
  , ("container", "sha512:" ++ hex64, none)
  , ("container", "sha256:" ++ hex64 ++ " x", none)
  , ("container", "3.24", none)
  , ("container", "sha256:" ++ "é" ++ (hex64.drop 2), none) ]  -- 64 bytes, not hex

def sbomHolds : Bool :=
  sbomRows.all fun (ty, v, want) =>
    Sbom.imageBackref none ty v.toList == want.map String.toList

theorem sbomVectors_hold : sbomHolds = true := by decide

/-! ### Windows program path: (dir, argv0, expected name or refused) -/

/-- Drive D's current directory, the only drive-relative lookup the rows use. -/
def driveCwd (c : Char) : Text := if c = 'D' then "\\dcwd".toList else []

def programRows : List (String × String × Option String) :=
  [ ("C:\\work", "tool.exe",               some "C:\\work\\tool.exe")
  , ("C:\\work", "bin\\tool.exe",          some "C:\\work\\bin\\tool.exe")
  , ("C:\\work", "\\tools\\tool.exe",      some "C:\\tools\\tool.exe")
  , ("C:\\work", "/tools/tool.exe",        some "C:/tools/tool.exe")
  , ("C:\\work", "C:tool.exe",             some "C:\\work\\tool.exe")
  , ("C:\\work", "c:tool.exe",             some "C:\\work\\tool.exe")
  , ("C:\\work", "D:tool.exe",             some "D:\\dcwd\\tool.exe")
  , ("C:\\work", "D:\\bin\\tool.exe",      some "D:\\bin\\tool.exe")
  , ("C:\\work", "\\\\srv\\share\\t.exe",  some "\\\\srv\\share\\t.exe")
  , ("C:\\work", "",                       none)
  , ("C:\\work", "C:",                     none)
  , ("\\\\srv\\share\\work", "tool.exe",   none) ]

def resolvedAs : Program.Resolved → Option Text
  | .name p => some p
  | .refused => none

def programHolds : Bool :=
  programRows.all fun (dir, p, want) =>
    resolvedAs (Program.joinExe driveCwd dir.toList p.toList) == want.map String.toList

theorem programVectors_hold : programHolds = true := by decide

/-- The replaced concatenation disagrees on exactly the five rooted and
    drive-relative rows, and agrees on every other resolvable row. -/
def oldRuleWrongRows : Nat :=
  (programRows.filter fun (dir, p, want) =>
    want.isSome && some (Program.oldConcat dir.toList p.toList) != want.map String.toList).length

theorem oldRule_wrong_on_five : oldRuleWrongRows = 5 := by decide

/-! ### Set-id: (mode bit, has descriptor, xattr, expected) -/

def setIdRows : List (Bool × Bool × Program.Xattr × Option Bool) :=
  [ (true,  false, .otherErr,   some true)
  , (false, true,  .present,    some true)
  , (false, true,  .enodata,    some false)
  , (false, true,  .eopnotsupp, some false)
  , (false, true,  .otherErr,   none)
  , (false, false, .enodata,    none) ]

theorem setIdVectors_hold :
    setIdRows.all (fun (m, f, x, want) => Program.setIdOf m f x == want) = true := by decide

/-! ### `sh -c` reading: (argv, env defines functions, expected words) -/

def shRows : List (List String × Bool × Option (List String)) :=
  [ (["sh", "-c", "bash build.sh"],       false, some ["bash", "build.sh"])
  , (["/bin/sh", "-c", "./build.sh"],     false, some ["./build.sh"])
  , (["sh", "-c", "  make \tall  "],       false, some ["make", "all"])
  , (["sh", "-c", "printf hi"],           false, some ["printf", "hi"])
  , (["bash", "-c", "bash build.sh"],     false, none)
  , (["dash", "-c", "bash build.sh"],     false, none)
  , (["sh", "-x", "-c", "bash build.sh"], false, none)
  , (["sh", "-c", "bash build.sh", "x"],  false, none)
  , (["sh", "-c", "a | b"],               false, none)
  , (["sh", "-c", "bash $F"],             false, none)
  , (["sh", "-c", "bash 'a b'"],          false, none)
  , (["sh", "-c", "bash b.sh # c"],       false, none)
  , (["sh", "-c", "A=1 ./x.sh"],          false, none)
  , (["sh", "-c", "   "],                 false, none)
  , (["sh", "-c", "bash build.sh"],       true,  none) ]

def shHolds : Bool :=
  shRows.all fun (argv, fns, want) =>
    Script.shWords fns (argv.map String.toList) == want.map (·.map String.toList)

theorem shVectors_hold : shHolds = true := by decide

/-! ### Guard: sensitive names and shapes fixed for the rows -/

def sensitiveName (n : Text) : Bool :=
  n == "API_TOKEN".toList || n == "GITHUB_PAT".toList ||
  n == "DB_PASSWORD".toList || n == "SESSION_TOKEN".toList
def ghShape (b : Text) : Bool := contains "ghp_AAAAAAAAAAAAAAAA".toList b

def guardEnv : List Script.EnvVar :=
  [ ⟨"API_TOKEN".toList, "s3cr3tvalue1".toList⟩
  , ⟨"GITHUB_PAT".toList, "short7x".toList⟩
  , ⟨"HOME".toList, "/home/runner".toList⟩
  , ⟨"DB_PASSWORD".toList, "éééé".toList⟩      -- 4 characters, 8 bytes
  , ⟨"SESSION_TOKEN".toList, "éééx".toList⟩ ]  -- 4 characters, 7 bytes

def guardRows : List (String × Bool) :=
  [ ("curl -H s3cr3tvalue1 x", true)     -- sensitive value, 12 bytes
  , ("echo short7x", false)              -- sensitive name, value under 8 bytes
  , ("cd /home/runner", false)           -- value of a name that is not sensitive
  , ("echo ghp_AAAAAAAAAAAAAAAA", true)  -- credential shape
  , ("make all", false)
  , ("echo éééé", true)                  -- 8 bytes: at the floor, refused
  , ("echo éééx", false) ]               -- 7 bytes: under the floor

/-- The byte floor, not a character count: a character count of 8 would let
    `éééé` (4 characters) through. -/
theorem multibyte_value_at_floor_refused :
    Script.refuses ghShape sensitiveName guardEnv "echo éééé".toList = true := by decide

theorem guardVectors_hold :
    guardRows.all (fun (body, want) =>
      Script.refuses ghShape sensitiveName guardEnv body.toList == want) = true := by decide

end AttestorEvidence.Vectors
