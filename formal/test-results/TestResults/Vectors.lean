import TestResults.Model

/-!
# Differential vectors

`vectors/junit.json`: reports rendered as JUnit XML, each with the summary the
model computes. Consumer:
`plugins/attestors/test-results/formal_differential_test.go`, which parses
each document with `parseJUnit` and requires the same summary.

The build fails when the committed file differs from what the model
generates. Regenerate with:

    cd subtrees/rookery/formal/test-results && TESTRESULTS_VECTORS_REGEN=1 lake env lean --run TestResults/Vectors.lean
-/

namespace TestResults.Vectors

def esc (s : String) : String :=
  s.foldl (fun acc ch => acc ++ (if ch = '"' then "\\\"" else if ch = '\\' then "\\\\" else ch.toString)) ""
def jstr (s : String) : String := "\"" ++ esc s ++ "\""

def xattr (k v : String) : String := if v.isEmpty then "" else s!" {k}='{v}'"

def renderCase (i : Nat) (c : Case) : String :=
  let attrs := s!"<testcase name='c{i}'" ++ xattr "classname" c.classname ++ xattr "status" c.status ++
    xattr "result" c.result ++ xattr "timestamp" c.timestamp ++
    s!" time='{if c.timeZero then "0" else "0.1"}'>"
  let kids :=
    (if c.failure then "<failure message='f'/>" else "") ++ (if c.error then "<error message='e'/>" else "") ++
    (if c.rerunFailure then "<rerunFailure message='rf'/>" else "") ++
    (if c.rerunError then "<rerunError message='re'/>" else "") ++
    (match c.skipped with | some m => s!"<skipped message='{m}'/>" | none => "")
  attrs ++ kids ++ "</testcase>"

def renderCases (cs : List Case) : String :=
  String.join ((cs.zip (List.range cs.length)).map fun (c, i) => renderCase i c)

mutual
def renderSuite : Suite → String
  | .mk n f e t k cs ss =>
    s!"<testsuite name='{n}' failures='{f}' errors='{e}' tests='{t}' skipped='{k}'>" ++
      renderCases cs ++ renderSuites ss ++ "</testsuite>"
def renderSuites : List Suite → String
  | [] => ""
  | s :: ss => renderSuite s ++ renderSuites ss
end

def render (r : Report) : String :=
  s!"<testsuites failures='{r.failures}' errors='{r.errors}' tests='{r.tests}' skipped='{r.skipped}'>" ++
    renderCases r.cases ++ renderSuites r.suites ++ "</testsuites>"

def pass : Case := {}
def suite (n : String) (cs : List Case) (f e t k : Nat := 0) (ss : List Suite := []) : Suite := .mk n f e t k cs ss

def reports : List (String × Report) := [
  ("one passing case", { suites := [suite "s" [pass]] }),
  ("failure child", { suites := [suite "s" [pass, { failure := true }]] }),
  ("error child", { suites := [suite "s" [{ error := true }]] }),
  ("unrecognized status failed", { suites := [suite "s" [{ status := "failed" }]] }),
  ("unrecognized status timeout", { suites := [suite "s" [{ status := "timeout" }]] }),
  ("unrecognized result failed", { suites := [suite "s" [{ status := "run", result := "failed" }]] }),
  ("status fail with skipped", { suites := [suite "s" [{ status := "fail", skipped := some "x" }]] }),
  ("status fail alone", { suites := [suite "s" [{ status := "fail" }]] }),
  ("lone rerunFailure", { suites := [suite "s" [{ rerunFailure := true }]] }),
  ("lone rerunError", { suites := [suite "s" [{ rerunError := true }]] }),
  ("suite claims a failure over bare cases", { suites := [suite "s" [pass, pass] 1 0 2] }),
  ("suite claims failures and errors over bare cases", { suites := [suite "s" [pass, pass, pass] 1 2 3] }),
  ("suite claims an error with no cases",
    { suites := [suite "s" [] 0 1, suite "t" [pass]] }),
  ("nested suite claims a failure", { suites := [suite "outer" [] 0 0 0 0 [suite "inner" [pass] 1]] }),
  ("root claims a failure over bare cases", { failures := 1, tests := 1, suites := [suite "s" [pass]] }),
  ("root claims an error over bare cases", { errors := 1, tests := 1, suites := [suite "s" [pass]] }),
  ("summary only, one failure", { suites := [suite "s" [] 1 0 10] }),
  ("summary only, suites without root attributes", { suites := [suite "s" [] 1 2 10] }),
  ("summary only, root attributes win", { failures := 1, tests := 4, suites := [suite "s" [] 1 0 4] }),
  ("summary only, passing", { suites := [suite "s" [] 0 0 3] }),
  ("summary only, nested failure", { suites := [suite "outer" [] 0 0 1 0 [suite "inner" [] 1 0 1]] }),
  ("summary only, root claims none", { tests := 2, suites := [suite "a" [] 0 0 1, suite "b" [] 0 1 1] }),
  ("declared skip without a child", { suites := [suite "gtest" [{ status := "run", result := "skipped" }, { status := "notrun", result := "suppressed" }]] }),
  ("ctest could not run", { suites := [suite "ctest" [{ status := "notrun", skipped := some "Unable to find executable" }]] }),
  ("ctest deliberate skip", { suites := [suite "ctest" [{ status := "notrun", skipped := some "SKIP_RETURN_CODE=4" }]] }),
  ("ctest disabled", { suites := [suite "ctest" [{ status := "disabled" }]] }),
  ("terraform run never started",
    { suites := [suite "a.tftest.hcl" [{ classname := "a.tftest.hcl", timeZero := true }]] }),
  ("terraform run that ran",
    { suites := [suite "a.tftest.hcl" [{ classname := "a.tftest.hcl", timestamp := "2026-09-25T06:25:36Z" }]] }),
  ("consistent pytest counts", { failures := 1, errors := 1, tests := 3, suites := [suite "pytest" [pass, { failure := true }, { error := true }] 1 1 3] }),
  ("googletest completed and skipped",
    { suites := [suite "gtest" [{ status := "run", result := "completed" }, { status := "run", result := "skipped", skipped := some "" }]] }),
  ("nested passing suites", { suites := [suite "outer" [pass] 0 0 0 0 [suite "inner" [pass, pass]]] }),
  ("root-level cases with a failure", { cases := [pass, { failure := true }] })
]

def summaryJson (s : Summary) : String :=
  s!"\{\"total\":{s.total},\"passed\":{s.passed},\"failed\":{s.failed},\"skipped\":{s.skipped},\"errors\":{s.errors}}"

def junitJson : String :=
  "{\"cases\":[\n" ++ ",\n".intercalate (reports.map fun (n, r) =>
    s!"\{\"name\":{jstr n},\"xml\":{jstr (render r)},\"summary\":{summaryJson (summarize r)}}") ++ "\n]}\n"

/- Staleness gate; skipped only while regenerating (TESTRESULTS_VECTORS_REGEN=1). -/
#eval show IO Unit from do
  if (← IO.getEnv "TESTRESULTS_VECTORS_REGEN").isSome then return
  let path : System.FilePath := "vectors" / "junit.json"
  let committed ← IO.FS.readFile path
  unless committed == junitJson do
    throw <| IO.userError s!"{path} is stale; regenerate: TESTRESULTS_VECTORS_REGEN=1 lake env lean --run TestResults/Vectors.lean"

end TestResults.Vectors

def main : IO Unit :=
  IO.FS.writeFile ("vectors" / "junit.json") TestResults.Vectors.junitJson
