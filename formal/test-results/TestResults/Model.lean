/-!
# JUnit report summaries

The model of how `plugins/attestors/test-results` turns a JUnit report into
the signed `summary`. Design: `docs/design/fix-security.md#test-results-verdict`.

A report is a tree of suites. The parser walks it depth first
(`junitTally.walk`), so the model flattens the tree to that walk: `enter` a
suite, its cases, its nested suites, then `exit` with the suite's own
`failures`/`errors` attributes, where the suite is reconciled against the
counts its subtree produced. A stack of baselines gives each `exit` the counts
at its `enter`, exactly as `walk` keeps `before`.

The invariant: `failed + errors` is zero only when no case is classified as a
failure or error and no suite claims more failures than its subtree shows.
-/

namespace TestResults

/-- One `<testcase>`, as the classifier reads it. -/
structure Case where
  failure      : Bool := false
  error        : Bool := false
  rerunFailure : Bool := false
  rerunError   : Bool := false
  /-- `<skipped message=...>`, if present. -/
  skipped      : Option String := none
  status       : String := ""
  result       : String := ""
  classname    : String := ""
  timestamp    : String := ""
  /-- The case's `time` attribute is zero. -/
  timeZero     : Bool := false
  deriving DecidableEq, Repr

inductive Outcome | passed | failed | error | skipped
  deriving DecidableEq, Repr

def knownStatus (s : String) : Bool :=
  s == "" || s == "run" || s == "fail" || s == "notrun" || s == "disabled"

def knownResult (s : String) : Bool :=
  s == "" || s == "completed" || s == "skipped" || s == "suppressed"

/-- `terraformRunNotStarted`: a bare case in a `.tftest.hcl`/`.tftest.json`
suite with no outcome, timestamp or time. -/
def terraformNotStarted (suite : String) (c : Case) : Bool :=
  (suite.endsWith ".tftest.hcl" || suite.endsWith ".tftest.json") && c.classname == suite &&
    !c.failure && !c.error && c.skipped.isNone && c.timestamp == "" && c.timeZero

/-- `notRunError`: CTest's `status="notrun"` with a `<skipped>` reason that
is not one of its two deliberate skips. -/
def couldNotRun (c : Case) : Bool :=
  match c.skipped with
  | none => false
  | some reason =>
    c.status == "notrun" && !(reason.startsWith "SKIP_RETURN_CODE=" || reason == "SKIP_REGULAR_EXPRESSION_MATCHED")

/-- `classifyCase`, in the parser's order. -/
def classify (suite : String) (c : Case) : Outcome :=
  if terraformNotStarted suite c then .error
  else if c.failure then .failed
  else if c.error then .error
  else if c.rerunFailure then .failed
  else if c.rerunError then .error
  else if couldNotRun c then .error
  else if c.status == "fail" then .failed
  else if !knownStatus c.status then .error
  else if !knownResult c.result then .error
  else if c.skipped.isSome || c.status == "notrun" || c.status == "disabled" ||
      c.result == "skipped" || c.result == "suppressed" then .skipped
  else .passed

/-- A case that records a run that did not pass. -/
def Outcome.bad : Outcome → Bool
  | .failed | .error => true
  | _ => false

inductive Suite where
  | mk (name : String) (failures errors tests skipped : Nat) (cases : List Case) (suites : List Suite)
  deriving Repr

structure Report where
  failures : Nat := 0
  errors   : Nat := 0
  tests    : Nat := 0
  skipped  : Nat := 0
  /-- Cases directly under `<testsuites>`. -/
  cases    : List Case := []
  suites   : List Suite := []
  deriving Repr

inductive Step
  | case (suite : String) (c : Case)
  | enter
  | exit (failures errors : Nat)
  deriving Repr

mutual
def Suite.steps : Suite → List Step
  | .mk n f e _ _ cs ss => Step.enter :: cs.map (Step.case n) ++ Suite.stepsList ss ++ [Step.exit f e]
def Suite.stepsList : List Suite → List Step
  | [] => []
  | s :: ss => s.steps ++ Suite.stepsList ss
end

structure Summary where
  total   : Nat := 0
  passed  : Nat := 0
  failed  : Nat := 0
  skipped : Nat := 0
  errors  : Nat := 0
  deriving DecidableEq, Repr

def Summary.bad (s : Summary) : Nat := s.failed + s.errors

def count (s : Summary) (o : Outcome) : Summary :=
  let s := { s with total := s.total + 1 }
  match o with
  | .passed => { s with passed := s.passed + 1 }
  | .failed => { s with failed := s.failed + 1 }
  | .error => { s with errors := s.errors + 1 }
  | .skipped => { s with skipped := s.skipped + 1 }

/-- `junitTally.reconcile`: each claimed category against what the subtree
shows in that category since `before`. The shortfall is booked in its own
category, taken from the passes first. (Nat subtraction truncates at zero, as
the parser's `max(claimed-shown, 0)`.) -/
def reconcile (s before : Summary) (f e : Nat) : Summary :=
  let failedShort := f - (s.failed - before.failed)
  let errorsShort := e - (s.errors - before.errors)
  let excess := failedShort + errorsShort
  let fromPassed := min excess (s.passed - before.passed)
  { s with passed := s.passed - fromPassed, total := s.total + (excess - fromPassed),
           failed := s.failed + failedShort, errors := s.errors + errorsShort }

structure St where
  sum   : Summary := {}
  stack : List Summary := []
  cases : Nat := 0

def step (st : St) : Step → St
  | .case n c => { st with sum := count st.sum (classify n c), cases := st.cases + 1 }
  | .enter => { st with stack := st.sum :: st.stack }
  | .exit f e =>
    match st.stack with
    | before :: rest => { st with sum := reconcile st.sum before f e, stack := rest }
    | [] => { st with sum := reconcile st.sum {} f e }

def run (st : St) (steps : List Step) : St := steps.foldl step st

def Report.steps (r : Report) : List Step :=
  r.cases.map (Step.case "") ++ Suite.stepsList r.suites

structure Attrs where
  failures : Nat := 0
  errors   : Nat := 0
  tests    : Nat := 0
  skipped  : Nat := 0
  deriving DecidableEq, Repr

def Attrs.add (a b : Attrs) : Attrs := ⟨a.failures + b.failures, a.errors + b.errors, a.tests + b.tests, a.skipped + b.skipped⟩
def Attrs.max (a b : Attrs) : Attrs :=
  ⟨Nat.max a.failures b.failures, Nat.max a.errors b.errors, Nat.max a.tests b.tests, Nat.max a.skipped b.skipped⟩

mutual
/-- `subtreeCounts`: field by field, the larger of a suite's own attribute
and the sum of its nested suites' claims. -/
def Suite.claim : Suite → Attrs
  | .mk _ f e t k _ ss => Attrs.max ⟨f, e, t, k⟩ (Suite.claimList ss)
def Suite.claimList : List Suite → Attrs
  | [] => {}
  | s :: ss => Attrs.add s.claim (Suite.claimList ss)
end

/-- `summaryFromAttributes`: field by field, the larger of the root's
attributes and the sum of its suites' claims. -/
def fromAttributes (r : Report) : Summary :=
  let a := Attrs.max ⟨r.failures, r.errors, r.tests, r.skipped⟩ (Suite.claimList r.suites)
  { total := a.tests, passed := a.tests - a.failures - a.errors - a.skipped, failed := a.failures,
    skipped := a.skipped, errors := a.errors }

/-- `parseJUnit`: walk every case; a report with no case at all is read from
its attributes, otherwise the root is reconciled too. -/
def summarize (r : Report) : Summary :=
  let st := run {} r.steps
  if st.cases = 0 then fromAttributes r else reconcile st.sum {} r.failures r.errors

end TestResults
