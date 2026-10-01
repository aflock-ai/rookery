/-
  CilockEvaluators.Seeded.Rules: the seeded Rego rules of `cilock policy`
  (subtrees/rookery/cilock/cli/policy_rules.go), one Lean function per rule.

  Each `admits` function is the rule's verdict on one input: `true` exactly
  when the module's `deny` set is empty AND evaluation raises no error (the
  verifier runs with StrictBuiltinErrors, so a builtin type error or a
  function conflict is a refusal, attestation/policy/rego.go). A deny and an
  error are both "not admitted", which is the only distinction the verifier
  makes.

  The functions follow the Rego text rule by rule; the comment above each
  names the Rego it models. Nothing here is a specification written from the
  rule's summary: the specifications are the theorems in Proofs.lean, proved
  about these functions, and the differential test
  (cilock/cli/formal_seeded_rules_differential_test.go) checks these
  functions against OPA on generated inputs.
-/
import CilockEvaluators.Seeded.Json

namespace CilockEvaluators.Seeded

/-- The Rego input: the predicate itself, or `{attestation, steps}` when the
    step has attestationsFrom (buildRegoInput, attestation/policy/rego.go). -/
def inputOf (p : J) : Option J → J
  | none => p
  | some s => .obj [("attestation", p), ("steps", s)]

/-- `pred := object.get(input, "attestation", input)`. -/
def predOf (input : J) : J :=
  match input with
  | .obj kvs => (kvs.lookup "attestation").getD input
  | _ => input

/-- `input.steps[s]`. -/
def stepOf (input : J) (s : String) : Option J := (input.get "steps").bind (·.get s)

/-! ## command-run -/

/-- commandrun_succeeded: `readable_exit { is_number(field(pred, "exitcode", null)) }`,
    deny unless readable, deny when `pred.exitcode != 0`. -/
def commandSucceeded (pred : J) : Bool :=
  match field pred "exitcode" .null with
  | .num n => n == 0
  | _ => false

/-- commandrun_pinned: deny unless `cmd` is an array; deny when `pred.cmd != expected`. -/
def commandPin (expected : J) (pred : J) : Bool :=
  match field pred "cmd" .null with
  | .arr xs => J.eqv (.arr xs) expected
  | _ => false

/-! ## product -/

/-- product_recorded: numeric treeSize, string merkleRoot, treeSize ≥ 1. -/
def productRecorded (pred : J) : Bool :=
  match field pred "treeSize" .null, field pred "merkleRoot" .null with
  | .num n, .str _ => decide (1 ≤ n)
  | _, _ => false

/-! ## test-results -/

/-- tests_pass: `summary := field(field(pred, "predicate", {}), "summary", null)`;
    readable needs an object summary whose total, passed and failed, and
    errors and skipped (default 0), are each a `count_value`: a nonnegative
    integer (`is_number(x); x >= 0; floor(x) == x`; numbers are integers
    here). Deny total < 1, (total ≥ 1 and passed < 1), failed > 0, errors > 0. -/
def testsPass (pred : J) : Bool :=
  let summary := field (field pred "predicate" (.obj [])) "summary" .null
  match summary, field summary "total" .null, field summary "passed" .null,
      field summary "failed" .null, field summary "errors" (.num 0), field summary "skipped" (.num 0) with
  | .obj _, .num t, .num p, .num f, .num e, .num k =>
    decide (0 ≤ f) && decide (0 ≤ e) && decide (0 ≤ k) &&
    decide (1 ≤ t) && decide (1 ≤ p) && decide (f ≤ 0) && decide (e ≤ 0)
  | _, _, _, _, _, _ => false

/-! ## SARIF -/

def sarifLevels : List String := ["none", "note", "warning", "error"]

/-- `rules_of(run)`: the driver's rules, `[]` when absent or null. -/
def rulesOf (run : J) : J :=
  match field (field (field run "tool" (.obj [])) "driver" (.obj [])) "rules" .null with
  | .null => .arr []
  | rs => rs

/-- `ref(r) = field(r, "rule", null)`. -/
def refOf (r : J) : J := field r "rule" .null

/-- `index_refs(r)`: `ruleIndex` and `rule.index`, each when not null. -/
def indexRefs (r : J) : List J :=
  [field r "ruleIndex" .null, field (refOf r) "index" .null].filter (fun x => !x.isNull)

/-- `id_refs(r)`: `ruleId` and `rule.id`, each when not null. -/
def idRefs (r : J) : List J :=
  [field r "ruleId" .null, field (refOf r) "id" .null].filter (fun x => !x.isNull)

/-- `rule_level(rule)`: its defaultConfiguration level, else `"warning"`. -/
def ruleLevel (rule : J) : J :=
  field (field rule "defaultConfiguration" (.obj [])) "level" (.str "warning")

/-- `names(rule, x)`: a string id equal to the rule's id, or a hierarchical
    sub-rule of a non-empty string id (`startswith(x, id + "/")`). -/
def names (rule x : J) : Bool :=
  match x with
  | .str s =>
    J.eqv (field rule "id" .null) x ||
    (match field rule "id" .null with
     | .str id => id != "" && strStarts s (id ++ "/")
     | _ => false)
  | _ => false

/-- `default_levels(run, r)` (a set, kept as a list): the level of the rule
    at every index reference that names an element, and of every listed rule
    an id reference names. -/
def defaultLevels (run r : J) : List J :=
  (indexRefs r).filterMap (fun i => ((rulesOf run).at i).map ruleLevel) ++
  (idRefs r).flatMap (fun x => ((rulesOf run).elems.filter (fun rule => names rule x)).map ruleLevel)

def isLevel (x : J) : Bool := memStr x sarifLevels

/-- `listed_rule(run, i)`: a number naming an object in the rules array. -/
def listedRule (run i : J) : Bool :=
  match i with
  | .num n => decide (0 ≤ n) && decide (n < (rulesOf run).len) &&
      (match (rulesOf run).at (.num n) with | some (.obj _) => true | _ => false)
  | _ => false

/-- An invocation that is not an object, or whose `executionSuccessful` is
    not `true` (SARIF 2.1.0 §3.20.14): the run has no complete result list. -/
def unfinishedInvocations (run : J) : Bool :=
  !(field run "invocations" (.arr [])).isArr ||
  (field run "invocations" (.arr [])).elems.any
    (fun inv => !inv.isObj || !J.eqv (field inv "executionSuccessful" .null) (.bool true))

/-- `unreadable_run` for one run: results or rules not an array, invocations
    not an array, an invocation that is not an object or did not finish, an
    invocation with ruleConfigurationOverrides other than `[]`, or policies
    other than `[]`. -/
def unreadableRun (run : J) : Bool :=
  !(field run "results" .null).isArr || !(rulesOf run).isArr ||
  unfinishedInvocations run ||
  (field run "invocations" (.arr [])).elems.any
    (fun inv => !J.eqv (field inv "ruleConfigurationOverrides" (.arr [])) (.arr [])) ||
  !J.eqv (field run "policies" (.arr [])) (.arr [])

/-- `unreadable_result` for one (run, result). -/
def unreadableResult (run r : J) : Bool :=
  !r.isObj ||
  !isLevel (field r "level" (.str "warning")) ||
  (!(refOf r).isNull && !(refOf r).isObj) ||
  !(field (refOf r) "toolComponent" .null).isNull ||
  (indexRefs r).any (fun i => !listedRule run i) ||
  (idRefs r).any (fun x => !x.isStr) ||
  (defaultLevels run r).any (fun l => !isLevel l)

/-- `error_level(run, r)`. -/
def errorLevel (run r : J) : Bool :=
  (field r "level" .null).isStrEq "error" ||
  ((field r "level" .null).isNull && memJ (.str "error") (defaultLevels run r))

def sarifResults (runs : List J) : List (J × J) :=
  runs.flatMap (fun run => (field run "results" (.arr [])).elems.map (fun r => (run, r)))

/-- sarif_no_errors: readable (a non-empty array of runs, no unreadable run,
    no unreadable result) and no error-level result. -/
def sarifNoErrors (pred : J) : Bool :=
  match field (field pred "report" (.obj [])) "runs" .null with
  | .arr runs =>
    !runs.isEmpty &&
    runs.all (fun r => !unreadableRun r) &&
    (sarifResults runs).all (fun (run, r) => !unreadableResult run r) &&
    (sarifResults runs).all (fun (run, r) => !errorLevel run r)
  | _ => false

/-! ## secretscan -/

/-- `findings`: `[]` for an explicit null, the list for an array, undefined otherwise. -/
def secretFindings (pred : J) : Option (List J) :=
  match pred.get "findings" with
  | some .null => some []
  | some (.arr xs) => some xs
  | _ => none

/-- `mismatches`: `[]` when scope is absent or null, or an object whose
    productDigestMismatches is absent or null; the list when it is an array. -/
def secretMismatches (pred : J) : Option (List J) :=
  match field pred "scope" .null with
  | .null => some []
  | .obj _ =>
    match field (field pred "scope" .null) "productDigestMismatches" .null with
    | .null => some []
    | .arr ms => some ms
    | _ => none
  | _ => none

/-- secretscan_no_findings: readable (findings a list of objects, mismatches a
    list) and both empty. -/
def secretscanClean (pred : J) : Bool :=
  match secretFindings pred, secretMismatches pred with
  | some fs, some ms => fs.isEmpty && ms.isEmpty
  | _, _ => false

/-! ## govulncheck -/

def vulnSummary (pred : J) : J := field pred "summary" (.obj [])

/-- `findings`: `[]` for an explicit null, the list for an array. -/
def vulnFindings (summary : J) : Option (List J) :=
  match summary.get "findings" with
  | some .null => some []
  | some (.arr xs) => some xs
  | _ => none

def scanned (summary : J) : Bool :=
  match field summary "scanRoots" .null with
  | .arr roots => !roots.isEmpty
  | _ => false

/-- govulncheck_no_reachable: a symbol-level scan with numeric non-negative
    counts and a findings list; no reachable count, every finding flagged
    unreachable, and the counts agree with the list. (The rule does not read
    scanRoots; `scanned` is for govulncheck-vex-covered.) -/
def govulncheckReachable (pred : J) : Bool :=
  let s := vulnSummary pred
  match field s "reachableCount" .null, field s "unreachableCount" .null, vulnFindings s with
  | .num rc, .num uc, some fs =>
    decide (0 ≤ rc) && decide (0 ≤ uc) && (field s "scanLevel" (.str "")).isStrEq "symbol" &&
    decide (rc ≤ 0) &&
    fs.all (fun f => (field f "reachable" .null).isBool) &&
    fs.all (fun f => !(f.get "reachable").any (fun v => J.eqv v (.bool true))) &&
    decide ((fs.length : Int) = rc + uc)
  | _, _, _ => false

/-! ## VEX coverage -/

def vexType : String := "https://openvex.dev/ns"

/-- `vex_docs`: the vexDocument of every collection of the named step. -/
def vexDocs (input : J) (vexStep : String) : List J :=
  match stepOf input vexStep with
  | some st =>
    (st.get "collections").elim [] (fun cs => cs.elems.filterMap (fun c =>
      (field (field c "attestations" (.obj [])) vexType (.obj [])).get "vexDocument"))
  | none => []

def nonEmpty (x : J) : Bool := !J.eqv x (.str "")

/-- `statement_names(s)`. -/
def statementNames (s : J) : List J :=
  let v := field s "vulnerability" (.obj [])
  [field v "name" (.str ""), field v "@id" (.str "")].filter nonEmpty ++
    (field v "aliases" (.arr [])).elems.filter nonEmpty

/-- `statement_products(s)`. -/
def statementProducts (s : J) : List J :=
  (field s "products" (.arr [])).elems.flatMap (fun p =>
    [field p "@id" (.str ""), field (field p "identifiers" (.obj [])) "purl" (.str ""),
     field (field p "hashes" (.obj [])) "sha-256" (.str "")])

def productMatches (products : List String) (s : J) : Bool :=
  products.isEmpty || (statementProducts s).any (fun i => memStr i products)

def settled (s : J) : Bool :=
  (field s "status" (.str "")).isStrEq "fixed" ||
  ((field s "status" (.str "")).isStrEq "not_affected" &&
    (match field s "justification" (.str "") with | .str j => j != "" | _ => false))

def covered (docs : List J) (products : List String) (names : List J) : Bool :=
  docs.any (fun d => (match d.get "statements" with | some st => st.elems | none => []).any (fun s =>
    (statementNames s).any (fun n => memJ n names) && productMatches products s && settled s))

def vexReadable (docs : List J) : Bool :=
  !docs.isEmpty && docs.all (fun d => (field d "statements" .null).isArr)

def validId (x : J) : Bool := match x with | .str s => s != "" | _ => false

def reachableFlagged (f : J) : Bool := J.eqv (field f "reachable" (.bool false)) (.bool true)

/-- `counts_agree`: numeric reachableCount, unreachableCount and
    totalFindings; with findings, the list length is reachable + unreachable,
    the reachable count is the number flagged reachable, and totalFindings is
    at least the length; with none, every count is 0. -/
def countsAgree (s : J) (fs : List J) : Bool :=
  match field s "reachableCount" .null, field s "unreachableCount" .null, field s "totalFindings" .null with
  | .num r, .num u, .num t =>
    (decide (0 < (fs.length : Int)) && decide ((fs.length : Int) = r + u) &&
      decide (((fs.filter reachableFlagged).length : Int) = r) && decide ((fs.length : Int) ≤ t)) ||
    (fs.isEmpty && decide (r = 0) && decide (u = 0) && decide (t = 0))
  | _, _, _ => false

/-- The govulncheck scan side: readable (every finding named, counts that
    agree, non-empty scanRoots), and each finding's id with its aliases. -/
def govulnScan (pred : J) : Option (List (J × List J)) :=
  let s := vulnSummary pred
  match vulnFindings s, field pred "report" (.arr []) with
  | some fs, .arr report =>
    if fs.all (fun f => validId (field f "osvId" .null)) && countsAgree s fs && scanned s then
      some (fs.map (fun f =>
        let id := field f "osvId" .null
        (id, id :: report.flatMap (fun m =>
          let o := field m "osv" (.obj [])
          if J.eqv (field o "id" (.str "")) id then
            (field o "aliases" (.arr [])).elems.filter (fun a => a.isStr && nonEmpty a)
          else []))))
    else none
  | _, _ => none

/-- The SARIF scan side: every run has a results array and finished
    invocations; every result a non-empty string ruleId, which is its own
    only name. -/
def sarifScan (pred : J) : Option (List (J × List J)) :=
  match field (field pred "report" (.obj [])) "runs" .null with
  | .arr runs =>
    let rs := runs.flatMap (fun r => (field r "results" .null).elems)
    if !runs.isEmpty && runs.all (fun r => (field r "results" .null).isArr && !unfinishedInvocations r) &&
       rs.all (fun r => validId (field r "ruleId" .null)) then
      some (rs.map (fun r => (field r "ruleId" .null, [field r "ruleId" .null])))
    else none
  | _ => none

/-- vex_covered: the scan is readable; with any finding the VEX documents
    are readable and every finding is covered by a settled statement for one
    of the products (any product when the list is empty). -/
def vexCovered (scan : J → Option (List (J × List J))) (vexStep : String) (products : List String)
    (input : J) : Bool :=
  match scan (predOf input) with
  | some findings =>
    let docs := vexDocs input vexStep
    findings.isEmpty || (vexReadable docs && findings.all (fun (_, names) => covered docs products names))
  | none => false

/-! ## trivy -/

/-- trivy_blocked_severity: summary.bySeverity an object; for every blocked
    severity the entry is absent or an object whose fail is absent or the
    number 0 (a count below zero is unreadable, not clean). -/
def trivySeverity (blocked : List String) (pred : J) : Bool :=
  match field (field pred "summary" (.obj [])) "bySeverity" .null with
  | .obj kvs => blocked.all (fun s =>
      match field (.obj kvs) s (.obj []) with
      | .obj e =>
        (match field (.obj e) "fail" (.num 0) with | .num n => decide (n = 0) | _ => false)
      | _ => false)
  | _ => false

/-! ## SLSA, SBOM, review -/

/-- `digest_ok`: a non-empty object whose every value is at least 32
    lowercase hex digits. -/
def hasDigest (d : J) : Bool :=
  match field d "digest" .null with
  | .obj kvs => !kvs.isEmpty && kvs.all (fun (_, v) => match v with | .str s => hexAtLeast 32 s | _ => false)
  | _ => false

/-- slsa_provenance: a non-empty array of inputs, each with a digest. -/
def slsaProvenance (pred : J) : Bool :=
  match field (field pred "buildDefinition" (.obj [])) "resolvedDependencies" .null with
  | .arr deps => !deps.isEmpty && deps.all hasDigest
  | _ => false

/-- sbom_inventory: `_sbomFormat` cyclonedx with components[] or spdx with
    packages[], non-empty. -/
def sbomInventory (pred : J) : Bool :=
  let items := match field pred "_sbomFormat" (.str "") with
    | .str "cyclonedx" => some (field pred "components" .null)
    | .str "spdx" => some (field pred "packages" .null)
    | _ => none
  match items with
  | some (.arr xs) => !xs.isEmpty
  | _ => false

/-- review_approved: prs an array, commit_sha a non-empty string, and some
    review with state APPROVED on exactly that commit. -/
def reviewApproved (pred : J) : Bool :=
  match field pred "prs" .null, field pred "commit_sha" .null with
  | .arr prs, .str c =>
    c != "" && prs.any (fun pr => (field pr "reviews" (.arr [])).elems.any (fun rv =>
      (field rv "state" (.str "")).isStrEq "APPROVED" && J.eqv (field rv "commit_id" (.str "")) (.str c)))
  | _, _ => false

/-! ## products-from -/

def productType : String := "https://aflock.ai/attestations/product/v0.3"

/-- `upstream_products`: per collection of the upstream step, its product
    attestation, or null when it has none. -/
def upstreamProducts (input : J) (up : String) : List J :=
  match stepOf input up with
  | some st => (st.get "collections").elim [] (fun cs =>
      cs.elems.map (fun c => field (field c "attestations" (.obj [])) productType .null))
  | none => []

/-- A product attestation's `leaves[_]`: its leaves, or none when it has no
    leaves list. -/
def leavesOf (c : J) : List J :=
  match c.get "leaves" with
  | some ls => ls.elems
  | none => []

/-- `valid_digest(field(l, "fileDigest", null))`: a sha256, 64 lowercase hex digits. -/
def digestOf (l : J) : Option String :=
  match field l "fileDigest" .null with
  | .str d => if hexExactly 64 d then some d else none
  | _ => none

/-- products_from: this step's leaves a non-empty list, each with a digest;
    the upstream step has product attestations, each with a leaves list; every
    leaf's digest is some upstream leaf's digest. -/
def productsFrom (up : String) (input : J) : Bool :=
  let pred := predOf input
  let ups := upstreamProducts input up
  let upDigests := ups.flatMap (fun c => (leavesOf c).filterMap digestOf)
  match field pred "leaves" .null with
  | .arr mine =>
    !ups.isEmpty && ups.all (fun c => (field c "leaves" .null).isArr) &&
    mine.all (fun l => (digestOf l).isSome) &&
    !mine.isEmpty &&
    mine.all (fun l => match digestOf l with | some d => upDigests.contains d | none => false)
  | _ => false

/-! ## Dispatch -/

def strList (x : J) : List String := x.elems.filterMap (fun v => match v with | .str s => some s | _ => none)

/-- The verdict of rule `id` with fill value `param` on predicate `p`, with
    `steps` when the step has attestationsFrom. `none` for an unknown rule. -/
def admits (id : String) (param : J) (p : J) (steps : Option J) : Option Bool :=
  let input := inputOf p steps
  let pred := predOf input
  if !input.isObj then some false else
  match id with
  | "command-succeeded" => some (commandSucceeded pred)
  | "command-pin" => some (commandPin param pred)
  | "product-recorded" => some (productRecorded pred)
  | "tests-pass" => some (testsPass pred)
  | "sarif-no-errors" => some (sarifNoErrors pred)
  | "secretscan-no-findings" => some (secretscanClean pred)
  | "govulncheck-no-reachable" => some (govulncheckReachable pred)
  | "govulncheck-vex-covered" =>
    some (vexCovered govulnScan (match field param "vexStep" .null with | .str s => s | _ => "")
      (strList (field param "products" (.arr []))) input)
  | "sarif-vex-covered" =>
    some (vexCovered sarifScan (match field param "vexStep" .null with | .str s => s | _ => "")
      (strList (field param "products" (.arr []))) input)
  | "trivy-no-blocked-severity" => some (trivySeverity (strList param) pred)
  | "slsa-provenance" => some (slsaProvenance pred)
  | "sbom-inventory" => some (sbomInventory pred)
  | "review-approved" => some (reviewApproved pred)
  | "products-from" => some (productsFrom (match param with | .str s => s | _ => "") input)
  | _ => none

end CilockEvaluators.Seeded
