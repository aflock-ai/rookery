/-
  CilockEvaluators.Oracle: the model as an executable, for differential
  testing against the Go implementation (AWS Cedar style).

  Input: JSON Lines on stdin, one case per line. Output: one line per case,
  the model's verdict, or `decode-error: …` when a case does not decode.
  The Go driver is attestation/policy/formal_differential_test.go; it builds
  each case, runs the real Go code on it, runs this binary on the same case,
  and fails on any disagreement.

  Nothing here re-implements a verdict: every answer is computed by the
  model's own functions (`Rego.eval`, `Ai.gate`, `Ai.jev`, `Gate.gate`,
  `Gate.external`, `Gate.verify`, `Vsa.toEnvelope`, `Gate.envGate`). The only
  logic added is decoding, and the consumer-Rego specifications of the VSA
  cases (`consumerOf`), which state what each Rego text the driver emits is
  meant to do.
-/
import Lean.Data.Json
import CilockEvaluators.Vsa
import CilockEvaluators.Verdict
import CilockEvaluators.Nested

namespace CilockEvaluators.Oracle

open Lean (Json)
open CilockEvaluators

abbrev D := Except String

def field (j : Json) (k : String) : D Json := j.getObjVal? k
def str (j : Json) (k : String) : D String := do (← field j k).getStr?
def bool (j : Json) (k : String) : D Bool := do (← field j k).getBool?
def int (j : Json) (k : String) : D Int := do (← field j k).getInt?
def nat (j : Json) (k : String) : D Nat := do (← field j k).getNat?
def arr (j : Json) (k : String) : D (List Json) := do return (← (← field j k).getArr?).toList

def optInt (j : Json) (k : String) : D (Option Int) :=
  match j.getObjVal? k with
  | .error _ => pure none
  | .ok Json.null => pure none
  | .ok v => do return some (← v.getInt?)

def strs (j : Json) (k : String) : D (List String) := do
  (← arr j k).mapM (fun x => x.getStr?)

def optBool (j : Json) (k : String) : D Bool :=
  match j.getObjVal? k with
  | .error _ => pure false
  | .ok v => v.getBool?

def verdictStr : Verdict → String
  | .pass => "pass"
  | .deny => "deny"
  | .error => "error"
  | .refused => "refused"

/-! ## Rego -/

def decodeModule (j : Json) : D Rego.Module := do
  return ⟨← str j "name", ← str j "pkg", ← bool j "parses", ← optBool j "allowUnread"⟩

/-- The missing-field probe; absent means `clean`. -/
def decodeProbe (j : Json) : D Rego.Probe :=
  match j.getObjVal? "probe" with
  | .error _ => pure .clean
  | .ok v => do
    match ← v.getStr? with
    | "clean" => pure .clean
    | "missing" => pure .missing
    | "timeout" => pure .timeout
    | k => throw s!"probe {k}"

def decodeDeny (j : Json) : D Rego.DenyValue := do
  match ← str j "k" with
  | "undefined" => pure .undefined
  | "collection" => return .collection (← nat j "n")
  | "scalar" => pure .scalar
  | k => throw s!"deny kind {k}"

/-- An OPA run: per-package deny values; a package not listed is undefined. -/
def decodeRun (j : Json) : D Rego.OpaRun := do
  let entries ← (← arr j "deny").mapM (fun e => do return (← str e "pkg", ← decodeDeny e))
  let fault ← bool j "fault"
  return ⟨fault, ← optBool j "timeout",
    fun p => (entries.find? (fun e => e.1 == p)).map Prod.snd |>.getD .undefined,
    fun _ => none, ← decodeProbe j⟩

def regoCase (j : Json) : D String := do
  let mods ← (← arr j "modules").mapM decodeModule
  return verdictStr (Rego.eval (← bool j "rejectDup") mods (← decodeRun j))

/-! ## AI -/

def decodeModel (j : Json) : D Ai.ModelName :=
  match j.getObjVal? "pinned" with
  | .ok v => do
    let xs ← v.getArr?
    match xs.toList with
    | [a, b, c] => return .pinned (← a.getNat?) (← b.getNat?) (← c.getNat?)
    | _ => throw "pinned model needs three numbers"
  | .error _ => do return .other (← str j "other")

def decodeDecision (j : Json) : D (Option Ai.Decision) := do
  if j.isNull then return none
  match j.getObjVal? "yesNo" with
  | .ok y => return some (.yesNo (← optInt y "min") (← optInt y "max"))
  | .error _ =>
  match j.getObjVal? "choice" with
  | .ok c => return some (.choice (← strs c "options") (← strs c "allow") (← strs c "deny") (← optInt c "minConf"))
  | .error _ =>
  match j.getObjVal? "score" with
  | .ok s => return some (.score (← nat s "levels") (← optInt s "min") (← optInt s "max"))
  | .error _ => throw "decision kind"

def decodePolicy (j : Json) : D Ai.AiPolicy := do
  return ⟨← str j "name", ← decodeModel (← field j "model"), ← str j "prompt",
    ← decodeDecision ((j.getObjVal? "decision").toOption.getD Json.null)⟩

def decodeAnswer (j : Json) : D (Option (Option Ai.Answer)) := do
  match j with
  | Json.str "missing" => pure none
  | Json.str "bad" => pure (some none)
  | _ =>
  match j.getObjVal? "yesNo" with
  | .ok v => return some (some (.yesNo (← v.getInt?)))
  | .error _ =>
  match j.getObjVal? "choice" with
  | .ok c => return some (some (.choice (← str c "c") (← int c "conf")))
  | .error _ =>
  match j.getObjVal? "score" with
  | .ok v => return some (some (.score (← v.getInt?)))
  | .error _ => throw "answer kind"

def decodeReply (j : Json) : D Ai.JevReply := do
  match ← str j "t" with
  | "transport" => pure .transport
  | "http" => return .http (← nat j "code")
  | "malformed" => pure .malformed
  | "envelope" =>
    let resolved : Option Ai.ModelName ← match j.getObjVal? "resolved" with
      | .ok Json.null | .error _ => pure none
      | .ok m => do
        let x ← decodeModel m
        pure (some x)
    let ans ← decodeAnswer (← field j "ans")
    return .envelope resolved ans
  | t => throw s!"reply kind {t}"

def aiCase (j : Json) : D String := do
  let items ← (← arr j "items").mapM (fun it => do
    return (← decodePolicy (← field it "policy"), ← decodeReply (← field it "reply")))
  let pols := items.map Prod.fst
  return verdictStr (Ai.gate pols (Ai.jev true true items))

/-! ## Step gate -/

def decodeErrKind (j : Json) : D (Option Ai.ErrKind) := do
  match j with
  | Json.null => pure none
  | Json.str "refusal" => pure (some .refusal)
  | Json.str "denied" => pure (some .denied)
  | Json.str "other" => pure (some .other)
  | _ => throw "err kind"

/-- A response's recorded model; absent means the provider named none. -/
def decodeRespModel (r : Json) : D Ai.ModelName :=
  match r.getObjVal? "model" with
  | .error _ | .ok Json.null => pure (.other "")
  | .ok m => decodeModel m

def decodeOutcome (j : Json) : D Ai.Outcome := do
  let rs ← (← arr j "rs").mapM (fun r => do
    return (⟨← str r "status", "", ← decodeRespModel r, none⟩ : Ai.Response))
  return ⟨rs, ← decodeErrKind ((j.getObjVal? "err").toOption.getD Json.null)⟩

def decodeExpected (j : Json) : D Gate.Expected := do
  return ⟨← str j "type", ← (← arr j "rego").mapM decodeModule, ← (← arr j "ai").mapM decodePolicy⟩

def outcomeStr : Gate.Outcome → String
  | .wrongName => "wrongName"
  | .passed => "passed"
  | .rejected r => s!"rejected:{r}"

/-- Per (attestor ref, expected type): the OPA run and the provider outcome. -/
def gateCase (j : Json) : D String := do
  let sj ← field j "step"
  let step : Gate.Step := ⟨← str sj "name", ← (← arr sj "expected").mapM decodeExpected⟩
  let cj ← field j "collection"
  let atts ← (← arr cj "attestors").mapM (fun a => do return (⟨← nat a "ref", ← str a "type"⟩ : Gate.Attestor))
  let coll : Gate.Collection := ⟨← str cj "name", ← bool cj "errors", atts⟩
  let runs ← (← arr j "runs").mapM (fun r => do
    return (← nat r "ref", ← str r "type", ← decodeRun r, ← decodeOutcome (← field r "ai")))
  let rd ← bool j "rejectDup"
  let find := fun (a : Gate.Attestor) (e : Gate.Expected) =>
    runs.find? (fun r => r.1 == a.ref && r.2.1 == e.type)
  let ev : Gate.Evaluators :=
    { rego := fun a e => match find a e with
        | some r => Rego.eval rd e.rego r.2.2.1
        | none => .error
      ai := fun a e => match find a e with
        | some r => Ai.gate e.ai r.2.2.2
        | none => .error }
  return outcomeStr (Gate.gate ev step coll)

/-! ## VSA consumption through externals -/

def decodeVsa (j : Json) : D Vsa.Vsa := do
  let subjects ← (← strs j "subjects").mapM (fun s => pure (⟨⟨s⟩⟩ : Subject))
  let result ← match ← str j "result" with
    | "PASSED" => pure Vsa.Result.passed
    | "FAILED" => pure Vsa.Result.failed
    | r => throw s!"result {r}"
  return ⟨subjects, ← str j "policyUri", ⟨← str j "policyDigest"⟩, "aflock", ← nat j "timeVerified", [], result⟩

/-- What each consumer Rego the driver emits is specified to do.
* `none`: no Rego modules at all (the engine then applies no content check);
* `resultOnly`: deny unless `verificationResult == "PASSED"`;
* `exact`: deny unless PASSED, `policy.digest.sha256 == expected`, and
  `now - window <= timeVerified <= now`. -/
def consumerOf (kind : String) (expected : String) (now window : Nat) : Vsa.Vsa → Verdict :=
  match kind with
  | "resultOnly" => fun v => if v.result == .passed then .pass else .deny
  | "exact" => fun v =>
    if v.result == .passed && v.policyDigest == ⟨expected⟩ && decide (v.timeVerified ≤ now) &&
        decide (now ≤ v.timeVerified + window) then .pass else .deny
  | _ => fun _ => .pass

def verifyStr : Gate.VerifyOutcome → String
  | .accepted b => s!"accepted:{b}"
  | .failed r => s!"failed:{r}"

def vsaCase (j : Json) : D String := do
  let requested : Subject := ⟨⟨← str j "requested"⟩⟩
  let allowedIds ← strs j "allowed"
  let allowed := fun (v : VerifierIdentity) => allowedIds.contains v.id
  let now ← nat j "now"
  let window ← nat j "window"
  let exts ← (← arr j "externals").mapM (fun e => do
    let consumer := consumerOf (← str e "consumer") (← str e "expected") now window
    let cands ← (← arr e "candidates").mapM (fun c => do
      let vc : Vsa.Candidate := ⟨← decodeVsa (← field c "vsa"), ⟨← str c "signer"⟩, ← bool c "sigOk"⟩
      let stamped : List Nat ← match c.getObjVal? "stamped" with
        | .error _ => pure []
        | .ok v => do (← v.getArr?).toList.mapM (·.getNat?)
      -- The nested view: the stock envelope plus what admission reads.
      return (⟨Vsa.toEnvelope allowed requested consumer vc, vc.vsa.policyDigest,
        some vc.vsa.timeVerified, stamped⟩ : Nested.Candidate))
    let child : Option Digest ← match e.getObjVal? "child" with
      | .error _ | .ok Json.null => pure none
      | .ok v => do let s ← v.getStr?; pure (some (Digest.mk s))
    let maxAge : Option Nat ← match e.getObjVal? "maxAge" with
      | .error _ | .ok Json.null => pure none
      | .ok v => do let n ← v.getNat?; pure (some n)
    -- `externalLatest` is `Gate.external` over the envelopes when neither
    -- nested field is set.
    let required ← bool e "required"
    let x : Nested.External := { required, child, maxAge }
    return Nested.externalLatest now x cands)
  return verifyStr (Gate.verify true [] exts)

/-! ## Failure verdicts (deny reasons, no verdict, exit code) -/

/-- An error tree: `{"k": kind, "rs": [...]}` for `denied`, `"e"` for `wrap`,
`"es"` for `join`, nothing else for a leaf. -/
partial def decodeErr (j : Json) : D Verdict.ErrTree := do
  match ← str j "k" with
  | "denied" => return .denied (← strs j "rs")
  | "unavailable" => pure .unavailable
  | "aiRefused" => pure .aiRefused
  | "regoRefused" => pure .regoRefused
  | "assignmentBound" => pure .assignmentBound
  | "other" => pure .other
  | "wrap" => return .wrap (← decodeErr (← field j "e"))
  | "join" => return .join (← (← arr j "es").mapM decodeErr)
  | k => throw s!"error kind {k}"

/-- `{"denies":[...],"exit":n}`, keys in the order Go's struct writes them. -/
def verdictCase (j : Json) : D String := do
  let e ← decodeErr (← field j "err")
  let denies := Json.arr (e.denies.map Json.str).toArray
  return (Json.mkObj [("denies", denies), ("exit", Json.num (Verdict.exitCode (some e)))]).compress

def runCase (line : String) : String :=
  match Json.parse line with
  | .error e => s!"decode-error: {e}"
  | .ok j =>
    let r : D String := do
      match ← str j "kind" with
      | "rego" => regoCase j
      | "ai" => aiCase j
      | "gate" => gateCase j
      | "vsa" => vsaCase j
      | "verdict" => verdictCase j
      | k => throw s!"case kind {k}"
    match r with
    | .ok s => s
    | .error e => s!"decode-error: {e}"

end CilockEvaluators.Oracle
