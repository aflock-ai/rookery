import Lean.Data.Json
import SemgrepAttestor.Select
import SemgrepAttestor.Summary

/-!
# JSON evaluation of the model's functions

One JSON case per line in, one JSON result per line out, so the Go
differential tests (`plugins/attestors/semgrep/formal_differential_test.go`)
can run the same cases through `Attest` and through the model and diff them.
Every function evaluated here is the one the theorems are about; nothing is
re-implemented for the harness.

  {"fn":"select","classes":["foreign"|"broken"|"good",..]}
      -> {"outcome":"soft"|"refuse"|"attest"}
  {"fn":"summary","errors":n,"findings":[{"id":n,"sev":s,"ignored":b,"file":n|null},..]}
      -> {"scanComplete":b,"critical":n,..,"unknown":n,"ignored":n,"live":n,
          "subjects":["finding:<id>"|"file:<digest>",..]}
-/

namespace SemgrepAttestor.Eval

open Lean (Json)

def field (j : Json) (k : String) : Except String Json := j.getObjVal? k

def cls : String → Except String Class
  | "foreign" => pure .foreign
  | "broken" => pure .broken
  | "good" => pure .good
  | s => throw s!"unknown class {s}"

def sev : String → Except String Sev
  | "critical" => pure .critical
  | "high" => pure .high
  | "medium" => pure .medium
  | "low" => pure .low
  | "info" => pure .info
  | "unknown" => pure .unknown
  | s => throw s!"unknown severity {s}"

def outcome : Outcome → String
  | .soft => "soft"
  | .refuse => "refuse"
  | .attest => "attest"

def subject : Subject → String
  | .finding i => s!"finding:{i}"
  | .file d => s!"file:{d}"

def finding (j : Json) : Except String Finding := do
  let file ← match j.getObjVal? "file" with
    | .ok Json.null => pure none
    | .ok v => some <$> v.getNat?
    | .error _ => pure none
  return {
    id := ← (← field j "id").getNat?
    sev := ← sev (← (← field j "sev").getStr?)
    ignored := ← (← field j "ignored").getBool?
    fileDigest := file }

def evalCase (j : Json) : Except String Json := do
  match ← (← field j "fn").getStr? with
  | "select" =>
    let cs ← (← (← field j "classes").getArr?).toList.mapM fun c => do cls (← c.getStr?)
    return Json.mkObj [("outcome", Json.str (outcome (select cs)))]
  | "summary" =>
    let n ← (← field j "errors").getNat?
    let fs ← (← (← field j "findings").getArr?).toList.mapM finding
    let b := fun s => Json.num (bucket fs s)
    return Json.mkObj [
      ("scanComplete", Json.bool (scanComplete (List.replicate n ()))),
      ("critical", b .critical), ("high", b .high), ("medium", b .medium),
      ("low", b .low), ("info", b .info), ("unknown", b .unknown),
      ("ignored", Json.num (ignoredCount fs)),
      ("live", Json.num (liveCount fs)),
      ("subjects", Json.arr ((subjects fs).toArray.map fun s => Json.str (subject s)))]
  | f => throw s!"unknown fn {f}"

def evalLine (line : String) : String :=
  match Json.parse line >>= evalCase with
  | .ok r => r.compress
  | .error e => (Json.mkObj [("error", Json.str e)]).compress

end SemgrepAttestor.Eval
