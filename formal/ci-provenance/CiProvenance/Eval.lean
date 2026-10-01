import Lean.Data.Json
import CiProvenance.Alps
import CiProvenance.Slsa
import CiProvenance.Subjects
import CiProvenance.Verdict
import CiProvenance.SlsaL3Workflow
import CiProvenance.BuilderIdentity

/-!
# JSON evaluation of the model's decision functions

One JSON case per line in, one JSON result per line out, so a Go test can run
the same random cases through the Go implementation and the model and diff
them. Every function evaluated here is the one the theorems are about; nothing
is re-implemented for the harness.

  {"fn":"verdict","unexamined":[..],"stopped":"..","matched":b,"unbound":".."}
      -> {"status":"detected|not-detected|incomplete"}
  {"fn":"slsaSubjects","products":[[name,[[alg,val],..]],..],"extra":[..]}
      -> {"subjects":[[name,[[alg,val],..]],..]}
  {"fn":"alps", <Evidence Booleans>}   -> {"level":"ALPS-n|unknown"}
  {"fn":"slsa", <ProvEvidence Booleans>} -> {"level":"L1|L2|L3|none"}
  {"fn":"builderIdentity","types":[..],"body":<provenance JSON>,"signers":[..]}
      -> {"ok":b,"reason":"legacy-type|malformed|unbacked|"}   (BuilderIdentity.refusal)
-/

namespace CiProvenance.Eval

open Lean (Json)

def field (j : Json) (k : String) : Except String Json := j.getObjVal? k

def str (j : Json) (k : String) : Except String String := do (← field j k).getStr?

def bool (j : Json) (k : String) : Except String Bool := do (← field j k).getBool?

def strs (j : Json) (k : String) : Except String (List String) := do
  let a ← (← field j k).getArr?
  a.toList.mapM (·.getStr?)

def pair (j : Json) : Except String (String × String) := do
  let a ← j.getArr?
  match a.toList with
  | [x, y] => return (← x.getStr?, ← y.getStr?)
  | _ => throw "want a [string, string] pair"

def digestSet (j : Json) : Except String DigestSet := do
  (← j.getArr?).toList.mapM pair

def named (j : Json) (k : String) : Except String (Named DigestSet) := do
  let a ← (← field j k).getArr?
  a.toList.mapM fun e => do
    match (← e.getArr?).toList with
    | [n, ds] => return (← n.getStr?, ← digestSet ds)
    | _ => throw "want a [name, digests] pair"

def renderNamed (m : Named DigestSet) : Json :=
  Json.arr <| m.toArray.map fun (n, ds) =>
    Json.arr #[Json.str n, Json.arr (ds.toArray.map fun (a, v) => Json.arr #[Json.str a, Json.str v])]

def nat (j : Json) (k : String) : Except String Nat := do (← field j k).getNat?

def event : String → Except String L3.Event
  | "push" => pure .push
  | "release" => pure .release
  | "workflow_dispatch" => pure .workflowDispatch
  | "pull_request" => pure .pullRequest
  | "pull_request_target" => pure .pullRequestTarget
  | "workflow_run" => pure .workflowRun
  | e => throw s!"unknown event {e}"

def root : String → Except String L3.Root
  | "platform" => pure .platform
  | "public-sigstore" => pure .publicSigstore
  | r => throw s!"unknown root {r}"

def cert (j : Json) : Except String L3.Cert := do
  let x ← field j "ext"
  return { root := ← root (← str j "root"),
           ext := { signerPath := ← str x "buildSignerPath", signerRef := ← str x "buildSignerRef",
                    signerDigest := ← str x "buildSignerDigest", sourceRepo := ← str x "sourceRepository",
                    sourceDigest := ← str x "sourceDigest", runInvocation := ← nat x "runId",
                    trigger := ← event (← str x "trigger"), hosted := ← bool x "hosted" } }

def l3Case (j : Json) : Except String Bool := do
  let p ← field j "policy"
  let roots ← (← (← field p "roots").getArr?).toList.mapM fun r => do root (← r.getStr?)
  let pol : L3.Policy := ⟨roots, ← str p "path", ← str p "sha", ← str p "repo"⟩
  let e ← field j "evidence"
  let s ← field e "stmt"
  let bid ← pair (← field s "builderId")
  let builds ← (← (← field e "builds").getArr?).toList.mapM fun b => do
    return ({ cert := ← cert (← field b "cert"), subjects := ← strs b "subjects" } : L3.Collection)
  let ev : L3.Evidence :=
    { signer := ← cert (← field e "signer"),
      stmt := { builderId := bid, repo := ← str s "repo", commit := ← str s "commit",
                runId := ← nat s "runId", subjects := ← strs s "subjects" },
      builds := builds }
  return L3.l3Accept pol ev

def evalCase (j : Json) : Except String Json := do
  match ← str j "fn" with
  | "verdict" =>
    let c : Coverage :=
      { unexamined := ← strs j "unexamined", stopped := ← str j "stopped",
        matched := ← bool j "matched", unbound := ← str j "unbound" }
    return Json.mkObj [("status", Json.str (verdict c).wire)]
  | "slsaSubjects" =>
    return Json.mkObj [("subjects", renderNamed (slsaSubjects (← named j "products") (← named j "extra")))]
  | "alps" =>
    let e : Evidence :=
      { signed := ← bool j "signed", issued := ← bool j "issued", timestamped := ← bool j "timestamped",
        boundaryClaimed := ← bool j "boundaryClaimed", boundaryByObserver := ← bool j "boundaryByObserver",
        isolated := ← bool j "isolated", attribution := ⟨[], ""⟩, execution := ⟨[], 0, ""⟩, products := [] }
    return Json.mkObj [("level", Json.str (deriveAlps e).name)]
  | "slsa" =>
    let p : ProvEvidence :=
      { present := ← bool j "present", hostedWorkflowSigner := ← bool j "hostedWorkflowSigner",
        trustedBuilderSigner := ← bool j "trustedBuilderSigner", timestamped := ← bool j "timestamped",
        ephemeralRunner := ← bool j "ephemeralRunner", subjects := [] }
    return Json.mkObj [("level", Json.str (deriveSlsa p).name)]
  | "l3Accept" =>
    return Json.mkObj [("accept", Json.bool (← l3Case j))]
  | "builderIdentity" =>
    let b := BuilderIdentity.decode (← field j "body")
    let r := BuilderIdentity.refusal (← strs j "types") b (← strs j "signers")
    return Json.mkObj [("ok", Json.bool r.isNone), ("reason", Json.str ((r.map (·.name)).getD ""))]
  | other => throw s!"unknown fn {other}"

def evalLine (line : String) : String :=
  match Json.parse line >>= evalCase with
  | .ok r => r.compress
  | .error e => (Json.mkObj [("error", Json.str e)]).compress

end CiProvenance.Eval
