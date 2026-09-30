import Lean.Data.Json
import CilockCi.Token
import CilockCi.Plan
import CilockCi.Login
import CilockCi.Automode
import CilockCi.Review
import CilockCi.Trust

/-!
# JSON evaluation, for the Go differential tests

One JSON case per line in, one JSON result per line out. Every function
evaluated is the one the theorems are about.

An environment is `[[name, value], ..]` where value is
`{"t":"str","s":".."}` (a plain value; never a JWT) or
`{"t":"jwt","iss":"..","aud":[..],"jobId":"..","exp":n}`.

  {"fn":"select","env":E,"serverUrl":"..","jobId":"..","aud":"..","explicit":null|"..","now":n}
      -> {"ok":VAR} | {"refuse":KIND,"var":".."}
  {"fn":"route","env":E,"flags":{"platformDisabled":b,"localSigner":b,"explicitToken":b,"session":"none|bearer|workflow"},
   "explicit":null|"..","now":n}
      -> {"route":KIND,"var":"..","why":".."}
  {"fn":"upload","env":E,"flags":F,"archivistaAud":"..","now":n} -> {"upload":KIND,"var":".."}
  {"fn":"login","env":E,"flags":{"token":b,"interactive":b,"workflowFlag":b,"url":"..","defaultUrl":".."},"now":n}
      -> {"tier":KIND,"var":"..","why":".."}
  {"fn":"ci","env":E} -> {"ci":[..],"provider":"none|github|github-nomint|gitlab|buildkite|circleci"}

The provider is always computed from E by `provider`, as cilock computes it
from its own environment.
-/

namespace CilockCi.Eval

open Lean (Json)

def field (j : Json) (k : String) : Except String Json := j.getObjVal? k
def str (j : Json) (k : String) : Except String String := do (← field j k).getStr?
def bool (j : Json) (k : String) : Except String Bool := do (← field j k).getBool?
def nat (j : Json) (k : String) : Except String Nat := do (← field j k).getNat?

def optStr (j : Json) (k : String) : Except String (Option String) :=
  match j.getObjVal? k with
  | .ok .null => pure none
  | .ok v => do pure (some (← v.getStr?))
  | .error _ => pure none

inductive Raw where
  | str (s : String)
  | jwt (c : Claims)

def raw (j : Json) : Except String Raw := do
  match ← str j "t" with
  | "str" => pure (.str (← str j "s"))
  | "jwt" =>
    let aud ← (← (← field j "aud").getArr?).toList.mapM (·.getStr?)
    pure (.jwt { iss := ← str j "iss", aud := aud, jobId := ← str j "jobId", exp := ← nat j "exp" })
  | t => throw s!"unknown value kind {t}"

def rawEnv (j : Json) : Except String (List (String × Raw)) := do
  (← (← field j "env").getArr?).toList.mapM fun e => do
    match (← e.getArr?).toList with
    | [n, v] => pure (← n.getStr?, ← raw v)
    | _ => throw "env entry must be [name, value]"

def tokenEnv (e : List (String × Raw)) : Env :=
  e.map fun (n, v) => match v with
    | .str s => (n, if (s.toList.filter (fun c => !isWs c)).isEmpty then .empty else .junk)
    | .jwt c => (n, .jwt c)

def strEnv (e : List (String × Raw)) : StrEnv :=
  e.map fun (n, v) => match v with
    | .str s => (n, s)
    | .jwt _ => (n, "<jwt>")

def refusalKind : Refusal → String × String
  | .noAudience => ("noAudience", "")
  | .noJob => ("noJob", "")
  | .notJWT v => ("notJWT", v)
  | .notThisJob v => ("notThisJob", v)
  | .expired v => ("expired", v)
  | .explicitEmpty v => ("explicitEmpty", v)
  | .wrongAud => ("wrongAud", "")
  | .missing => ("missing", "")

def session : String → Except String Session
  | "none" => pure .none
  | "bearer" => pure .bearer
  | "workflow" => pure .workflow
  | s => throw s!"unknown session {s}"

def runFlags (j : Json) : Except String RunFlags := do
  let f ← field j "flags"
  pure { platformDisabled := ← bool f "platformDisabled", localSigner := ← bool f "localSigner",
         explicitToken := ← bool f "explicitToken", session := ← session (← str f "session") }

def providerName : Provider → String
  | .none => "none"
  | .github true => "github"
  | .github false => "github-nomint"
  | .gitlab _ => "gitlab"
  | .buildkite => "buildkite"
  | .circleci => "circleci"

def evalCase (j : Json) : Except String Json := do
  let fn ← str j "fn"
  let e ← rawEnv j
  let env := tokenEnv e
  let p := provider (strEnv e)
  match fn with
  | "select" =>
    let job : Job := { serverUrl := ← str j "serverUrl", jobId := ← str j "jobId" }
    match selectToken env job (← str j "aud") (← optStr j "explicit") (← nat j "now") with
    | .ok t => pure (Json.mkObj [("ok", t.var)])
    | .error r => let (k, v) := refusalKind r; pure (Json.mkObj [("refuse", k), ("var", v)])
  | "route" =>
    let r := route p (← runFlags j) env (← optStr j "explicit") (← nat j "now")
    let (k, v, w) : String × String × String := match r with
      | .offline => ("offline", "", "")
      | .localKey => ("localKey", "", "")
      | .explicitToken => ("explicitToken", "", "")
      | .sessionExchange => ("sessionExchange", "", "")
      | .githubMint => ("githubMint", "", "")
      | .gitlabToken t => ("gitlabToken", t.var, "")
      | .signerFetch => ("signerFetch", "", "")
      | .refuse .notSignedIn => ("refuse", "", "notSignedIn")
      | .refuse (.gitlab r) => ("refuse", "", "gitlab:" ++ (refusalKind r).1)
    pure (Json.mkObj [("route", k), ("var", v), ("why", w)])
  | "upload" =>
    let u := upload p (← runFlags j) env (← str j "archivistaAud") (← nat j "now")
    let (k, v) : String × String := match u with
      | .sessionBearer => ("sessionBearer", "")
      | .githubMint => ("githubMint", "")
      | .gitlabToken t => ("gitlabToken", t.var)
      | .none => ("none", "")
    pure (Json.mkObj [("upload", k), ("var", v)])
  | "trusted" =>
    let sf ← field j "store"
    let s : StoreFlags := { explicit := ← bool sf "explicit", value := ← bool sf "value",
                            sameOrigin := ← bool sf "sameOrigin" }
    let d := trusted p (← runFlags j) s env (← str j "archivistaAud") (← nat j "now")
    let g : String := match d.gate with | .proceed => "proceed" | .refuse => "refuse"
    pure (Json.mkObj [("held", d.held), ("enabled", d.enabled), ("gate", g)])
  | "login" =>
    let f ← field j "flags"
    let tok ← bool f "token"
    let inter ← bool f "interactive"
    let wf ← bool f "workflowFlag"
    let url ← str f "url"
    let du ← str f "defaultUrl"
    let ci := inCI (isTrue (strEnv e) "CI") p
    let lf : LoginFlags := { token := tok, interactive := inter, workflowFlag := wf, url := url, defaultUrl := du, ci := ci }
    let (k, v, w) : String × String × String := match tier p lf env (← nat j "now") with
      | .token => ("token", "", "")
      | .githubWorkflow => ("githubWorkflow", "", "")
      | .gitlabWorkflow t => ("gitlabWorkflow", t.var, "")
      | .browser => ("browser", "", "")
      | .refuse .githubNonDefault => ("refuse", "", "githubNonDefault")
      | .refuse .noIdentity => ("refuse", "", "noIdentity")
      | .refuse .ciNoIdentity => ("refuse", "", "ciNoIdentity")
      | .refuse .interactiveInCI => ("refuse", "", "interactiveInCI")
      | .refuse (.gitlab r) => ("refuse", "", "gitlab:" ++ (refusalKind r).1)
    pure (Json.mkObj [("tier", k), ("var", v), ("why", w)])
  | "review" =>
    let vs ← (← (← field j "versions").getArr?).toList.mapM fun v => do
      pure ({ head := ← str v "head", createdAt := ← nat v "createdAt" } : Review.Version)
    let as ← (← (← field j "approvals").getArr?).toList.mapM fun a => do
      pure ({ user := ← nat a "user", approvedAt := ← nat a "at" } : Review.Approval)
    let skew ← nat j "skew"
    let author : Option Nat := match j.getObjVal? "author" with
      | .ok (.num n) => some n.mantissa.toNat
      | _ => none
    let t ← nat j "t"
    let bound := match Review.boundHead skew vs t with
      | some h => Json.str h
      | none => Json.null
    pure (Json.mkObj [("bound", bound),
      ("count", Json.num (Review.countFor skew vs as (← nat j "mergedAt") (← str j "head") author))])
  | "jctlAnswer" =>
    let a : Answer ← match ← str j "answer" with
      | "matched" => pure (.matched { tenant := "t", product := "p" })
      | "noMatch" => pure .noMatch
      | "notMapped" => pure .notMapped
      | "ambiguous" => pure .ambiguous
      | "unavailable" => pure .unavailable
      | a => throw s!"unknown answer {a}"
    let k := match jctlAnswerOut a with
      | .session _ => "session" | .markerUnbound => "marker" | .refuse _ => "refuse" | .other _ => "other"
    pure (Json.mkObj [("out", k)])
  | "ci" =>
    pure (Json.mkObj [("ci", Json.arr ((ciContext (strEnv e)).toArray.map Json.str)), ("provider", providerName p)])
  | f => throw s!"unknown fn {f}"

def evalLine (line : String) : String :=
  match Json.parse line >>= evalCase with
  | .ok j => j.compress
  | .error e => (Json.mkObj [("error", e)]).compress

end CilockCi.Eval
