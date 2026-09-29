/-!
# Which GitLab ID token cilock sends where

GitLab does not mint a token on request as GitHub Actions does. A job
declares one token per audience under `id_tokens:` and the runner exports
each into the job's environment under the name the job chose. `selectToken`
is how cilock picks the one it hands to a relying party (Fulcio, the platform
login, the platform Archivista).

It is the model of `cijobtoken.Select`
(attestation/cijobtoken/cijobtoken.go). The Go differential test
(attestation/cijobtoken/formal_differential_test.go) runs both over generated
environments and requires the same answer, token variable included.

Environment values are abstracted to what `ParseClaims` makes of them: blank,
not a JWT, or a JWT with the claims below. The signature is not modelled: the
relying party checks it, and this model is the client-side half.
-/

namespace CilockCi

/-- The claims `selectToken` reads, plus the ones the platform binds. -/
structure Claims where
  iss : String
  aud : List String
  jobId : String
  /-- Unix seconds; 0 means the token carries no `exp`. -/
  exp : Nat
  projectId : String := ""
  projectPath : String := ""
  ref : String := ""
  refType : String := ""
deriving Repr, DecidableEq, Inhabited

/-- An environment value, as `ParseClaims` sees it. -/
inductive Val where
  /-- empty or whitespace only -/
  | empty
  /-- not a compact JWT with a JSON payload -/
  | junk
  | jwt (c : Claims)
deriving Repr, DecidableEq

/-- The process environment, in `os.Environ` order. -/
abbrev Env := List (String × Val)

/-- The job, from GitLab's predefined CI_SERVER_URL and CI_JOB_ID. -/
structure Job where
  serverUrl : String
  jobId : String
deriving Repr, DecidableEq

/-- A selected token: the variable it came from and its claims. -/
structure Token where
  var : String
  claims : Claims
deriving Repr, DecidableEq, Inhabited

/-- Why no token was selected. -/
inductive Refusal where
  | noAudience
  | noJob
  /-- the explicitly named variable holds something that is not a JWT -/
  | notJWT (v : String)
  /-- the explicitly named variable holds another job's (or issuer's) token -/
  | notThisJob (v : String)
  /-- the only tokens for this audience have expired -/
  | expired (v : String)
  /-- the explicitly named variable is unset or blank -/
  | explicitEmpty (v : String)
  /-- the job has tokens, none for exactly this audience -/
  | wrongAud
  | missing
deriving Repr, DecidableEq

def isWs (c : Char) : Bool := c == ' ' || c == '\t' || c == '\n' || c == '\r'

/-- `strings.TrimRight(strings.TrimSpace(s), "/")` over ASCII whitespace. -/
def trimIssuer (s : String) : String :=
  let r := ((s.toList.dropWhile isWs).reverse.dropWhile isWs).dropWhile (· == '/')
  String.ofList r.reverse

/-- The token was issued by this job's GitLab to this job. -/
def issuedFor (j : Job) (c : Claims) : Bool :=
  j.serverUrl != "" && j.jobId != "" && trimIssuer c.iss == trimIssuer j.serverUrl && c.jobId == j.jobId

/-- The audience is exactly `want`, and nothing else. -/
def exactAud (aud : List String) (want : String) : Bool := aud == [want]

/-- Not expired at `now`. -/
def live (c : Claims) (now : Nat) : Bool := c.exp == 0 || now < c.exp

def defaultVar (aud : String) : String :=
  if aud == "sigstore" then "SIGSTORE_ID_TOKEN"
  else if aud.endsWith "/login" then "CILOCK_LOGIN_ID_TOKEN"
  else if aud.endsWith "/archivista" then "CILOCK_ARCHIVISTA_ID_TOKEN"
  else "CILOCK_ID_TOKEN"

structure Acc where
  found : List Token := []
  near : List String := []
  expired : List String := []

/-- Whether a variable is considered at all. -/
def considered (explicit : Option String) (n : String) : Bool :=
  match explicit with
  | none => true
  | some x => n == x

/-- One pass over the environment, in order. An explicitly named variable
that holds a non-JWT or another job's token stops the pass. -/
def scan (job : Job) (aud : String) (explicit : Option String) (now : Nat) : Env → Acc → Except Refusal Acc
  | [], acc => .ok acc
  | (n, v) :: rest, acc =>
    if !considered explicit n then scan job aud explicit now rest acc else
    match v with
    | .empty => scan job aud explicit now rest acc
    | .junk => if explicit.isSome then .error (.notJWT n) else scan job aud explicit now rest acc
    | .jwt c =>
      if !issuedFor job c then
        (if explicit.isSome then .error (.notThisJob n) else scan job aud explicit now rest acc)
      else if !exactAud c.aud aud then scan job aud explicit now rest { acc with near := n :: acc.near }
      else if !live c now then scan job aud explicit now rest { acc with expired := n :: acc.expired }
      else scan job aud explicit now rest { acc with found := ⟨n, c⟩ :: acc.found }

/-- `a` sorts before `b`: the documented name first, then by name. -/
def before (aud : String) (a b : Token) : Bool :=
  let da := a.var == defaultVar aud
  let db := b.var == defaultVar aud
  if da != db then da else decide (a.var < b.var)

def pick (aud : String) : Token → List Token → Token
  | t, [] => t
  | t, u :: us => pick aud (if before aud u t then u else t) us

def minName : String → List String → String
  | s, [] => s
  | s, u :: us => minName (if u < s then u else s) us

/-- `cijobtoken.Select`. -/
def selectToken (env : Env) (job : Job) (aud : String) (explicit : Option String) (now : Nat) : Except Refusal Token :=
  if aud == "" then .error .noAudience
  else if job.serverUrl == "" || job.jobId == "" then .error .noJob
  else match scan job aud explicit now env {} with
    | .error r => .error r
    | .ok acc =>
      match acc.found with
      | t :: ts => .ok (pick aud t ts)
      | [] =>
        match acc.expired, explicit with
        | e :: es, _ => .error (.expired (minName e es))
        | [], some x => if acc.near.isEmpty then .error (.explicitEmpty x) else .error .wrongAud
        | [], none => if acc.near.isEmpty then .error .missing else .error .wrongAud

end CilockCi
