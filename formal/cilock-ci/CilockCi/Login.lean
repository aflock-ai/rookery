import CilockCi.Plan

/-!
# `cilock login` in CI

`tier` is the model of `decideLoginTierCI` (cilock/cli/login.go; compared in
cilock/cli/ci_differential_test.go); `login` adds
the platform's answer to the workflow-identity exchange
(POST <platform>/api/auth/resolve-binding, `auth.AmbientWorkflowLogin`).

The platform's credential match is a PARAMETER (`credMatch`), not modelled
here: the platform lane's flow model (formal/forge-webhook-tenancy) supplies
it. What this model proves is the client side: a session only ever comes out
of a platform `match`, and the only GitLab token sent to the login endpoint
is one minted for exactly `<platform>/login`.
-/

namespace CilockCi

structure LoginFlags where
  /-- `--token` -/
  token : Bool
  /-- `--interactive` -/
  interactive : Bool
  /-- `--workflow-identity` -/
  workflowFlag : Bool
  /-- the normalized `--platform-url` -/
  url : String
  /-- the compiled-in default platform -/
  defaultUrl : String
  /-- running in CI: `CI=true`, or any detected CI provider (`inCI`); read from
  the environment, not a flag. There is no browser in CI, and a device flow
  there hangs the job to its timeout. -/
  ci : Bool
deriving Repr, DecidableEq

inductive LoginWhy where
  /-- GitHub mints a token for any audience asked for, so a non-default
  platform needs `--workflow-identity` before cilock mints one for it. -/
  | githubNonDefault
  | noIdentity
  | gitlab (r : Refusal)
  /-- in CI with no usable workflow identity: fail fast naming what to add,
  never a browser or device flow -/
  | ciNoIdentity
  /-- `--interactive` in CI: refused rather than hang the job -/
  | interactiveInCI
deriving Repr, DecidableEq

inductive Tier where
  | token
  | githubWorkflow
  | gitlabWorkflow (t : Token)
  | browser
  | refuse (w : LoginWhy)
deriving Repr, DecidableEq

/-- `config.Derive(url).OIDCLoginAudience` for a normalized url. -/
def loginAud (url : String) : String := url ++ "/login"

/-- `decideLoginTier`. A GitLab job never falls back to the browser: there is
none, and the job would hang to its timeout. It also needs no
`--workflow-identity` for a non-default platform, unlike GitHub, because a
GitLab token's audience is fixed by the pipeline, so a hostile `--platform-url`
finds no token minted for it. -/
def tier (p : Provider) (f : LoginFlags) (env : Env) (now : Nat) : Tier :=
  if f.token then .token
  else if f.interactive then (if f.ci then .refuse .interactiveInCI else .browser)
  else match p with
    | .github true => if f.url == f.defaultUrl || f.workflowFlag then .githubWorkflow else .refuse .githubNonDefault
    | .gitlab job =>
      match selectToken env job (loginAud f.url) none now with
      | .ok t => .gitlabWorkflow t
      | .error r => .refuse (.gitlab r)
    | _ => if f.workflowFlag then .refuse .noIdentity
           else if f.ci then .refuse .ciNoIdentity else .browser

/-- Whether cilock is in CI (`auth.InCI`): `CI=true` or a detected provider. -/
def inCI (ciVar : Bool) (p : Provider) : Bool := ciVar || p != .none

structure Binding where
  tenant : String
  product : String
deriving Repr, DecidableEq

/-- The platform's answer to the login exchange. -/
inductive Answer where
  /-- a tenant OIDC credential matched the token -/
  | matched (b : Binding)
  /-- 401/403: no credential matches this token -/
  | noMatch
  | notMapped
  | ambiguous
  /-- 404, 5xx or transport: the endpoint is not there to ask -/
  | unavailable
deriving Repr, DecidableEq

inductive LoginOut where
  | session (b : Binding)
  /-- a workflow marker with no binding: the run re-resolves it, and the
  platform refuses the run if it still cannot match -/
  | markerUnbound
  /-- a non-workflow tier; its result is not a CI decision -/
  | other (t : Tier)
  | refuse (w : String)
deriving Repr, DecidableEq

def answerOut : Answer → LoginOut
  | .matched b => .session b
  | .unavailable => .markerUnbound
  | .noMatch => .refuse "no platform credential matches this job's identity"
  | .notMapped => .refuse "repository not mapped to a product"
  | .ambiguous => .refuse "repository maps to several products; pass --product"

/-- The whole login. `credMatch` is the platform for a GitLab token;
`githubAnswer` is its answer for the token GitHub mints (not modelled). -/
def login (p : Provider) (f : LoginFlags) (env : Env) (now : Nat)
    (credMatch : Token → Answer) (githubAnswer : Answer) : LoginOut :=
  match tier p f env now with
  | .gitlabWorkflow t => answerOut (credMatch t)
  | .githubWorkflow => answerOut githubAnswer
  | .refuse _ => .refuse "login refused before contacting the platform"
  | t => .other t

/-- jctl's workflow login (judge-api/cmd/jctl/cmd/auth_workflow.go,
`jctlLoginAnswer`). jctl binds no product, so a platform that recognised the
identity but has no single product for it still signs it in; a platform that
did not recognise it (401/403) refuses, exactly as `answerOut` does. -/
def jctlAnswerOut : Answer → LoginOut
  | .matched b => .session b
  | .notMapped => .markerUnbound
  | .ambiguous => .markerUnbound
  | .unavailable => .markerUnbound
  | .noMatch => .refuse "no platform credential matches this job's identity"

/-- jctl never signs in an identity the platform refused, and a session with
a binding only comes from a platform match. -/
theorem jctl_refuses_no_match : jctlAnswerOut .noMatch ≠ .markerUnbound ∧
    ∀ b, jctlAnswerOut .noMatch ≠ .session b := by
  exact ⟨fun h => LoginOut.noConfusion h, fun _ h => LoginOut.noConfusion h⟩

theorem jctl_session_only_via_match (a : Answer) (b : Binding) (h : jctlAnswerOut a = .session b) :
    a = .matched b := by
  cases a <;> simp [jctlAnswerOut] at h
  exact congrArg Answer.matched h

end CilockCi
