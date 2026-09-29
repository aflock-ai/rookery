import CilockCi.Plan

/-!
# Automode: which CI context attestor a zero-flag `cilock run` attaches

With no `-a`, `cilock run` runs the catalog detectors against the wrapped
argv, its environment and working directory (`detectCatalogAttestors`,
cilock/cli/run.go). `ciContext` is the part of that decision that depends on
which CI the job runs in; everything else is a function of the argv and the
working tree, which a GitHub job and a GitLab job building the same commit
share. The Go differential test (cilock/cmd/cilock/ci_automode_test.go, where
the shipped attestor set is linked)
runs the REAL detectors over generated environments, checks their CI-context
attestors against `ciContext`, and checks that the rest does not change when
only the CI vendor does.

`provider` is the model of `auth.CIProviderFromEnv`
(cilock/internal/auth/ciidentity.go; compared in cilock/cli/ci_differential_test.go), the one place cilock's own
code (signing, login, preflight) decides which CI it is in.
-/

namespace CilockCi

/-- A plain string environment, `NAME=value` split. -/
abbrev StrEnv := List (String × String)

def lookup (e : StrEnv) (k : String) : Option String :=
  (e.find? (·.1 == k)).map (·.2)

def isTrue (e : StrEnv) (k : String) : Bool := lookup e k == some "true"

/-- The CI context attestors the detectors attach: the github and gitlab
detectors match `env_equals: {GITHUB_ACTIONS|GITLAB_CI: "true"}`. -/
def ciContext (e : StrEnv) : List String :=
  (if isTrue e "GITHUB_ACTIONS" then ["github"] else []) ++
  (if isTrue e "GITLAB_CI" then ["gitlab"] else [])

/-- `ciProviderFromEnv`. GitLab wins over GitHub when a job somehow has both
markers, because GitLab's is the one whose tokens cilock would select; the
two cannot both be true of a real job. -/
def provider (e : StrEnv) : Provider :=
  if isTrue e "GITLAB_CI" then
    .gitlab { serverUrl := (lookup e "CI_SERVER_URL").getD "", jobId := (lookup e "CI_JOB_ID").getD "" }
  else if isTrue e "GITHUB_ACTIONS" || (lookup e "ACTIONS_ID_TOKEN_REQUEST_URL").isSome then
    .github ((lookup e "ACTIONS_ID_TOKEN_REQUEST_URL").getD "" != "" && (lookup e "ACTIONS_ID_TOKEN_REQUEST_TOKEN").getD "" != "")
  else if isTrue e "BUILDKITE" then .buildkite
  else if isTrue e "CIRCLECI" then .circleci
  else .none

end CilockCi
