import CilockCi.Token

/-!
# How `cilock run` signs in CI, and when it refuses before the build

`route` is the model of `decideSigningRoute`
(cilock/internal/options/signing_route.go), which `PreflightIdentity` runs
before the wrapped command so a job that cannot sign fails before its build,
not after it. The Go differential test
(cilock/internal/options/signing_route_differential_test.go) compares them.

Out of scope, named so nobody reads more into the theorems: an enrolled agent
credential (it pre-empts everything here and is modelled in the agent
contract), KMS/Vault/SPIFFE signers (covered by `localSigner`), and whether
Fulcio accepts the token (the platform lane's model).
-/

namespace CilockCi

/-- The CI the process runs in, from its own environment. -/
inductive Provider where
  | none
  /-- GitHub Actions; `canMint` is ACTIONS_ID_TOKEN_REQUEST_URL and _TOKEN both set
  (`permissions: id-token: write`). -/
  | github (canMint : Bool)
  | gitlab (job : Job)
  | buildkite
  | circleci
deriving Repr, DecidableEq

/-- A stored platform credential for this platform URL. -/
inductive Session where
  | none
  /-- a bearer session (`cilock login` in a browser, or `--token`) -/
  | bearer
  /-- a workflow-identity marker: no stored token, the CI identity signs -/
  | workflow
deriving Repr, DecidableEq

structure RunFlags where
  /-- `--offline` or `--platform-url ""` -/
  platformDisabled : Bool
  /-- `-k`, `--signer-file-*`, KMS, Vault, SPIFFE -/
  localSigner : Bool
  /-- `--signer-fulcio-token`, `-token-path` or `-oidc-issuer` -/
  explicitToken : Bool
  session : Session
deriving Repr, DecidableEq

inductive Why where
  | notSignedIn
  | gitlab (r : Refusal)
deriving Repr, DecidableEq

inductive Route where
  | offline
  | localKey
  | explicitToken
  /-- exchange the stored session at /oauth/sign-token -/
  | sessionExchange
  /-- mint a sigstore-audience token from the GitHub Actions endpoint -/
  | githubMint
  /-- send this job token to Fulcio -/
  | gitlabToken (t : Token)
  /-- the Fulcio signer asks the Buildkite / CircleCI agent for a token -/
  | signerFetch
  | refuse (w : Why)
deriving Repr, DecidableEq

def fulcioAud : String := "sigstore"

def route (p : Provider) (f : RunFlags) (env : Env) (explicit : Option String) (now : Nat) : Route :=
  if f.platformDisabled then .offline
  else if f.localSigner then .localKey
  else if f.explicitToken then .explicitToken
  else if f.session == .bearer then .sessionExchange
  else match p with
    | .github true => .githubMint
    | .gitlab job =>
      match selectToken env job fulcioAud explicit now with
      | .ok t => .gitlabToken t
      | .error r => .refuse (.gitlab r)
    | .buildkite => .signerFetch
    | .circleci => .signerFetch
    | _ => .refuse .notSignedIn

/-- The route with the CI vendor forgotten, for the parity theorem. -/
inductive Kind where
  | offline | localKey | explicitToken | sessionExchange | jobToken | signerFetch | refuse
deriving Repr, DecidableEq

def Route.kind : Route → Kind
  | .offline => .offline
  | .localKey => .localKey
  | .explicitToken => .explicitToken
  | .sessionExchange => .sessionExchange
  | .githubMint => .jobToken
  | .gitlabToken _ => .jobToken
  | .signerFetch => .signerFetch
  | .refuse _ => .refuse

/-- Keyless with a CI job identity. -/
def Route.keylessJob (r : Route) : Bool := r.kind == .jobToken

/-- The platform Archivista upload's bearer. A job that declared no upload
token uploads unauthenticated only if the operator forced it, and the
platform answers 401: that is not a signing decision, so it is `none` here. -/
inductive Upload where
  | sessionBearer
  | githubMint
  | gitlabToken (t : Token)
  | none
deriving Repr, DecidableEq

def upload (p : Provider) (f : RunFlags) (env : Env) (archivistaAud : String) (now : Nat) : Upload :=
  if f.platformDisabled then .none
  else if f.session == .bearer then .sessionBearer
  else match p with
    | .github true => .githubMint
    | .gitlab job =>
      match selectToken env job archivistaAud none now with
      | .ok t => .gitlabToken t
      | .error _ => .none
    | _ => .none

end CilockCi
