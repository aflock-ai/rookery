/-
  CilockPolicy.Holdout: three real policies, set aside before modelling and
  encoded after. Only the functionary constraints are encoded, verbatim; the
  signing certificate is the shape a GitHub Actions keyless signature gets
  (URI SAN = the workflow ref, no DNS/email/organization SAN, the Fulcio
  extensions). That cert shape is INFERRED from Fulcio's GitHub issuance, not
  read from a captured certificate.

  * scripts/dr/verification.policy.json (judge repo), step weekly-dr-observation
  * deploy/cilock/release.policy.json (rookery), step release-build
  * deploy/dist/self-host-minimal.policy.json (judge repo), step clone
-/
import CilockPolicy.Vacuity

namespace CilockPolicy.Holdout
open CilockPolicy

set_option maxRecDepth 20000

def ghCert (root uri repo buildConfig ref runner : String) : Cert :=
  { keyId := "ephemeral", cn := "", dns := [], emails := [], orgs := [], uris := [uri]
    exts := [("Issuer", "https://token.actions.githubusercontent.com"), ("SourceRepositoryURI", repo),
      ("BuildConfigURI", buildConfig), ("SourceRepositoryRef", ref), ("RunnerEnvironment", runner)]
    policyOids := [], chainsTo := [root], notBefore := 0, notAfter := 600 }

/-! ### scripts/dr/verification.policy.json, weekly-dr-observation -/

def drWorkflow : String := "https://github.com/testifysec/judge/.github/workflows/weekly-dr.yml@refs/heads/main"
def drF : Functionary :=
  { type := "root"
    cc := { cn := "*", uris := [drWorkflow], roots := ["fulcio-root"], dns := ["*"], emails := ["*"],
            orgs := ["*"]
            exts := [("Issuer", "https://token.actions.githubusercontent.com"),
                     ("SourceRepositoryURI", "https://github.com/testifysec/judge"),
                     ("BuildConfigURI", drWorkflow)] } }
def drCert : Cert := ghCert "fulcio-root" drWorkflow "https://github.com/testifysec/judge" drWorkflow
  "refs/heads/main" "github-hosted"
/-- The same workflow run from a pull-request ref. -/
def drPrCert : Cert :=
  ghCert "fulcio-root" "https://github.com/testifysec/judge/.github/workflows/weekly-dr.yml@refs/pull/1/merge"
    "https://github.com/testifysec/judge"
    "https://github.com/testifysec/judge/.github/workflows/weekly-dr.yml@refs/pull/1/merge"
    "refs/pull/1/merge" "github-hosted"

/-! ### deploy/cilock/release.policy.json, release-build -/

def relF : Functionary :=
  { type := "root"
    cc := { cn := "*", dns := ["*"], emails := ["*"], orgs := ["*"], uris := ["*"]
            roots := ["platform-testifysec-fulcio"]
            exts := [("Issuer", "https://token.actions.githubusercontent.com"),
                     ("SourceRepositoryURI", "https://github.com/aflock-ai/rookery"),
                     ("BuildConfigURI", "https://github.com/aflock-ai/rookery/.github/workflows/release.yml@*")] } }
/-- The functionary as encoded at holdout time, before #9866: dnsnames, emails
    and organizations left empty. -/
def relFBefore9866 : Functionary :=
  { relF with cc := { relF.cc with dns := [], emails := [], orgs := [] } }
def relCert : Cert :=
  ghCert "platform-testifysec-fulcio" "https://github.com/aflock-ai/rookery/.github/workflows/release.yml@refs/tags/v1.2.3"
    "https://github.com/aflock-ai/rookery"
    "https://github.com/aflock-ai/rookery/.github/workflows/release.yml@refs/tags/v1.2.3" "refs/tags/v1.2.3" "github-hosted"

/-! ### deploy/dist/self-host-minimal.policy.json, clone -/

def shmF : Functionary :=
  { type := "root"
    cc := { cn := "*", dns := ["*"], emails := ["*"], orgs := ["*"], uris := ["*"]
            roots := ["platform-testifysec-fulcio"]
            exts := [("Issuer", "https://token.actions.githubusercontent.com"),
                     ("SourceRepositoryURI", "https://github.com/testifysec/judge"),
                     ("SourceRepositoryRef", "refs/tags/self-host-minimal-v*"),
                     ("BuildConfigURI", "https://github.com/testifysec/judge/.github/workflows/release-self-host-minimal.yml@*"),
                     ("RunnerEnvironment", "self-hosted")] } }
def shmCert (ref runner : String) : Cert :=
  ghCert "platform-testifysec-fulcio"
    ("https://github.com/testifysec/judge/.github/workflows/release-self-host-minimal.yml@" ++ ref)
    "https://github.com/testifysec/judge"
    ("https://github.com/testifysec/judge/.github/workflows/release-self-host-minimal.yml@" ++ ref) ref runner

/-! ## Predictions, computed by the model (not tuned to any observation) -/

/-- DR: the main-branch workflow is admitted under enforce; a PR run is not. -/
theorem dr_prediction :
    fValidate .enforce ["fulcio-root"] drF (.cert drCert) = true ∧
    fValidate .enforce ["fulcio-root"] drF (.cert drPrCert) = false := by decide

/-- As held out, release.policy.json left dnsnames/emails/organizations EMPTY.
    The GitHub cert has none of those SANs, so R3_181 fired: REFUSED under the
    cilock CLI default (enforce), ADMITTED under --policy-hardening=warn. The
    engine agreed, and #9866 fixed the policy. -/
theorem release_prediction :
    fValidate .enforce ["platform-testifysec-fulcio"] relFBefore9866 (.cert relCert) = false ∧
    fValidate .warn ["platform-testifysec-fulcio"] relFBefore9866 (.cert relCert) = true := by decide

/-- The shipped policy after #9866 sets those lists to "*", and the GitHub
    cert is ADMITTED under enforce and under warn. -/
theorem release_prediction_after_9866 :
    fValidate .enforce ["platform-testifysec-fulcio"] relF (.cert relCert) = true ∧
    fValidate .warn ["platform-testifysec-fulcio"] relF (.cert relCert) = true := by decide

/-- self-host-minimal: a tagged self-hosted build is admitted; the same tag on
    a GitHub-hosted runner, or a branch build, is refused. -/
theorem shm_prediction :
    fValidate .enforce ["platform-testifysec-fulcio"] shmF
      (.cert (shmCert "refs/tags/self-host-minimal-v1.0.0" "self-hosted")) = true ∧
    fValidate .enforce ["platform-testifysec-fulcio"] shmF
      (.cert (shmCert "refs/tags/self-host-minimal-v1.0.0" "github-hosted")) = false ∧
    fValidate .enforce ["platform-testifysec-fulcio"] shmF
      (.cert (shmCert "refs/heads/main" "self-hosted")) = false := by decide

end CilockPolicy.Holdout
