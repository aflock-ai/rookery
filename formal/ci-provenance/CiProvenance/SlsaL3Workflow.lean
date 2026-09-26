/-!
# SLSA Build L3 through an isolated provenance workflow

The design (approved; designed, not implemented):

* the build job runs CI/lock inline (SLSA L2, ALPS 1 content) and signs a
  collection whose subjects are the product digests;
* a separate job `uses:` the reusable workflow
  `aflock-ai/cilock-action/.github/workflows/provenance.yml@<sha>`, runs CI/lock
  as policy step `provenance`, and signs a SLSA v1 statement whose builder,
  repository, commit and run come from its own Fulcio certificate;
* `cilock verify --slsa-level 3` (`l3Accept` below) accepts a statement only
  from a signer whose Fulcio extensions name the pinned workflow, and only for
  subjects some build collection of the SAME run carries.

The adversary controls every step and every input of the caller workflow, can
trigger it with any event (fork pull requests included), and can move tags in
the builder repository. GitHub stamps the OIDC claims; Fulcio copies them into
certificate extensions (monorepo, outside this tree: see
subtrees/fulcio/pkg/identity/github/principal.go:197-223, BuildSignerURI =
job_workflow_ref, BuildSignerDigest = job_workflow_sha, SourceRepositoryDigest
= sha, RunInvocationURI = run_id and attempt, BuildTrigger = event_name).

What exists in code today: the SLSA attestor emits a constant builder id, and
the wrong predicate type (#9827). The id names a CI vendor only for a verified
GitHub Actions or gitlab.com token, the issuers a Fulcio CA maps; every other
CI gets the default id (#9839):
-- cite: plugins/attestors/slsa/slsa.go:48-50 sha256:26f324cb42fd3b41502e639a01493ee6ee7adf65058745efc695077c1b0190f5
-- cite: plugins/attestors/slsa/slsa.go:62-88 sha256:364e234bd882b351bf3101caf89f2baf07363100452ef0bac8d8789d16ee8dba
Policy functionaries can already constrain Fulcio extensions; an empty field
allows every value, and a field containing a glob metacharacter is matched as
a glob:
-- cite: attestation/policy/constraints.go:109-116 sha256:208a832ff24c03297e7d791ec31ee1f2efa73d9ea1d6f0c8ce23af7f9878beae
-- cite: attestation/policy/constraints.go:346-353 sha256:9dbd6b15aae6492a30ef0b4324fa51cfdfe95a344410a4b9634430422e4be58f
`cilock verify --slsa-level` does not exist, so `l3Accept` is the reference.
-/

namespace CiProvenance.L3

inductive Event where
  | push | release | workflowDispatch | pullRequest | pullRequestTarget | workflowRun
  deriving DecidableEq, Repr

/-- Events only a repository writer can cause. -/
def Event.allowed : Event → Bool
  | .push => true
  | .release => true
  | .workflowDispatch => true
  | _ => false

/-- The claims GitHub stamps on one job's OIDC token. -/
structure Claims where
  /-- `job_workflow_ref`, path part: the workflow file whose steps this job runs. -/
  workflowPath : String
  /-- `job_workflow_ref`, ref part, as the caller wrote it (`@v1`, `@<sha>`). -/
  workflowRef  : String
  /-- `job_workflow_sha`: the commit that ref resolved to for this run. -/
  workflowSha  : String
  repository   : String
  sha          : String
  runId        : Nat
  event        : Event
  /-- `runner_environment == github-hosted`. -/
  hosted       : Bool
  deriving DecidableEq, Repr

/-- The Fulcio extensions the verifier reads. -/
structure Ext where
  signerPath    : String
  signerRef     : String
  signerDigest  : String
  sourceRepo    : String
  sourceDigest  : String
  runInvocation : Nat
  trigger       : Event
  hosted        : Bool
  deriving DecidableEq, Repr

/-- Fulcio's GitHub principal: extensions are the claims, copied. -/
def deriveExt (c : Claims) : Ext :=
  ⟨c.workflowPath, c.workflowRef, c.workflowSha, c.repository, c.sha, c.runId, c.event, c.hosted⟩

inductive Root where
  /-- The platform's Fulcio: the default signer. -/
  | platform
  /-- Public Sigstore (Fulcio + its root): the optional mode. -/
  | publicSigstore
  deriving DecidableEq, Repr

structure Cert where
  root : Root
  ext  : Ext
  deriving DecidableEq, Repr

structure Job where
  claims : Claims
  /-- Someone without write access to the repository caused this run
  (a fork pull request, `pull_request_target`, a `workflow_run` off one). -/
  outsiderTriggered : Bool
  deriving DecidableEq, Repr

/-- The world: every job GitHub ran, and which CA roots issue certificates that
match no job. -/
structure World where
  jobs        : List Job
  compromised : Root → Bool

/-- The SLSA v1 fields the theorem is about. `builderId` is (path, ref). -/
structure Statement where
  builderId : String × String
  repo      : String
  commit    : String
  runId     : Nat
  subjects  : List String
  deriving DecidableEq, Repr

/-- A build-step collection: tenant-asserted, linked by subject digest. -/
structure Collection where
  cert     : Cert
  subjects : List String
  deriving DecidableEq, Repr

structure Evidence where
  signer : Cert
  stmt   : Statement
  builds : List Collection
  deriving DecidableEq, Repr

/-- The built-in `--slsa-level 3` policy. -/
structure Policy where
  roots : List Root
  /-- `aflock-ai/cilock-action/.github/workflows/provenance.yml` -/
  path  : String
  /-- The pinned commit of that workflow. -/
  sha   : String
  deriving DecidableEq, Repr

/-! ## The verifier -/

/-- Step `provenance`'s functionary: the signer is the pinned workflow, pinned
by commit and not by tag, on a GitHub-hosted runner, for a writer-only event. -/
def signerOk (pol : Policy) (x : Ext) : Bool :=
  x.signerPath == pol.path && x.signerDigest == pol.sha && x.signerRef == pol.sha &&
    x.hosted && x.trigger.allowed

/-- A subject is linked when a build collection signed under a trusted root,
for the same repository, commit and run, carries it. -/
def linked (pol : Policy) (e : Evidence) (s : String) : Bool :=
  e.builds.any fun b =>
    pol.roots.contains b.cert.root && b.cert.ext.runInvocation == e.signer.ext.runInvocation &&
      b.cert.ext.sourceRepo == e.signer.ext.sourceRepo &&
      b.cert.ext.sourceDigest == e.signer.ext.sourceDigest && b.subjects.contains s

/-- `cilock verify --slsa-level 3`. Every statement field is compared with
the signer's certificate, never taken from the statement alone. -/
def l3Accept (pol : Policy) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && signerOk pol e.signer.ext &&
    e.stmt.builderId == (e.signer.ext.signerPath, e.signer.ext.signerRef) &&
    e.stmt.repo == e.signer.ext.sourceRepo && e.stmt.commit == e.signer.ext.sourceDigest &&
    e.stmt.runId == e.signer.ext.runInvocation &&
    !e.stmt.subjects.isEmpty && e.stmt.subjects.all (linked pol e)

/-! ## What the adversary can produce

A certificate under root `r` exists only for a job GitHub ran, unless `r`'s
CA is compromised. Everything else in the evidence (statement bytes, build
collections, which certificates to present) is the adversary's choice: this
covers a provenance job that leaks its token or signs caller inputs. -/

def Issued (w : World) (c : Cert) : Prop :=
  w.compromised c.root = true ∨ ∃ j ∈ w.jobs, c.ext = deriveExt j.claims

def Producible (w : World) (e : Evidence) : Prop :=
  Issued w e.signer ∧ ∀ b ∈ e.builds, Issued w b.cert

/-- A job the adversary controls: anything other than the pinned workflow
commit on a GitHub-hosted runner. A moved tag and a self-hosted runner both
land here. -/
def controlled (pol : Policy) (j : Job) : Bool :=
  !(j.claims.workflowPath == pol.path && j.claims.workflowSha == pol.sha && j.claims.hosted)

/-! ## Assumptions, named -/

/-- The CA of every root the policy trusts issues only for real jobs. -/
def RootsHonest (w : World) (pol : Policy) : Prop :=
  ∀ r ∈ pol.roots, w.compromised r = false

/-- GitHub's event semantics: a writer-only event is never outsider-triggered. -/
def GithubEvents (w : World) : Prop :=
  ∀ j ∈ w.jobs, j.claims.event.allowed = true → j.outsiderTriggered = false

/-! ## The main theorem -/

theorem issued_of_trusted (w : World) (pol : Policy) (c : Cert) (hr : RootsHonest w pol)
    (hc : pol.roots.contains c.root = true) (hi : Issued w c) : ∃ j ∈ w.jobs, c.ext = deriveExt j.claims := by
  rcases hi with h | h
  · have := hr c.root (by simpa using hc)
    rw [this] at h
    cases h
  · exact h

/-- **L3 soundness.** If `--slsa-level 3` accepts, then (with the trusted roots
honest and GitHub's event semantics) the signer is a job of the pinned
workflow commit on a hosted runner, triggered by a writer; builder.id,
repository, commit and run are that job's platform-attested claims; and every
subject is carried by a build collection signed by a job of the SAME run of the
same repository and commit. -/
theorem l3_sound (w : World) (pol : Policy) (e : Evidence)
    (hr : RootsHonest w pol) (hg : GithubEvents w) (hp : Producible w e)
    (ha : l3Accept pol e = true) :
    ∃ j ∈ w.jobs, e.signer.ext = deriveExt j.claims ∧ controlled pol j = false ∧
      j.outsiderTriggered = false ∧
      e.stmt.builderId = (pol.path, pol.sha) ∧ e.stmt.repo = j.claims.repository ∧
      e.stmt.commit = j.claims.sha ∧ e.stmt.runId = j.claims.runId ∧
      ∀ s ∈ e.stmt.subjects, ∃ b ∈ e.builds, s ∈ b.subjects ∧
        ∃ jb ∈ w.jobs, b.cert.ext = deriveExt jb.claims ∧ jb.claims.runId = j.claims.runId ∧
          jb.claims.repository = j.claims.repository ∧ jb.claims.sha = j.claims.sha := by
  simp only [l3Accept, signerOk, Bool.and_eq_true] at ha
  obtain ⟨⟨⟨⟨⟨⟨⟨hroot, ⟨⟨⟨⟨hpath, hdig⟩, href⟩, hhost⟩, htrig⟩⟩, hbid⟩, hrepo⟩, hcommit⟩, hrun⟩, _⟩, hsubs⟩ := ha
  replace hpath := beq_iff_eq.mp hpath
  replace hdig := beq_iff_eq.mp hdig
  replace href := beq_iff_eq.mp href
  replace hbid := beq_iff_eq.mp hbid
  replace hrepo := beq_iff_eq.mp hrepo
  replace hcommit := beq_iff_eq.mp hcommit
  replace hrun := beq_iff_eq.mp hrun
  obtain ⟨j, hj, hext⟩ := issued_of_trusted w pol e.signer hr hroot hp.1
  refine ⟨j, hj, hext, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [controlled, hext, deriveExt] at hpath hdig hhost ⊢
    exact ⟨⟨hpath, hdig⟩, hhost⟩
  · apply hg j hj
    simpa [hext, deriveExt] using htrig
  · rw [hbid, hpath, href]
  · rw [hrepo, hext]; rfl
  · rw [hcommit, hext]; rfl
  · rw [hrun, hext]; rfl
  · intro s hs
    have hl := (List.all_eq_true.mp hsubs) s hs
    simp only [linked, List.any_eq_true, Bool.and_eq_true] at hl
    obtain ⟨b, hb, ⟨⟨⟨⟨hbroot, hbrun⟩, hbrepo⟩, hbsha⟩, hbs⟩⟩ := hl
    replace hbrun := beq_iff_eq.mp hbrun
    replace hbrepo := beq_iff_eq.mp hbrepo
    replace hbsha := beq_iff_eq.mp hbsha
    obtain ⟨jb, hjb, hbext⟩ := issued_of_trusted w pol b.cert hr hbroot (hp.2 b hb)
    refine ⟨b, hb, by simpa using hbs, jb, hjb, hbext, ?_, ?_, ?_⟩
    · have := hbrun; rw [hbext, hext] at this; exact this
    · have := hbrepo; rw [hbext, hext] at this; exact this
    · have := hbsha; rw [hbext, hext] at this; exact this

/-- Corollary: no job the adversary controls signed accepted L3 provenance,
and no subject came from another run. -/
theorem l3_signer_not_controlled (w : World) (pol : Policy) (e : Evidence)
    (hr : RootsHonest w pol) (hg : GithubEvents w) (hp : Producible w e)
    (ha : l3Accept pol e = true) (j : Job) (_hj : j ∈ w.jobs) (hext : e.signer.ext = deriveExt j.claims) :
    controlled pol j = false := by
  obtain ⟨j', _, hext', hc, _⟩ := l3_sound w pol e hr hg hp ha
  have : deriveExt j.claims = deriveExt j'.claims := hext ▸ hext'
  simp only [controlled] at hc ⊢
  simp only [deriveExt, Ext.mk.injEq] at this
  rw [this.1, this.2.2.1, this.2.2.2.2.2.2.2]
  exact hc

/-! ## Both trust roots -/

/-- Platform Fulcio, the default. Assumptions: the platform CA issues only for
real jobs, maps claims with Fulcio's GitHub principal (`deriveExt`), and
GitHub's event semantics hold. -/
theorem l3_sound_platform (w : World) (path sha : String) (e : Evidence)
    (hca : w.compromised .platform = false) (hg : GithubEvents w) (hp : Producible w e)
    (ha : l3Accept ⟨[.platform], path, sha⟩ e = true) :
    ∃ j ∈ w.jobs, e.signer.ext = deriveExt j.claims ∧ controlled ⟨[.platform], path, sha⟩ j = false ∧
      e.stmt.builderId = (path, sha) ∧ e.stmt.commit = j.claims.sha := by
  have hr : RootsHonest w ⟨[.platform], path, sha⟩ := by
    intro r hr; simp at hr; subst hr; exact hca
  obtain ⟨j, hj, hx, hc, _, hb, _, hcm, _⟩ := l3_sound w _ e hr hg hp ha
  exact ⟨j, hj, hx, hc, hb, hcm⟩

/-- Public Sigstore, the option. Same shape, public CA assumed honest instead. -/
theorem l3_sound_public (w : World) (path sha : String) (e : Evidence)
    (hca : w.compromised .publicSigstore = false) (hg : GithubEvents w) (hp : Producible w e)
    (ha : l3Accept ⟨[.publicSigstore], path, sha⟩ e = true) :
    ∃ j ∈ w.jobs, e.signer.ext = deriveExt j.claims ∧ controlled ⟨[.publicSigstore], path, sha⟩ j = false ∧
      e.stmt.builderId = (path, sha) ∧ e.stmt.commit = j.claims.sha := by
  have hr : RootsHonest w ⟨[.publicSigstore], path, sha⟩ := by
    intro r hr; simp at hr; subst hr; exact hca
  obtain ⟨j, hj, hx, hc, _, hb, _, hcm, _⟩ := l3_sound w _ e hr hg hp ha
  exact ⟨j, hj, hx, hc, hb, hcm⟩

/-! ## Counterexamples: weaker designs, each refuted

A shared scene. Repository `acme/app`, commit `c1`, run 1. The pinned builder
commit is `good`. -/

def P : String := "aflock-ai/cilock-action/.github/workflows/provenance.yml"
def pol : Policy := ⟨[.platform], P, "good"⟩

/-- The caller's build job: attacker-controlled steps. -/
def buildJob : Job :=
  ⟨⟨"acme/app/.github/workflows/release.yml", "refs/heads/main", "c1", "acme/app", "c1", 1, .push, true⟩, false⟩

/-- The honest provenance job, pinned by commit. -/
def provJob : Job := ⟨⟨P, "good", "good", "acme/app", "c1", 1, .push, true⟩, false⟩

def certOf (j : Job) : Cert := ⟨.platform, deriveExt j.claims⟩

def honestWorld (extra : List Job) : World := ⟨[buildJob, provJob] ++ extra, fun _ => false⟩

/-- The accepted, honest case, as a sanity check that `l3Accept` is satisfiable. -/
def honestEvidence : Evidence :=
  ⟨certOf provJob, ⟨(P, "good"), "acme/app", "c1", 1, ["sha256:app"]⟩, [⟨certOf buildJob, ["sha256:app"]⟩]⟩

theorem honest_accepted : l3Accept pol honestEvidence = true := by decide

/-- 1. Tag-pinned: the verifier pins `@v1` and never the digest. The tag moves
to `evil`; the job running `evil` signs whatever it likes. -/
def l3AcceptTagPinned (pol : Policy) (tag : String) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && e.signer.ext.signerPath == pol.path &&
    e.signer.ext.signerRef == tag && e.signer.ext.hosted && e.signer.ext.trigger.allowed &&
    e.stmt.builderId == (e.signer.ext.signerPath, e.signer.ext.signerRef) &&
    e.stmt.commit == e.signer.ext.sourceDigest

def swappedJob : Job := ⟨⟨P, "v1", "evil", "acme/app", "c1", 1, .push, true⟩, false⟩

theorem tag_pinned_swapped :
    l3AcceptTagPinned pol "v1" ⟨certOf swappedJob, ⟨(P, "v1"), "acme/app", "c1", 1, ["sha256:backdoor"]⟩, []⟩ = true ∧
      controlled pol swappedJob = true ∧ l3Accept pol ⟨certOf swappedJob, ⟨(P, "v1"), "acme/app", "c1", 1, ["sha256:backdoor"]⟩, []⟩ = false := by
  decide

/-- 2. Caller inputs flow into builder/source fields, and the verifier trusts
the statement: the honest pinned job signs the commit the caller passed in. -/
def l3AcceptTrustingStatement (pol : Policy) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && signerOk pol e.signer.ext && e.stmt.builderId == (pol.path, pol.sha) &&
    e.stmt.subjects.all (linked pol e)

def inputsEvidence : Evidence :=
  ⟨certOf provJob, ⟨(P, "good"), "acme/app", "c-release-v9", 1, ["sha256:app"]⟩, [⟨certOf buildJob, ["sha256:app"]⟩]⟩

theorem caller_inputs_into_fields :
    l3AcceptTrustingStatement pol inputsEvidence = true ∧ inputsEvidence.stmt.commit ≠ provJob.claims.sha ∧
      l3Accept pol inputsEvidence = false := by
  decide

/-- 3. Outputs of a different run are mixed in: the verifier links subjects by
digest but not by run. -/
def linkedAnyRun (pol : Policy) (e : Evidence) (s : String) : Bool :=
  e.builds.any fun b => pol.roots.contains b.cert.root && b.subjects.contains s

def l3AcceptAnyRun (pol : Policy) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && signerOk pol e.signer.ext &&
    e.stmt.builderId == (e.signer.ext.signerPath, e.signer.ext.signerRef) &&
    e.stmt.commit == e.signer.ext.sourceDigest && e.stmt.subjects.all (linkedAnyRun pol e)

/-- Run 2 of another repository built something else. -/
def otherRunBuild : Job :=
  ⟨⟨"mallory/tool/.github/workflows/ci.yml", "refs/heads/main", "m9", "mallory/tool", "m9", 2, .push, true⟩, false⟩

def mixedEvidence : Evidence :=
  ⟨certOf provJob, ⟨(P, "good"), "acme/app", "c1", 1, ["sha256:mallory"]⟩, [⟨certOf otherRunBuild, ["sha256:mallory"]⟩]⟩

theorem other_run_outputs_mixed_in :
    l3AcceptAnyRun pol mixedEvidence = true ∧ l3Accept pol mixedEvidence = false := by
  decide

/-- 4. `pull_request_target` (or a fork run): the verifier does not check the
trigger. An outsider causes a run whose provenance names the base commit. -/
def l3AcceptAnyTrigger (pol : Policy) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && e.signer.ext.signerPath == pol.path &&
    e.signer.ext.signerDigest == pol.sha && e.signer.ext.signerRef == pol.sha && e.signer.ext.hosted &&
    e.stmt.builderId == (e.signer.ext.signerPath, e.signer.ext.signerRef) &&
    e.stmt.commit == e.signer.ext.sourceDigest && e.stmt.subjects.all (linked pol e)

def prtBuild : Job :=
  ⟨⟨"acme/app/.github/workflows/release.yml", "refs/heads/main", "c1", "acme/app", "c1", 3, .pullRequestTarget, true⟩, true⟩
def prtProv : Job := ⟨⟨P, "good", "good", "acme/app", "c1", 3, .pullRequestTarget, true⟩, true⟩
def prtEvidence : Evidence :=
  ⟨certOf prtProv, ⟨(P, "good"), "acme/app", "c1", 3, ["sha256:fork"]⟩, [⟨certOf prtBuild, ["sha256:fork"]⟩]⟩

theorem pull_request_target_accepted :
    l3AcceptAnyTrigger pol prtEvidence = true ∧ prtProv.outsiderTriggered = true ∧ l3Accept pol prtEvidence = false := by
  decide

/-- 5. The verifier accepts the inline (L2) provenance as L3: a SLSA statement
from a hosted runner under a trusted root, whoever signed it. -/
def l3AcceptInline (pol : Policy) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && e.signer.ext.hosted && e.signer.ext.trigger.allowed &&
    e.stmt.commit == e.signer.ext.sourceDigest

def inlineEvidence : Evidence :=
  ⟨certOf buildJob, ⟨("https://aflock.ai/attestation-github-action-builder", "v0.1"), "acme/app", "c1", 1, ["sha256:anything"]⟩, []⟩

theorem inline_l2_accepted_as_l3 :
    l3AcceptInline pol inlineEvidence = true ∧ controlled pol buildJob = true ∧ l3Accept pol inlineEvidence = false := by
  decide

/-- 6. builder.id compared without the certificate extension: the caller's
own build step writes the pinned builder id into a statement it signs. -/
def l3AcceptBuilderIdOnly (pol : Policy) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && e.stmt.builderId == (pol.path, pol.sha) &&
    e.stmt.commit == e.signer.ext.sourceDigest

def spoofEvidence : Evidence :=
  ⟨certOf buildJob, ⟨(P, "good"), "acme/app", "c1", 1, ["sha256:anything"]⟩, []⟩

theorem builder_id_without_extension :
    l3AcceptBuilderIdOnly pol spoofEvidence = true ∧ controlled pol buildJob = true ∧ l3Accept pol spoofEvidence = false := by
  decide

/-- 7. The runner is not checked: the pinned workflow commit runs on a
self-hosted runner the caller chose, which reads the job's token. -/
def l3AcceptAnyRunner (pol : Policy) (e : Evidence) : Bool :=
  pol.roots.contains e.signer.root && e.signer.ext.signerPath == pol.path &&
    e.signer.ext.signerDigest == pol.sha && e.signer.ext.signerRef == pol.sha &&
    e.signer.ext.trigger.allowed && e.stmt.builderId == (e.signer.ext.signerPath, e.signer.ext.signerRef) &&
    e.stmt.commit == e.signer.ext.sourceDigest

def selfHostedProv : Job := ⟨⟨P, "good", "good", "acme/app", "c1", 1, .push, false⟩, false⟩

theorem self_hosted_runner_accepted :
    l3AcceptAnyRunner pol ⟨certOf selfHostedProv, ⟨(P, "good"), "acme/app", "c1", 1, ["sha256:x"]⟩, []⟩ = true ∧
      controlled pol selfHostedProv = true := by
  decide

/-- 8. Trusting both roots needs both honest: with the public root trusted and
its CA compromised, a certificate for no job at all is accepted. -/
def bothRoots : Policy := ⟨[.platform, .publicSigstore], P, "good"⟩
def phantom : Cert := ⟨.publicSigstore, deriveExt provJob.claims⟩
def phantomEvidence : Evidence :=
  ⟨phantom, ⟨(P, "good"), "acme/app", "c1", 1, ["sha256:x"]⟩, [⟨⟨.publicSigstore, deriveExt buildJob.claims⟩, ["sha256:x"]⟩]⟩

theorem both_roots_need_both :
    let w : World := ⟨[], fun r => r == .publicSigstore⟩
    l3Accept bothRoots phantomEvidence = true ∧ Producible w phantomEvidence ∧ w.jobs = [] := by
  refine ⟨by decide, ⟨Or.inl rfl, ?_⟩, rfl⟩
  intro b hb
  simp [phantomEvidence] at hb
  subst hb
  exact Or.inl rfl

/-- The honest scene is producible: the theorems above are not vacuous. -/
theorem honest_world_producible : Producible (honestWorld []) honestEvidence := by
  refine ⟨Or.inr ⟨provJob, by simp [honestWorld], rfl⟩, ?_⟩
  intro b hb
  simp [honestEvidence] at hb
  subst hb
  exact Or.inr ⟨buildJob, by simp [honestWorld], rfl⟩

end CiProvenance.L3
