import CilockCi.Plan

/-!
# The trusted-identity tier: `cilock trust` once, then the job's own identity

Cole, 2026-09-29: "we shouldnt need a token we should be able to use cilock
trust". A tenant admin registers the CI identity once (`cilock trust`); after
that a CI job with no `cilock login` signs keyless and uploads with its own
job token, and no secret is stored in the CI system.

`trusted` is the model of what `ResolvePlatformDefaults` and
`EnforceEvidenceStorage` decide for such a run
(cilock/internal/options/run.go, `resolvePlatformIdentity`'s ambient branch,
`holdAmbientIdentityToStore`, `enforceEvidenceStorage`; compared in
cilock/internal/options/trusted_differential_test.go).

The run is HELD when its upload token reaches the platform's own Archivista:
then its evidence is stored, or the run is refused before the command runs.
A run that signs and stores nothing while exiting 0 is the fail-open this tier
closes (a GitHub job on main did exactly that until #10621).
-/

namespace CilockCi

/-- What the operator set about storing evidence. -/
structure StoreFlags where
  /-- `--enable-archivista` given on the command line -/
  explicit : Bool
  /-- its value when given -/
  value : Bool
  /-- the Archivista the run uploads to is the platform's own
  (`--archivista-server` unset or same origin as `--platform-url`) -/
  sameOrigin : Bool
deriving Repr, DecidableEq

inductive Gate where
  | proceed
  /-- refused before the command runs: it would sign as a principal and store
  nothing, and the operator did not ask for that -/
  | refuse
deriving Repr, DecidableEq

structure StoreDecision where
  /-- a workflow-identity principal the evidence gate holds -/
  held : Bool
  /-- the upload is on -/
  enabled : Bool
  gate : Gate
deriving Repr, DecidableEq

/-- The upload route authenticates with the job's own identity. -/
def jobUploads : Upload → Bool
  | .githubMint => true
  | .gitlabToken _ => true
  | _ => false

/-- The trusted-identity tier: no stored session, a platform, the job's own
upload token, and the platform's own Archivista. -/
def trusted (p : Provider) (f : RunFlags) (s : StoreFlags) (env : Env) (aud : String) (now : Nat) :
    StoreDecision :=
  let held := f.session == .none && !f.platformDisabled && s.sameOrigin && jobUploads (upload p f env aud now)
  let enabled := if s.explicit then s.value else held
  { held := held, enabled := enabled,
    gate := if held && !enabled && !s.explicit then .refuse else .proceed }

/-- A held run uploads unless the operator explicitly said not to: it never
signs, stores nothing and exits 0 on its own. -/
theorem held_uploads_unless_opted_out (p : Provider) (f : RunFlags) (s : StoreFlags) (env : Env) (aud : String)
    (now : Nat) (h : (trusted p f s env aud now).held = true) (hx : s.explicit = false) :
    (trusted p f s env aud now).enabled = true := by
  simp only [trusted] at h ⊢
  simp [hx, h]

/-- A held run with the upload off is one the operator explicitly opted out
of: storing nothing is never the default. -/
theorem held_never_silent (p : Provider) (f : RunFlags) (s : StoreFlags) (env : Env) (aud : String) (now : Nat)
    (h : (trusted p f s env aud now).held = true) (hoff : (trusted p f s env aud now).enabled = false) :
    s.explicit = true := by
  cases hx : s.explicit
  · have := held_uploads_unless_opted_out p f s env aud now h hx
    rw [this] at hoff
    exact absurd hoff (by decide)
  · rfl

/-- The gate refuses exactly a principal that would store nothing without
having asked to. -/
theorem gate_refuses_silent_loss (p : Provider) (f : RunFlags) (s : StoreFlags) (env : Env) (aud : String)
    (now : Nat) :
    (trusted p f s env aud now).gate = .refuse ↔
      ((trusted p f s env aud now).held = true ∧ (trusted p f s env aud now).enabled = false ∧ s.explicit = false) := by
  simp only [trusted]
  split <;> simp_all

/-- A foreign Archivista is never where the job's identity is held: the job's
token belongs to the platform, so the run is not bound to it. -/
theorem foreign_archivista_not_held (p : Provider) (f : RunFlags) (s : StoreFlags) (env : Env) (aud : String)
    (now : Nat) (hs : s.sameOrigin = false) : (trusted p f s env aud now).held = false := by
  simp [trusted, hs]

/-- A GitLab job is held only with a token minted for exactly the platform's
Archivista audience (the one `cilock trust` registers), never with its
sigstore token: the sigstore audience is not an upload credential. -/
theorem gitlab_held_needs_archivista_token (job : Job) (f : RunFlags) (s : StoreFlags) (env : Env) (aud : String)
    (now : Nat) (h : (trusted (.gitlab job) f s env aud now).held = true) :
    ∃ t, selectToken env job aud none now = .ok t := by
  simp only [trusted, Bool.and_eq_true] at h
  obtain ⟨_, hj⟩ := h
  cases hs : selectToken env job aud none now with
  | ok t => exact ⟨t, rfl⟩
  | error e =>
    exfalso
    unfold upload at hj
    split at hj
    · simp [jobUploads] at hj
    · split at hj
      · simp [jobUploads] at hj
      · simp [hs, jobUploads] at hj

end CilockCi
