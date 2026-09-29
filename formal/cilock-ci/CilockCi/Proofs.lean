import CilockCi.Token
import CilockCi.Plan
import CilockCi.Login
import CilockCi.Automode

/-!
# What the CI decisions guarantee

- `select_sound`: a selected GitLab token is in the environment, was issued by
  this job's GitLab to this job, is not expired, and names exactly the one
  audience it was selected for (the explicitly named variable, when one was).
- `forwarded_aud_exact`: so every token cilock forwards (Fulcio, platform
  login, platform Archivista) was minted for exactly that relying party.
- `keyless_needs_job_token`: `cilock run` signs keyless with a CI identity only
  through GitHub's token endpoint or a selected, live GitLab token for
  `sigstore` issued to this job.
- `gitlab_github_parity`: for the same flags, a GitLab job with a sigstore
  token and a GitHub job that can mint one take the same kind of route, and
  so do the two without one (both refuse before the build).
- `login_only_via_match`: `cilock login` yields a bound session only when the
  platform matched the job's token (GitLab: the token for exactly
  `<platform>/login`).
- `gitlab_login_never_browser`: a GitLab job never falls back to a browser.
-/

namespace CilockCi

/-- A token that may be forwarded to `aud`. -/
def Fit (job : Job) (aud : String) (explicit : Option String) (now : Nat) (env : Env) (t : Token) : Prop :=
  t.claims.aud = [aud] ∧ issuedFor job t.claims = true ∧ live t.claims now = true ∧
  (t.var, Val.jwt t.claims) ∈ env ∧ considered explicit t.var = true

theorem scan_found (job : Job) (aud : String) (explicit : Option String) (now : Nat) :
    ∀ (env : Env) (acc acc' : Acc), scan job aud explicit now env acc = .ok acc' →
      ∀ t ∈ acc'.found, t ∈ acc.found ∨ Fit job aud explicit now env t := by
  intro env
  induction env with
  | nil =>
    intro acc acc' h t ht
    simp [scan] at h
    subst h
    exact Or.inl ht
  | cons hd rest ih =>
    obtain ⟨n, v⟩ := hd
    intro acc acc' h t ht
    have lift : ∀ a : Acc, (t ∈ a.found ∨ Fit job aud explicit now rest t) → t ∈ a.found ∨ Fit job aud explicit now ((n, v) :: rest) t := by
      intro a h'
      rcases h' with h' | ⟨h1, h2, h3, h4, h5⟩
      · exact Or.inl h'
      · exact Or.inr ⟨h1, h2, h3, List.mem_cons_of_mem _ h4, h5⟩
    unfold scan at h
    by_cases hc : considered explicit n = true
    · simp only [hc, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
      cases v with
      | empty => exact lift acc (ih acc acc' h t ht)
      | junk =>
        by_cases hx : explicit.isSome = true
        · simp [hx] at h
        · simp only [hx, Bool.false_eq_true, ↓reduceIte] at h
          exact lift acc (ih acc acc' h t ht)
      | jwt c =>
        by_cases hi : issuedFor job c = true
        · simp only [hi, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
          by_cases ha : exactAud c.aud aud = true
          · simp only [ha, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
            by_cases hl : live c now = true
            · simp only [hl, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
              rcases ih _ acc' h t ht with h' | h'
              · simp only [List.mem_cons] at h'
                rcases h' with h' | h'
                · subst h'
                  refine Or.inr ⟨?_, hi, hl, List.mem_cons_self .., hc⟩
                  simpa [exactAud] using ha
                · exact Or.inl h'
              · exact lift acc (Or.inr h')
            · simp only [hl, Bool.not_false, ↓reduceIte] at h
              exact lift acc (ih _ acc' h t ht)
          · simp only [ha, Bool.not_false, ↓reduceIte] at h
            exact lift acc (ih _ acc' h t ht)
        · by_cases hx : explicit.isSome = true
          · simp [hi, hx] at h
          · simp only [hi, hx, Bool.not_false, Bool.false_eq_true, ↓reduceIte] at h
            exact lift acc (ih acc acc' h t ht)
    · simp only [hc, Bool.not_false, ↓reduceIte] at h
      exact lift acc (ih acc acc' h t ht)

theorem pick_mem (aud : String) : ∀ (t : Token) (ts : List Token), pick aud t ts ∈ t :: ts := by
  intro t ts
  induction ts generalizing t with
  | nil => simp [pick]
  | cons u us ih =>
    simp only [pick]
    split
    · have := ih u
      simp only [List.mem_cons] at this ⊢
      rcases this with h | h
      · exact Or.inr (Or.inl h)
      · exact Or.inr (Or.inr h)
    · have := ih t
      simp only [List.mem_cons] at this ⊢
      rcases this with h | h
      · exact Or.inl h
      · exact Or.inr (Or.inr h)

theorem select_sound (env : Env) (job : Job) (aud : String) (explicit : Option String) (now : Nat) (t : Token)
    (h : selectToken env job aud explicit now = .ok t) : Fit job aud explicit now env t := by
  unfold selectToken at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i acc hs
  split at h
  · rename_i u us hf
    simp only [Except.ok.injEq] at h
    subst h
    have hm := pick_mem aud u us
    rw [← hf] at hm
    rcases scan_found job aud explicit now env {} acc hs _ hm with h' | h'
    · simp at h'
    · exact h'
  · split at h <;> (try split at h) <;> simp at h

/-- Every token cilock forwards names exactly the relying party it goes to. -/
theorem forwarded_aud_exact (env : Env) (job : Job) (aud : String) (explicit : Option String) (now : Nat) (t : Token)
    (h : selectToken env job aud explicit now = .ok t) : t.claims.aud = [aud] :=
  (select_sound env job aud explicit now t h).1

/-- ...and was issued to this job. -/
theorem forwarded_this_job (env : Env) (job : Job) (aud : String) (explicit : Option String) (now : Nat) (t : Token)
    (h : selectToken env job aud explicit now = .ok t) :
    trimIssuer t.claims.iss = trimIssuer job.serverUrl ∧ t.claims.jobId = job.jobId := by
  have := (select_sound env job aud explicit now t h).2.1
  simp only [issuedFor, Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at this
  exact ⟨this.1.2, this.2⟩

/-- An explicitly named variable is the only one ever used. -/
theorem explicit_respected (env : Env) (job : Job) (aud x : String) (now : Nat) (t : Token)
    (h : selectToken env job aud (some x) now = .ok t) : t.var = x := by
  have := (select_sound env job aud (some x) now t h).2.2.2.2
  simpa [considered] using this

/-- `cilock run` signs keyless with a GitLab job token only when that token was
selected for `sigstore`, from this job, live. -/
theorem keyless_needs_job_token (p : Provider) (f : RunFlags) (env : Env) (explicit : Option String) (now : Nat) (t : Token)
    (h : route p f env explicit now = .gitlabToken t) :
    ∃ job, p = .gitlab job ∧ selectToken env job fulcioAud explicit now = .ok t ∧ Fit job fulcioAud explicit now env t := by
  unfold route at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h
  · simp at h
  · rename_i job
    split at h
    · rename_i t' hs
      simp only [Route.gitlabToken.injEq] at h
      subst h
      exact ⟨job, rfl, hs, select_sound _ _ _ _ _ _ hs⟩
    · simp at h
  all_goals simp at h

/-- Every CI-identity keyless route has a job token behind it: GitHub's
endpoint (the job's own) or a selected GitLab token. -/
theorem keyless_job_has_token (p : Provider) (f : RunFlags) (env : Env) (explicit : Option String) (now : Nat)
    (h : (route p f env explicit now).keylessJob = true) :
    p = .github true ∨ ∃ job t, p = .gitlab job ∧ selectToken env job fulcioAud explicit now = .ok t := by
  unfold route at h
  split at h; · simp [Route.keylessJob, Route.kind] at h
  split at h; · simp [Route.keylessJob, Route.kind] at h
  split at h; · simp [Route.keylessJob, Route.kind] at h
  split at h; · simp [Route.keylessJob, Route.kind] at h
  split at h
  · exact Or.inl rfl
  · rename_i job
    split at h
    · rename_i t hs
      exact Or.inr ⟨job, t, rfl, hs⟩
    · simp [Route.keylessJob, Route.kind] at h
  all_goals simp [Route.keylessJob, Route.kind] at h

def okB {ε α : Type} : Except ε α → Bool
  | .ok _ => true
  | .error _ => false

/-- GitHub and GitLab are treated alike: same flags, and the GitLab job has a
sigstore token exactly when the GitHub job can mint one, give the same kind
of route. -/
theorem gitlab_github_parity (f : RunFlags) (envGh envGl : Env) (job : Job) (explicit : Option String) (now : Nat)
    (canMint : Bool) (hEq : canMint = okB (selectToken envGl job fulcioAud explicit now)) :
    (route (.github canMint) f envGh explicit now).kind = (route (.gitlab job) f envGl explicit now).kind := by
  unfold route
  split; · rfl
  split; · rfl
  split; · rfl
  split; · rfl
  cases hs : selectToken envGl job fulcioAud explicit now with
  | ok t => simp [hs, okB] at hEq; subst hEq; simp [hs, Route.kind]
  | error r => simp [hs, okB] at hEq; subst hEq; simp [hs, Route.kind]

/-- The route kind a GitHub or GitLab job takes, as a function of the flags and
ONE bit: whether the job has a CI token for Fulcio. -/
def ciKind (f : RunFlags) (hasToken : Bool) : Kind :=
  if f.platformDisabled then .offline
  else if f.localSigner then .localKey
  else if f.explicitToken then .explicitToken
  else if f.session == .bearer then .sessionExchange
  else if hasToken then .jobToken
  else .refuse

/-- Vendor-blind: for both vendors the route kind is `ciKind` of the flags and
whether a job token exists, and of nothing else about the vendor. (What
"exists" means differs, and is where the vendors differ: GitHub's endpoint,
or a GitLab token `selectToken` accepts.) -/
theorem route_kind_vendor_blind (f : RunFlags) (env : Env) (explicit : Option String) (now : Nat) (job : Job) (canMint : Bool) :
    (route (.github canMint) f env explicit now).kind = ciKind f canMint ∧
    (route (.gitlab job) f env explicit now).kind = ciKind f (okB (selectToken env job fulcioAud explicit now)) := by
  constructor
  · unfold route ciKind
    split; · rfl
    split; · rfl
    split; · rfl
    split; · rfl
    cases canMint <;> rfl
  · unfold route ciKind
    split; · rfl
    split; · rfl
    split; · rfl
    split; · rfl
    cases hs : selectToken env job fulcioAud explicit now <;> simp [hs, okB, Route.kind]

/-- The Archivista upload token, when it is a GitLab one, names exactly the
Archivista audience. -/
theorem upload_aud_exact (p : Provider) (f : RunFlags) (env : Env) (archAud : String) (now : Nat) (t : Token)
    (h : upload p f env archAud now = .gitlabToken t) : t.claims.aud = [archAud] := by
  unfold upload at h
  split at h; · simp at h
  split at h; · simp at h
  split at h
  · simp at h
  · split at h
    · rename_i t' hs
      simp only [Upload.gitlabToken.injEq] at h
      subst h
      exact forwarded_aud_exact _ _ _ _ _ _ hs
    · simp at h
  all_goals simp at h

/-- A session comes only from a platform credential match. -/
theorem login_only_via_match (p : Provider) (f : LoginFlags) (env : Env) (now : Nat)
    (cm : Token → Answer) (ga : Answer) (b : Binding)
    (h : login p f env now cm ga = .session b) :
    (∃ job t, p = .gitlab job ∧ tier p f env now = .gitlabWorkflow t ∧ cm t = .matched b ∧
      t.claims.aud = [loginAud f.url] ∧ issuedFor job t.claims = true) ∨
    (tier p f env now = .githubWorkflow ∧ ga = .matched b) := by
  unfold login at h
  split at h
  · rename_i t ht
    left
    have ht' := ht
    unfold tier at ht
    split at ht; · simp at ht
    split at ht; · split at ht <;> simp at ht
    split at ht
    · split at ht <;> simp at ht
    · rename_i job
      split at ht
      · rename_i t' hs
        simp only [Tier.gitlabWorkflow.injEq] at ht
        subst ht
        have hfit := select_sound _ _ _ _ _ _ hs
        refine ⟨job, t', rfl, ht', ?_, hfit.1, hfit.2.1⟩
        cases hc : cm t' <;> simp [hc, answerOut] at h
        exact congrArg Answer.matched h
      · simp at ht
    · split at ht <;> (try split at ht) <;> simp at ht
  · rename_i ht
    right
    refine ⟨ht, ?_⟩
    cases ga <;> simp [answerOut] at h
    exact congrArg Answer.matched h
  · simp at h
  · simp at h

/-- A GitLab job never falls back to the browser flow. -/
theorem gitlab_login_never_browser (job : Job) (f : LoginFlags) (env : Env) (now : Nat)
    (hi : f.interactive = false) : tier (.gitlab job) f env now ≠ .browser := by
  unfold tier
  split
  · simp
  · simp only [hi, Bool.false_eq_true, ↓reduceIte]
    split <;> simp

/-- In CI, login never starts the browser or device flow, whatever the flags
and provider: it signs in, or refuses before anything interactive. -/
theorem ci_login_never_browser (p : Provider) (f : LoginFlags) (env : Env) (now : Nat)
    (hci : f.ci = true) : tier p f env now ≠ .browser := by
  unfold tier
  split
  · simp
  · split
    · simp_all
    · split
      · split <;> simp
      · split <;> simp
      · split
        · simp
        · simp_all

/-- A detected provider is CI, whatever `CI` says. -/
theorem provider_is_ci (ciVar : Bool) (p : Provider) (hp : p ≠ .none) : inCI ciVar p = true := by
  simp [inCI, hp]

/-- The login token sent for a GitLab job is minted for exactly this
platform's login audience, so a `--platform-url` the pipeline did not name
receives nothing. -/
theorem gitlab_login_aud (job : Job) (f : LoginFlags) (env : Env) (now : Nat) (t : Token)
    (h : tier (.gitlab job) f env now = .gitlabWorkflow t) : t.claims.aud = [loginAud f.url] := by
  unfold tier at h
  split at h; · simp at h
  split at h; · split at h <;> simp at h
  simp only at h
  split at h
  · rename_i t' hs
    simp only [Tier.gitlabWorkflow.injEq] at h
    subst h
    exact forwarded_aud_exact _ _ _ _ _ _ hs
  · simp at h

/-- Automode attaches the gitlab context attestor in a GitLab job exactly
where it attaches the github one in a GitHub job. -/
theorem automode_ci_parity (base : StrEnv)
    (hgh : lookup base "GITHUB_ACTIONS" ≠ some "true") (hgl : lookup base "GITLAB_CI" ≠ some "true") :
    ciContext (("GITHUB_ACTIONS", "true") :: base) = ["github"] ∧
    ciContext (("GITLAB_CI", "true") :: base) = ["gitlab"] := by
  have l1 : lookup (("GITHUB_ACTIONS", "true") :: base) "GITLAB_CI" = lookup base "GITLAB_CI" := by
    simp [lookup, List.find?]
  have l2 : lookup (("GITLAB_CI", "true") :: base) "GITHUB_ACTIONS" = lookup base "GITHUB_ACTIONS" := by
    simp [lookup, List.find?]
  have gh : isTrue (("GITHUB_ACTIONS", "true") :: base) "GITHUB_ACTIONS" = true := by simp [isTrue, lookup, List.find?]
  have gl : isTrue (("GITLAB_CI", "true") :: base) "GITLAB_CI" = true := by simp [isTrue, lookup, List.find?]
  have ngl : isTrue (("GITHUB_ACTIONS", "true") :: base) "GITLAB_CI" = false := by
    simp only [isTrue, l1]; simpa using hgl
  have ngh : isTrue (("GITLAB_CI", "true") :: base) "GITHUB_ACTIONS" = false := by
    simp only [isTrue, l2]; simpa using hgh
  exact ⟨by simp [ciContext, gh, ngl], by simp [ciContext, gl, ngh]⟩

end CilockCi
