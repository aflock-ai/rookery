import CiProvenance.Alps

/-!
# ALPS guarantees, level by level

Each theorem's hypotheses name exactly what is trusted. Each "counterexample"
theorem shows a hypothesis is load-bearing: drop it and a verifier derives the
level while the guarantee is false.
-/

namespace CiProvenance

/-! ## The verifier, as Boolean conditions -/

theorem deriveAlps_l0 (e : Evidence) : (deriveAlps e).atLeast .l0 = e.signed := by
  obtain ⟨s, i, ts, bc, bo, iso, a, x, p⟩ := e
  cases s <;> cases i <;> cases ts <;> cases bo <;> cases iso <;> rfl

theorem deriveAlps_l1 (e : Evidence) :
    (deriveAlps e).atLeast .l1 = (e.signed && e.issued && e.timestamped) := by
  obtain ⟨s, i, ts, bc, bo, iso, a, x, p⟩ := e
  cases s <;> cases i <;> cases ts <;> cases bo <;> cases iso <;> rfl

theorem deriveAlps_l2 (e : Evidence) :
    (deriveAlps e).atLeast .l2 = (e.signed && e.issued && e.timestamped && e.boundaryByObserver) := by
  obtain ⟨s, i, ts, bc, bo, iso, a, x, p⟩ := e
  cases s <;> cases i <;> cases ts <;> cases bo <;> cases iso <;> rfl

theorem deriveAlps_l3 (e : Evidence) :
    (deriveAlps e = .l3) =
      (e.signed = true ∧ e.issued = true ∧ e.timestamped = true ∧ e.boundaryByObserver = true ∧
        e.isolated = true) := by
  obtain ⟨s, i, ts, bc, bo, iso, a, x, p⟩ := e
  cases s <;> cases i <;> cases ts <;> cases bo <;> cases iso <;> simp [deriveAlps]

/-- Withholding: any party on the path can drop the envelope, and the result
is Unknown, never a level. -/
theorem withheld_is_unknown (e : Evidence) : deriveAlps { e with signed := false } = .unknown := rfl

/-- No level reads attribution. The verifier's answer is the same whatever the
harness says about the model mix or the invoker: no ALPS level certifies it. -/
theorem deriveAlps_ignores_attribution (e : Evidence) (a : Attribution) :
    deriveAlps { e with attribution := a } = deriveAlps e := rfl

/-- At every deployment and trust base, the attribution a verifier sees is
the harness's claim. The `alps-evidence` attestor says the same of itself.
-- cite: plugins/attestors/alps-evidence/alps_evidence.go:120-134 sha256:4d58fc3be4d56ba6ddbafe2b58fc60ae3257f6a2c4eea3d34bf4aa43f9fe7387
-/
theorem attribution_is_harness_claim (d : Deployment) (tb : TrustBase) (adv : Adversary) (t : Facts) :
    (emit d tb adv t).attribution = adv.claim.attribution := rfl

/-! ## What the adversary can forge, characterised

The adversary can make the signed execution record differ from what ran iff
no trusted recorder outside it wrote the record. -/

theorem execution_forgeable_iff (d : Deployment) (tb : TrustBase) (t : Facts) :
    (∃ adv : Adversary, (emit d tb adv t).execution ≠ t.execution) ↔ executionTrusted d tb = false := by
  constructor
  · intro ⟨adv, h⟩
    cases hx : executionTrusted d tb
    · rfl
    · simp [emit, hx] at h
  · intro hx
    let bad : Execution := { t.execution with exitCode := t.execution.exitCode + 1 }
    refine ⟨⟨false, { t with execution := bad }⟩, ?_⟩
    simp only [emit, hx]
    intro h
    have := congrArg Execution.exitCode h
    simp [bad] at this

theorem products_forgeable_iff (d : Deployment) (tb : TrustBase) (t : Facts) :
    (∃ adv : Adversary, (emit d tb adv t).products ≠ t.products) ↔ productsTrusted d tb = false := by
  constructor
  · intro ⟨adv, h⟩
    cases hx : productsTrusted d tb
    · rfl
    · simp [emit, hx] at h
  · intro hx
    refine ⟨⟨false, { t with products := ("forged", "") :: t.products }⟩, ?_⟩
    simp only [emit, hx]
    intro h
    have := congrArg List.length h
    simp at this

/-! ## ALPS 1 · Authenticated -/

/-- ALPS 1, "who": with an honest CA and TSA, a derived ALPS 1 means the
signer was a platform-issued, non-human principal and the time is the TSA's.
Nothing here says the principal was used honestly: the agent holds it.
-- see (monorepo, outside this tree): jade/factory/edge/git/docspage.js:397-397 -/
theorem alps1_who (d : Deployment) (tb : TrustBase) (adv : Adversary) (t : Facts)
    (hf : tb.fulcio = true) (ht : tb.tsa = true)
    (h : (deriveAlps (emit d tb adv t)).atLeast .l1 = true) :
    d.keyless = true ∧ d.humanSession = false ∧ d.tsa = true := by
  rw [deriveAlps_l1] at h
  simp [emit, hf, ht] at h
  exact ⟨h.1.1, h.1.2, h.2⟩

/-- ALPS 1, "what": everything the evidence says about what happened is true
when the harness is faithful. The level contributes nothing to this half. -/
theorem harness_faithful_what (d : Deployment) (tb : TrustBase) (adv : Adversary) (t : Facts)
    (hh : HarnessFaithful adv t) :
    (emit d tb adv t).attribution = t.attribution ∧ (emit d tb adv t).execution = t.execution ∧
      (emit d tb adv t).products = t.products := by
  unfold HarnessFaithful at hh
  subst hh
  refine ⟨rfl, ?_, ?_⟩ <;> simp [emit]

/-- The ALPS 1 provenance guarantee, with its assumptions named: an honest CA
and TSA give "who"; a faithful harness gives "what". -/
theorem alps1_guarantee (d : Deployment) (tb : TrustBase) (adv : Adversary) (t : Facts)
    (hf : tb.fulcio = true) (ht : tb.tsa = true) (hh : HarnessFaithful adv t)
    (h : (deriveAlps (emit d tb adv t)).atLeast .l1 = true) :
    d.keyless = true ∧ d.humanSession = false ∧ d.tsa = true ∧
      (emit d tb adv t).attribution = t.attribution ∧ (emit d tb adv t).execution = t.execution ∧
      (emit d tb adv t).products = t.products := by
  obtain ⟨k, hs, ts⟩ := alps1_who d tb adv t hf ht h
  obtain ⟨a, x, p⟩ := harness_faithful_what d tb adv t hh
  exact ⟨k, hs, ts, a, x, p⟩

/-- What the code builds today derives exactly ALPS 1 under an honest trust
base, whatever the adversary does. -/
theorem asBuilt_is_alps1 (adv : Adversary) (t : Facts) :
    deriveAlps (emit asBuilt TrustBase.honest adv t) = .l1 := by
  obtain ⟨f, c⟩ := adv
  cases f <;> rfl

/-- ALPS 1 today is the harness's report: on the as-built deployment every
content field a verifier reads is exactly what the adversary wrote, for every
trust base. A faithful harness is therefore the whole of the "what". -/
theorem asBuilt_content_is_harness_report (tb : TrustBase) (adv : Adversary) (t : Facts) :
    (emit asBuilt tb adv t).attribution = adv.claim.attribution ∧
      (emit asBuilt tb adv t).execution = adv.claim.execution ∧
      (emit asBuilt tb adv t).products = adv.claim.products := by
  refine ⟨rfl, ?_, ?_⟩ <;> simp [emit, executionTrusted, productsTrusted, asBuilt]

/-- A concrete run: model A served it, the tests failed (exit 1), one artifact. -/
def realRun : Facts :=
  { attribution := ⟨["model-a"], "agent"⟩,
    execution := ⟨["make", "test"], 1, "cilock"⟩,
    products := [("bin", "d1")] }

/-- An unfaithful harness's story about the same run: no model named, the
tests passed, no artifact. It forges nothing cryptographic. -/
def unfaithful : Adversary :=
  { forge := false,
    claim := { attribution := ⟨[], "agent"⟩, execution := ⟨["make", "test"], 0, "cilock"⟩, products := [] } }

/-- Counterexample: without `HarnessFaithful`, valid-looking ALPS 1 evidence
lies about model mix, result and products, with every signer honest. -/
theorem alps1_unfaithful_harness :
    deriveAlps (emit asBuilt TrustBase.honest unfaithful realRun) = .l1 ∧
      (emit asBuilt TrustBase.honest unfaithful realRun).attribution ≠ realRun.attribution ∧
      (emit asBuilt TrustBase.honest unfaithful realRun).execution ≠ realRun.execution ∧
      (emit asBuilt TrustBase.honest unfaithful realRun).products ≠ realRun.products := by
  refine ⟨rfl, ?_, ?_, ?_⟩
  · intro h
    have := congrArg (fun a => a.models.length) h
    simp [emit, unfaithful, realRun] at this
  · intro h
    have := congrArg Execution.exitCode h
    simp [emit, executionTrusted, asBuilt, unfaithful, realRun] at this
  · intro h
    have := congrArg List.length h
    simp [emit, productsTrusted, executionTrusted, asBuilt, unfaithful, realRun] at this

/-- A signing principal that is a human session the agent inherited is not
ALPS 1, whatever else holds. -/
theorem human_session_not_alps1 (d : Deployment) (adv : Adversary) (t : Facts)
    (hs : d.humanSession = true) :
    (deriveAlps (emit d TrustBase.honest adv t)).atLeast .l1 = false := by
  rw [deriveAlps_l1]
  simp [emit, hs, TrustBase.honest]

/-! ## ALPS 2 · Constrained -/

/-- ALPS 2: with an honest CA, TSA and observer, a derived ALPS 2 means the
sandbox was enforced, the agent held no key, and the execution record is what
ran, with no assumption about the harness.
-- see (monorepo, outside this tree): jade/factory/edge/git/docspage.js:554-554 -/
theorem alps2_sound (d : Deployment) (tb : TrustBase) (adv : Adversary) (t : Facts)
    (hf : tb.fulcio = true) (ht : tb.tsa = true) (ho : tb.observer = true)
    (h : (deriveAlps (emit d tb adv t)).atLeast .l2 = true) :
    d.observer = true ∧ d.sandbox = true ∧ agentHoldsKey d = false ∧
      (emit d tb adv t).execution = t.execution := by
  rw [deriveAlps_l2] at h
  simp [emit, hf, ht, ho] at h
  obtain ⟨_, hob, hsb⟩ := h
  refine ⟨hob, hsb, by simp [agentHoldsKey, hsb], ?_⟩
  simp [emit, executionTrusted, hob, hsb, ho]

/-- Products at ALPS 2 additionally need sibling mutation closed. -/
theorem alps2_products (d : Deployment) (tb : TrustBase) (adv : Adversary) (t : Facts)
    (hf : tb.fulcio = true) (ht : tb.tsa = true) (ho : tb.observer = true) (hc : d.siblingClosed = true)
    (h : (deriveAlps (emit d tb adv t)).atLeast .l2 = true) :
    (emit d tb adv t).products = t.products := by
  obtain ⟨hob, hsb, _, _⟩ := alps2_sound d tb adv t hf ht ho h
  simp [emit, productsTrusted, executionTrusted, hob, hsb, ho, hc]

/-- Counterexample: a verifier that accepts a boundary reference without
checking that a non-agent signed it derives ALPS 2 for a bare workstation,
and the execution record is the adversary's. -/
theorem alps2_lax_boundary :
    let adv : Adversary := { unfaithful with forge := true }
    deriveAlpsLax (emit asBuilt TrustBase.honest adv realRun) = .l2 ∧ asBuilt.sandbox = false ∧
      (emit asBuilt TrustBase.honest adv realRun).execution ≠ realRun.execution := by
  refine ⟨rfl, rfl, ?_⟩
  intro h
  have := congrArg Execution.exitCode h
  simp [emit, executionTrusted, asBuilt, unfaithful, realRun] at this

/-- An ALPS 2 deployment: sandbox plus observer, no daemon, tree writable. -/
def sandboxed : Deployment := { asBuilt with sandbox := true, observer := true }

/-- Counterexample: ALPS 2 does not bind products while the agent's uid can
write the tree. -/
theorem alps2_products_need_sibling_closed :
    deriveAlps (emit sandboxed TrustBase.honest unfaithful realRun) = .l2 ∧
      (emit sandboxed TrustBase.honest unfaithful realRun).products ≠ realRun.products := by
  refine ⟨rfl, ?_⟩
  intro h
  have := congrArg List.length h
  simp [emit, productsTrusted, sandboxed, asBuilt, unfaithful, realRun] at this

/-- Counterexample: ALPS 2 does not certify attribution either. -/
theorem alps2_attribution_needs_harness :
    deriveAlps (emit sandboxed TrustBase.honest unfaithful realRun) = .l2 ∧
      (emit sandboxed TrustBase.honest unfaithful realRun).attribution ≠ realRun.attribution := by
  refine ⟨rfl, ?_⟩
  intro h
  have := congrArg (fun a => a.models.length) h
  simp [emit, unfaithful, realRun] at this

/-! ## ALPS 3 · Isolated (cilockd, designed, not implemented)

-- see (monorepo, outside this tree): jade/factory/edge/git/docspage.js:576-577
-- designed, not implemented (docs/design/cilockd/cilockd.md:4060-4106, PR #9042)
-/

/-- ALPS 3: with the whole trust base honest, a derived ALPS 3 means the
daemon executed and signed outside the agent's uid with a measured binary and
an attested key, the agent held no signing key, and the execution record is
what ran, with no assumption about the harness. -/
theorem alps3_sound (d : Deployment) (adv : Adversary) (t : Facts)
    (h : deriveAlps (emit d TrustBase.honest adv t) = .l3) :
    d.daemon = true ∧ d.uidSeparated = true ∧ d.measuredCilock = true ∧ d.hwKey = true ∧
      agentHoldsKey d = false ∧ (emit d TrustBase.honest adv t).execution = t.execution := by
  rw [deriveAlps_l3] at h
  simp [emit, TrustBase.honest] at h
  obtain ⟨_, _, ⟨_, hsb⟩, ⟨⟨⟨hdm, hus⟩, hmc⟩, hhw⟩⟩ := h
  refine ⟨hdm, hus, hmc, hhw, by simp [agentHoldsKey, hsb], ?_⟩
  simp [emit, executionTrusted, hdm, hus, TrustBase.honest]

/-- The designed Linux-with-TPM deployment reaches ALPS 3 whatever the
adversary does. -- designed, not implemented (docs/design/cilockd/cilockd.md:4121-4123, PR #9042) -/
theorem cilockdLinuxTpm_is_alps3 (adv : Adversary) (t : Facts) :
    deriveAlps (emit cilockdLinuxTpm TrustBase.honest adv t) = .l3 := by
  obtain ⟨f, c⟩ := adv
  cases f <;> rfl

/-- Counterexample (T18): ALPS 3 does not bind products while a sibling
process of the agent's uid can rewrite the tree.
-- designed, not implemented (docs/design/cilockd/cilockd.md:317-334, PR #9042) -/
theorem alps3_products_need_sibling_closed :
    deriveAlps (emit cilockdLinuxTpm TrustBase.honest unfaithful realRun) = .l3 ∧
      (emit cilockdLinuxTpm TrustBase.honest unfaithful realRun).products ≠ realRun.products := by
  refine ⟨rfl, ?_⟩
  intro h
  have := congrArg List.length h
  simp [emit, productsTrusted, cilockdLinuxTpm, unfaithful, realRun] at this

theorem alps3_products (d : Deployment) (adv : Adversary) (t : Facts) (hc : d.siblingClosed = true)
    (h : deriveAlps (emit d TrustBase.honest adv t) = .l3) :
    (emit d TrustBase.honest adv t).products = t.products := by
  obtain ⟨hdm, hus, _, _, _, _⟩ := alps3_sound d adv t h
  simp [emit, productsTrusted, executionTrusted, hdm, hus, hc, TrustBase.honest]

/-- Counterexample: even ALPS 3 leaves model attribution to the harness. The
cilockd design says so: it "does not buy ... model or tool authentication".
-- designed, not implemented (docs/design/cilockd/cilockd.md:315-316, PR #9042) -/
theorem alps3_attribution_needs_harness :
    deriveAlps (emit cilockdLinuxTpm TrustBase.honest unfaithful realRun) = .l3 ∧
      (emit cilockdLinuxTpm TrustBase.honest unfaithful realRun).attribution ≠ realRun.attribution := by
  refine ⟨rfl, ?_⟩
  intro h
  have := congrArg (fun a => a.models.length) h
  simp [emit, unfaithful, realRun] at this

/-- macOS 14 to 26: the execution-statement key has no attestation format, so
the answer is not ALPS 3 however the rest is configured.
-- designed, not implemented (docs/design/cilockd/cilockd.md:4126, PR #9042) -/
theorem no_attested_key_not_alps3 (d : Deployment) (adv : Adversary) (t : Facts) (hk : d.hwKey = false) :
    deriveAlps (emit d TrustBase.honest adv t) ≠ .l3 := by
  intro h
  have := (alps3_sound d adv t h).2.2.2.1
  rw [hk] at this
  cases this

/-- `cilock daemon install --user`: the daemon runs as the caller's uid, so
never ALPS 3. -- designed, not implemented (docs/design/cilockd/cilockd.md:4131, PR #9042) -/
theorem same_uid_daemon_not_alps3 (d : Deployment) (adv : Adversary) (t : Facts) (hu : d.uidSeparated = false) :
    deriveAlps (emit d TrustBase.honest adv t) ≠ .l3 := by
  intro h
  have := (alps3_sound d adv t h).2.1
  rw [hu] at this
  cases this

/-- Counterexample: the daemon's honesty is load-bearing for the level. A
dishonest daemon yields ALPS 3 for a host with no daemon at all. -/
theorem alps3_needs_daemon_trust :
    deriveAlps (emit sandboxed { TrustBase.honest with daemon := false } { unfaithful with forge := true } realRun) = .l3 ∧
      sandboxed.daemon = false := ⟨rfl, rfl⟩

/-- Counterexample: the hardware root's honesty is load-bearing too. A
dishonest root yields ALPS 3 for a host whose key is not attested (the macOS
14 to 26 row). -/
theorem alps3_needs_hw_root_trust :
    let d : Deployment := { cilockdLinuxTpm with hwKey := false }
    deriveAlps (emit d { TrustBase.honest with hwRoot := false } { unfaithful with forge := true } realRun) = .l3 ∧
      d.hwKey = false := ⟨rfl, rfl⟩

end CiProvenance
