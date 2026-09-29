-- cite: attestation/policy/external_latest.go:29-44 sha256:a87bab1cfb0ed2da4bcb0aeb76e6d7c2903b36acb4e18b80383ebb11a05fd958
/-
  CilockEvaluators.Nested: a parent policy over child VSAs.

  A stock external matches on predicate type and passes when ANY envelope
  passes (`Gate.external`). Over child VSAs that means an older passing VSA of
  a child satisfies it after a newer one failed: the consumer's Rego judges
  one envelope at a time and cannot see the newer one. An external that sets
  `childPolicyDigest` or `timestampConstraint` is decided instead by the
  nested semantics (attestation/policy/external_latest.go):

  * only VSAs of the bound child policy are about it (others are unbound);
  * a candidate needs a TSA-verified time, a signed `timeVerified` that is not
    after that time beyond clock skew, and both times inside the window;
  * each candidate decides at its SIGNED `timeVerified`;
  * the external passes iff some candidate at the latest time passed, and
    none there failed.

  Why the signed time and not the TSA time: a DSSE signature's timestamps
  are not covered by the signature, so anyone who can download an envelope
  can publish the same signature bytes with a fresh token. Ordered by TSA
  time, an old passing VSA re-stamped after a newer failing one becomes the
  latest (`tsa_ordering_restamp_passes`). The signed time belongs to the
  functionary, which is already trusted with the verdict itself.

  Only `timestampConstraint.maxAge` is modelled; notBefore/notAfter are not
  (the driver never sets them). Rego and AI enter as `Gate.envGate` verdicts.
-/
import CilockEvaluators.Vsa

namespace CilockEvaluators.Nested

open CilockEvaluators

/-- `external` over already-computed envelope outcomes (policy.go Analyze
and the two error returns). `Gate.external` is this over `envGate`. -/
def externalOf (required : Bool) (outs : List Gate.EnvOutcome) : Gate.ExtOutcome :=
  let anyPass := outs.any Gate.isPassed
  let anyRej := outs.any Gate.isRejected
  if !anyPass && !anyRej then (if required then .missing else .skipped)
  else if !anyPass && required then .allRejected
  else .result anyPass (!anyPass && outs.any Gate.isRefusedRej)

theorem external_eq (required : Bool) (envs : List Gate.Envelope) :
    Gate.external required envs = externalOf required (envs.map Gate.envGate) := rfl

theorem externalOf_pass_has_witness (required : Bool) (outs : List Gate.EnvOutcome) (r : Bool)
    (h : externalOf required outs = .result true r) : Gate.EnvOutcome.passed ∈ outs := by
  unfold externalOf at h
  simp only at h
  split at h
  · split at h <;> simp at h
  · split at h
    · simp at h
    · simp only [Gate.ExtOutcome.result.injEq] at h
      obtain ⟨hp, _⟩ := h
      simp only [List.any_eq_true] at hp
      obtain ⟨o, ho, hop⟩ := hp
      cases o <;> simp_all [Gate.isPassed]

/-- A candidate VSA envelope for a nested external. `env` is what the stock
external gate reads; `stamped` are the TSA-verified times of the
functionary-matched signatures (`VerifiedTimestampsByKeyID`, source.go);
`signed` is the decoded `predicate.timeVerified` (none: absent or not
RFC 3339). -/
structure Candidate where
  env : Gate.Envelope
  policyDigest : PolicyDigest
  signed : Option Timestamp
  stamped : List Timestamp
  deriving DecidableEq, Repr

/-- An external as the nested semantics reads it. -/
structure External where
  required : Bool
  child : Option PolicyDigest := none
  maxAge : Option Nat := none
  deriving DecidableEq, Repr

-- cite: attestation/policy/external_latest.go:48-51 sha256:0bf935a2dca1567548e6ad4ad47c33478d8aca2ed7c4566fef468e5edbee9c07
/-- latestDecides: either field set. -/
def External.nested (x : External) : Bool := x.child.isSome || x.maxAge.isSome

/-- maxClockSkew (timestamp_constraint.go): a fixed 5 minutes. -/
def maxClockSkew : Nat := 300

-- cite: attestation/policy/timestamp_constraint.go:107-147 sha256:51e3358d09fd59549f11114317687fbf53baabed4c15845b9aec3ecab80bd2d0
/-- `TimestampConstraint.Check` with maxAge only: the EARLIEST time is judged,
none is a rejection, a time beyond now + skew or older than maxAge fails. -/
def windowOk (maxAge : Option Nat) (now : Timestamp) (ts : List Timestamp) : Bool :=
  match maxAge with
  | none => true
  | some m =>
    match ts.min? with
    | none => false
    | some e => decide (e ≤ now + maxClockSkew) && decide (now - e ≤ m)

inductive Admission where
  | unbound
  | rejected
  | admitted (t : Timestamp)
  deriving DecidableEq, Repr

-- cite: attestation/policy/external_latest.go:101-145 sha256:73ba048caa8a448f83820d7e7b1d9e960ba59191a821779e7474ce5bfa599aaf
/-- admitExternal. -/
def admission (now : Timestamp) (x : External) (c : Candidate) : Admission :=
  if x.child.isSome && x.child != some c.policyDigest then .unbound
  else match c.stamped.min?, c.signed with
    | some st, some sg =>
      if st + maxClockSkew < sg then .rejected
      else if !windowOk x.maxAge now c.stamped then .rejected
      else if !windowOk x.maxAge now [sg] then .rejected
      else .admitted sg
    | _, _ => .rejected

-- cite: attestation/policy/policy.go:1807-1889 sha256:863a20aef8109ad07ab14b804ed1c0c3a17f3a639ac5314cb741ad5bb99851ad
/-- What the envelope gate decides before admission runs: signature and
subject errors, commit unbinding, and the functionary check (policy.go). -/
def pre (e : Gate.Envelope) : Option Gate.EnvOutcome :=
  if e.sigErrors then some (if e.subjectUnbound then .unbound else .rejected false)
  else if e.commitUnbound then some .unbound
  else if !e.signerAllowed then some (.rejected false)
  else none

/-- One candidate before the latest decides: its outcome, and for an admitted
candidate, its time and whether it passed Rego and AI (`mark`, policy.go). -/
def outcome0 (now : Timestamp) (x : External) (c : Candidate) : Gate.EnvOutcome × Option (Timestamp × Bool) :=
  match pre c.env with
  | some o => (o, none)
  | none =>
    match admission now x c with
    | .unbound => (.unbound, none)
    | .rejected => (.rejected false, none)
    | .admitted t => (Gate.envGate c.env, some (t, Gate.envGate c.env == .passed))

def marks (now : Timestamp) (x : External) (cs : List Candidate) : List (Timestamp × Bool) :=
  cs.filterMap fun c => (outcome0 now x c).2

def latest (ms : List (Timestamp × Bool)) : Timestamp := ms.foldr (fun m acc => max m.1 acc) 0

def latestFailed (ms : List (Timestamp × Bool)) : Bool :=
  ms.any fun m => m.1 == latest ms && !m.2

-- cite: attestation/policy/external_latest.go:177-212 sha256:c0e6f84aed2703f321ca393afb603cd7cdc5fb3525b5c37095e42e0c07346228
/-- decideLatest: a pass stays a pass only at the latest time with no failure
there; every other pass is demoted to a (non-refusal) rejection. -/
def final (now : Timestamp) (x : External) (cs : List Candidate) (c : Candidate) : Gate.EnvOutcome :=
  match outcome0 now x c with
  | (_, some (t, true)) =>
    let ms := marks now x cs
    if latestFailed ms || t != latest ms then .rejected false else .passed
  | (o, _) => o

/-- The external's result: nested semantics when either field is set, the
stock gate otherwise. -/
def externalLatest (now : Timestamp) (x : External) (cs : List Candidate) : Gate.ExtOutcome :=
  if x.nested then externalOf x.required (cs.map (final now x cs))
  else Gate.external x.required (cs.map (·.env))

/-! ## Lemmas -/

theorem le_latest {ms : List (Timestamp × Bool)} {m : Timestamp × Bool} (h : m ∈ ms) : m.1 ≤ latest ms := by
  induction ms with
  | nil => cases h
  | cons a rest ih =>
    simp only [latest, List.foldr_cons] at *
    rcases List.mem_cons.1 h with rfl | hin
    · exact Nat.le_max_left _ _
    · exact Nat.le_trans (ih hin) (Nat.le_max_right _ _)

theorem pre_not_passed {e : Gate.Envelope} {o : Gate.EnvOutcome} (h : pre e = some o) : o ≠ .passed := by
  unfold pre at h
  split at h
  · split at h <;> simp at h <;> subst h <;> simp
  · split at h
    · simp at h; subst h; simp
    · split at h
      · simp at h; subst h; simp
      · simp at h

theorem pre_none {e : Gate.Envelope} (h : pre e = none) :
    e.sigErrors = false ∧ e.commitUnbound = false ∧ e.signerAllowed = true := by
  unfold pre at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i h1 h2 h3
        simp_all

theorem outcome0_passed {now : Timestamp} {x : External} {c : Candidate}
    (h : (outcome0 now x c).1 = .passed) : ∃ t, (outcome0 now x c).2 = some (t, true) := by
  cases hp : pre c.env with
  | some o => simp only [outcome0, hp] at h; exact absurd h (pre_not_passed hp)
  | none =>
    cases ha : admission now x c with
    | unbound => simp [outcome0, hp, ha] at h
    | rejected => simp [outcome0, hp, ha] at h
    | admitted t => exact ⟨t, by simp [outcome0, hp, ha] at h ⊢; exact h⟩

theorem outcome0_true {now : Timestamp} {x : External} {c : Candidate} {t : Timestamp}
    (h : (outcome0 now x c).2 = some (t, true)) : (outcome0 now x c).1 = .passed := by
  cases hp : pre c.env with
  | some o => simp [outcome0, hp] at h
  | none =>
    cases ha : admission now x c with
    | unbound => simp [outcome0, hp, ha] at h
    | rejected => simp [outcome0, hp, ha] at h
    | admitted t' => simp [outcome0, hp, ha] at h ⊢; exact h.2

/-- A final pass is an admitted candidate that passed the envelope gate, at
the latest admitted time, with no admitted failure there. -/
theorem final_passed {now : Timestamp} {x : External} {cs : List Candidate} {c : Candidate}
    (h : final now x cs c = .passed) :
    ∃ t, outcome0 now x c = (.passed, some (t, true)) ∧ t = latest (marks now x cs) ∧
      latestFailed (marks now x cs) = false := by
  unfold final at h
  cases hoc : outcome0 now x c with
  | mk o tp =>
    rw [hoc] at h
    cases tp with
    | none =>
      simp only at h
      obtain ⟨t, ht⟩ := outcome0_passed (now := now) (x := x) (c := c) (by rw [hoc]; exact h)
      rw [hoc] at ht; simp at ht
    | some p =>
      obtain ⟨t, b⟩ := p
      cases b with
      | false =>
        simp only at h
        obtain ⟨t', ht⟩ := outcome0_passed (now := now) (x := x) (c := c) (by rw [hoc]; exact h)
        rw [hoc] at ht; simp at ht
      | true =>
        simp only at h
        split at h
        · simp at h
        · rename_i hn
          simp only [Bool.or_eq_true, bne_iff_ne, ne_eq, not_or, Bool.not_eq_true,
            Decidable.not_not] at hn
          have ho := outcome0_true (now := now) (x := x) (c := c) (t := t) (by rw [hoc])
          rw [hoc] at ho
          simp only at ho
          subst ho
          exact ⟨t, rfl, hn.2, hn.1⟩

/-! ## Soundness -/

/-- **latest_sound.** A passing nested external has a candidate that passed
the envelope gate, signed by an allowed functionary, of the bound child
policy, admitted (a TSA-verified time, its signed time not after it, both in
the window) at signed time `t`; and every admitted candidate is no later
than `t`, and every one at `t` passed. -/
theorem latest_sound (now : Timestamp) (x : External) (cs : List Candidate) (r : Bool)
    (hn : x.nested = true) (h : externalLatest now x cs = .result true r) :
    ∃ c ∈ cs, ∃ t, admission now x c = .admitted t ∧ Gate.envGate c.env = .passed ∧
      (∀ d, x.child = some d → c.policyDigest = d) ∧ c.signed = some t ∧
      ∀ c' ∈ cs, ∀ t', pre c'.env = none → admission now x c' = .admitted t' →
        t' ≤ t ∧ (t' = t → Gate.envGate c'.env = .passed) := by
  unfold externalLatest at h
  rw [hn] at h
  simp only [↓reduceIte] at h
  have hw := externalOf_pass_has_witness _ _ _ h
  simp only [List.mem_map] at hw
  obtain ⟨c, hc, hfc⟩ := hw
  obtain ⟨t, h0, hlat, hnf⟩ := final_passed hfc
  unfold outcome0 at h0
  split at h0
  · simp at h0
  · rename_i hpre
    split at h0
    · simp at h0
    · simp at h0
    · rename_i t0 hadm
      simp only [Prod.mk.injEq, Option.some.injEq, beq_iff_eq] at h0
      obtain ⟨hg, ht, _⟩ := h0
      subst ht
      refine ⟨c, hc, t0, hadm, hg, ?_, ?_, ?_⟩
      · intro d hd
        unfold admission at hadm
        split at hadm
        · simp at hadm
        · rename_i hb
          simp only [hd, Option.isSome_some, Bool.true_and, bne_iff_ne, ne_eq, Decidable.not_not] at hb
          exact (Option.some.inj hb).symm
      · unfold admission at hadm
        split at hadm
        · simp at hadm
        · split at hadm
          · rename_i st sg _ _
            split at hadm
            · simp at hadm
            · split at hadm
              · simp at hadm
              · split at hadm
                · simp at hadm
                · simp at hadm; subst hadm; assumption
          · simp at hadm
      · intro c' hc' t' hpre' hadm'
        have hm : (t', Gate.envGate c'.env == .passed) ∈ marks now x cs := by
          unfold marks
          rw [List.mem_filterMap]
          refine ⟨c', hc', ?_⟩
          simp [outcome0, hpre', hadm']
        refine ⟨hlat ▸ le_latest hm, fun hteq => ?_⟩
        unfold latestFailed at hnf
        simp only [List.any_eq_false, Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true'] at hnf
        have := hnf _ hm
        rw [hteq, hlat] at this
        simp only [true_and] at this
        cases hge : Gate.envGate c'.env <;> simp_all

/-- The decision time is the signed time: re-stamping a candidate (any other
TSA times) cannot move it. -/
theorem admit_time_is_signed (now : Timestamp) (x : External) (c : Candidate) (t : Timestamp)
    (h : admission now x c = .admitted t) : c.signed = some t := by
  unfold admission at h
  split at h
  · simp at h
  · split at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · split at h
          · simp at h
          · simp at h; subst h; assumption
    · simp at h

/-- A candidate with no TSA-verified time never decides. -/
theorem untimed_never_decides (now : Timestamp) (x : External) (c : Candidate) (h : c.stamped = []) :
    ∀ t, admission now x c ≠ .admitted t := by
  intro t ha
  unfold admission at ha
  split at ha
  · simp at ha
  · rw [h] at ha
    simp at ha

/-- A candidate whose signed time is after its own TSA time (beyond skew)
never decides: the signature existed before the verdict it claims. -/
theorem forward_dated_never_decides (now : Timestamp) (x : External) (c : Candidate) (st sg : Timestamp)
    (hst : c.stamped.min? = some st) (hsg : c.signed = some sg) (hlt : st + maxClockSkew < sg) :
    ∀ t, admission now x c ≠ .admitted t := by
  intro t ha
  unfold admission at ha
  split at ha
  · simp at ha
  · rw [hst, hsg] at ha
    simp only [hlt, ↓reduceIte] at ha
    cases ha

/-- **parent_sound.** A parent whose externals are all required and nested
verifies PASSED only when every one of them has such a latest passing
candidate. -/
theorem parent_sound (now : Timestamp) (xs : List (External × List Candidate))
    (hreq : ∀ p ∈ xs, p.1.required = true ∧ p.1.nested = true)
    (h : Gate.verify true [] (xs.map fun p => externalLatest now p.1 p.2) = .accepted true) :
    ∀ p ∈ xs, ∃ c ∈ p.2, ∃ t, admission now p.1 c = .admitted t ∧ Gate.envGate c.env = .passed ∧
      (∀ d, p.1.child = some d → c.policyDigest = d) ∧ c.signed = some t ∧
      ∀ c' ∈ p.2, ∀ t', pre c'.env = none → admission now p.1 c' = .admitted t' →
        t' ≤ t ∧ (t' = t → Gate.envGate c'.env = .passed) := by
  intro p hp
  obtain ⟨_, herr, _, _, _, han, _⟩ := (Gate.verify_accepts_iff _ _ _).1 h
  have hin : externalLatest now p.1 p.2 ∈ xs.map fun p => externalLatest now p.1 p.2 :=
    List.mem_map.2 ⟨p, hp, rfl⟩
  have ha := han _ hin
  have he := herr _ hin
  obtain ⟨hr, hnest⟩ := hreq p hp
  -- a required external analyzes true only as `.result true _`
  cases hx : externalLatest now p.1 p.2 with
  | missing => rw [hx] at ha; simp [Gate.extAnalyze] at ha
  | allRejected => rw [hx] at ha; simp [Gate.extAnalyze] at ha
  | skipped =>
    exfalso
    unfold externalLatest at hx
    rw [hnest] at hx
    simp only [↓reduceIte] at hx
    unfold externalOf at hx
    rw [hr] at hx
    simp only at hx
    split at hx
    · simp at hx
    · split at hx <;> simp at hx
  | result b r =>
    rw [hx] at ha
    simp only [Gate.extAnalyze] at ha
    subst ha
    exact latest_sound now p.1 p.2 r hnest hx

/-! ## Refutations and vectors -/

/-- A stock-shaped candidate: signature fine, allowed signer, Rego verdict `v`. -/
def cand (d : String) (v : Verdict) (signed : Option Timestamp) (stamped : List Timestamp) : Candidate :=
  ⟨⟨false, false, false, true, true, v, .pass⟩, ⟨d⟩, signed, stamped⟩

def childA : External := { required := true, child := some ⟨"a"⟩, maxAge := some 3600 }
def stockA : External := { required := true }

/-- The three holes and the re-stamp, at now = 5000. -/
theorem nested_closes_holes :
    -- (c) stock: an older passing VSA masks a newer failing one.
    externalLatest 5000 stockA [cand "a" .pass (some 4000) [4000], cand "a" .deny (some 4500) [4500]]
      = .result true false ∧
    externalLatest 5000 childA [cand "a" .pass (some 4000) [4000], cand "a" .deny (some 4500) [4500]]
      = .allRejected ∧
    -- (a) another child's pass is not a candidate.
    externalLatest 5000 childA [cand "b" .pass (some 4500) [4500]] = .missing ∧
    -- (b) untimed and stale.
    externalLatest 5000 childA [cand "a" .pass (some 4500) []] = .allRejected ∧
    externalLatest 5000 childA [cand "a" .pass (some 1000) [1000]] = .allRejected ∧
    -- re-stamped old pass (same signed time, fresh token) stays superseded.
    externalLatest 5000 childA
      [cand "a" .pass (some 4000) [4000], cand "a" .deny (some 4500) [4500], cand "a" .pass (some 4000) [4990]]
      = .allRejected ∧
    -- a newer pass supersedes an older failure.
    externalLatest 5000 childA [cand "a" .deny (some 4000) [4000], cand "a" .pass (some 4500) [4500]]
      = .result true false := by
  decide

/-- The semantics as fedramp-lean patch 0012 shipped it: a candidate decides
at its earliest TSA time. -/
def admissionByTsa (now : Timestamp) (x : External) (c : Candidate) : Admission :=
  if x.child.isSome && x.child != some c.policyDigest then .unbound
  else match c.stamped.min? with
    | some st => if !windowOk x.maxAge now c.stamped then .rejected else .admitted st
    | none => .rejected

/-- **Refuted for TSA ordering.** Re-publishing the old passing envelope with a
fresh token makes it the latest under `admissionByTsa`: the old pass (TSA 4990)
outranks the newer failure (4500). Under `admission` it decides at its signed
4000 and stays superseded (`nested_closes_holes`). -/
theorem tsa_ordering_restamp_passes :
    let cs := [cand "a" .pass (some 4000) [4000], cand "a" .deny (some 4500) [4500], cand "a" .pass (some 4000) [4990]]
    let ts := cs.filterMap fun c => match admissionByTsa 5000 childA c with
      | .admitted t => some (t, Gate.envGate c.env == .passed) | _ => none
    latestFailed ts = false ∧ latest ts = 4990 := by
  decide

end CilockEvaluators.Nested
