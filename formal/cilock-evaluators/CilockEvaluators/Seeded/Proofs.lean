/-
  CilockEvaluators.Seeded.Proofs: what each seeded rule admits.

  Three kinds of result, for every rule in Rules.lean:

  * **Empty evidence is refused** (`*_empty`, `admits_empty`): no rule admits
    the empty predicate `{}`. A rule that admitted `{}` would admit any
    predicate missing the fields it reads.
  * **Fail closed** (`*_sound`): an admitted predicate has every decision
    field present with the JSON kind the rule compares, so a missing,
    mistyped or malformed field can only be a refusal.
  * **Characterization**: each `*_sound` theorem states the whole admission
    condition of the rule table in docs/design/cilock-policy-init.md ("What
    each rule admits"); where the condition is short, the `_iff` form is
    proved too.

  Plus two structural results: evidence that is not a JSON object is refused
  by every rule (`admits_nonobject`), and the rules that read only their own
  predicate give the same verdict whether or not the step has an
  attestationsFrom edge (`admits_wrapped_eq`), which is discipline 1 of the
  design.
-/
import CilockEvaluators.Seeded.Rules

namespace CilockEvaluators.Seeded

/-! ## Empty evidence -/

/-- The ids of every seeded rule. -/
def ruleIds : List String :=
  ["command-succeeded", "command-pin", "product-recorded", "tests-pass", "sarif-no-errors",
   "secretscan-no-findings", "govulncheck-no-reachable", "govulncheck-vex-covered", "sarif-vex-covered",
   "trivy-no-blocked-severity", "slsa-provenance", "sbom-inventory", "review-approved", "products-from"]

theorem commandSucceeded_empty : commandSucceeded (.obj []) = false := rfl
theorem commandPin_empty (e : J) : commandPin e (.obj []) = false := rfl
theorem productRecorded_empty : productRecorded (.obj []) = false := rfl
theorem testsPass_empty : testsPass (.obj []) = false := rfl
theorem sarifNoErrors_empty : sarifNoErrors (.obj []) = false := rfl
theorem secretscanClean_empty : secretscanClean (.obj []) = false := rfl
theorem govulncheckReachable_empty : govulncheckReachable (.obj []) = false := rfl
theorem trivySeverity_empty (b : List String) : trivySeverity b (.obj []) = false := rfl
theorem slsaProvenance_empty : slsaProvenance (.obj []) = false := rfl
theorem sbomInventory_empty : sbomInventory (.obj []) = false := rfl
theorem reviewApproved_empty : reviewApproved (.obj []) = false := rfl

theorem govulnScan_empty : govulnScan (.obj []) = none := rfl
theorem sarifScan_empty : sarifScan (.obj []) = none := rfl

theorem vexCovered_govuln_empty (s : String) (ps : List String) :
    vexCovered govulnScan s ps (.obj []) = false := rfl
theorem vexCovered_sarif_empty (s : String) (ps : List String) :
    vexCovered sarifScan s ps (.obj []) = false := rfl

theorem productsFrom_empty (up : String) : productsFrom up (.obj []) = false := by
  simp [productsFrom, field, List.lookup, predOf]

/-- No seeded rule admits the empty predicate, whatever its fill value, with
    or without an attestationsFrom edge for the rules that do not read one. -/
theorem admits_empty (id : String) (param : J) (h : id ∈ ruleIds) :
    admits id param (.obj []) none = some false := by
  simp only [ruleIds, List.mem_cons, List.not_mem_nil, or_false] at h
  rcases h with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl <;>
  first
  | rfl
  | simp [admits, inputOf, predOf, productsFrom_empty, vexCovered_govuln_empty, vexCovered_sarif_empty,
      J.isObj]

/-- Evidence that is not a JSON object is refused by every rule, known or not. -/
theorem admits_nonobject (id : String) (param p : J) (h : p.isObj = false) :
    admits id param p none = some false := by
  simp [admits, inputOf, h]

/-! ## Wrapped input (discipline 1) -/

theorem predOf_wrapped (p s : J) : predOf (inputOf p (some s)) = p := by
  simp [predOf, inputOf, List.lookup]

theorem predOf_plain (kvs : List (String × J)) (h : kvs.lookup "attestation" = none) :
    predOf (inputOf (.obj kvs) none) = .obj kvs := by
  simp [predOf, inputOf, h]

/-- The rules that read only their own predicate return the same verdict for
    a step with an attestationsFrom edge (input `{attestation, steps}`) as for
    one without: a rule that read `input.<field>` directly would not. -/
theorem admits_wrapped_eq (id : String) (param : J) (kvs : List (String × J)) (s : J)
    (h : kvs.lookup "attestation" = none)
    (hid : id ∉ ["govulncheck-vex-covered", "sarif-vex-covered", "products-from"]) :
    admits id param (.obj kvs) (some s) = admits id param (.obj kvs) none := by
  have hw : predOf (inputOf (.obj kvs) (some s)) = .obj kvs := predOf_wrapped _ _
  have hp : predOf (inputOf (.obj kvs) none) = .obj kvs := predOf_plain kvs h
  simp only [List.mem_cons, List.not_mem_nil, or_false, not_or] at hid
  obtain ⟨h1, h2, h3⟩ := hid
  unfold admits
  simp only [hw, hp]
  simp only [inputOf, J.isObj, Bool.not_true, Bool.false_eq_true, ite_false]
  split <;> simp_all

/-! ## Per-rule soundness and characterization -/

theorem commandSucceeded_iff (p : J) :
    commandSucceeded p = true ↔ field p "exitcode" .null = .num 0 := by
  unfold commandSucceeded
  split <;> simp_all

theorem commandPin_sound (e p : J) (h : commandPin e p = true) :
    ∃ xs, field p "cmd" .null = .arr xs ∧ J.eqv (.arr xs) e = true := by
  unfold commandPin at h
  split at h <;> simp_all

theorem productRecorded_iff (p : J) :
    productRecorded p = true ↔
      ∃ n s, field p "treeSize" .null = .num n ∧ field p "merkleRoot" .null = .str s ∧ 1 ≤ n := by
  unfold productRecorded
  split
  · rename_i n s h1 h2; simp [h1, h2]
  · rename_i hne
    simp only [Bool.false_eq_true, false_iff, not_exists, not_and]
    intro n s h1 h2 _
    exact hne _ _ h1 h2

theorem testsPass_sound (p : J) (h : testsPass p = true) :
    let s := field (field p "predicate" (.obj [])) "summary" .null
    s.isObj = true ∧ ∃ t q e k,
      field s "total" .null = .num t ∧ field s "passed" .null = .num q ∧
      field s "failed" .null = .num 0 ∧ field s "errors" (.num 0) = .num e ∧
      field s "skipped" (.num 0) = .num k ∧
      1 ≤ t ∧ 1 ≤ q ∧ e = 0 ∧ 0 ≤ k := by
  unfold testsPass at h
  dsimp only at h ⊢
  split at h
  · rename_i kvs t q f e k h0 h1 h2 h3 h4 h5
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h
    obtain ⟨⟨⟨⟨⟨⟨hf0, he0⟩, hk⟩, ht⟩, hq⟩, hf⟩, he⟩ := h
    have : f = 0 := by omega
    subst this
    exact ⟨by simp [h0, J.isObj], t, q, e, k, h1, h2, h3, h4, h5, ht, hq, by omega, hk⟩
  · simp at h

theorem secretscanClean_iff (p : J) :
    secretscanClean p = true ↔ secretFindings p = some [] ∧ secretMismatches p = some [] := by
  unfold secretscanClean
  split
  · rename_i fs ms h1 h2
    simp [h1, h2, List.isEmpty_iff]
  · rename_i hne
    simp only [Bool.false_eq_true, false_iff, not_and]
    intro h1 h2
    exact hne _ _ h1 h2

/-- secretscan: a findings list holding anything, even a non-object, is never
    admitted (Codex round 1 on #10194: a `null` finding dropped the deny). -/
theorem secretscan_nonempty_findings_refused (p : J) (f : J) (fs : List J)
    (h : secretFindings p = some (f :: fs)) : secretscanClean p = false := by
  unfold secretscanClean
  rw [h]
  cases secretMismatches p <;> simp

theorem sarifNoErrors_sound (p : J) (h : sarifNoErrors p = true) :
    ∃ runs, field (field p "report" (.obj [])) "runs" .null = .arr runs ∧ runs ≠ [] ∧
      (∀ run ∈ runs, unreadableRun run = false) ∧
      (∀ x ∈ sarifResults runs, unreadableResult x.1 x.2 = false ∧ errorLevel x.1 x.2 = false) := by
  unfold sarifNoErrors at h
  split at h
  · rename_i runs hr
    simp only [Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff, List.all_eq_true] at h
    refine ⟨runs, hr, ?_, fun r hm => by simpa using h.1.1.2 r hm, fun x hx => ?_⟩
    · intro he; simp [he] at h
    · have a := h.1.2 x hx
      have b := h.2 x hx
      exact ⟨by simpa using a, by simpa using b⟩
  · simp at h

/-- An admitted run has a results array and a rules array, no configuration
    overrides in any invocation, and no policies. -/
theorem unreadableRun_false (run : J) (h : unreadableRun run = false) :
    (field run "results" .null).isArr = true ∧ (rulesOf run).isArr = true ∧
    (field run "invocations" (.arr [])).isArr = true ∧
    (∀ inv ∈ (field run "invocations" (.arr [])).elems,
      J.eqv (field inv "ruleConfigurationOverrides" (.arr [])) (.arr []) = true) ∧
    J.eqv (field run "policies" (.arr [])) (.arr []) = true := by
  unfold unreadableRun at h
  simp only [Bool.or_eq_false_iff, Bool.not_eq_false', List.any_eq_false, Bool.not_eq_true'] at h
  refine ⟨h.1.1.1.1, h.1.1.1.2, h.1.1.2, fun inv hi => ?_, h.2⟩
  simpa using h.1.2 inv hi

/-- sarif: an admitted result has an explicit level, or a default level, only
    from SARIF's enum (Codex round 1 on #10194: a level of 42 read as a
    warning); every index reference names a listed rule object, every id
    reference is a string, and no reference points into a tool extension. -/
theorem sarif_levels_in_enum (run r : J) (h : unreadableResult run r = false) :
    isLevel (field r "level" (.str "warning")) = true ∧
    (∀ i ∈ indexRefs r, listedRule run i = true) ∧
    (∀ x ∈ idRefs r, x.isStr = true) ∧
    (field (refOf r) "toolComponent" .null).isNull = true ∧
    ∀ l ∈ defaultLevels run r, isLevel l = true := by
  unfold unreadableResult at h
  simp only [Bool.or_eq_false_iff, Bool.not_eq_false', List.any_eq_false, Bool.not_eq_true'] at h
  refine ⟨h.1.1.1.1.1.2, fun i hi => ?_, fun x hx => ?_, h.1.1.1.2, fun l hl => ?_⟩
  · simpa using h.1.1.2 i hi
  · simpa using h.1.2 x hx
  · simpa using h.2 l hl

theorem govulncheckReachable_sound (p : J) (h : govulncheckReachable p = true) :
    let s := vulnSummary p
    ∃ uc fs, field s "reachableCount" .null = .num 0 ∧ field s "unreachableCount" .null = .num uc ∧
      vulnFindings s = some fs ∧ (field s "scanLevel" (.str "")).isStrEq "symbol" = true ∧
      (fs.length : Int) = uc ∧
      ∀ f ∈ fs, (field f "reachable" .null).isBool = true ∧
        (f.get "reachable").any (fun v => J.eqv v (.bool true)) = false := by
  unfold govulncheckReachable at h
  dsimp only at h ⊢
  split at h
  · rename_i rc uc fs h1 h2 h3
    simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, Bool.not_eq_true'] at h
    obtain ⟨⟨⟨⟨⟨⟨h0, _⟩, hl⟩, hle⟩, hb⟩, hr⟩, hc⟩ := h
    have : rc = 0 := by omega
    subst this
    refine ⟨uc, fs, h1, h2, h3, hl, by omega, fun f hf => ⟨hb f hf, hr f hf⟩⟩
  · simp at h

theorem scanned_nonempty (s : J) (h : scanned s = true) :
    ∃ r rs, field s "scanRoots" .null = .arr (r :: rs) := by
  unfold scanned at h
  split at h
  · rename_i roots hr
    cases roots with
    | nil => simp at h
    | cons r rs => exact ⟨r, rs, hr⟩
  · simp at h

theorem vexCovered_sound (scan : J → Option (List (J × List J))) (st : String) (ps : List String) (i : J)
    (h : vexCovered scan st ps i = true) :
    ∃ fs, scan (predOf i) = some fs ∧
      (fs = [] ∨ (vexReadable (vexDocs i st) = true ∧
        ∀ x ∈ fs, covered (vexDocs i st) ps x.2 = true)) := by
  unfold vexCovered at h
  split at h
  · rename_i fs hf
    refine ⟨fs, hf, ?_⟩
    simp only [Bool.or_eq_true, List.isEmpty_iff, Bool.and_eq_true, List.all_eq_true] at h
    rcases h with h | ⟨h1, h2⟩
    · exact Or.inl h
    · exact Or.inr ⟨h1, fun x hx => h2 x hx⟩
  · simp at h

/-- A covering statement is settled: fixed, or not_affected with a non-empty
    justification string. -/
theorem settled_iff (s : J) :
    settled s = true ↔ (field s "status" (.str "")).isStrEq "fixed" = true ∨
      ((field s "status" (.str "")).isStrEq "not_affected" = true ∧
        ∃ j, field s "justification" (.str "") = .str j ∧ j ≠ "") := by
  unfold settled
  constructor
  · intro h
    simp only [Bool.or_eq_true, Bool.and_eq_true] at h
    rcases h with h | ⟨h1, h2⟩
    · exact Or.inl h
    · refine Or.inr ⟨h1, ?_⟩
      split at h2
      · rename_i j hj; exact ⟨j, hj, by simpa using h2⟩
      · simp at h2
  · intro h
    simp only [Bool.or_eq_true, Bool.and_eq_true]
    rcases h with h | ⟨h1, j, hj, hne⟩
    · exact Or.inl h
    · refine Or.inr ⟨h1, ?_⟩
      simp [hj, hne]

theorem govulnScan_sound (p : J) (fs : List (J × List J)) (h : govulnScan p = some fs) :
    scanned (vulnSummary p) = true ∧ ∃ raw, vulnFindings (vulnSummary p) = some raw ∧
      (∀ f ∈ raw, validId (field f "osvId" .null) = true) ∧
      ∃ r u t, field (vulnSummary p) "reachableCount" .null = .num r ∧
        field (vulnSummary p) "unreachableCount" .null = .num u ∧
        field (vulnSummary p) "totalFindings" .null = .num t ∧
        (raw.length : Int) = r + u ∧ ((raw.filter reachableFlagged).length : Int) = r ∧
        (raw.length : Int) ≤ t := by
  unfold govulnScan at h
  dsimp only at h
  cases hf : vulnFindings (vulnSummary p) with
  | none => simp [hf] at h
  | some raw =>
    cases hr : field p "report" (.arr []) <;> simp only [hf, hr] at h <;> try (simp at h; done)
    by_cases hc : (raw.all (fun f => validId (field f "osvId" .null)) && countsAgree (vulnSummary p) raw &&
        scanned (vulnSummary p)) = true
    · simp only [Bool.and_eq_true, List.all_eq_true] at hc
      obtain ⟨⟨hid, hca⟩, hs⟩ := hc
      refine ⟨hs, raw, rfl, hid, ?_⟩
      unfold countsAgree at hca
      split at hca
      · rename_i r u t h1 h2 h3
        refine ⟨r, u, t, h1, h2, h3, ?_⟩
        simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, List.isEmpty_iff] at hca
        rcases hca with ⟨⟨⟨_, h4⟩, h5⟩, h6⟩ | ⟨⟨⟨he, h4⟩, h5⟩, h6⟩
        · exact ⟨h4, h5, h6⟩
        · subst he
          simp only [List.length_nil, List.filter_nil, Int.natCast_zero]
          omega
      · simp at hca
    · simp [hc] at h

theorem trivySeverity_sound (b : List String) (p : J) (h : trivySeverity b p = true) :
    ∃ kvs, field (field p "summary" (.obj [])) "bySeverity" .null = .obj kvs ∧
      ∀ s ∈ b, ∃ e, field (.obj kvs) s (.obj []) = .obj e ∧
        ∃ n, field (.obj e) "fail" (.num 0) = .num n ∧ n = 0 := by
  unfold trivySeverity at h
  split at h
  · rename_i kvs hk
    refine ⟨kvs, hk, fun s hs => ?_⟩
    simp only [List.all_eq_true] at h
    have := h s hs
    split at this
    · rename_i e he
      refine ⟨e, he, ?_⟩
      split at this
      · rename_i n hn; exact ⟨n, hn, by simpa using this⟩
      · simp at this
    · simp at this
  · simp at h

theorem slsaProvenance_iff (p : J) :
    slsaProvenance p = true ↔
      ∃ deps, field (field p "buildDefinition" (.obj [])) "resolvedDependencies" .null = .arr deps ∧
        deps ≠ [] ∧ ∀ d ∈ deps, hasDigest d = true := by
  unfold slsaProvenance
  split
  · rename_i deps hd
    simp only [hd, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff, List.all_eq_true,
      J.arr.injEq, exists_eq_left', ne_eq]
  · rename_i hne
    simp only [Bool.false_eq_true, false_iff, not_exists, not_and]
    intro deps hd
    exact absurd hd (hne deps)

theorem hexAtLeast_length (n : Nat) (s : String) (h : hexAtLeast n s = true) : n ≤ s.length := by
  simp only [hexAtLeast, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1

/-- Every digest value of an admitted build input is at least 32 lowercase
    hex digits, so an empty map, an empty value or a non-hex value refuses. -/
theorem hasDigest_sound (d : J) (h : hasDigest d = true) :
    ∃ k v kvs, field d "digest" .null = .obj ((k, v) :: kvs) ∧
      ∀ x ∈ (k, v) :: kvs, ∃ s, x.2 = .str s ∧ hexAtLeast 32 s = true := by
  unfold hasDigest at h
  split at h
  · rename_i kvs hk
    cases kvs with
    | nil => simp at h
    | cons kv rest =>
      refine ⟨kv.1, kv.2, rest, hk, fun x hx => ?_⟩
      simp only [Bool.and_eq_true, List.all_eq_true] at h
      have := h.2 x hx
      split at this
      · rename_i s hs; exact ⟨s, hs, this⟩
      · simp at this
  · simp at h

theorem sbomInventory_sound (p : J) (h : sbomInventory p = true) :
    (field p "_sbomFormat" (.str "") = .str "cyclonedx" ∧
      ∃ x xs, field p "components" .null = .arr (x :: xs)) ∨
    (field p "_sbomFormat" (.str "") = .str "spdx" ∧
      ∃ x xs, field p "packages" .null = .arr (x :: xs)) := by
  unfold sbomInventory at h
  dsimp only at h
  split at h
  · rename_i xs hf
    split at hf
    · rename_i hfmt
      cases xs with
      | nil => simp at h
      | cons x r => exact Or.inl ⟨hfmt, x, r, by simpa using hf⟩
    · rename_i hfmt
      cases xs with
      | nil => simp at h
      | cons x r => exact Or.inr ⟨hfmt, x, r, by simpa using hf⟩
    · simp at hf
  · simp at h

theorem reviewApproved_sound (p : J) (h : reviewApproved p = true) :
    ∃ c, field p "commit_sha" .null = .str c ∧ c ≠ "" ∧
      ∃ prs pr, field p "prs" .null = .arr prs ∧ pr ∈ prs ∧
        ∃ rv ∈ (field pr "reviews" (.arr [])).elems,
          (field rv "state" (.str "")).isStrEq "APPROVED" = true ∧
          J.eqv (field rv "commit_id" (.str "")) (.str c) = true := by
  unfold reviewApproved at h
  split at h
  · rename_i prs c hp hc
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, List.any_eq_true] at h
    obtain ⟨hne, pr, hpr, rv, hrv, hs, hid⟩ := h
    exact ⟨c, hc, hne, prs, pr, hp, hpr, rv, hrv, hs, hid⟩
  · simp at h

theorem productsFrom_sound (up : String) (i : J) (h : productsFrom up i = true) :
    ∃ l ls, field (predOf i) "leaves" .null = .arr (l :: ls) ∧ upstreamProducts i up ≠ [] ∧
      ∀ x ∈ l :: ls, ∃ d, digestOf x = some d ∧
        ∃ c ∈ upstreamProducts i up,
          ∃ y ∈ leavesOf c, digestOf y = some d := by
  unfold productsFrom at h
  simp only at h
  split at h
  · rename_i mine hm
    simp only [Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff, List.all_eq_true] at h
    obtain ⟨⟨⟨⟨hu, _⟩, _⟩, hne⟩, hall⟩ := h
    cases mine with
    | nil => simp at hne
    | cons l ls =>
      refine ⟨l, ls, hm, fun he => by simp [he] at hu, fun x hx => ?_⟩
      have := hall x hx
      split at this
      · rename_i d hd; exact ⟨d, hd, by simpa using this⟩
      · simp at this
  · simp at h

/-- A digest products-from compares is a sha256: 64 lowercase hex digits. -/
theorem digestOf_sha256 (l : J) (d : String) (h : digestOf l = some d) : hexExactly 64 d = true := by
  unfold digestOf at h
  split at h
  · split at h
    · rename_i hx; cases h; exact hx
    · simp at h
  · simp at h

theorem digestOf_nonempty (l : J) (d : String) (h : digestOf l = some d) : d ≠ "" := by
  have hx := digestOf_sha256 l d h
  intro he
  subst he
  simp [hexExactly] at hx

end CilockEvaluators.Seeded
