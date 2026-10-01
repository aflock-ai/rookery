-- cite: attestation/policy/rego.go:63-255 sha256:76586675bac26f9f675a7427cf9971fdf95d83dffd0072c1a204d1b5375f936c
-- cite: attestation/policy/rego.go:33-38 sha256:842103b4eef11ae89d6e0fb75474a4d1a430065ebfa01b7c1f5f105babbc4a01
-- cite: attestation/policy/rego.go:101-101 sha256:8ba0d3e19b058269478748cefd49715d8105ef20fdab122a0c62ac2c673a451e
-- cite: attestation/policy/rego.go:169-182 sha256:f2d1c2a9adf342f61c56856c27a0c0cae27c3249c2afa71d0151297c4852eebe
-- cite: attestation/policy/regoallow.go:24-31 sha256:44a14ab874136e53c7aa6002846fcadaf5346339eeb7e1c5e71aabc3b5cbdaa7
-- cite: attestation/policy/regostrict.go:81-101 sha256:7f64aa8be20a2e978d2b539e29c9bf3471a9d704542b12fae7df2f6a7d70f653
-- cite: attestation/policy/regorefusal.go:19-30 sha256:809bb7442173a1ef44dde9b334669736344fdbcb3ca455b7088f83b10d8b820f
/-
  CilockEvaluators.Rego: `EvaluateRegoPolicy` / `evaluateRegoInput`
  (attestation/policy/rego.go), with the checks it runs before and after the
  deny query: the unread-`allow` refusal (regoallow.go) and the missing-field
  refusal (regostrict.go).

  OPA itself is not modelled. What the evaluator does with OPA's answer is:
  the model receives, per package path, the value OPA computed for
  `data.<pkg>.deny` after merging every module of that package, a flag for
  "OPA returned an error" (compile error, builtin error under
  StrictBuiltinErrors, conflicting complete rules), whether that error is the
  30 s deadline (rego.go), and what regostrict.go's missing-field probe
  reported. Everything the Go code decides from those values is modelled
  exactly.
-/
import CilockEvaluators.Types

namespace CilockEvaluators.Rego

open CilockEvaluators

-- cite: attestation/policy/rego.go:201-229 sha256:f629fd993e64c26bf4d6e346f8b27f9a1346a2ee40e3e2ce50bbd6dc7ca4f41e
/-- The value OPA returns for `data.<pkg>.deny`, as the evaluator sees it
(rego.go). -/
inductive DenyValue where
  -- cite: attestation/policy/rego.go:189-189 sha256:4828acdaaf08996f04b4636ab0ba4537d822c7b4b5fed3237bf575bc173cc4b5
  /-- No `deny` rule in the package, or a complete `deny` rule whose body did
  not fire. The query row is then missing (rego.go). -/
  | undefined
  -- cite: attestation/policy/rego.go:194-225 sha256:dcce83b5314db62f42eb9f8046c2c65933768e78501cc5dfc542198ebb97ec8b
  /-- A set (`[]interface{}`) or object (`map[string]interface{}`). `n` is its
  number of elements; element types do not matter (rego.go). -/
  | collection (n : Nat)
  -- cite: attestation/policy/rego.go:226-227 sha256:fe7d27bcaff68433465a646333cfe7e5c3ef9c8138d4cfd31cad0646ebda2a1e
  /-- Any other JSON value: boolean, number, string, null (rego.go). -/
  | scalar
  deriving DecidableEq, Repr

-- cite: attestation/policy/rego.go:126-129 sha256:fa2694426e2b64f34dd53131bea0cc5716d9ec79a6221e2d82af139eab73128a
-- cite: attestation/policy/regoallow.go:58-76 sha256:da706586ccdb852b7a2a53ab964fdbe451d801b63644406ea780b1778ff40948
/-- One module of the `regopolicies` list. `parses` abstracts
`ast.ParseModule` (rego.go). `allowUnread` abstracts `checkAllowUsed`
(regoallow.go): the set compiles, this module defines `allow`, and no rule
that `deny` reaches refers to it. -/
structure Module where
  name : String
  pkg : String
  parses : Bool
  allowUnread : Bool
  deriving DecidableEq, Repr

-- cite: attestation/policy/regostrict.go:28-58 sha256:c5a1116b0f62cd47dfcf1f768f454db0f22277a44b0e025567054cf029cd45da
-- cite: attestation/policy/regostrict.go:103-123 sha256:0dc126d08e508cc2af6bfdcb281d52324f90be98887ccea7050c2476cf71239e
/-- What regostrict.go's missing-field probe reports. It runs only after the
deny query admitted, against the same input and under the same deadline.
* `clean`: no input read an admitting deny body depended on is undefined;
* `missing`: some such read is undefined, or the probe could not be built or
  evaluated (both are errors, regostrict.go);
* `timeout`: the shared deadline ran out during the probe (regostrict.go). -/
inductive Probe where
  | clean
  | missing
  | timeout
  deriving DecidableEq, Repr

/-- What OPA produced for one evaluation. `allow` is carried only so the model
can state that nothing reads it. `timeout` says whether a `fault` is the
deadline or a cancellation (`ctx.Err() != nil`, rego.go). -/
structure OpaRun where
  fault : Bool
  timeout : Bool
  deny : String → DenyValue
  allow : String → Option Bool
  probe : Probe

-- cite: attestation/policy/rego.go:132-148 sha256:c9fab1498b4544e08727c26e727f66d6c79912a203cfa99979be0efc34ed91db
/-- Two modules share a package (rego.go). -/
def hasDupPkg : List Module → Bool
  | [] => false
  | m :: ms => ms.any (fun n => n.pkg == m.pkg) || hasDupPkg ms

def DenyValue.isUndefined : DenyValue → Bool
  | .undefined => true
  | _ => false

def DenyValue.isScalar : DenyValue → Bool
  | .scalar => true
  | _ => false

def DenyValue.nonEmpty : DenyValue → Bool
  | .collection n => n != 0
  | _ => false

-- cite: attestation/policy/hardening.go:55-60 sha256:d6eedfa047d5874d20eec2f9466a069f138103e5f86f015f8f0f701826fc00f0
-- cite: attestation/policy/rego.go:63-65 sha256:f7ad4788660ef2733252e69afa3d5557e9aa471420923b55606cc8459586b0ff
-- cite: attestation/policy/rego.go:88-92 sha256:0e64ef6b6f918c2896be460470c9a9da5a72be10c9edcc84f5330f6ba94179d1
-- cite: attestation/policy/rego.go:126-129 sha256:fa2694426e2b64f34dd53131bea0cc5716d9ec79a6221e2d82af139eab73128a
-- cite: attestation/policy/rego.go:142-145 sha256:917cf75f3dc243cd95443572aa04b52e883a1aa7d866c34b0ea37f4026b55356
-- cite: attestation/policy/rego.go:133-136 sha256:f1124a69976cbfc14aa79c7bf72e8ee3acdadd6fa3d452edc57bd22076239638
-- cite: attestation/policy/rego.go:169-182 sha256:f2d1c2a9adf342f61c56856c27a0c0cae27c3249c2afa71d0151297c4852eebe
-- cite: attestation/policy/rego.go:189-191 sha256:c3de20442e68a81e757aaae977cec966e4fa27d3c3924633da910b7d6aca8b65
-- cite: attestation/policy/rego.go:226-227 sha256:fe7d27bcaff68433465a646333cfe7e5c3ef9c8138d4cfd31cad0646ebda2a1e
-- cite: attestation/policy/rego.go:232-233 sha256:8652ff077745e11f2003b1666ef3c4c0c42d5ff4e3db04531c39cb35eae5ae44
-- cite: attestation/policy/rego.go:121-126 sha256:57c560957a350c92e4d5c7fe8087f3e948e3a8f82f281e73a5ed8824740360b4
-- cite: attestation/policy/regostrict.go:82-101 sha256:7f85cf00e3427d6486044bde567d70cd7fc82643742ef80f07b825712cbf5eeb
/-- The evaluator. `rejectDup` is `Hardening().RejectDuplicateRegoPackage`
(hardening.go, default false).

Order, as in the Go code:
1. no modules: pass (rego.go);
2. a module that does not parse: error (rego.go);
3. a module whose `allow` no deny reaches: error (`CheckRegoAllowUsed`,
   regoallow.go, #9870); a set that does not compile skips this check and
   fails at step 2 or 5 instead, so the order of 2 and 3 does not matter;
4. a duplicate package with hardening on: error (rego.go);
   without it the query names the package once and OPA merges (rego.go);
5. OPA error: refused when it is the deadline, else error (rego.go, #9872);
6. some queried `deny` undefined: the conjunctive query has no row: error (rego.go);
7. some `deny` not a collection: `ErrRegoInvalidData` (rego.go);
8. some `deny` non-empty: deny (rego.go);
9. otherwise the admit goes to the missing-field probe: clean passes, a
   missing read is an error, a deadline is refused (regostrict.go, #9869). -/
def eval (rejectDup : Bool) (mods : List Module) (run : OpaRun) : Verdict :=
  if mods.isEmpty then .pass
  else if mods.any (fun m => !m.parses) then .error
  else if mods.any (fun m => m.allowUnread) then .error
  else if rejectDup && hasDupPkg mods then .error
  else if run.fault then (if run.timeout then .refused else .error)
  else if mods.any (fun m => (run.deny m.pkg).isUndefined) then .error
  else if mods.any (fun m => (run.deny m.pkg).isScalar) then .error
  else if mods.any (fun m => (run.deny m.pkg).nonEmpty) then .deny
  else match run.probe with
    | .clean => .pass
    | .missing => .error
    | .timeout => .refused

/-! ## Characterisation -/

/-- The exact pass condition: no modules, or every module parses, no module
has an unread `allow`, no enforced duplicate, no OPA fault, every module's
`deny` is an EMPTY collection, and the missing-field probe is clean. -/
theorem eval_pass_iff (rd : Bool) (mods : List Module) (run : OpaRun) :
    eval rd mods run = .pass ↔
      mods = [] ∨
      ((∀ m ∈ mods, m.parses = true) ∧ (∀ m ∈ mods, m.allowUnread = false) ∧
        ¬ (rd = true ∧ hasDupPkg mods = true) ∧
        run.fault = false ∧ (∀ m ∈ mods, run.deny m.pkg = .collection 0) ∧
        run.probe = .clean) := by
  unfold eval
  cases mods with
  | nil => simp
  | cons m ms =>
    simp only [List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte, reduceCtorEq, false_or]
    by_cases hp : (m :: ms).any (fun m => !m.parses) = true
    · simp only [hp, ↓reduceIte, reduceCtorEq, false_iff, not_and]
      intro hall
      simp only [List.any_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true] at hp
      obtain ⟨x, hx, hxp⟩ := hp
      have := hall x hx
      simp_all
    · simp only [hp, Bool.false_eq_true, ↓reduceIte]
      have hall : ∀ x ∈ m :: ms, x.parses = true := by
        intro x hx
        simp only [List.any_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, not_exists, not_and] at hp
        have := hp x hx
        cases h : x.parses <;> simp_all
      by_cases ha : (m :: ms).any (fun m => m.allowUnread) = true
      · simp only [ha, ↓reduceIte, reduceCtorEq, false_iff, not_and]
        intro _ hna
        simp only [List.any_eq_true] at ha
        obtain ⟨x, hx, hxa⟩ := ha
        rw [hna x hx] at hxa; cases hxa
      · simp only [ha, Bool.false_eq_true, ↓reduceIte]
        have hna : ∀ x ∈ m :: ms, x.allowUnread = false := by
          intro x hx
          simp only [List.any_eq_true, not_exists, not_and] at ha
          have := ha x hx
          cases h : x.allowUnread <;> simp_all
        by_cases hd : (rd && hasDupPkg (m :: ms)) = true
        · simp only [hd, ↓reduceIte, reduceCtorEq, false_iff, not_and]
          intro _ _ hn
          simp only [Bool.and_eq_true] at hd
          exact absurd (hn hd.1 hd.2) id
        · simp only [hd, Bool.false_eq_true, ↓reduceIte]
          have hd' : ¬ (rd = true ∧ hasDupPkg (m :: ms) = true) := by
            simpa [Bool.and_eq_true] using hd
          by_cases hf : run.fault = true
          · simp only [hf, ↓reduceIte]
            cases run.timeout <;> simp
          · simp only [hf, Bool.false_eq_true, ↓reduceIte]
            by_cases hu : (m :: ms).any (fun m => (run.deny m.pkg).isUndefined) = true
            · simp only [hu, ↓reduceIte, reduceCtorEq, false_iff, not_and]
              intro _ _ _ _ hc
              simp only [List.any_eq_true] at hu
              obtain ⟨x, hx, hxu⟩ := hu
              rw [hc x hx] at hxu
              simp [DenyValue.isUndefined] at hxu
            · simp only [hu, Bool.false_eq_true, ↓reduceIte]
              by_cases hs : (m :: ms).any (fun m => (run.deny m.pkg).isScalar) = true
              · simp only [hs, ↓reduceIte, reduceCtorEq, false_iff, not_and]
                intro _ _ _ _ hc
                simp only [List.any_eq_true] at hs
                obtain ⟨x, hx, hxs⟩ := hs
                rw [hc x hx] at hxs
                simp [DenyValue.isScalar] at hxs
              · simp only [hs, Bool.false_eq_true, ↓reduceIte]
                by_cases hn : (m :: ms).any (fun m => (run.deny m.pkg).nonEmpty) = true
                · simp only [hn, ↓reduceIte, reduceCtorEq, false_iff, not_and]
                  intro _ _ _ _ hc
                  simp only [List.any_eq_true] at hn
                  obtain ⟨x, hx, hxn⟩ := hn
                  rw [hc x hx] at hxn
                  simp [DenyValue.nonEmpty] at hxn
                · simp only [hn, Bool.false_eq_true, ↓reduceIte]
                  have hcoll : ∀ x ∈ m :: ms, run.deny x.pkg = .collection 0 := by
                    intro x hx
                    simp only [List.any_eq_true, not_exists, not_and] at hu hs hn
                    have h1 := hu x hx
                    have h2 := hs x hx
                    have h3 := hn x hx
                    cases hv : run.deny x.pkg with
                    | undefined => simp [hv, DenyValue.isUndefined] at h1
                    | scalar => simp [hv, DenyValue.isScalar] at h2
                    | collection k =>
                      cases k with
                      | zero => rfl
                      | succ k => simp [hv, DenyValue.nonEmpty] at h3
                  cases hpr : run.probe with
                  | clean => exact iff_of_true rfl ⟨hall, hna, hd', trivial, hcoll, rfl⟩
                  | missing => simp
                  | timeout => simp

/-! ## E1 for Rego: every failure mode rejects -/

theorem fault_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (hne : mods ≠ []) (hf : run.fault = true) : eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, h, _⟩
  · exact hne h
  · rw [hf] at h; cases h

theorem parse_error_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (hp : m.parses = false) : eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨h, _⟩
  · subst h; cases hm
  · rw [h m hm] at hp; cases hp

-- cite: attestation/policy/rego.go:184-191 sha256:ad71a34ef52e2833d16bfb472e7b0df3e1c76b0034953ac5e77b9f11d922ce7a
/-- A module whose package defines no `deny` (or whose complete `deny` did not
fire) cannot pass: the missing-deny bypass is closed (rego.go). -/
theorem undefined_deny_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (hu : run.deny m.pkg = .undefined) :
    eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, _, h, _⟩
  · subst h; cases hm
  · rw [h m hm] at hu; cases hu

-- cite: attestation/policy/rego.go:226-227 sha256:fe7d27bcaff68433465a646333cfe7e5c3ef9c8138d4cfd31cad0646ebda2a1e
/-- A `deny` that is a boolean, number, string or null cannot pass (rego.go). -/
theorem scalar_deny_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (hs : run.deny m.pkg = .scalar) :
    eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, _, h, _⟩
  · subst h; cases hm
  · rw [h m hm] at hs; cases hs

-- cite: attestation/policy/rego.go:194-233 sha256:12379b4c601fbba254dbb681c638b8e45efbbec5ff4fffe4e764c86356758328
/-- Any element in any queried `deny` rejects, whatever the element is
(`deny[42]`; rego.go). -/
theorem nonempty_deny_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (n : Nat) (hn : run.deny m.pkg = .collection (n + 1)) :
    eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, _, h, _⟩
  · subst h; cases hm
  · rw [h m hm] at hn; cases hn

-- cite: attestation/policy/rego.go:121-126 sha256:57c560957a350c92e4d5c7fe8087f3e948e3a8f82f281e73a5ed8824740360b4
/-- An admit that the missing-field probe does not clear cannot pass: a
missing read is an error and a probe deadline a refusal (regostrict.go,
#9869). -/
theorem probe_unclean_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (hne : mods ≠ []) (hp : run.probe ≠ .clean) : eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, _, _, h⟩
  · exact hne h
  · exact hp h

-- cite: attestation/policy/rego.go:169-182 sha256:f2d1c2a9adf342f61c56856c27a0c0cae27c3249c2afa71d0151297c4852eebe
/-- A refusal comes only from the deadline: the deny query or the probe ran
out of time (rego.go, regostrict.go). Nothing else the evaluator sees
produces `refused`, and the deadline never produces a pass or a deny
(#9872: a timeout is unsigned, not a FAILED verdict). -/
theorem refused_only_on_deadline (rd : Bool) (mods : List Module) (run : OpaRun)
    (h : eval rd mods run = .refused) :
    (run.fault = true ∧ run.timeout = true) ∨ run.probe = .timeout := by
  unfold eval at h
  repeat' split at h
  all_goals first
    | (simp at h; done)
    | (left; constructor <;> assumption)
    | (right; assumption)

/-! ## E2 for Rego: several modules combine by AND -/

-- cite: attestation/policy/rego.go:135-135 sha256:09ea9c05e2ef7098b2cdd568a6092391627da77a631ff73a26576a18aa2073ea
-- cite: attestation/policy/rego.go:166-166 sha256:b97b564fb367eeded2b269656dc4e00daa95b5e330a659347c06e21b34235c12
/-- With several modules, the result passes only if EVERY module's package
yields an empty `deny`. The query is one conjunctive expression list
(rego.go), so this is AND, never OR. -/
theorem modules_conjunctive (rd : Bool) (mods : List Module) (run : OpaRun)
    (h : eval rd mods run = .pass) : ∀ m ∈ mods, run.deny m.pkg = .collection 0 ∧ m.parses = true := by
  intro m hm
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨hp, _, _, _, hd, _⟩
  · subst h; cases hm
  · exact ⟨hd m hm, hp m hm⟩

/-! ## E3: polarity is deny-only and cannot be inverted by module content -/

-- cite: attestation/policy/rego.go:132-136 sha256:678cbbaa4a072c5410115df5e47a5db9a30166123a8151deb1c6f64c8d4538ea
-- cite: attestation/policy/rego.go:166-166 sha256:b97b564fb367eeded2b269656dc4e00daa95b5e330a659347c06e21b34235c12
/-- The verdict does not depend on the value of `allow` or of any rule other
than `deny`: two runs that agree on `deny`, on the fault and its kind, and on
the probe give the same verdict. The only query the evaluator builds is
`<pkg>.deny` (rego.go). -/
theorem only_deny_is_read (rd : Bool) (mods : List Module) (r₁ r₂ : OpaRun)
    (hf : r₁.fault = r₂.fault) (ht : r₁.timeout = r₂.timeout) (hp : r₁.probe = r₂.probe)
    (hd : ∀ p, r₁.deny p = r₂.deny p) :
    eval rd mods r₁ = eval rd mods r₂ := by
  have : r₁.deny = r₂.deny := funext hd
  unfold eval; rw [hf, ht, hp, this]

/-- `allow` in particular is inert: its value is never read. -/
theorem allow_is_inert (rd : Bool) (mods : List Module) (run : OpaRun) (a : String → Option Bool) :
    eval rd mods { run with allow := a } = eval rd mods run :=
  only_deny_is_read rd mods _ _ rfl rfl rfl (fun _ => rfl)

/-- A module that defines neither `deny` nor `allow` cannot pass. -/
theorem neither_rejects (rd : Bool) (m : Module) (run : OpaRun)
    (hd : run.deny m.pkg = .undefined) : eval rd [m] run ≠ .pass :=
  undefined_deny_rejects rd [m] run m (by simp) hd

-- cite: attestation/policy/regoallow.go:38-56 sha256:4d1971a960e394378f0e10caba5aa2a53c2733b7c9395858bad526f145604a3c
/-- A module that defines an `allow` no deny depends on cannot pass, whatever
its `deny` says: the set is refused before evaluation (regoallow.go, #9870). -/
theorem allow_unread_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (ha : m.allowUnread = true) : eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, h, _⟩
  · subst h; cases hm
  · rw [h m hm] at ha; cases ha

-- cite: attestation/policy/regolint.go:29-48 sha256:3aaece87646daabb73eaf4c32725b9083a204fde94dcb67f1cc6bcd665be1e00
-- cite: attestation/policy/rego.go:94-97 sha256:de8a8a83d5a2569f8851e25a1b8bcdcc396838ceb4f41514f3499b08bc62be53
-- cite: attestation/policy/regolint.go:45-48 sha256:db237813944a5ab2ac43ac1c3a0f4b853f964fb1fcbb52964ca9d7f8ff2304f8
-- cite: attestation/policy/regolint.go:402-409 sha256:22a5184016f5a510b13ac9cadd0078dde9e2ca9d474b3ab43a423430e906baa8
-- cite: attestation/policy/regostrict.go:28-58 sha256:c5a1116b0f62cd47dfcf1f768f454db0f22277a44b0e025567054cf029cd45da
/-! ## The deny-body hazard (regolint.go, regostrict.go)

The deny query alone cannot be fail-closed about the BODIES that build the
`deny` value: a body that reads a missing input field is undefined, so its
element is not added, and an empty set is the passing value. The OPA compiler
hoists input reads out of `not`, so `not startswith(input.reftype, "tag")`
never fires when `reftype` is absent. regolint.go reports this; since #9869
regostrict.go also re-asks Rego, after an admit, whether any read an
admitting deny body depended on was undefined for the bindings it had, and
turns such an admit into an error (rego.go, regostrict.go). The
micro-language below reproduces both halves. -/

/-- A deny-body literal over one input field. `negHoisted f v` is the compiled
form of `not (input.f == v)`: `x = input.f; not x == v`. -/
inductive Lit where
  | fieldEq (f v : String)
  | negHoisted (f v : String)
  deriving DecidableEq, Repr

/-- The input field a literal reads. -/
def Lit.field : Lit → String
  | .fieldEq f _ => f
  | .negHoisted f _ => f

/-- `none` is "undefined": the body stops. -/
def Lit.holds (input : String → Option String) : Lit → Bool
  | .fieldEq f v => input f == some v
  | .negHoisted f v =>
    match input f with
    | none => false          -- the hoisted read is undefined: body fails
    | some x => x != v

/-- A partial-set `deny` rule: one message per body that fires. -/
def denyOf (bodies : List (List Lit)) (input : String → Option String) : DenyValue :=
  .collection (bodies.filter (fun b => b.all (Lit.holds input))).length

-- cite: attestation/policy/regostrict.go:421-480 sha256:518e582a9097196dfd4b72c446ea771aca3481d062f9721272614f26e3ce3053
/-- regostrict.go's probe for one body: for each literal, the literals before
it hold and its read is undefined (`addProbe`: the body's prefix, then
`count([1 | v = target]) == 0`). Both literal kinds are probed: a positive
comparison in a deny body, and a negation the lint reports. -/
def bodyMisses (input : String → Option String) : List Lit → Bool
  | [] => false
  | l :: ls => (input l.field).isNone || (l.holds input && bodyMisses input ls)

def probeOf (bodies : List (List Lit)) (input : String → Option String) : Probe :=
  if bodies.any (bodyMisses input) then .missing else .clean

/-- The run of one module whose deny is `bodies`, on `input`. -/
def litRun (bodies : List (List Lit)) (input : String → Option String) : OpaRun :=
  ⟨false, false, fun _ => denyOf bodies input, fun _ => none, probeOf bodies input⟩

/-- E1's former boundary, closed. The policy author meant "deny unless the ref
is a tag". On an input with no `reftype` at all the deny query admits, and
the probe turns that admit into an error.

As built at the first version of this model (testifysec/judge#9820) the same
trace PASSED (`hoisted_negation_admits_missing_field`, refuted as built);
fixed by #9869 (regostrict.go). -/
theorem hoisted_negation_missing_field_rejected :
    let m : Module := ⟨"tag-gate", "tag", true, false⟩
    let bodies := [[Lit.negHoisted "reftype" "tag"]]
    (litRun bodies (fun _ => none)).deny "tag" = .collection 0 ∧
      eval false [m] (litRun bodies (fun _ => none)) = .error := by
  decide

/-- The same policy on an input that has the field with a wrong value denies. -/
theorem hoisted_negation_denies_present_field :
    let m : Module := ⟨"tag-gate", "tag", true, false⟩
    let bodies := [[Lit.negHoisted "reftype" "tag"]]
    eval false [m] (litRun bodies (fun f => if f = "reftype" then some "branch" else none)) = .deny := by
  decide

/-- In the micro-language, an empty `deny` that some body produced only
because a read was undefined never passes: whenever a body is silenced by a
missing field, the module is rejected. -/
theorem missing_read_never_passes (rd : Bool) (m : Module) (bodies : List (List Lit))
    (input : String → Option String) (h : bodies.any (bodyMisses input) = true) :
    eval rd [m] (litRun bodies input) ≠ .pass := by
  apply probe_unclean_rejects rd [m] _ (by simp)
  simp [litRun, probeOf, h]

/-- A module with an empty `deny` and `allow := false`, where `deny` does not
read `allow`, is REFUSED (regoallow.go, #9870). As built at the first version
of this model it passed (`both_defined_allow_false_passes`, testifysec/judge#9820);
`allow` is still never queried (`allow_is_inert`), but a module can no longer
define one that gates nothing. -/
theorem both_defined_allow_unread_rejected :
    let m : Module := ⟨"both", "both", true, true⟩
    let run : OpaRun := ⟨false, false, fun _ => .collection 0, fun _ => some false, .clean⟩
    eval false [m] run = .error := by
  decide

/-- Duplicate packages: without hardening two same-package modules are merged
and can pass together; with `RejectDuplicateRegoPackage` they are an error. -/
theorem duplicate_package_merged_by_default :
    let a : Module := ⟨"a", "p", true, false⟩
    let b : Module := ⟨"b", "p", true, false⟩
    let run : OpaRun := ⟨false, false, fun _ => .collection 0, fun _ => none, .clean⟩
    eval false [a, b] run = .pass ∧ eval true [a, b] run = .error := by
  decide

end CilockEvaluators.Rego
