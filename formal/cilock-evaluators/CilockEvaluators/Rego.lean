-- cite: attestation/policy/rego.go:59-212 sha256:d62dd37a8b189d2fa3c5c7a19e743369b312ab4b7d66e9ff118e12e637bf6de3
-- cite: attestation/policy/rego.go:35-35 sha256:daec36e5dd1531d7c807faa9c2b4578625f22a9953668db2671690ee88f65498
-- cite: attestation/policy/rego.go:91-91 sha256:8ba0d3e19b058269478748cefd49715d8105ef20fdab122a0c62ac2c673a451e
-- cite: attestation/policy/rego.go:154-157 sha256:b2d28c2ac3bc9cdbee3c1c4a90b13024b96b6330f1ad8badb6672695bee74b28
/-
  CilockEvaluators.Rego: `EvaluateRegoPolicy` / `evaluateRegoInput`
  (attestation/policy/rego.go).

  OPA itself is not modelled. What the evaluator does with OPA's answer is:
  the model receives, per package path, the value OPA computed for
  `data.<pkg>.deny` after merging every module of that package, plus a single
  flag for "OPA returned an error" (compile error, builtin error under
  StrictBuiltinErrors, conflicting complete rules, or the 30 s context
  deadline, rego.go). Everything the Go code decides from those
  values is modelled exactly.
-/
import CilockEvaluators.Types

namespace CilockEvaluators.Rego

open CilockEvaluators

-- cite: attestation/policy/rego.go:176-204 sha256:f629fd993e64c26bf4d6e346f8b27f9a1346a2ee40e3e2ce50bbd6dc7ca4f41e
/-- The value OPA returns for `data.<pkg>.deny`, as the evaluator sees it
(rego.go). -/
inductive DenyValue where
  -- cite: attestation/policy/rego.go:164-164 sha256:4828acdaaf08996f04b4636ab0ba4537d822c7b4b5fed3237bf575bc173cc4b5
  /-- No `deny` rule in the package, or a complete `deny` rule whose body did
  not fire. The query row is then missing (rego.go). -/
  | undefined
  -- cite: attestation/policy/rego.go:169-200 sha256:dcce83b5314db62f42eb9f8046c2c65933768e78501cc5dfc542198ebb97ec8b
  /-- A set (`[]interface{}`) or object (`map[string]interface{}`). `n` is its
  number of elements; element types do not matter (rego.go). -/
  | collection (n : Nat)
  -- cite: attestation/policy/rego.go:201-202 sha256:fe7d27bcaff68433465a646333cfe7e5c3ef9c8138d4cfd31cad0646ebda2a1e
  /-- Any other JSON value: boolean, number, string, null (rego.go). -/
  | scalar
  deriving DecidableEq, Repr

-- cite: attestation/policy/rego.go:111-114 sha256:fa2694426e2b64f34dd53131bea0cc5716d9ec79a6221e2d82af139eab73128a
/-- One module of the `regopolicies` list. `parses` abstracts
`ast.ParseModule` (rego.go). -/
structure Module where
  name : String
  pkg : String
  parses : Bool
  deriving DecidableEq, Repr

/-- What OPA produced for one evaluation. `allow` is carried only so the model
can state that nothing reads it. -/
structure OpaRun where
  fault : Bool
  deny : String → DenyValue
  allow : String → Option Bool

-- cite: attestation/policy/rego.go:117-133 sha256:c9fab1498b4544e08727c26e727f66d6c79912a203cfa99979be0efc34ed91db
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
-- cite: attestation/policy/rego.go:60-62 sha256:f7ad4788660ef2733252e69afa3d5557e9aa471420923b55606cc8459586b0ff
-- cite: attestation/policy/rego.go:111-114 sha256:fa2694426e2b64f34dd53131bea0cc5716d9ec79a6221e2d82af139eab73128a
-- cite: attestation/policy/rego.go:127-130 sha256:917cf75f3dc243cd95443572aa04b52e883a1aa7d866c34b0ea37f4026b55356
-- cite: attestation/policy/rego.go:118-121 sha256:f1124a69976cbfc14aa79c7bf72e8ee3acdadd6fa3d452edc57bd22076239638
-- cite: attestation/policy/rego.go:154-157 sha256:b2d28c2ac3bc9cdbee3c1c4a90b13024b96b6330f1ad8badb6672695bee74b28
-- cite: attestation/policy/rego.go:164-166 sha256:c3de20442e68a81e757aaae977cec966e4fa27d3c3924633da910b7d6aca8b65
-- cite: attestation/policy/rego.go:201-202 sha256:fe7d27bcaff68433465a646333cfe7e5c3ef9c8138d4cfd31cad0646ebda2a1e
-- cite: attestation/policy/rego.go:207-208 sha256:8652ff077745e11f2003b1666ef3c4c0c42d5ff4e3db04531c39cb35eae5ae44
-- cite: attestation/policy/rego.go:211-211 sha256:ada1d7914809e3499d4573e8bfe5826ae082ea2e2a14db7cc14172577c6a735a
/-- The evaluator. `rejectDup` is `Hardening().RejectDuplicateRegoPackage`
(hardening.go, default false).

Order, as in the Go code:
1. no modules: pass (rego.go);
2. a module that does not parse: error (rego.go);
3. a duplicate package with hardening on: error (rego.go);
   without it the query names the package once and OPA merges (rego.go);
4. OPA error or timeout: error (rego.go);
5. some queried `deny` undefined: the conjunctive query has no row: error (rego.go);
6. some `deny` not a collection: `ErrRegoInvalidData` (rego.go);
7. some `deny` non-empty: deny (rego.go);
8. otherwise pass (rego.go). -/
def eval (rejectDup : Bool) (mods : List Module) (run : OpaRun) : Verdict :=
  if mods.isEmpty then .pass
  else if mods.any (fun m => !m.parses) then .error
  else if rejectDup && hasDupPkg mods then .error
  else if run.fault then .error
  else if mods.any (fun m => (run.deny m.pkg).isUndefined) then .error
  else if mods.any (fun m => (run.deny m.pkg).isScalar) then .error
  else if mods.any (fun m => (run.deny m.pkg).nonEmpty) then .deny
  else .pass

/-! ## Characterisation -/

/-- The exact pass condition: no modules, or every module parses, no enforced
duplicate, no OPA fault, and every module's `deny` is an EMPTY collection. -/
theorem eval_pass_iff (rd : Bool) (mods : List Module) (run : OpaRun) :
    eval rd mods run = .pass ↔
      mods = [] ∨
      ((∀ m ∈ mods, m.parses = true) ∧ ¬ (rd = true ∧ hasDupPkg mods = true) ∧
        run.fault = false ∧ ∀ m ∈ mods, run.deny m.pkg = .collection 0) := by
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
      by_cases hd : (rd && hasDupPkg (m :: ms)) = true
      · simp only [hd, ↓reduceIte, reduceCtorEq, false_iff, not_and]
        intro _ hn
        simp only [Bool.and_eq_true] at hd
        exact absurd (hn hd.1 hd.2) id
      · simp only [hd, Bool.false_eq_true, ↓reduceIte]
        have hd' : ¬ (rd = true ∧ hasDupPkg (m :: ms) = true) := by
          simpa [Bool.and_eq_true] using hd
        by_cases hf : run.fault = true
        · simp [hf]
        · simp only [hf, Bool.false_eq_true, ↓reduceIte]
          have hf' : run.fault = false := by simpa using hf
          by_cases hu : (m :: ms).any (fun m => (run.deny m.pkg).isUndefined) = true
          · simp only [hu, ↓reduceIte, reduceCtorEq, false_iff, not_and]
            intro _ _ _ hc
            simp only [List.any_eq_true] at hu
            obtain ⟨x, hx, hxu⟩ := hu
            rw [hc x hx] at hxu
            simp [DenyValue.isUndefined] at hxu
          · simp only [hu, Bool.false_eq_true, ↓reduceIte]
            by_cases hs : (m :: ms).any (fun m => (run.deny m.pkg).isScalar) = true
            · simp only [hs, ↓reduceIte, reduceCtorEq, false_iff, not_and]
              intro _ _ _ hc
              simp only [List.any_eq_true] at hs
              obtain ⟨x, hx, hxs⟩ := hs
              rw [hc x hx] at hxs
              simp [DenyValue.isScalar] at hxs
            · simp only [hs, Bool.false_eq_true, ↓reduceIte]
              by_cases hn : (m :: ms).any (fun m => (run.deny m.pkg).nonEmpty) = true
              · simp only [hn, ↓reduceIte, reduceCtorEq, false_iff, not_and]
                intro _ _ _ hc
                simp only [List.any_eq_true] at hn
                obtain ⟨x, hx, hxn⟩ := hn
                rw [hc x hx] at hxn
                simp [DenyValue.nonEmpty] at hxn
              · simp only [hn, Bool.false_eq_true, ↓reduceIte, true_iff]
                refine ⟨hall, hd', by first | trivial | exact hf', ?_⟩
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

/-! ## E1 for Rego: every failure mode rejects -/

theorem fault_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (hne : mods ≠ []) (hf : run.fault = true) : eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, h, _⟩
  · exact hne h
  · rw [hf] at h; cases h

theorem parse_error_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (hp : m.parses = false) : eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨h, _, _, _⟩
  · subst h; cases hm
  · rw [h m hm] at hp; cases hp

-- cite: attestation/policy/rego.go:159-166 sha256:ad71a34ef52e2833d16bfb472e7b0df3e1c76b0034953ac5e77b9f11d922ce7a
/-- A module whose package defines no `deny` (or whose complete `deny` did not
fire) cannot pass: the missing-deny bypass is closed (rego.go). -/
theorem undefined_deny_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (hu : run.deny m.pkg = .undefined) :
    eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, h⟩
  · subst h; cases hm
  · rw [h m hm] at hu; cases hu

-- cite: attestation/policy/rego.go:201-202 sha256:fe7d27bcaff68433465a646333cfe7e5c3ef9c8138d4cfd31cad0646ebda2a1e
/-- A `deny` that is a boolean, number, string or null cannot pass (rego.go). -/
theorem scalar_deny_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (hs : run.deny m.pkg = .scalar) :
    eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, h⟩
  · subst h; cases hm
  · rw [h m hm] at hs; cases hs

-- cite: attestation/policy/rego.go:169-208 sha256:12379b4c601fbba254dbb681c638b8e45efbbec5ff4fffe4e764c86356758328
/-- Any element in any queried `deny` rejects, whatever the element is
(`deny[42]`; rego.go). -/
theorem nonempty_deny_rejects (rd : Bool) (mods : List Module) (run : OpaRun)
    (m : Module) (hm : m ∈ mods) (n : Nat) (hn : run.deny m.pkg = .collection (n + 1)) :
    eval rd mods run ≠ .pass := by
  intro h
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨_, _, _, h⟩
  · subst h; cases hm
  · rw [h m hm] at hn; cases hn

/-- The evaluator never produces `refused`: that constructor is reserved for AI. -/
theorem eval_ne_refused (rd : Bool) (mods : List Module) (run : OpaRun) :
    eval rd mods run ≠ .refused := by
  unfold eval; split <;> (try split) <;> (try split) <;> (try split) <;> (try split) <;>
    (try split) <;> (try split) <;> simp

/-! ## E2 for Rego: several modules combine by AND -/

-- cite: attestation/policy/rego.go:120-120 sha256:09ea9c05e2ef7098b2cdd568a6092391627da77a631ff73a26576a18aa2073ea
-- cite: attestation/policy/rego.go:151-151 sha256:b97b564fb367eeded2b269656dc4e00daa95b5e330a659347c06e21b34235c12
/-- With several modules, the result passes only if EVERY module's package
yields an empty `deny`. The query is one conjunctive expression list
(rego.go), so this is AND, never OR. -/
theorem modules_conjunctive (rd : Bool) (mods : List Module) (run : OpaRun)
    (h : eval rd mods run = .pass) : ∀ m ∈ mods, run.deny m.pkg = .collection 0 ∧ m.parses = true := by
  intro m hm
  rcases (eval_pass_iff rd mods run).1 h with h | ⟨hp, _, _, hd⟩
  · subst h; cases hm
  · exact ⟨hd m hm, hp m hm⟩

/-! ## E3: polarity is deny-only and cannot be inverted by module content -/

-- cite: attestation/policy/rego.go:117-121 sha256:678cbbaa4a072c5410115df5e47a5db9a30166123a8151deb1c6f64c8d4538ea
-- cite: attestation/policy/rego.go:151-151 sha256:b97b564fb367eeded2b269656dc4e00daa95b5e330a659347c06e21b34235c12
/-- The verdict does not depend on `allow` or on any rule other than `deny`:
two runs that agree on `deny` and on the fault flag give the same verdict. The
only query the evaluator builds is `<pkg>.deny` (rego.go). -/
theorem only_deny_is_read (rd : Bool) (mods : List Module) (r₁ r₂ : OpaRun)
    (hf : r₁.fault = r₂.fault) (hd : ∀ p, r₁.deny p = r₂.deny p) :
    eval rd mods r₁ = eval rd mods r₂ := by
  have : r₁.deny = r₂.deny := funext hd
  unfold eval; rw [hf, this]

/-- `allow` in particular is inert. -/
theorem allow_is_inert (rd : Bool) (mods : List Module) (run : OpaRun) (a : String → Option Bool) :
    eval rd mods { run with allow := a } = eval rd mods run :=
  only_deny_is_read rd mods _ _ rfl (fun _ => rfl)

/-- A module that defines neither `deny` nor `allow` cannot pass. -/
theorem neither_rejects (rd : Bool) (m : Module) (run : OpaRun)
    (hd : run.deny m.pkg = .undefined) : eval rd [m] run ≠ .pass :=
  undefined_deny_rejects rd [m] run m (by simp) hd

-- cite: attestation/policy/regolint.go:29-49 sha256:afe1ccf5acd2dc6712f35937b18d8fb8103a36e41751e7b0b74b76e880b31f2d
-- cite: attestation/policy/rego.go:85-87 sha256:f866fac95091d8a73c8bba6c0f7825cd364e755db711ec40deb6a46383c340f3
-- cite: attestation/policy/regolint.go:44-49 sha256:f0fa96f68bdc54e707cd80a4601c0efc2e3c03e9898308dfb739b8d9403c4b71
-- cite: attestation/policy/regolint.go:403-410 sha256:22a5184016f5a510b13ac9cadd0078dde9e2ca9d474b3ab43a423430e906baa8
/-! ## The deny-body hazard (regolint.go)

`eval` is fail-closed about the value OPA returns for `deny`. It cannot be
fail-closed about the BODIES that build that value: a body that reads a
missing input field is undefined, so its element is not added, and an empty
set is the passing value. The OPA compiler hoists input reads out of `not`,
so `not startswith(input.reftype, "tag")` never fires when `reftype` is
absent. regolint.go reports this as a WARNING only (rego.go,
regolint.go). The micro-language below reproduces it. -/

/-- A deny-body literal over one input field. `negHoisted f v` is the compiled
form of `not (input.f == v)`: `x = input.f; not x == v`. -/
inductive Lit where
  | fieldEq (f v : String)
  | negHoisted (f v : String)
  deriving DecidableEq, Repr

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

/-- The policy author meant "deny unless the ref is a tag". On an input with
no `reftype` at all, the evaluator PASSES. This is E1's boundary: an undefined
`deny` rejects, an undefined sub-expression inside a deny body admits. -/
-- Tracked: testifysec/judge#9820
theorem hoisted_negation_admits_missing_field :
    let m : Module := ⟨"tag-gate", "tag", true⟩
    let bodies := [[Lit.negHoisted "reftype" "tag"]]
    let run : OpaRun := ⟨false, fun _ => denyOf bodies (fun _ => none), fun _ => none⟩
    eval false [m] run = .pass := by
  decide

/-- The same policy on an input that has the field with a wrong value denies. -/
theorem hoisted_negation_denies_present_field :
    let m : Module := ⟨"tag-gate", "tag", true⟩
    let bodies := [[Lit.negHoisted "reftype" "tag"]]
    let run : OpaRun :=
      ⟨false, fun _ => denyOf bodies (fun f => if f = "reftype" then some "branch" else none),
        fun _ => none⟩
    eval false [m] run = .deny := by
  decide

/-- A module with an empty `deny` and `allow := false` PASSES: defining both
does not make `allow` count. Under a deny-only convention this is intended,
and it is the concrete sense in which E3's "defines both cannot pass" is
false as stated. -/
-- Tracked: testifysec/judge#9820
theorem both_defined_allow_false_passes :
    let m : Module := ⟨"both", "both", true⟩
    let run : OpaRun := ⟨false, fun _ => .collection 0, fun _ => some false⟩
    eval false [m] run = .pass := by
  decide

/-- Duplicate packages: without hardening two same-package modules are merged
and can pass together; with `RejectDuplicateRegoPackage` they are an error. -/
theorem duplicate_package_merged_by_default :
    let a : Module := ⟨"a", "p", true⟩
    let b : Module := ⟨"b", "p", true⟩
    let run : OpaRun := ⟨false, fun _ => .collection 0, fun _ => none⟩
    eval false [a, b] run = .pass ∧ eval true [a, b] run = .error := by
  decide

end CilockEvaluators.Rego
