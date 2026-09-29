/-
  CilockPolicy.LinkingCounterexamples: where the linking statements, read
  literally, fail, plus the L2 and L4 facts that are per-collection.
-/
import CilockPolicy.LinkingOptions
import CilockPolicy.Fixtures
import CilockPolicy.Bound9813

namespace CilockPolicy.LinkingCounterexamples
open CilockPolicy CilockPolicy.Fixtures

def one : Policy := basePolicy [step "build"]

/-! ## L2 / Theorem 3: the algorithm label is compared (testifysec/judge#9816, fixed by #9863) -/

/-- The seed is a sha256 digest; the verifier keys it `sha256:<value>`
    (`policyverify.go`). A subject that carries the same value under the
    `gitoid:sha256` label is keyed `gitoid:sha256:<value>` and no longer
    anchors the match. Before #9863 seeds were bare values and this envelope
    verified; that was the #9816 counterexample.
    -- cite: plugins/attestors/policyverify/policyverify.go:117-134 sha256:237f48662d314cab35a32b69eb277b293aa328896b84e717a3ce9548e4f5790b
    -/
def relabelled : Envelope :=
  env "r" { coll "build" with subjects := [⟨"x", ⟨"gitoid:sha256", seedD⟩⟩] }

theorem l2_algorithm_label_compared : verifyFixed rego regoExt .enforce one opts [relabelled] = false := by
  decide

/-- The strict half of L2 that does hold: an artifactsFrom hop compares
    DigestSets with DigestSet.Equal, which refuses to fall back to a weaker
    shared algorithm (GHSA-pgpm-j729-qcvh). -/
theorem l2_no_downgrade :
    dsEq [("sha1", "x")] [("sha1", "x"), ("sha256", builtD)] = false ∧
    dsEq [("sha256", builtD)] [("sha256", builtD), ("sha1", "y")] = true := by decide

/-! ## L4: BackRefs are never read -/

/-- A collection whose only link to the seed is a BackRef is not found: the
    engine follows no relationship edge (`policy.go`, `policy.go`).
    -- cite: attestation/policy/policy.go:296-302 sha256:622ef1746c7cbd22794ce5b31a655ad8578aa11f15a245e63b8434b4c875e82a
    -- cite: attestation/policy/policy.go:974-979 sha256:02729af599c32c78c149bc44223b5c85ab327eaf880015995a092724246ced22
    -/
def viaBackRef : Envelope :=
  env "b" { coll "build" with subjects := [⟨"x", ⟨"sha256", otherD⟩⟩], backRefs := [⟨"sha256", seedD⟩] }

theorem l4_backref_not_followed : verifyFixed rego regoExt .enforce one opts [viaBackRef] = false := by
  decide

/-- Every per-collection decision ignores BackRefs, so an attacker's choice of
    BackRef subjects cannot change one. (Rego sees attestors and input.steps
    collections {reference, name, attestations, and the verifier-derived
    tsaTime since #10528}, `step.go`, not BackRefs.)
    -- cite: attestation/policy/step.go:688-698 sha256:7403de55e807cc68fb49a22de3ad4f4ba039c68243f8df00fd3dff0990bdaa8a
    -/
theorem l4_backrefs_irrelevant (h : Hardening) (p : Policy) (o : Options) (s : Step) (e : Envelope)
    (rego : Rego) (ctx : Ctx) (u : Collection) (b : List Digest) :
    authorized h p o s { e with payload := { e.payload with backRefs := b } } = authorized h p o s e ∧
    gate rego o s ctx { e.payload with backRefs := b } = gate rego o s ctx e.payload ∧
    edgeOk o { e.payload with backRefs := b } u = edgeOk o e.payload u :=
  ⟨rfl, rfl, rfl⟩

/-! ## V6: AllowedUntracked (testifysec/judge#9815, enforced since #9862) -/

def srcStep : Step := step "source"
def buildStep : Step := { step "build" with artifactsFrom := ["source"], allowedUntracked := [] }
def chainPol : Policy := basePolicy [srcStep, buildStep]
def srcEnv : Envelope := env "s" (coll "source" [] [] [("app.bin", [("sha256", builtD)])])
/-- Consumes the real product AND a material nobody produced. -/
def injected : Envelope :=
  env "i" (coll "build" [] [("app.bin", [("sha256", builtD)]), ("/tmp/injected.sh", [("sha256", otherD)])])

/-- With `allowedUntracked = []`, documented as STRICT (`step.go`), an
    untracked material rejects the collection under EnforceAllowedUntracked,
    which EnforcedHardening turns on for the cilock CLI and Judge
    (`allowed_untracked.go`, called after the edge loop in `policy.go`).
    With the flag off, the library zero value, compareArtifacts skips the
    material and the chain passes (the pre-#9862 behaviour). A glob in
    `allowedUntracked` excuses it, and `*` stays inside one path segment.
    -- cite: attestation/policy/step.go:70-77 sha256:556edead02680ff85bcbf7b05ca1fdd18be3f2f29bd7026bf3d3f40c3615b742
    -- cite: attestation/policy/allowed_untracked.go:143-162 sha256:fd50a952b4fd8d99f65804bca12b9c6b4c03b3e360e70b4691a25edfadfc9606
    -- cite: attestation/policy/policy.go:2634-2636 sha256:93112d8f7b6e5a90b7d93151f030f13f2f75ed13bbc40f22787a289769c61b85
    -/
def allowPol (g : String) : Policy :=
  basePolicy [srcStep, { buildStep with allowedUntracked := [g] }]

theorem v6_untracked_material :
    verifyFixed rego regoExt .enforce chainPol opts [srcEnv, injected] = false ∧
    verifyFixed rego regoExt .warn chainPol { opts with enforceUntracked := false }
      [srcEnv, injected] = true ∧
    verifyFixed rego regoExt .enforce (allowPol "/tmp/**") opts [srcEnv, injected] = true ∧
    verifyFixed rego regoExt .enforce (allowPol "/tmp/*") opts [srcEnv, injected] = true ∧
    verifyFixed rego regoExt .enforce (allowPol "/*") opts [srcEnv, injected] = false := by decide

/-- The model's `**` needs its literal neighbours on both sides: `a**a`
    does not excuse the path `a`. The engine's gobwas matcher used to (it
    let a literal prefix and suffix overlap); allowedUntracked now matches
    through the RE2 translation cert constraints use, and
    `TestFormalDifferentialGlobs` holds it to this answer. -/
theorem v6_overlap_not_allowed :
    untrackedAllowed { buildStep with allowedUntracked := ["a**a"] } "a" = false := by decide

/-- The RE2 translation's answers on the cases the gobwas matcher got wrong
    or that the old model left unspecified, each checked by `decide` against
    the full grammar (`sepGlob`, Verify.lean): the literals around `**` never
    overlap (`vendor/**/x.go` does not excuse `vendor/x.go`, while
    `vendor/**/*.go` excuses `vendor/a/b.go`); a run of three `*` is `**`; a
    class ignores the separator (`[!a]` admits `/`); braces expand, and a
    `}` or `,` outside braces is a literal. -/
theorem v6_re2_grammar :
    sepGlob "vendor/**/x.go" "vendor/x.go" = false ∧
    sepGlob "vendor/**/x.go" "vendor/a/x.go" = true ∧
    sepGlob "vendor/**/*.go" "vendor/a/b.go" = true ∧
    sepGlob "vendor/*.go" "vendor/a/b.go" = false ∧
    sepGlob "a***" "a" = true ∧
    sepGlob "a***" "a/b/c" = true ∧
    sepGlob "[!a]" "/" = true ∧
    sepGlob "?" "/" = false ∧
    sepGlob "{a,b}/*" "b/c" = true ∧
    sepGlob "{a,b}/*" "c/c" = false ∧
    sepGlob "{a,{b,c}}" "c" = true ∧
    sepGlob "a}," "a}," = true ∧
    sepGlob "cilock{,.exe}" "cilock.exe" = true ∧
    sepGlob "\\*" "*" = true ∧
    sepGlob "\\*" "a" = false := by decide

/-- requireAll is the reverse direction and does hold: every upstream artifact
    must be consumed. -/
theorem requireAll_consumes {o : Options} (ho : o.requireAll = true) {c u : Collection}
    (h : edgeOk o c u = true) : ∀ a ∈ artifacts u, (c.materials.lookup a.1).isSome = true := by
  simp only [edgeOk, ho, Bool.not_true, Bool.false_or, Bool.and_eq_true, List.all_eq_true] at h
  exact h.2

/-! ## Theorem 7 with the fan-out guard: PASS -> FAIL (documented) -/

/-- maxFanout = 1. A second AUTHORIZED collection on the same seed, which
    itself FAILS its gate, makes the seed a hub and demotes the good one
    (`policy.go` says so). Opt-in; cilock verify never sets it.
    -- cite: attestation/policy/policy.go:1433-1450 sha256:5e9863ea9e233cf1c62b5167d761080b6703e83ca83423931b0aca24adc02a23
    -/
def fanOpts : Options := { opts with maxFanout := 1 }
def good : Envelope := env "g" (coll "build")
def badGate : Envelope := env "x" { coll "build" with attestors := [⟨"other", 0, none⟩] }

theorem fanout_flood_flips :
    verifyFixed rego regoExt .enforce one fanOpts [good] = true ∧
    verifyFixed rego regoExt .enforce one fanOpts [good, badGate] = false := by decide

/-! ## L5: artifactsFrom cycles, and the joint iteration's bound -/

/-- The joint fixed point does not cycle-check artifactsFrom: two collections
    that each consume the other's product both survive the greatest fixed
    point. The engine no longer reaches that point. Since #9860 Validate refuses
    an artifactsFrom cycle before any evidence is read (`policy.go`, as
    cilock's static validator did, `validate.go`), which `verifyShipped`
    states through `unionAcyclic`.
    -- cite: attestation/policy/policy.go:2292-2298 sha256:9866424669cd90ea2c8f3f795c82526c2dd2155673f24649448a3b4f0eaff014
    -- cite: cilock/internal/policy/validate.go:443 sha256:d60598f26e04616b9da3fd7fc8f4bea5ba6a738a9f31fa01d1e49a500a78d4e5
    -/
def aStep : Step := { step "a" with artifactsFrom := ["b"] }
def bStep : Step := { step "b" with artifactsFrom := ["a"] }
def cyc : Policy := basePolicy [aStep, bStep]
def aEnv : Envelope := env "a" (coll "a" [] [("y", [("sha256", otherD)])] [("x", [("sha256", builtD)])])
def bEnv : Envelope := env "b" (coll "b" [] [("x", [("sha256", builtD)])] [("y", [("sha256", otherD)])])

theorem l5_artifact_cycle_passes : verifyFixed rego regoExt .enforce cyc opts [aEnv, bEnv] = true ∧
    verifyShipped rego regoExt .enforce cyc opts [aEnv, bEnv] = false := by
  decide

/-- A policy whose joint iteration never settles: `b`'s gate passes only when
    `a` has no survivor, and `a` survives only with a `b` partner. The fixed
    semantics exhausts its bound and FAILS closed; as-built also fails. -/
def regoOsc : Rego := fun g _ ctx => g == 0 || ctx.steps.isEmpty
def oa : Step := { step "a" with artifactsFrom := ["b"] }
def ob : Step := { step "b" 1 with attestationsFrom := ["a"] }
def osc : Policy := basePolicy [oa, ob]
def oaEnv : Envelope := env "a" (coll "a" [] [("x", [("sha256", builtD)])])
def obEnv : Envelope := env "b" (coll "b" [] [] [("x", [("sha256", builtD)])])

theorem l5_oscillation_fails_closed :
    fixLoop regoOsc .enforce osc opts [oaEnv, obEnv] [] opts.fixFuel
      (prune osc opts (phaseFrom regoOsc .enforce osc opts [oaEnv, obEnv] [] [])) = none ∧
    verifyFixed regoOsc regoExt .enforce osc opts [oaEnv, obEnv] = false ∧
    verifyAsBuilt regoOsc regoExt .enforce osc opts [oaEnv, obEnv] = false := by decide


/-! ## The hardened-git SHA-1 subject arm (`isGitCommitSubject`)
  -- cite: attestation/cryptoutil/digestset.go:216-681 sha256:abeaf498c5237a990f7ecf8fc00a18380c745e230eb2c38ef849bdcdd758a078
-/
namespace GitSubject

def sha : String := "3d7b1c0e9f2a4b6c8d0e1f2a3b4c5d6e7f8a9b0c"
def shaUpper : String := "3D7B1C0E9F2A4B6C8D0E1F2A3B4C5D6E7F8A9B0C"
def subj (name value : String) : Subject := ⟨name, ⟨"sha1", value⟩⟩

/-- The null object id never anchors, even under a hardened git attestation
    and a name bound to it. -/
theorem null_oid_not_matchable :
    matchable true (subj ("commithash:" ++ gitNullOID) gitNullOID) = false := by decide +kernel

/-- The bare and hardened-namespaced forms anchor; only the digest is case-folded. -/
theorem commit_forms_matchable :
    matchable true (subj ("commithash:" ++ sha) sha) = true ∧
    matchable true (subj ("commithash:" ++ shaUpper) sha) = true ∧
    matchable true (subj (hardenedGitType ++ "/commithash:" ++ sha) sha) = true := by decide +kernel

/-- Everything before the digest is exact: another attestor's namespace, a
    case variant of the git type, a missing segment boundary, a relabelled
    digest, and the sha1 arm outside a hardened git collection all refuse. -/
theorem commit_forms_refused :
    matchable true (subj ("https://aflock.ai/attestations/sbom/v0.1/commithash:" ++ sha) sha) = false ∧
    matchable true (subj ("https://aflock.ai/attestations/GIT/v0.1/commithash:" ++ sha) sha) = false ∧
    matchable true (subj ("notacommithash:" ++ sha) sha) = false ∧
    matchable true (subj ("commithash:" ++ sha) "3d7b1c0e9f2a4b6c8d0e1f2a3b4c5d6e7f8a9b0d") = false ∧
    matchable false (subj ("commithash:" ++ sha) sha) = false := by decide +kernel

end GitSubject

end CilockPolicy.LinkingCounterexamples
