/-
  CilockPolicy.Policy: the signed policy document and the verify options.
  Field-for-field with `policy.go` and `step.go`, except the plain-language
  documentation fields (Policy.description, Step.title/description,
  RegoPolicy.checks), which verification never reads.
  -- cite: attestation/policy/policy.go:48-66 sha256:06c10496148ae4114e880433e54a5fb80ea4b77e0e4c79ef14eb2f56887fdc1c
  -- cite: attestation/policy/step.go:39-131 sha256:31a9a038355fd2113a8dc0647700982901eb16d766ef1e4de62934e933ca26b0
-/
import CilockPolicy.Types

namespace CilockPolicy

/-- CertConstraint (`constraints.go`). `exts` lists the Fulcio extension
    constraints; an empty value is "no constraint" for that field.
    -- cite: attestation/policy/constraints.go:109-126 sha256:fe95a235e6c8211b342070dc1f8ed8c525e1c3b52a634b0451f63ed7fce2566b
    -/
structure CertConstraint where
  cn     : String := ""
  dns    : List String := []
  emails : List String := []
  orgs   : List String := []
  uris   : List String := []
  roots  : List RootId := []
  exts   : List (String × String) := []
  oids   : List String := []
deriving DecidableEq, Repr

/-- CertConstraint.IsSet (`constraints.go`): anything but the zero value.
  -- cite: attestation/policy/constraints.go:134 sha256:76e124931953bfa3be191751652b90cbc17bcbe064713d643da240af1ea56de4
-/
def CertConstraint.isSet (cc : CertConstraint) : Bool := cc != {}

/-- Functionary (`step.go`). `type` is kept because the policy carries it,
    but Functionary.Validate never reads it (`step.go`).
    -- cite: attestation/policy/step.go:185-189 sha256:251824ce2b22fae1d014c8b22c100a52ffc12333f578412ee09f2525d2c473ad
    -- cite: attestation/policy/step.go:562-597 sha256:0be8c018de52408f0de33beca61fbfe26205cd40a30256af8907a9cef64a529c
    -/
structure Functionary where
  type      : String := "root"
  keyId     : String := ""
  cc        : CertConstraint := {}
deriving DecidableEq, Repr

/-- One required attestation. `gate` names the opaque Rego+AI bundle
    (`step.go`); its semantics is a model parameter.
    -- cite: attestation/policy/step.go:283-287 sha256:e5a7ca0bacf2e8bc2d6cdb93e579d2eacd4b25db87bf0283aadde46f3de646ca
    -/
structure AttReq where
  type : String
  gate : Nat
deriving DecidableEq, Repr

/-- TimestampConstraint (timestamp_constraint.go). `maxAge` in seconds. -/
structure TsConstraint where
  notBefore : Option Time := none
  notAfter  : Option Time := none
  maxAge    : Option Nat  := none
deriving DecidableEq, Repr

/-- Step (`step.go`). The map key is taken to equal `name` (`validate.go`; the engine refuses a mismatch under EnforceStepNameCoherence, `policy.go`).
  RequiredArtifacts (#9946) is not modelled: every step here has none, which
  the engine treats as no requirement.
  -- cite: attestation/policy/step.go:39-131 sha256:31a9a038355fd2113a8dc0647700982901eb16d766ef1e4de62934e933ca26b0
  -- cite: cilock/internal/policy/validate.go:349-352 sha256:16297b0f0b687d9a6ecf5d5b872937a20dd90d2d3c4077e1a1edfeaf55b0ac90
  -- cite: attestation/policy/policy.go:496 sha256:5839f38abbb0838072bd486680ea33d28649db7abff272bc900592e4c49a76a6
-/
structure Step where
  name             : String
  functionaries    : List Functionary
  atts             : List AttReq
  artifactsFrom    : List String := []
  attestationsFrom : List String := []
  externalFrom     : List String := []
  /-- Globs naming materials this step may consume without an upstream
      producer. Read only by the artifact pass (`untrackedOk`, Verify.lean),
      and only when `Options.enforceUntracked` holds (#9815).
  -- cite: attestation/policy/step.go:77 sha256:9461a2d8c0ca10919d3d7fff039c7e47493a76f35cb49ecef582e8ca96fed3ef
  -/
  allowedUntracked : List String := []
  tsc              : Option TsConstraint := none
  about            : String := ""
deriving DecidableEq, Repr

/-- ExternalAttestation (`step.go`). CommitSubject (#10067) is not modelled:
  every external here has none, the strict default.
  -- cite: attestation/policy/step.go:137-160 sha256:f428848ae63911b12cbee9b71352d633f391141c1170a036a688f718a95b8b08
-/
structure External where
  name          : String
  predicateType : String
  functionaries : List Functionary
  gate          : Nat
  required      : Bool := true
deriving DecidableEq, Repr

/-- Policy (`policy.go`). Steps are listed in the engine's topological
    order (`policy.go`); see `stepsOrdered`.
    -- cite: attestation/policy/policy.go:48-66 sha256:06c10496148ae4114e880433e54a5fb80ea4b77e0e4c79ef14eb2f56887fdc1c
    -- cite: attestation/policy/policy.go:603-659 sha256:d3d162656defee17a14273bb468cef2b2f65146073be5f3915fd09469454410e
    -/
structure Policy where
  expires   : Time
  roots     : List RootId
  tsas      : List RootId
  keys      : List KeyId
  steps     : List Step
  externals : List External := []
  /-- Decoded from a v0.2 envelope (payloadVersion, `policy.go`).
  -- cite: attestation/policy/policy.go:62 sha256:abe59f66ce355085caa8307e04b434b483c683f1d6c82d0ee852d543f5d72ae7
  -/
  v02       : Bool := false
deriving DecidableEq, Repr

/-- HardeningOptions (`hardening.go`). The library default is all false;
    the cilock CLI sets all true (`hardening.go`).
    -- cite: attestation/policy/hardening.go:39-84 sha256:520feb756ab0fd6e64bad161e3409051152e82d38c6a09107c9264d99826e626
    -- cite: cilock/cli/hardening.go:48-52 sha256:e4233a0469c9b3f9a113e0fb2284b5c6b53483100d1d3536faecca6de064b192
    -/
structure Hardening where
  keyIdCC       : Bool   -- EnforceCertConstraintOnKeyIDMatch (R3_184)
  emptyField    : Bool   -- RejectEmptyConstraintEmptyField   (R3_181)
  dupRego       : Bool   -- RejectDuplicateRegoPackage (Rego internals: evaluator model)
  nameCoherence : Bool   -- EnforceStepNameCoherence (R3_185/187/209)
deriving DecidableEq, Repr

def Hardening.enforce : Hardening := ⟨true, true, true, true⟩
def Hardening.warn    : Hardening := ⟨false, false, false, false⟩

/-- `h` is at least as strict as `g` on every flag. -/
def Hardening.le (g h : Hardening) : Prop :=
  (g.keyIdCC → h.keyIdCC) ∧ (g.emptyField → h.emptyField) ∧ (g.nameCoherence → h.nameCoherence)

/-- verifyOptions (`policy.go`) plus the verify clock.
  -- cite: attestation/policy/policy.go:196-228 sha256:6bf1a97f300c93d260f955e0aa8c1e3ef6e750f8c7a34d66e5048ccd31cdf755
-/
structure Options where
  now       : Time
  seeds     : List String
  skew      : Nat := 0
  commit    : Option String := none
  maxFanout : Nat := 0
  requireAll : Bool := false
  /-- Round bound for the joint fixed point of `verifyFixed` (the proposed
      #9813 semantics). Not settling within it is a failure. -/
  fixFuel   : Nat := 64
  /-- HardeningOptions.EnforceAllowedUntracked (#9815). The other hardening
      flags live in `Hardening`; this one is read only by the artifact pass,
      which takes `Options`, so it sits here. Default on, as in
      EnforcedHardening, which the cilock CLI and Judge install. The library
      zero value (`Hardening.warn`) has it off, and the oracle turns it off
      for a "warn" case (Main.lean).
      -- cite: attestation/policy/hardening.go:102-110 sha256:6ef154b976327c74787cf3cbd13a79e7167fb50ebdf58dec4395b5e63aacc50c
      -/
  enforceUntracked : Bool := true
deriving DecidableEq, Repr

end CilockPolicy
