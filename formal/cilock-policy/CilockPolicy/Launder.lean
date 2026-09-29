/-
  CilockPolicy.Launder: testifysec/judge#9813, as a machine-checked trace.

  Before #9860 the attestationsFrom Rego context was built from the
  dependency's Passed set before artifactsFrom pruning, so a collection that
  the engine REJECTS for a broken artifact chain could still decide a
  dependent step's Rego (`verifyAsBuilt`). #9860 reads the context from the
  converged results instead (`regoContextResults`, `policy.go`; the context
  builder, `step.go`; pruning, `policy.go`), and `fixed_flooded_fails`
  holds for it. The differential test keeps this trace as its sensitivity
  check: the pre-#9860 model must disagree with the engine on it.

  Reproduced against the Go engine on d023787f95, before the fix, with the
  same shape (lazy_fixtures_test.go helpers): control FAIL, with the rejected
  scan PASS, the scan recorded as "mismatched digests for app.bin".
  -- cite: attestation/policy/policy.go:1006 sha256:3c4ad285bf16007f3ad8d88adef106e95609d49f88b1c8358a1d292a39b17cde
  -- cite: attestation/policy/step.go:730-758 sha256:736a4b92255e9b790d8c3f61dd2a1bf887f81a1d160d0ea34e24cae1868ae0ad
  -- cite: attestation/policy/policy.go:1148 sha256:c2e494e031a8e25b0662fe4d1a69e0567568aa36eaf18bff7f72ddc8fc8d88c0
-/
import CilockPolicy.Fixtures

namespace CilockPolicy.Launder
open CilockPolicy CilockPolicy.Fixtures

def srcStep : Step := step "source"
def scanStep : Step := { step "scan" with artifactsFrom := ["source"] }
def gateStep : Step := { step "gate" 1 with attestationsFrom := ["scan"] }
def pol : Policy := basePolicy [srcStep, scanStep, gateStep]

def source : Envelope := env "source-1" (coll "source" [] [] [("app.bin", [("sha256", builtD)])])
/-- A clean scan of a DIFFERENT input: its material chain does not link. -/
def scanClean : Envelope :=
  env "a-scan-clean" (coll "scan" [⟨"clean", 1, none⟩] [("app.bin", [("sha256", otherD)])])
/-- The scan of the real input: the chain links, no clean result. -/
def scanReal : Envelope := env "b-scan-real" (coll "scan" [] [("app.bin", [("sha256", builtD)])])
def gateC : Envelope := env "gate-1" (coll "gate")

def control : List Envelope := [source, scanReal, gateC]
def flooded : List Envelope := [source, scanClean, scanReal, gateC]

/-- Control: the only linked scan is not clean, so the gate fails. -/
theorem control_fails : verifyAsBuilt rego regoExt .enforce pol opts control = false := by decide

/-- Adding a collection the engine itself rejects flips FAIL to PASS. -/
theorem flooded_passes : verifyAsBuilt rego regoExt .enforce pol opts flooded = true := by decide

/-- ...and the engine does reject it: it is not among the scan survivors. -/
theorem scanClean_pruned :
    scanClean ∉ (prune pol opts (phaseAsBuilt rego .enforce pol opts flooded [])).get "scan" := by
  decide

/-- Under the joint fixed point the flood changes nothing. -/
theorem fixed_flooded_fails : verifyFixed rego regoExt .enforce pol opts flooded = false := by decide
theorem fixed_control_fails : verifyFixed rego regoExt .enforce pol opts control = false := by decide

end CilockPolicy.Launder
