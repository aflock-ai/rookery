/-
  SigningTrust.Counterexamples: where the code at the pinned commit departs
  from the spec, each a closed term the kernel checks.
-/
import SigningTrust.Tsp

namespace SigningTrust

def root : Cert := ⟨1, true, true, none, some ⟨false, false, true⟩, .none, 0, 1000, false⟩
def leafWith (ku : Option KU) (eku : EKU) : Cert := ⟨2, true, false, none, ku, eku, 100, 200, false⟩

/-- A signing leaf whose keyUsage asserts only keyEncipherment is accepted:
    Go ignores the leaf's keyUsage bits. -/
def encLeafPath : Path := ⟨leafWith (some ⟨false, false, false⟩) .codeSigning, [], some root⟩

theorem ce_leaf_without_digitalSignature :
    x509Verify encLeafPath 150 = true ∧ specPath encLeafPath 150 = false ∧ x509VerifyReq encLeafPath 150 = false := by
  decide

/-- A CA leaf is refused as built (#9842, fixed by #9876). -/
def caLeafPath : Path := ⟨⟨2, true, true, none, some ⟨true, false, true⟩, .codeSigning, 100, 200, false⟩, [], some root⟩

theorem ca_leaf_refused : x509Verify caLeafPath 150 = false := by decide

/-- Go is stricter than RFC 5280 on the anchor: a spec-valid path under an
    anchor without basicConstraints is refused. Conservative; kept. -/
def bareAnchorPath : Path :=
  ⟨leafWith (some ⟨true, false, false⟩) .codeSigning, [], some ⟨1, false, false, none, none, .none, 0, 1000, false⟩⟩

theorem go_refuses_more_on_anchor :
    specPath bareAnchorPath 150 = true ∧ x509VerifyReq bareAnchorPath 150 = false := by decide

def tsaLeaf (id : Nat) (nb na : Time) : Cert := ⟨id, true, false, none, some ⟨true, false, false⟩, .timeStamping, nb, na, false⟩

def tok (ess : Ess) : Token := ⟨.sha256, true, true, 150, some 150, tsaLeaf 2 100 200, root, ess⟩

/-- A token with no ESS signing-certificate attribute verifies. -/
theorem ce_token_without_ess :
    tspVerify [1] (tok .none) 5000 = some 150 ∧ ¬ tspSpec [1] (tok .none) ∧ tspVerifyReq [1] (tok .none) 5000 = none := by
  refine ⟨by decide, ?_, by decide⟩
  intro h; exact absurd h.2.2.2.2.1 (by decide)

/-- A token whose ESS attribute names a different certificate verifies. -/
theorem ce_token_ess_names_other_cert :
    tspVerify [1] (tok .v2BadHash) 5000 = some 150 ∧ tspVerifyReq [1] (tok .v2BadHash) 5000 = none := by
  decide

/-- Trust configuration, not code: pinning the TSA LEAF instead of its root
    breaks re-issue. A token minted under leaf 2 stops verifying once the
    configuration names only the re-issued leaf 3, though nothing about the
    token changed. (With the root anchored, `reissue_keeps_verifying`.) -/
def reissued : Token := { tok .v2 with root := { root with id := 9 } }

theorem leaf_pinning_breaks_reissue :
    tspVerify [2] reissued 5000 = some 150 ∧ tspVerify [3] reissued 5000 = none := by decide

end SigningTrust
