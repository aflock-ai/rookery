/-
  SigningTrust.Audit: every headline result and the axioms it rests on.
  `lake build` prints one `#print axioms` line per theorem; each must list
  only Lean's core axioms (propext, Quot.sound, Classical.choice).
  `sorryAx` or `Lean.ofReduceBool` in any line is a failure.
-/
import SigningTrust.Counterexamples

namespace SigningTrust

-- RFC 5280 path validation and the signing profile
#print axioms x509VerifyReq_iff
#print axioms x509Verify_never_ca_leaf
#print axioms x509VerifyReq_never_ca_leaf
#print axioms x509VerifyReq_leaf_signs
-- RFC 3161 / 5816 and the verify time
#print axioms tspVerify_returns_genTime
#print axioms tspVerify_now_irrelevant
#print axioms tspVerifyReq_iff
#print axioms dsseCertOk_now_irrelevant
#print axioms dsseCertOk_at_genTime
#print axioms reissue_keeps_verifying
-- the code at the pin: what holds and what is refuted
#print axioms ca_leaf_refused
#print axioms ce_leaf_without_digitalSignature
#print axioms ce_token_without_ess
#print axioms ce_token_ess_names_other_cert
#print axioms go_refuses_more_on_anchor
#print axioms leaf_pinning_breaks_reissue

end SigningTrust
