/-
  DsseIntoto.Audit: every headline result and the axioms it rests on.
  `lake build` prints one `#print axioms` line per theorem; each must list
  only Lean's core axioms (propext, Quot.sound, Classical.choice).
  `sorryAx` or `Lean.ofReduceBool` in any line is a failure.
-/
import DsseIntoto.Counterexamples
import DsseIntoto.Verify
import DsseIntoto.Sidecar

namespace DsseIntoto

-- PAE
#print axioms lenEnc_isLen
#print axioms isLen_unique
#print axioms pae_injective
#print axioms preauthEncode_eq
#print axioms preauthEncode_injective
-- verification
#print axioms verify_iff_spec
#print axioms verify_counts_distinct
#print axioms verify_ignores_keyid
-- the fixed behaviour
#print axioms newStatementReq_conforms
#print axioms newStatementBuilt_conformsBody
#print axioms toCollectionReq_reads
#print axioms externalReadReq_sameBytes
#print axioms decodesReq_iff
-- sidecar acceptance (#10165) and the base64 alphabets
#print axioms sidecarAccepts_iff
#print axioms sidecar_accepted_is_signed_statement
#print axioms sidecar_url_safe_accepted
#print axioms encodeUrl_eq
#print axioms either_reads_url_as_std
-- the code at the pin, refuted; still holds as built
#print axioms ce_type_v01
-- refuted at the pin, fixed since (each carries its original counterexample)
#print axioms empty_predicateType_refused
#print axioms predicate_array_refused
#print axioms subject_without_digest_refused
#print axioms foreign_payload_type_refused
#print axioms external_source_decode_not_handed_on
#print axioms external_unrequested_type_refused
#print axioms url_safe_accepted
#print axioms missing_fields_refused

end DsseIntoto
