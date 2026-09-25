/-
  DsseIntoto.Audit: every headline result and the axioms it rests on.
  `lake build` prints one `#print axioms` line per theorem; each must list
  only Lean's core axioms (propext, Quot.sound, Classical.choice).
  `sorryAx` or `Lean.ofReduceBool` in any line is a failure.
-/
import DsseIntoto.Counterexamples
import DsseIntoto.Verify

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
#print axioms toCollectionReq_reads
#print axioms externalReadReq_sameBytes
#print axioms decodesReq_iff
-- the code at the pin, refuted
#print axioms ce_type_v01
#print axioms ce_empty_predicateType
#print axioms ce_predicate_array
#print axioms ce_subject_without_digest
#print axioms ce_foreign_payload_type
#print axioms ce_external_not_from_verified_bytes
#print axioms ce_external_unrequested_type
#print axioms ce_url_safe_refused
#print axioms ce_missing_fields_decode

end DsseIntoto
