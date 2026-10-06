# Formal model: DSSE v1.0.2 and in-toto Attestation Framework v1 (Lean 4)

A Lean 4 model of the DSSE protocol and JSON envelope, and of the in-toto
Statement and Envelope layers, set against the rookery code that emits and
reads them (#9915, epic #9914). Paths in `-- cite:` lines are
rookery-relative, because this directory syncs to aflock-ai/rookery.

- **Spec** clauses carry a `-- spec:` line quoting the normative text: DSSE
  protocol.md and envelope.md v1.0.2, and in-toto `spec/v1` statement.md,
  envelope.md, digest_set.md and resource_descriptor.md.
- **As built** definitions carry hashed `-- cite: path:a-b sha256:…` lines;
  `jade check formal-citations` fails when the cited code changes.
- **Required** definitions are the fixed behaviour, proved to meet the spec.
  Since #10058, #10060 and #10057 landed they are also the code as built,
  so the citations sit on them (`newStatementBuilt` is `newStatementReq` at
  `_type` v0.1, and `newStatementBuilt_conformsBody` proves what it signs
  meets every v1 body clause). The as-built definitions `newStatement`,
  `toCollection`, `externalRead` and `decodes` stay, uncited, as the code
  before each fix. Each fixed counterexample is now a theorem named for
  what the code does with that trace (for example
  `empty_predicateType_refused`), which also carries the original
  counterexample against the pre-fix definition. `ce_type_v01` still holds,
  and is stated against the constructor as built now.

## Results

| theorem | status | what it says |
|---|---|---|
| `lenEnc_isLen`, `isLen_unique` | proved | the length field is exactly the spec's LEN(): unique, digits only, no leading zero |
| `pae_injective` | proved | PAE(t, b) = PAE(t', b') implies t = t' and b = b' |
| `preauthEncode_eq` | proved | `preauthEncode` (Go `%d` modeled by core `Nat.toDigits`) is the spec's PAE on every input |
| `verify_iff_spec` | proved | `Envelope.Verify` accepts exactly the (t, n)-valid envelopes |
| `verify_counts_distinct` | proved | the count it reports is the number of distinct trusted keys; a duplicated signature, or one key presented as both a raw verifier and a certificate, counts once |
| `verify_ignores_keyid` | proved | KEYID never affects the verdict |
| `newStatementReq_conforms` | proved | the fixed constructor meets every v1 body clause |
| `toCollectionReq_reads`, `externalReadReq_sameBytes` | proved | the fixed readers read in-toto only when it is typed so, from the verified bytes, of a requested type |
| `decodesReq_iff` | proved | the fixed decoder accepts exactly the envelopes the parsing rules allow |
| `sidecarAccepts_iff`, `sidecar_accepted_is_signed_statement` | proved | cilock's one sidecar decoder (#10165 `decodeSidecarEnvelope`) admits exactly an envelope meeting the DSSE parsing rules with a non-empty payload, at least one signature, and a payload that is a statement naming a non-empty `predicateType` |
| `sidecar_url_safe_accepted` | proved | the payload's base64 alphabet never decides sidecar acceptance |
| `encodeUrl_eq`, `either_reads_url_as_std` | proved | the URL-safe spelling of any byte string is the standard spelling with 62/63 swapped, and reading either through `decodeBase64Field`'s either-alphabet index gives the same sextets, so both decode to the same bytes |
| `ce_type_v01` | refuted as built | `NewStatement` signs `_type` v0.1 (known: #9827, #9841) |
| `empty_predicateType_refused`, `predicate_array_refused`, `subject_without_digest_refused` (formerly `ce_empty_predicateType`, `ce_predicate_array`, `ce_subject_without_digest`) | refuted as built; fixed by #10058; each also states the pre-fix counterexample | #10030 |
| `foreign_payload_type_refused`, `external_source_decode_not_handed_on`, `external_unrequested_type_refused` (formerly `ce_foreign_payload_type`, `ce_external_not_from_verified_bytes`, `ce_external_unrequested_type`) | refuted as built; fixed by #10060; each also states the pre-fix counterexample | #10026 |
| `url_safe_accepted`, `missing_fields_refused` (formerly `ce_url_safe_refused`, `ce_missing_fields_decode`) | refuted as built; fixed by #10057; each also states the pre-fix counterexample | #10029 |

Every theorem depends only on Lean's core axioms (`propext`, `Quot.sound`,
`Classical.choice`); `DsseIntoto/Audit.lean` prints them on every build.

The model of verification is at the level DSSE is: signatures are ideal
(a key verifies a signature iff it made it over exactly that message), a
certificate is its key, whether it chains to a configured root, and its
validity window, and a TSA is the time it vouches for. Certificate path
validation and RFC 3161 are modeled in `../signing-trust` (#9917).

## Build

```bash
cd subtrees/rookery/formal/dsse-intoto
lake build        # Lean 4.34.1 via elan; no Mathlib
```

`lake build` also fails when `vectors/dsse-intoto.json` is not exactly what
`DsseIntoto/Vectors.lean` generates. Regenerate after a model change:

```bash
DSSE_INTOTO_VECTORS_REGEN=1 lake env lean --run DsseIntoto/Vectors.lean > vectors/dsse-intoto.json
```

## Differential tests

Each `// formal:differential` test replays the model's vectors against the
real code. They skip when the vectors are not on disk and FAIL instead when
`JADE_FORMAL_DIFFERENTIAL=1`.

| test | section | cases | compares |
|---|---|---|---|
| `attestation/dsse/formal_dsse_differential_test.go` | pae | 96 | `preauthEncode` bytes, bodies up to 64 KiB, UTF-8 and space-bearing types |
| | verify | 819 | `Envelope.Verify` verdict and distinct-key count, real P-256 keys, real X.509 leaves under trusted and untrusted roots, FakeTimestamper TSAs, fallback on and off |
| | decode | 288 | `json.Unmarshal` into `Envelope`, per base64 alphabet and field presence |
| | alphabet | 32 | `decodeBase64Field` on the model's standard and URL-safe spellings of each byte string: both decode to exactly those bytes |
| `cilock/cli/formal_sidecar_differential_test.go` (lands with #10165) | sidecar | 504 | `decodeSidecarEnvelope` accept/refuse per field presence, alphabet and payload content |
| `attestation/intoto/formal_statement_differential_test.go` | statement | 70 | `NewStatement` refusals and emitted `_type`, subjects, predicateType, predicate kind |
| `attestation/source/formal_consume_differential_test.go` | consume | 91 | `EnvelopeToCollectionEnvelope` |
| | external | 27 | `VerifiedSource.SearchByPredicateType` over a source that lies about its decode, searched for the claimed or the signed type |

Constants `envelopeDecodeModel`, `newStatementModel` and `consumeModel` name
the model each area must match: `asbuilt` until its fix lands, then
`required`. All three fixes have landed (#10057, #10058, #10060), so all
three name `required`; the `ce_*` counterexamples stand as statements about
the code before those fixes.

Sabotage (measured on the pinned commit): PAE length taken mod 1000 gives
24/96 PAE mismatches; dropping the #5237 no-timestamp gate gives 7/819
verify mismatches; inflating the verified-key count gives 133/819. Pointing
each area at the `required` model before its fix lands gives 169/288
decode, 57/70 statement, 17/91 consume and 16/27 external mismatches; with the three fixes applied the same `required` runs agree on every case.

## Holdout

Run once, after the model and the three fixes were final, against
origin/main 562f2b08c7 plus #10026, #10029 and #10030. Nothing below was
used to build or tune the model. The runner is a `formalholdout`-tagged test
that is not committed, because it links every attestor and the in-toto
reference module.

| holdout | result | disagreements |
|---|---|---|
| DSSE PAE vectors (protocol.md and go-securesystemslib `TestPAE`) | 3/3 | none |
| DSSE protocol.md example envelope (P-256) | 2/3 | the raw `r‖s` signature does not verify: rookery's ECDSA verifier takes ASN.1 DER. The same signature re-encoded as DER verifies. DSSE leaves the signature format to be "agreed upon out-of-band", so this is not a conformance failure. |
| go-securesystemslib base64 vectors (std, URL-safe, both unpadded) | 4/4 | none (with #10029) |
| in-toto `go/v1` statement vectors, through the verified read path | 6/11 | the reader accepts a statement with no subjects, a subject with no digest, a subject with none of name, uri or digest, an empty `predicateType`, and no `predicate`. The model's reading clause (`SpecReads`) checked the envelope and `_type` but not the statement body, and the holdout caught that gap. The two digest-less subjects and the empty `predicateType` break spec MUSTs and are filed as #10068. "No predicate" is valid in the spec prose ("`predicate` _object, optional_"), and only the reference `Validate` refuses it. "No subjects" is open. The prose says only "required", and cilock itself signs `subject: []` for a step that produces no artifact, so refusing it would make those steps unverifiable. That is a product call, and it is recorded on #10068. Since then `decodeInTotoStatement` refuses the two digest-less subjects and the empty `predicateType` (#10068); this holdout has not been re-run. |
| 26 recorded cilock fixtures, through the in-toto `Statement` type (strict protojson plus `Validate`) | 26/26 | none |
| statements cilock emits now: a real `workflow.RunWithExports` with material, command-run, product and exported slsa, plus a VSA built the way `cilock verify` builds it, checked against the in-toto `Statement`, `provenance/v1` and `verification_summary/v1` types | 5/5 | none. On main, the slsa predicateType is still `v1.0`; #9827 and #9879 own that. |

## What is assumed, not proved

- Go's `%d` of a non-negative `int` is `Nat.toDigits 10` (the differential
  checks it up to 65,536).
- ECDSA and the X.509/TSA layers behave as the ideal model says; the
  differential drives them for real, and `../signing-trust` models them.
- The digest values attestors put in subjects are lowercase hex for the
  standard algorithm names. The constructor does not check this, and this
  model does not prove it.

The spec is the asset: if the code changes, the as-built half can be
rebuilt from the cited lines in a day, and the proofs then say whether it
still conforms.
