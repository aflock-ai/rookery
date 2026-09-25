# Formal model: signing trust (Lean 4)

X.509 path validation (the RFC 5280 subset rookery relies on) and RFC 3161
time-stamp verification with the RFC 5816 ESSCertIDv2 update, for
testifysec/judge#9917 (epic #9914).

The issue asks to *extend* `subtrees/rookery/formal/signing-trust`. No such
project existed on `origin/main` or on any branch when this was written
(2026-09-25), so this project creates it.

## What is modeled

| file | what |
|---|---|
| `SigningTrust/X509.lean` | certificates, the path Go builds, RFC 5280 §6.1 subset + signing profile (`specPath`), Go's `Verify` (`goVerify`), `X509Verifier.Verify` before #10097 (`x509Verify`), its path checks as built (`x509VerifyReq`), and the whole verifier with the CT check (`x509VerifyCT`) |
| `SigningTrust/Tsp.lean` | RFC 3161 tokens, `TSPVerifier.Verify` as built and as required, how `dsse/verify.go` uses the verified time, TSA re-issue |
| `SigningTrust/Counterexamples.lean` | where the code departs from the spec, each a `decide`d term |
| `SigningTrust/Vectors.lean` | generates `vectors/signing-trust.json`; `lake build` fails when it is stale |
| `SigningTrust/Audit.lean` | `#print axioms` for every headline result |

Every as-built definition carries hashed `-- cite:` lines (rookery-relative
paths); every spec definition carries `-- spec:` lines quoting the RFC. Go's
own `crypto/x509` (go1.26.6) is described in `X509.lean`'s header with file
and line, but cannot be hash-cited because it lives outside this repository.

## Results

Proved (core axioms only: `propext`, `Quot.sound`, `Classical.choice`):

- `x509VerifyReq_iff`: the fixed verifier is exactly the RFC 5280 subset with
  the signing profile, AND Go's two extra refusals (it checks the anchor like
  an intermediate, and nests EKUs through CAs). Both only refuse more.
- `x509VerifyCT_iff`: the whole verifier as built, with the certificate
  transparency check #10124 added (`checkCertificateTransparency`, modeled
  as `Ct`), is the same RFC 5280 subset plus the CT profile (`specCt`: a
  leaf from a CT-logging CA embeds an SCT that verifies), plus one more
  refusal of the code's own (`ctStrict`: SCTs a non-CT leaf embeds anyway
  must verify). `x509VerifyCT_uncovered`: with no CT root on the chain and
  no SCT on the leaf, which is every chain the differential test mints, it
  is `x509VerifyReq`.
- `x509Verify_never_ca_leaf`: as built (after #9876), no CA certificate is
  accepted as a signing leaf (#9842); `x509VerifyCT_signing_leaf` states it,
  with the keyUsage clause, for the verifier as built now.
- `tspVerify_now_irrelevant`, `dsseCertOk_now_irrelevant`,
  `dsseCertOk_at_genTime`: the verify time is the timestamp time.
  `dsseCertOk` runs the whole verifier as built (`x509VerifyCT`), since
  `verifyX509Time` hands it the configured CT roots (#10124). A
  timestamped certificate signature's verdict does not depend on the
  verifier's clock; the zero genTime, which Go would read as "now", is
  refused first.
- `reissue_keeps_verifying` (#9843): a token keeps verifying after the TSA
  certificate is re-issued, under any trust configuration that still anchors
  the TSA root. `leaf_pinning_breaks_reissue` shows why the root, not the
  leaf, must be the anchor.
- `tspVerifyReq_iff`: the fixed token verifier accepts exactly the spec's
  tokens, and returns genTime.

Refuted as built by the first version of this model, fixed since (each
theorem states both: the pre-fix definition accepts, the one as built now
refuses):

- `leaf_without_digitalSignature_refused` (formerly
  `ce_leaf_without_digitalSignature`; fixed by #10097): a signing leaf whose
  keyUsage lacks digitalSignature was accepted (Go ignores leaf keyUsage
  bits), and so was a non-CA leaf asserting keyCertSign (RFC 5280 §4.2.1.9;
  x509-limbo `rfc5280::leaf-ku-keycertsign`). `x509Verify` (before)
  accepts, `x509VerifyReq` (now) refuses.
- `token_without_ess_refused`, `token_ess_naming_other_cert_refused`
  (formerly `ce_token_without_ess`, `ce_token_ess_names_other_cert`; fixed
  by #10099): a token with no ESS signing-certificate attribute, or one
  naming another certificate, was accepted (RFC 3161 §2.4.1, RFC 5816
  §2.2.1). `tspVerify` (before) accepts, `tspVerifyReq` (now) refuses.

Checked and NOT a finding: an intermediate whose keyUsage lacks keyCertSign
is already refused, by Go's `CheckSignatureFrom` (go1.26.6
`crypto/x509/x509.go:939`), which applies to the anchor too.

Model choices: an absent extKeyUsage is unrestricted (RFC 5280 §4.2.1.12);
the CT check is an input (`Ct`: covered, has SCTs, one verifies), not a
model of SCT parsing or log signatures, and it never reads the verify time;
RFC 3161 §2.3's "MUST be critical" on the TSA EKU is not enforced (see the
note in `timestamp/tsp.go`); TSTInfo `accuracy` is ignored (genTime is taken
as the signing-time bound); name constraints and policies are not modeled
(no certificate rookery accepts carries them).

## Differential tests

`// formal:differential` tests replay the vectors against the real code:

- `attestation/cryptoutil/formal_x509_differential_test.go`: 1200 chains
  built with `x509.CreateCertificate` through `X509Verifier.Verify`.
- `attestation/timestamp/formal_tsp_differential_test.go`: 400 hand-minted
  RFC 3161 tokens through `TSPVerifier.Verify`.

Both skip when the vectors are not on disk and FAIL when
`JADE_FORMAL_DIFFERENTIAL=1`. `x509Model` / `tspModel` name the model the
code must match: `asbuilt` until the fixes land, then `required`.

## Build

```bash
cd subtrees/rookery/formal/signing-trust
lake build            # Lean 4.34.1 via elan; no Mathlib
SIGNING_TRUST_VECTORS_REGEN=1 lake env lean --run SigningTrust/Vectors.lean > vectors/signing-trust.json
```

The spec is the asset: if the code changes, the as-built half can be rebuilt
from the cited lines in a day, and the proofs then say whether it still
conforms.
