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
| `SigningTrust/X509.lean` | certificates, the path Go builds, RFC 5280 §6.1 subset + signing profile (`specPath`), Go's `Verify` (`goVerify`), `X509Verifier.Verify` as built and as required |
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
- `x509Verify_never_ca_leaf`: as built (after #9876), no CA certificate is
  accepted as a signing leaf (#9842).
- `tspVerify_now_irrelevant`, `dsseCertOk_now_irrelevant`,
  `dsseCertOk_at_genTime`: the verify time is the timestamp time. A
  timestamped certificate signature's verdict does not depend on the
  verifier's clock; the zero genTime, which Go would read as "now", is
  refused first.
- `reissue_keeps_verifying` (#9843): a token keeps verifying after the TSA
  certificate is re-issued, under any trust configuration that still anchors
  the TSA root. `leaf_pinning_breaks_reissue` shows why the root, not the
  leaf, must be the anchor.
- `tspVerifyReq_iff`: the fixed token verifier accepts exactly the spec's
  tokens, and returns genTime.

Refuted as built (findings):

- `ce_leaf_without_digitalSignature`: a signing leaf whose keyUsage lacks
  digitalSignature is accepted (Go ignores leaf keyUsage bits), and so is a
  non-CA leaf asserting keyCertSign (RFC 5280 §4.2.1.9; x509-limbo
  `rfc5280::leaf-ku-keycertsign`).
- `ce_token_without_ess`, `ce_token_ess_names_other_cert`: a token with no ESS
  signing-certificate attribute, or one naming another certificate, is
  accepted (RFC 3161 §2.4.1, RFC 5816 §2.2.1).

Checked and NOT a finding: an intermediate whose keyUsage lacks keyCertSign
is already refused, by Go's `CheckSignatureFrom` (go1.26.6
`crypto/x509/x509.go:939`), which applies to the anchor too.

Model choices: an absent extKeyUsage is unrestricted (RFC 5280 §4.2.1.12);
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
