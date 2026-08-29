// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dsse

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/aflock-ai/rookery/attestation/log"
)

type ErrNoSignatures struct{}

func (e ErrNoSignatures) Error() string {
	return "no signatures in dsse envelope"
}

type ErrNoMatchingSigs struct {
	Verifiers []CheckedVerifier
	// TrustMismatch, when non-nil, carries a precise diagnostic explaining
	// that the signature failed because the artifact's signing chain shares
	// a Subject CN with a policy-trusted root but uses a different key (the
	// "wrong platform" case). It is purely informational — it does not change
	// the verdict (verification already failed) — and is surfaced via Unwrap
	// so callers can pull it out with errors.As at the top-level error.
	TrustMismatch *TrustNameKeyMismatchError
}

func (e ErrNoMatchingSigs) Error() string {
	mess := "no valid signatures for the provided verifiers found for keyids:\n"
	reported := 0
	for _, v := range e.Verifiers {
		if v.Error != nil {
			kid := "<nil verifier>"
			if v.Verifier != nil {
				var err error
				kid, err = v.Verifier.KeyID()
				if err != nil {
					log.Warnf("failed to get key id from verifier: %v", err)
				}
			}

			s := fmt.Sprintf("  %s: %v\n", kid, v.Error)
			mess += s
			reported++
		}
	}

	// An EMPTY keyid list is not "every verifier failed" — it means no verifier
	// ever ran, so none had a failure to report. Saying only "no valid signatures
	// ... for keyids:" followed by nothing reads like a verification failure with
	// the detail missing, and sends readers hunting for a key mismatch that is not
	// there.
	//
	// The cause is working-as-designed: when timestamp verifiers ARE configured,
	// Verify only attempts a cert-based signature once one of that signature's
	// RFC3161 timestamps verifies. A signature that never clears that gate is
	// skipped without recording a per-verifier error, so the list comes back
	// empty.
	//
	// TWO different things clear that gate, and they need OPPOSITE fixes:
	// a signature carrying no timestamp at all (the signer is not stamping),
	// and a signature whose timestamp is present but issued by a TSA the policy
	// does not trust (the policy is missing a timestamp root). This message used
	// to assert the first as the likely cause, which sent anyone hitting the
	// second to go looking for a missing timestamp that was in fact right there.
	// Naming both is longer and correct; naming one is shorter and sometimes a
	// wild goose chase.
	if reported == 0 {
		mess += "  (empty: no verifier was attempted for any signature, so none reported an error.\n" +
			"  With timestamp verifiers configured, a cert-based signature is only attempted\n" +
			"  once one of its RFC3161 timestamps verifies. Two things prevent that, and they\n" +
			"  need opposite fixes: the signature carries NO timestamp (the signer is not\n" +
			"  stamping), or it carries one issued by a TSA this policy does not trust (the\n" +
			"  policy is missing that timestamp root). Check which before hunting for a key\n" +
			"  mismatch — enable debug logging to see the per-signature TSA result.)\n"
	}

	// Lead with the trust-mismatch block when present: it is the actionable
	// root cause, whereas the per-verifier "unknown authority" lines above are
	// just the generic symptom.
	if e.TrustMismatch != nil {
		mess = e.TrustMismatch.Error() + "\n" + mess
	}

	return mess
}

// Unwrap exposes the embedded trust-mismatch diagnostic (if any) so that
// errors.As(err, &TrustNameKeyMismatchError{}) succeeds anywhere this error is
// wrapped up the call stack.
func (e ErrNoMatchingSigs) Unwrap() error {
	if e.TrustMismatch == nil {
		return nil
	}
	return e.TrustMismatch
}

type ErrThresholdNotMet struct {
	Theshold int
	Actual   int
}

func (e ErrThresholdNotMet) Error() string {
	return fmt.Sprintf("envelope did not meet verifier threshold. expected %v valid verifiers but got %v", e.Theshold, e.Actual)
}

type ErrInvalidThreshold int

func (e ErrInvalidThreshold) Error() string {
	return fmt.Sprintf("invalid threshold (%v). thresholds must be greater than 0", int(e))
}

// ErrNoTimestamp is the per-signature error recorded when a cert-based
// signature cannot be verified because there is no trusted RFC3161 timestamp
// verifier configured and the caller has not opted into the wall-clock
// (time.Now()) fallback via VerifyWithCurrentTimeFallback(). The signature is
// rejected — it does not count toward the verification threshold — to preserve
// proof-of-signing-time and avoid silently verifying against the current time
// (see #5237).
type ErrNoTimestamp struct{}

func (e ErrNoTimestamp) Error() string {
	return "cert-based signature rejected: no trusted timestamp verifier configured and current-time fallback not enabled (proof-of-signing-time required)"
}

// ErrCertNotValidAtSigningTime is the per-signature error recorded when a
// cert-based signature carries an RFC3161 timestamp that VERIFIED, but the
// certificate's validity window did not contain that timestamped time. The
// common shape is a short-lived leaf (a Fulcio cert lives about ten minutes)
// that expired before a slow step got round to signing: the timestamp is
// trustworthy and says so. This is a DEFINITIVE failure — the envelope will
// never verify, however often it is re-read — and it must be told apart from
// "no timestamp could be verified", which is what this branch used to report.
// SignedAt is the timestamped time; NotBefore/NotAfter are the certificate's.
type ErrCertNotValidAtSigningTime struct {
	SignedAt  time.Time
	NotBefore time.Time
	NotAfter  time.Time
	Err       error
}

func (e ErrCertNotValidAtSigningTime) Error() string {
	if e.SignedAt.After(e.NotAfter) {
		return fmt.Sprintf("certificate expired at %s, before signing at %s",
			e.NotAfter.UTC().Format(time.RFC3339), e.SignedAt.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("certificate not yet valid until %s when signed at %s",
		e.NotBefore.UTC().Format(time.RFC3339), e.SignedAt.UTC().Format(time.RFC3339))
}

func (e ErrCertNotValidAtSigningTime) Unwrap() error { return e.Err }

// timestampedSignatureError names why a cert-based signature failed at its
// verified timestamped time. A certificate outside its validity window at
// that time is ErrCertNotValidAtSigningTime; anything else (an untrusted
// chain, signature bytes that do not match) keeps its own cause, stated
// against the time it was checked at.
//
// THE DATES COME FROM THE CERTIFICATE THAT ACTUALLY FAILED, not from the leaf.
// x509.CertificateInvalidError carries the offending certificate in .Cert, and
// for a chain it may be an INTERMEDIATE that expired while the leaf is still
// inside its own window. Reporting the leaf's dates there states a falsehood
// about which certificate died and when — and because Error() picks between
// "expired" and "not yet valid" by comparing SignedAt to those dates, the
// wrong pair can also invert the DIAGNOSIS.
//
// A STRUCTURED ERROR IS ONLY PRODUCED WHEN ITS OWN FIELDS EXPLAIN THE FAILURE.
// If signedAt lies inside [NotBefore, NotAfter] of the certificate we are
// about to name, then those dates do not account for an Expired verdict —
// x509 reached it some other way, or .Cert is absent — and the honest answer
// is the original cause rather than a confidently wrong pair of timestamps.
func timestampedSignatureError(cert *x509.Certificate, signedAt time.Time, err error) error {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		culprit := invalid.Cert
		if culprit == nil {
			culprit = cert
		}
		if culprit != nil && (signedAt.Before(culprit.NotBefore) || signedAt.After(culprit.NotAfter)) {
			return ErrCertNotValidAtSigningTime{
				SignedAt:  signedAt,
				NotBefore: culprit.NotBefore,
				NotAfter:  culprit.NotAfter,
				Err:       err,
			}
		}
	}
	return fmt.Errorf("signature invalid at its timestamped signing time %s: %w", signedAt.UTC().Format(time.RFC3339), err)
}

const PemTypeCertificate = "CERTIFICATE"

type Envelope struct {
	Payload     []byte      `json:"payload" jsonschema:"title=Payload,description=Base64-encoded payload data"`
	PayloadType string      `json:"payloadType" jsonschema:"title=Payload Type,description=Media type describing the payload format"`
	Signatures  []Signature `json:"signatures" jsonschema:"title=Signatures,description=List of signatures over the payload"`
}

type Signature struct {
	KeyID         string               `json:"keyid" jsonschema:"title=Key ID,description=Identifier of the key used to create this signature"`
	Signature     []byte               `json:"sig" jsonschema:"title=Signature,description=Base64-encoded signature value"`
	Certificate   []byte               `json:"certificate,omitempty" jsonschema:"title=Certificate,description=PEM-encoded signing certificate"`
	Intermediates [][]byte             `json:"intermediates,omitempty" jsonschema:"title=Intermediates,description=PEM-encoded intermediate certificates in the chain"`
	Timestamps    []SignatureTimestamp `json:"timestamps,omitempty" jsonschema:"title=Timestamps,description=Trusted timestamps for this signature"`
}

type SignatureTimestampType string

const TimestampRFC3161 SignatureTimestampType = "tsp"

type SignatureTimestamp struct {
	Type SignatureTimestampType `json:"type" jsonschema:"title=Type,description=Type of timestamp (tsp for RFC 3161)"`
	Data []byte                 `json:"data" jsonschema:"title=Data,description=Base64-encoded timestamp data"`
}

// preauthEncode wraps the data to be signed or verified and it's type in the DSSE protocol's
// pre-authentication encoding as detailed at https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
//
// Built with one exact-size allocation rather than fmt.Sprintf: Sprintf routes
// the multi-megabyte body through fmt's growing internal buffer plus a final
// []byte conversion copy, which on a large evidence corpus contributed
// gigabytes of transient allocations per verify (#7572 wall-time follow-up).
// Output is byte-identical to the Sprintf form.
func preauthEncode(bodyType string, body []byte) []byte {
	const dsseVersion = "DSSEv1"
	head := fmt.Sprintf("%s %d %s %d ", dsseVersion, len(bodyType), bodyType, len(body))
	out := make([]byte, 0, len(head)+len(body))
	out = append(out, head...)
	out = append(out, body...)
	return out
}
