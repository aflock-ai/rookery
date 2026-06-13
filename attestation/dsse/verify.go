// Copyright 2022 The Witness Contributors
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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/timestamp"
)

// verifierKeyID returns a stable identifier for a verifier. If KeyID() fails,
// it falls back to a SHA-256 hash of the verifier's type and address to ensure
// the verification still counts toward the threshold.
func verifierKeyID(v cryptoutil.Verifier) string {
	if kid, err := v.KeyID(); err == nil {
		return kid
	}
	// Fallback: use a hash of the verifier pointer address formatted as a string.
	// This ensures each distinct verifier object gets a unique ID even if KeyID() fails.
	h := sha256.Sum256([]byte(fmt.Sprintf("%p", v)))
	return "fallback:" + hex.EncodeToString(h[:])
}

type verificationOptions struct {
	roots              []*x509.Certificate
	intermediates      []*x509.Certificate
	verifiers          []cryptoutil.Verifier
	threshold          int
	timestampVerifiers []timestamp.TimestampVerifier
	// allowCurrentTimeFallback opts a caller INTO verifying a cert-based
	// signature's validity window against the wall clock (time.Now()) when no
	// trusted RFC3161 timestamp verifier is configured. It is OFF by default:
	// substituting wall-clock time for the attested signing time loses
	// proof-of-signing-time, so by default such a signature does NOT count
	// toward the threshold and verification fails closed (see #5237). Only a
	// caller that knowingly accepts long-lived, non-Fulcio certs without a TSA
	// should turn this on via VerifyWithCurrentTimeFallback().
	allowCurrentTimeFallback bool
}

type VerificationOption func(*verificationOptions)

func VerifyWithRoots(roots ...*x509.Certificate) VerificationOption {
	return func(vo *verificationOptions) {
		vo.roots = roots
	}
}

func VerifyWithIntermediates(intermediates ...*x509.Certificate) VerificationOption {
	return func(vo *verificationOptions) {
		vo.intermediates = intermediates
	}
}

func VerifyWithVerifiers(verifiers ...cryptoutil.Verifier) VerificationOption {
	return func(vo *verificationOptions) {
		vo.verifiers = verifiers
	}
}

func VerifyWithThreshold(threshold int) VerificationOption {
	return func(vo *verificationOptions) {
		vo.threshold = threshold
	}
}

func VerifyWithTimestampVerifiers(verifiers ...timestamp.TimestampVerifier) VerificationOption {
	return func(vo *verificationOptions) {
		vo.timestampVerifiers = verifiers
	}
}

// VerifyWithCurrentTimeFallback explicitly permits verifying a cert-based
// signature against the current wall-clock time (time.Now()) when NO trusted
// RFC3161 timestamp verifier is configured.
//
// This is OFF by default and should stay off for any keyless/short-lived
// (Fulcio) signing flow: without it, a cert-based signature lacking a trusted
// timestamp does NOT count toward the verification threshold (fail closed),
// preserving proof-of-signing-time. Turn it on ONLY when you knowingly trust a
// long-lived CA and accept that the signing time is not cryptographically
// attested (see #5237).
func VerifyWithCurrentTimeFallback() VerificationOption {
	return func(vo *verificationOptions) {
		vo.allowCurrentTimeFallback = true
	}
}

type CheckedVerifier struct {
	Verifier           cryptoutil.Verifier
	TimestampVerifiers []timestamp.TimestampVerifier
	// VerifiedTimestamps holds the RFC3161 TSA-attested times (genTime) that
	// were cryptographically verified against the policy's trusted timestamp
	// authorities for this signature. Empty when the signature verified
	// without any timestamp verifier. These are TRUSTED times — consumers
	// (e.g. policy timestampConstraint) must use these, never self-asserted
	// attestor wall-clock fields.
	VerifiedTimestamps []time.Time
	Error              error
}

func (e Envelope) Verify(opts ...VerificationOption) ([]CheckedVerifier, error) { //nolint:gocognit,gocyclo,funlen
	options := &verificationOptions{
		threshold: 1,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.threshold <= 0 {
		return nil, ErrInvalidThreshold(options.threshold)
	}

	fmt.Fprintf(os.Stderr, "[dsse-verify] roots=%d intermediates=%d verifiers=%d timestampVerifiers=%d sigs=%d\n",
		len(options.roots), len(options.intermediates), len(options.verifiers), len(options.timestampVerifiers), len(e.Signatures))

	pae := preauthEncode(e.PayloadType, e.Payload)
	if len(e.Signatures) == 0 {
		return nil, ErrNoSignatures{}
	}

	checkedVerifiers := make([]CheckedVerifier, 0)
	// Track distinct verifier KeyIDs that have passed. This prevents an attacker
	// from duplicating the same valid signature in the envelope to inflate the
	// verified count and meet the threshold with a single key.
	verifiedKeyIDs := make(map[string]struct{})

	// detectedMismatch holds the first same-CN/different-key trust mismatch
	// found while a signature/timestamp FAILED to verify. It is purely
	// diagnostic — recorded here and surfaced on the verified==0 error path
	// below. It NEVER affects whether a signature counts toward the threshold.
	var detectedMismatch *TrustNameKeyMismatchError
	recordMismatch := func(m *TrustNameKeyMismatchError) {
		if m != nil && detectedMismatch == nil {
			detectedMismatch = m
		}
	}

	// Pre-compute stable KeyIDs for each provided verifier so that a verifier
	// with a non-deterministic KeyID() cannot inflate the threshold count by
	// producing a different ID on each call.
	stableKeyIDs := make(map[int]string, len(options.verifiers))
	for i, v := range options.verifiers {
		if v != nil {
			stableKeyIDs[i] = verifierKeyID(v)
		}
	}

	for _, sig := range e.Signatures {
		if len(sig.Certificate) > 0 { //nolint:nestif
			cert, err := cryptoutil.TryParseCertificate(sig.Certificate)
			if err != nil {
				// Log but don't skip — the raw verifier loop below must still
				// run. An attacker could inject unparseable Certificate data to
				// block raw-key verification if we used 'continue' here.
				log.Debugf("failed to parse certificate in signature, skipping cert verification: %v", err)
			} else {
				// artifactIssuerChain is the leaf's own issuer chain (its
				// embedded intermediates), kept separate from the policy's
				// configured intermediates so the trust-mismatch diagnostic
				// compares the ARTIFACT's CAs (cert + sig intermediates)
				// against the POLICY's CAs (roots + options.intermediates).
				artifactIssuerChain := make([]*x509.Certificate, 0, 1+len(sig.Intermediates))
				artifactIssuerChain = append(artifactIssuerChain, cert)
				sigIntermediates := make([]*x509.Certificate, 0)
				for _, int := range sig.Intermediates {
					intCert, err := cryptoutil.TryParseCertificate(int)
					if err != nil {
						continue
					}

					sigIntermediates = append(sigIntermediates, intCert)
					artifactIssuerChain = append(artifactIssuerChain, intCert)
				}

				sigIntermediates = append(sigIntermediates, options.intermediates...)
				// policyTrusted is the policy's CA set: roots plus any
				// configured intermediates. Built into a fresh slice so it never
				// aliases or mutates options.roots/intermediates. Diagnostic-only.
				policyTrusted := make([]*x509.Certificate, 0, len(options.roots)+len(options.intermediates))
				policyTrusted = append(policyTrusted, options.roots...)
				policyTrusted = append(policyTrusted, options.intermediates...)
				if len(options.timestampVerifiers) == 0 {
					// Emit the artifact issuer + trusted-root key fingerprints so a
					// same-CN/different-key mismatch is visible in debug output on
					// the no-timestamp path too.
					fmt.Fprintf(os.Stderr, "[dsse-verify] cert subject=%q issuer=%q issuerKey=%s trustedRootKeys=%s\n",
						cert.Subject.CommonName, cert.Issuer.CommonName,
						chainIssuerFingerprint(artifactIssuerChain), trustedRootFingerprints(options.roots))
					if !options.allowCurrentTimeFallback {
						// FAIL CLOSED (#5237): a cert-based signature has no trusted
						// signing-time source here (no RFC3161 timestamp verifier),
						// and the caller did not opt into the time.Now() fallback.
						// Verifying the cert's validity window against the wall clock
						// would substitute an untrusted time for the attested signing
						// time and silently lose proof-of-signing-time. So this
						// signature does NOT count toward the threshold. Record it as
						// a failed verifier (non-nil, for KeyID + nil-safety) so the
						// reason surfaces on the verified==0 ErrNoMatchingSigs path.
						fmt.Fprintf(os.Stderr, "[dsse-verify] cert signature rejected: no trusted timestamp verifier and current-time fallback not enabled\n")
						// Preserve the same-CN/different-key trust diagnostic on this
						// failure path too (diagnostic-only; never flips a verdict).
						recordMismatch(detectTrustNameKeyMismatch(artifactIssuerChain, policyTrusted, false))
						if verifier, verr := cryptoutil.NewX509Verifier(cert, sigIntermediates, options.roots, time.Time{}); verr == nil && verifier != nil {
							checkedVerifiers = append(checkedVerifiers, CheckedVerifier{Verifier: verifier, Error: ErrNoTimestamp{}})
						} else {
							log.Debugf("failed to create x509 verifier for no-timestamp rejection: %v", verr)
						}
					} else if verifier, err := verifyX509Time(cert, sigIntermediates, options.roots, pae, sig.Signature, time.Now()); err == nil {
						checkedVerifiers = append(checkedVerifiers, CheckedVerifier{Verifier: verifier})
						verifiedKeyIDs[verifierKeyID(verifier)] = struct{}{}
					} else if verifier != nil {
						// Verifier was created but signature verification failed
						recordMismatch(detectTrustNameKeyMismatch(artifactIssuerChain, policyTrusted, false))
						checkedVerifiers = append(checkedVerifiers, CheckedVerifier{Verifier: verifier, Error: err})
						log.Debugf("failed to verify signature: %v", err)
					} else {
						// Verifier creation failed (e.g., invalid cert chain) — don't
						// add a nil verifier to checkedVerifiers as it would cause nil
						// dereferences in consumers that iterate the list.
						recordMismatch(detectTrustNameKeyMismatch(artifactIssuerChain, policyTrusted, false))
						log.Debugf("failed to create x509 verifier: %v", err)
					}
				} else {
					var passedVerifier cryptoutil.Verifier
					failed := []cryptoutil.Verifier{}
					passedTimestampVerifiers := []timestamp.TimestampVerifier{}
					failedTimestampVerifiers := []timestamp.TimestampVerifier{}
					passedTimestamps := []time.Time{}

					// Surface the artifact issuer's key fingerprint and the
					// trusted-root key fingerprint(s) so a same-CN/different-key
					// mismatch is visible even in raw debug output.
					fmt.Fprintf(os.Stderr, "[dsse-verify] cert subject=%q issuer=%q notAfter=%s sigTimestamps=%d issuerKey=%s trustedRootKeys=%s\n",
						cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotAfter.Format(time.RFC3339), len(sig.Timestamps),
						chainIssuerFingerprint(artifactIssuerChain), trustedRootFingerprints(options.roots))
					for _, timestampVerifier := range options.timestampVerifiers {
						for _, sigTimestamp := range sig.Timestamps {
							tsTime, err := timestampVerifier.Verify(context.TODO(), bytes.NewReader(sigTimestamp.Data), bytes.NewReader(sig.Signature))
							if err != nil {
								fmt.Fprintf(os.Stderr, "[dsse-verify] TSA verify FAILED: %v\n", err)
								// The timestamp failed to verify. If the TSA token's
								// signing chain shares a CN with the policy's trusted
								// TSA roots but uses a different key, that is the
								// "wrong platform" timestamp mismatch — diagnose it.
								recordMismatch(detectTimestampMismatch(sigTimestamp.Data, timestampVerifier))
								continue
							}
							fmt.Fprintf(os.Stderr, "[dsse-verify] TSA verified, timestamp=%s\n", tsTime.Format(time.RFC3339))

							if verifier, err := verifyX509Time(cert, sigIntermediates, options.roots, pae, sig.Signature, tsTime); err == nil {
								// NOTE: do we not want to save all the passed verifiers?
								passedVerifier = verifier
								passedTimestampVerifiers = append(passedTimestampVerifiers, timestampVerifier)
								passedTimestamps = append(passedTimestamps, tsTime)
							} else {
								// TSA validated the time but the Fulcio chain still
								// failed: same diagnostic as the no-TSA branch.
								recordMismatch(detectTrustNameKeyMismatch(artifactIssuerChain, policyTrusted, false))
								// Only track non-nil verifiers in failed list to prevent
								// nil dereferences when iterating failed verifiers below.
								if verifier != nil {
									failed = append(failed, verifier)
								}
								failedTimestampVerifiers = append(failedTimestampVerifiers, timestampVerifier)
								log.Debugf("failed to verify with timestamp verifier: %v", err)
							}

						}
					}

					if len(passedTimestampVerifiers) > 0 && passedVerifier != nil {
						verifiedKeyIDs[verifierKeyID(passedVerifier)] = struct{}{}
						checkedVerifiers = append(checkedVerifiers, CheckedVerifier{
							Verifier:           passedVerifier,
							TimestampVerifiers: passedTimestampVerifiers,
							VerifiedTimestamps: passedTimestamps,
						})
					} else {
						for _, v := range failed {
							checkedVerifiers = append(checkedVerifiers, CheckedVerifier{
								Verifier:           v,
								TimestampVerifiers: failedTimestampVerifiers,
								Error:              fmt.Errorf("no valid timestamps found"),
							})
						}
					}
				}
			}
		}

		for i, verifier := range options.verifiers {
			if verifier != nil {
				kid := stableKeyIDs[i]
				log.Debug("verifying with verifier with KeyID ", kid)

				if err := verifier.Verify(bytes.NewReader(pae), sig.Signature); err == nil {
					verifiedKeyIDs[kid] = struct{}{}
					checkedVerifiers = append(checkedVerifiers, CheckedVerifier{Verifier: verifier})
				} else {
					checkedVerifiers = append(checkedVerifiers, CheckedVerifier{Verifier: verifier, Error: err})
				}
			}
		}
	}

	verified := len(verifiedKeyIDs)
	if verified == 0 {
		// Attach the trust-mismatch diagnostic (if any) only on the failure
		// path. detectedMismatch is non-nil only when a signature/timestamp
		// already failed AND a same-CN/different-key collision was found, so
		// this cannot change a passing verify into a failing one.
		return nil, ErrNoMatchingSigs{Verifiers: checkedVerifiers, TrustMismatch: detectedMismatch}
	} else if verified < options.threshold {
		return checkedVerifiers, ErrThresholdNotMet{Theshold: options.threshold, Actual: verified}
	}

	return checkedVerifiers, nil
}

func verifyX509Time(cert *x509.Certificate, sigIntermediates, roots []*x509.Certificate, pae, sig []byte, trustedTime time.Time) (cryptoutil.Verifier, error) {
	verifier, err := cryptoutil.NewX509Verifier(cert, sigIntermediates, roots, trustedTime)
	if err != nil {
		return nil, err
	}

	err = verifier.Verify(bytes.NewReader(pae), sig)

	return verifier, err
}
