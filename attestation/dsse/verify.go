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

type CheckedVerifier struct {
	Verifier           cryptoutil.Verifier
	TimestampVerifiers []timestamp.TimestampVerifier
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

	pae := preauthEncode(e.PayloadType, e.Payload)
	if len(e.Signatures) == 0 {
		return nil, ErrNoSignatures{}
	}

	checkedVerifiers := make([]CheckedVerifier, 0)
	// Track distinct verifier KeyIDs that have passed. This prevents an attacker
	// from duplicating the same valid signature in the envelope to inflate the
	// verified count and meet the threshold with a single key.
	verifiedKeyIDs := make(map[string]struct{})

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
				sigIntermediates := make([]*x509.Certificate, 0)
				for _, int := range sig.Intermediates {
					intCert, err := cryptoutil.TryParseCertificate(int)
					if err != nil {
						continue
					}

					sigIntermediates = append(sigIntermediates, intCert)
				}

				sigIntermediates = append(sigIntermediates, options.intermediates...)
				if len(options.timestampVerifiers) == 0 {
					if verifier, err := verifyX509Time(cert, sigIntermediates, options.roots, pae, sig.Signature, time.Now()); err == nil {
						checkedVerifiers = append(checkedVerifiers, CheckedVerifier{Verifier: verifier})
						verifiedKeyIDs[verifierKeyID(verifier)] = struct{}{}
					} else if verifier != nil {
						// Verifier was created but signature verification failed
						checkedVerifiers = append(checkedVerifiers, CheckedVerifier{Verifier: verifier, Error: err})
						log.Debugf("failed to verify signature: %v", err)
					} else {
						// Verifier creation failed (e.g., invalid cert chain) — don't
						// add a nil verifier to checkedVerifiers as it would cause nil
						// dereferences in consumers that iterate the list.
						log.Debugf("failed to create x509 verifier: %v", err)
					}
				} else {
					var passedVerifier cryptoutil.Verifier
					failed := []cryptoutil.Verifier{}
					passedTimestampVerifiers := []timestamp.TimestampVerifier{}
					failedTimestampVerifiers := []timestamp.TimestampVerifier{}

					for _, timestampVerifier := range options.timestampVerifiers {
						for _, sigTimestamp := range sig.Timestamps {
							timestamp, err := timestampVerifier.Verify(context.TODO(), bytes.NewReader(sigTimestamp.Data), bytes.NewReader(sig.Signature))
							if err != nil {
								continue
							}

							if verifier, err := verifyX509Time(cert, sigIntermediates, options.roots, pae, sig.Signature, timestamp); err == nil {
								// NOTE: do we not want to save all the passed verifiers?
								passedVerifier = verifier
								passedTimestampVerifiers = append(passedTimestampVerifiers, timestampVerifier)
							} else {
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
		return nil, ErrNoMatchingSigs{Verifiers: checkedVerifiers}
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
