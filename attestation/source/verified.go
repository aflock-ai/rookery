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

package source

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// payloadMatchesSubjects reports whether the in-toto statement encoded in the
// SIGNATURE-VERIFIED DSSE payload attests at least one of the requested subject
// digests.
//
// This is the client-side artifact-substitution guard, enforced at the
// source-agnostic VerifiedSource layer so it holds REGARDLESS of the underlying
// (untrusted) Sourcer's own filtering. It MUST read the subjects from the signed
// payload bytes, NOT from a CollectionEnvelope.Statement / StatementEnvelope
// field — those are populated by the untrusted source and can be set
// independently of what was actually signed, so trusting them would leave the
// substitution bypass open (a source could sign artifact X while claiming
// artifact D in the struct field). Callers invoke this only AFTER a signature
// has verified, so the payload bytes are authenticated. A malformed payload
// fails closed (returns false + error). MemorySource enforces the same binding
// internally (matchesSubjects); this brings the guarantee to ArchivistaSource,
// which delegates subject filtering to the remote store.
func payloadMatchesSubjects(payload []byte, subjectDigests []string) (bool, error) {
	if len(subjectDigests) == 0 {
		return true, nil
	}
	var stmt intoto.Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return false, fmt.Errorf("decode signed payload for subject check: %w", err)
	}
	return statementMatchesSubjects(stmt, subjectDigests), nil
}

// statementMatchesSubjects reports whether stmt attests at least one of the
// requested subject digests. An EMPTY request matches any statement (a
// subject-agnostic query — whole-policy walks, probes). A NON-EMPTY request
// requires the statement to actually carry one of the digests. Mirrors
// MemorySource's index-build digest matchability filter. Only call this on a
// statement decoded from signature-verified bytes (see payloadMatchesSubjects).
func statementMatchesSubjects(stmt intoto.Statement, subjectDigests []string) bool {
	if len(subjectDigests) == 0 {
		return true
	}
	have := make(map[string]struct{})
	for _, sub := range stmt.Subject {
		for algorithm, digest := range sub.Digest {
			if !cryptoutil.IsMatchableSubjectDigest(algorithm, digest) {
				continue
			}
			have[digest] = struct{}{}
		}
	}
	for _, d := range subjectDigests {
		if _, ok := have[d]; ok {
			return true
		}
	}
	return false
}

type CollectionVerificationResult struct {
	Verifiers          []cryptoutil.Verifier
	ValidFunctionaries []cryptoutil.Verifier
	// VerifiedTimestampsByKeyID holds the RFC3161 TSA-attested times that
	// were cryptographically verified against trusted timestamp authorities,
	// keyed by the KeyID of the PASSING verifier whose signature each token
	// covers. The per-signature association matters: a policy timestamp
	// constraint must judge the timestamps of the signature that matched the
	// step's functionary, not a timestamp riding on some other signature in
	// a multi-signature envelope. Empty when the envelope verified without
	// timestamp verification.
	VerifiedTimestampsByKeyID map[string][]time.Time
	CollectionEnvelope
	Errors   []error
	Warnings []string
}

type VerifiedSourcer interface {
	Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionVerificationResult, error)
	// SearchByPredicateType returns bare-predicate statements (non-Collection
	// DSSE envelopes) whose predicateType + subject digest match, with each
	// envelope's verifiers populated by DSSE signature verification. Used by
	// the policy engine's external-attestation flow (issue #39).
	SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error)
}

type VerifiedSource struct {
	source     Sourcer
	verifyOpts []dsse.VerificationOption
}

func NewVerifiedSource(source Sourcer, verifyOpts ...dsse.VerificationOption) *VerifiedSource {
	return &VerifiedSource{source, verifyOpts}
}

// truncLogField returns s truncated to n bytes for log-field display. It is
// panic-safe for strings shorter than n (e.g. short collection references like
// "step01" in tests).
func truncLogField(s string) string {
	const n = 12
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *VerifiedSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionVerificationResult, error) { //nolint:gocognit,gocyclo // per-candidate verify loop with per-verifier pass/fail accounting plus the artifact-substitution subject guard; the branches enumerate signature-verification states, which is the function's purpose.
	candidates, err := s.source.Search(ctx, collectionName, subjectDigests, attestations)
	if err != nil {
		return nil, err
	}

	results := make([]CollectionVerificationResult, 0)
	// These envelopes are candidates matched by subject/attestation — their
	// signatures are checked below; "candidate" (not "unverified") avoids reading
	// as a verdict when it just means "fetched, pending verification".
	fmt.Fprintf(os.Stderr, "[verified-source] verifying %d candidate envelope(s) for collection %q\n", len(candidates), collectionName)
	for _, toVerify := range candidates {
		envelopeVerifiers, err := toVerify.Envelope.Verify(s.verifyOpts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[verified-source] envelope %s signature verification FAILED: %v\n", toVerify.Reference, err)
			results = append(results,
				CollectionVerificationResult{
					Errors:             []error{fmt.Errorf("failed to verify envelope: %w", err)},
					CollectionEnvelope: toVerify,
				},
			)
			continue
		}

		// Log each checked verifier with an explicit pass/fail verdict rather
		// than a raw "error=<nil>", which reads as cryptic to an operator.
		for _, cv := range envelopeVerifiers {
			kid := "unknown"
			if cv.Verifier != nil {
				if k, err := cv.Verifier.KeyID(); err == nil {
					kid = truncLogField(k)
				}
			}
			if cv.Error == nil {
				fmt.Fprintf(os.Stderr, "[verified-source] envelope %s signature OK (verifier kid=%s)\n", truncLogField(toVerify.Reference), kid)
			} else {
				fmt.Fprintf(os.Stderr, "[verified-source] envelope %s signature rejected (verifier kid=%s): %v\n", truncLogField(toVerify.Reference), kid, cv.Error)
			}
		}

		passedVerifiers := make([]cryptoutil.Verifier, 0)
		timestampsByKeyID := make(map[string][]time.Time)
		for _, verifier := range envelopeVerifiers {
			if verifier.Error == nil {
				passedVerifiers = append(passedVerifiers, verifier.Verifier)
				if len(verifier.VerifiedTimestamps) > 0 && verifier.Verifier != nil {
					// Bind the verified TSA times to THIS verifier's key so
					// downstream policy checks can scope them to the
					// functionary-matched signature. A KeyID failure drops the
					// timestamps (fail-closed) rather than misattributing them.
					if kid, kerr := verifier.Verifier.KeyID(); kerr == nil {
						timestampsByKeyID[kid] = append(timestampsByKeyID[kid], verifier.VerifiedTimestamps...)
					}
				}
			}
		}

		var Errors []error
		if len(passedVerifiers) == 0 {
			Errors = append(Errors, fmt.Errorf("no verifiers passed"))
		} else if matches, merr := payloadMatchesSubjects(toVerify.Envelope.Payload, subjectDigests); merr != nil || !matches {
			// Artifact-substitution guard: signature(s) verified, so the payload
			// bytes are authentic — require the SIGNED payload's subjects to match
			// the requested artifact. Read from Envelope.Payload, never the
			// source-populated Statement field (which can differ from what was
			// signed). Fail closed on a malformed payload.
			fmt.Fprintf(os.Stderr, "[verified-source] envelope %s REJECTED: signed subject does not match requested artifact digest(s) (artifact-substitution guard)\n", truncLogField(toVerify.Reference))
			Errors = append(Errors, fmt.Errorf("collection subject does not match requested artifact digest(s): artifact-substitution guard"))
			passedVerifiers = nil
			timestampsByKeyID = nil
		}

		results = append(results, CollectionVerificationResult{
			Verifiers:                 passedVerifiers,
			VerifiedTimestampsByKeyID: timestampsByKeyID,
			CollectionEnvelope:        toVerify,
			Errors:                    Errors,
		})
	}

	return results, nil
}

// SearchByPredicateType delegates to the underlying Sourcer and then runs
// DSSE signature verification on every returned envelope, populating
// StatementEnvelope.Verifiers with successfully-verified verifiers.
// Envelopes whose signatures cannot be verified are still returned (with an
// empty Verifiers slice + an error in Errors) so that callers can surface
// the rejection reason rather than silently dropping them.
func (s *VerifiedSource) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error) {
	candidates, err := s.source.SearchByPredicateType(ctx, predicateTypes, subjectDigests)
	if err != nil {
		return nil, err
	}

	results := make([]StatementEnvelope, 0, len(candidates))
	for _, toVerify := range candidates {
		envelopeVerifiers, err := toVerify.Envelope.Verify(s.verifyOpts...)
		if err != nil {
			toVerify.Errors = append(toVerify.Errors, fmt.Errorf("failed to verify envelope: %w", err))
			results = append(results, toVerify)
			continue
		}

		passed := make([]cryptoutil.Verifier, 0, len(envelopeVerifiers))
		for _, v := range envelopeVerifiers {
			if v.Error == nil {
				passed = append(passed, v.Verifier)
			}
		}

		if len(passed) == 0 {
			toVerify.Errors = append(toVerify.Errors, fmt.Errorf("no verifiers passed"))
		} else if matches, merr := payloadMatchesSubjects(toVerify.Envelope.Payload, subjectDigests); merr != nil || !matches {
			// Artifact-substitution guard: read subjects from the signature-verified
			// payload, never the source-populated Statement field.
			toVerify.Errors = append(toVerify.Errors, fmt.Errorf("external attestation subject does not match requested artifact digest(s): artifact-substitution guard"))
			passed = nil
		}
		toVerify.Verifiers = passed
		results = append(results, toVerify)
	}
	return results, nil
}
