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

// StreamingVerifiedSourcer is an optional extension of VerifiedSourcer: it
// yields VERIFIED candidates one at a time, in the same order Search would
// return them, with per-candidate verdicts identical to Search's. The policy
// engine prefers this path (#7572): consuming — and compacting — each
// candidate's verification result before the next envelope's decoded body is
// materialized makes the verify peak O(largest envelope), not O(matching
// corpus). Search itself cannot deliver that: it must materialize every
// result before returning, so even with a streaming underlying Sourcer the
// full decoded candidate set is simultaneously resident.
type StreamingVerifiedSourcer interface {
	SearchStream(ctx context.Context, collectionName string, subjectDigests, attestations []string, yield func(CollectionVerificationResult) error) error
}

type VerifiedSource struct {
	source     Sourcer
	verifyOpts []dsse.VerificationOption
	// evidenceHashes, when non-empty, makes Search record each candidate's
	// payload DigestSet on the result (CollectionEnvelope.PayloadDigests)
	// before releaseEnvelopeBytes drops the bytes. The VSA's inputAttestations
	// must digest the exact signed payload of each evidence collection; once
	// the bytes are released, the digest is the only faithful carrier of that
	// identity. Callers that produce a VSA (the policyverify attestor) set
	// this to their attestation context's hash set so stored digests match
	// what the summary would have computed from the live bytes.
	evidenceHashes []cryptoutil.DigestValue
}

func NewVerifiedSource(source Sourcer, verifyOpts ...dsse.VerificationOption) *VerifiedSource {
	return &VerifiedSource{source: source, verifyOpts: verifyOpts}
}

// WithEvidenceHashes returns the same source configured to record payload
// digests (computed with the given hash set) on every Search result before
// the raw envelope bytes are released. See the evidenceHashes field doc.
func (s *VerifiedSource) WithEvidenceHashes(hashes []cryptoutil.DigestValue) *VerifiedSource {
	s.evidenceHashes = hashes
	return s
}

// recordPayloadDigests captures the payload's digest set on the result copy
// prior to byte release. Best-effort by design: a digest failure leaves
// PayloadDigests empty, and the VSA summary then behaves exactly as it does
// for a nil payload today (the descriptor is skipped with a debug log) —
// never a wrong digest.
func (s *VerifiedSource) recordPayloadDigests(ce *CollectionEnvelope) {
	if len(s.evidenceHashes) == 0 || len(ce.Envelope.Payload) == 0 {
		return
	}
	if ds, err := cryptoutil.CalculateDigestSetFromBytes(ce.Envelope.Payload, s.evidenceHashes); err == nil {
		ce.PayloadDigests = ds
	}
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

// releaseEnvelopeBytes drops the raw DSSE bytes from a result-bound copy of a
// candidate envelope AFTER verification has consumed them (R1 part 3, #7611 /
// #7590). PAE signature verification and the artifact-substitution subject
// guard are the only readers of Envelope.Payload, and Verifiers /
// ValidFunctionaries / VerifiedTimestampsByKeyID carry everything signature-
// derived that later stages read. Downstream, the policy gate reads the
// parsed Statement/Collection, rego reads the attestor (Statement.Predicate
// is retained untouched), the passed-collection dedup key hashes the
// Statement + verified-signer set, and diagnostics read Statement.Subject —
// none of them read the bytes. Retaining Payload (a full duplicate of
// statement+predicate) and Signatures (certificate PEMs) per candidate per
// step per depth multiplied resident verify memory (#7572).
//
// Operates on the RESULT copy only: CollectionEnvelope is a value, so the
// underlying Sourcer's stored envelope (e.g. MemorySource) keeps its bytes
// and later searches still verify (TestVerifiedSearch_ReleaseDoesNotCorruptTheSource).
func releaseEnvelopeBytes(ce *CollectionEnvelope) {
	ce.Envelope.Payload = nil
	ce.Envelope.Signatures = nil
}

// retainPayloadReleaseRest is the release applied to candidates whose
// signature verification and subject guard SUCCEEDED — candidates that may
// yet become PASSED collections. The policy gate's pass-time compaction
// (policy.compactPassed) drops the decoded Statement.Predicate + typed
// Collection and keeps the RAW payload as the single rehydration source for
// the post-decision re-readers (artifactsFrom chain checks, cross-step Rego
// context, the content-identity merge key). For that to work the payload
// must survive to the gate, so here we:
//
//   - KEEP Envelope.Payload (the signed statement bytes — the rehydration
//     source and the strongest content identity for the merge key)
//   - release Envelope.Signatures (certificate PEMs; everything signature-
//     derived that later stages read is carried by Verifiers /
//     ValidFunctionaries / VerifiedTimestampsByKeyID)
//   - release Statement.Predicate (a full second copy of the predicate that
//     Payload already contains; the gate reads the parsed Collection and
//     Statement.Subject, never this raw message)
//
// Net batch effect vs the previous full release: +Payload −Predicate ≈ the
// envelope framing overhead, so the per-depth transient peak is unchanged
// within noise while pass-time compaction becomes possible. Candidates with
// no verification future (signature failure, subject-guard failure) still
// get the FULL releaseEnvelopeBytes + predicate drop — their bytes have no
// reader at all.
func retainPayloadReleaseRest(ce *CollectionEnvelope) {
	ce.Envelope.Signatures = nil
	ce.Statement.Predicate = nil
}

func (s *VerifiedSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionVerificationResult, error) {
	// STREAMING: when the source can yield candidates one at a time, verify
	// each as it arrives and retain only the compact (bytes-released) result.
	// The slice path below materializes EVERY candidate's full envelope
	// simultaneously before the first verification runs — against a large
	// matching corpus that transient set, not any retained state, IS the heap
	// peak (#7572: two concurrent 220-candidate searches drove 168→4,140 MiB
	// in 14s; byte release after the fact moved the peak by only 4%). One
	// candidate's raw bytes in flight at a time makes the peak O(largest
	// envelope), not O(corpus).
	if streamer, ok := s.source.(StreamingSourcer); ok {
		results := make([]CollectionVerificationResult, 0)
		streamErr := streamer.SearchStream(ctx, collectionName, subjectDigests, attestations, func(toVerify CollectionEnvelope) error {
			results = append(results, s.verifyCandidate(toVerify, subjectDigests))
			return nil
		})
		if streamErr != nil {
			return nil, streamErr
		}
		fmt.Fprintf(os.Stderr, "[verified-source] verified %d candidate envelope(s) for collection %q (streamed)\n", len(results), collectionName)
		return results, nil
	}

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
		results = append(results, s.verifyCandidate(toVerify, subjectDigests))
	}

	return results, nil
}

// SearchStream implements StreamingVerifiedSourcer. When the underlying
// Sourcer streams, each candidate is verified and yielded before the next is
// fetched — at most one raw envelope in flight on this side. Otherwise the
// materialized Search result is replayed through yield: no memory win, but
// callers get ONE consumption path with verdicts identical to Search either
// way (both funnel through verifyCandidate).
func (s *VerifiedSource) SearchStream(ctx context.Context, collectionName string, subjectDigests, attestations []string, yield func(CollectionVerificationResult) error) error {
	if streamer, ok := s.source.(StreamingSourcer); ok {
		count := 0
		err := streamer.SearchStream(ctx, collectionName, subjectDigests, attestations, func(toVerify CollectionEnvelope) error {
			count++
			return yield(s.verifyCandidate(toVerify, subjectDigests))
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[verified-source] verified %d candidate envelope(s) for collection %q (streamed, interleaved)\n", count, collectionName)
		return nil
	}

	results, err := s.Search(ctx, collectionName, subjectDigests, attestations)
	if err != nil {
		return err
	}
	for i := range results {
		if err := yield(results[i]); err != nil {
			return err
		}
	}
	return nil
}

// verifyCandidate runs the full per-candidate pipeline — DSSE signature
// verification, verifier accounting, the artifact-substitution subject guard,
// digest recording and byte release — and returns the compact result. It is
// the single implementation behind both the streamed and slice Search paths,
// so the two can never diverge on a verdict.
func (s *VerifiedSource) verifyCandidate(toVerify CollectionEnvelope, subjectDigests []string) CollectionVerificationResult { //nolint:gocognit,gocyclo // per-candidate verify with per-verifier pass/fail accounting plus the artifact-substitution subject guard; the branches enumerate signature-verification states, which is the function's purpose.
	envelopeVerifiers, err := toVerify.Envelope.Verify(s.verifyOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[verified-source] envelope %s signature verification FAILED: %v\n", toVerify.Reference, err)
		s.recordPayloadDigests(&toVerify)
		releaseEnvelopeBytes(&toVerify)
		toVerify.Statement.Predicate = nil
		return CollectionVerificationResult{
			Errors:             []error{fmt.Errorf("failed to verify envelope: %w", err)},
			CollectionEnvelope: toVerify,
		}
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

	// Verification + subject guard are complete. A candidate that PASSED both
	// keeps its raw payload for the policy gate's pass-time compaction +
	// rehydration (see retainPayloadReleaseRest); a candidate with no
	// verification future releases everything.
	s.recordPayloadDigests(&toVerify)
	if len(passedVerifiers) > 0 {
		retainPayloadReleaseRest(&toVerify)
	} else {
		releaseEnvelopeBytes(&toVerify)
		toVerify.Statement.Predicate = nil
	}
	return CollectionVerificationResult{
		Verifiers:                 passedVerifiers,
		VerifiedTimestampsByKeyID: timestampsByKeyID,
		CollectionEnvelope:        toVerify,
		Errors:                    Errors,
	}
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
