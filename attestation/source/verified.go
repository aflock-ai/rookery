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
	// Decode ONLY the subject list, plus the one predicate FACT that decides
	// whether a SHA-1 commit subject may anchor a match. Decoding the full
	// intoto.Statement copies the predicate body into a fresh json.RawMessage —
	// for a prod SBOM/SARIF collection that is a multi-MB allocation per
	// candidate per Search call (per step per search depth). The narrow struct
	// still reads the signed payload bytes, so the artifact-substitution
	// guarantee is unchanged; the decoder scans (and syntax-validates) the
	// whole payload either way but retains only the subjects and a bool. A
	// malformed payload still fails closed.
	//
	// The git claim MUST be read here, from the signed bytes, and not lifted
	// off CollectionEnvelope.Collection: that field is populated by the
	// untrusted source and can be set independently of what was signed, so
	// trusting it would let a source hand a non-git statement the SHA-1 arm —
	// exactly the substitution bypass this function's subject rule closes.
	subjects, scope, err := decodeSignedSubjectScope(payload)
	if err != nil {
		return false, fmt.Errorf("decode signed payload for subject check: %w", err)
	}
	return subjectsMatchDigests(scope, subjects, subjectDigests), nil
}

// decodeSignedSubjectScope decodes the subject list and the git-attested scope
// from a SIGNATURE-VERIFIED payload. It is the SINGLE source of truth for every
// verification verdict that must read subjects/scope from the signed bytes
// rather than the source-populated Statement/Collection projection — the
// artifact-substitution subject guard here, and the subject fan-out guard via
// CollectionEnvelope.VerifiedSubjectScope — so those cannot disagree about what
// a candidate's signed subjects and git-attested-ness are.
//
// BIND THE GIT ARM TO A COLLECTION. gitAttestedClaim reads an attestations[]
// entry out of the predicate BODY, which a bare external predicate (SLSA, VSA,
// cosign) can hand-add to a plain object. The SHA-1 commit arm exists only for
// attestation collections, so the claim is granted only when the SIGNED
// statement's outer predicateType actually is the collection type. Reading the
// type from the predicate body instead would let the attacker-shaped body vouch
// for itself — exactly the bypass.
func decodeSignedSubjectScope(payload []byte) ([]intoto.Subject, cryptoutil.SubjectMatchScope, error) {
	var stmt struct {
		PredicateType string           `json:"predicateType"`
		Subject       []intoto.Subject `json:"subject"`
		Predicate     gitAttestedClaim `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, cryptoutil.SubjectMatchScope{}, err
	}
	gitAttested := bool(stmt.Predicate) && isCollectionPredicateType(stmt.PredicateType)
	return stmt.Subject, cryptoutil.SubjectMatchScope{HardenedGitAttested: gitAttested}, nil
}

// VerifiedSubjectScope derives a candidate's subjects and git-attested scope
// from its SIGNATURE-VERIFIED payload — the same source of truth
// payloadMatchesSubjects uses — for a caller making a VERIFICATION verdict (the
// subject fan-out guard). It exists because the Statement/Collection struct
// fields on a CollectionEnvelope are populated by the UNTRUSTED source and can
// be set independently of what was signed: a source can pass the substitution
// guard on the real signed evidence, then project DIFFERENT subjects/types into
// the envelope to skew a downstream classification. A verification verdict must
// never read those projected fields.
//
// The bool is false ONLY when no signed payload is retained — a
// directly-constructed envelope (a test, a legacy non-VerifiedSource path) that
// has no untrusted source behind it, where the envelope fields ARE the source of
// truth. A candidate that passed signature verification always retains its
// payload (VerifiedSource.retainPayloadReleaseRest), so on the real verified
// path this returns true and the caller never falls through to the projection.
// A retained-but-undecodable payload fails closed: true with no subjects, so the
// candidate is treated as closure-disjoint rather than read off the projection.
func (ce CollectionEnvelope) VerifiedSubjectScope() (subjects []intoto.Subject, scope cryptoutil.SubjectMatchScope, verified bool) {
	if len(ce.Envelope.Payload) == 0 {
		return nil, cryptoutil.SubjectMatchScope{}, false
	}
	subjects, scope, err := decodeSignedSubjectScope(ce.Envelope.Payload)
	if err != nil {
		return nil, cryptoutil.SubjectMatchScope{}, true
	}
	return subjects, scope, true
}

// gitAttestedClaim is "this predicate carries a HARDENED git attestation" —
// an attestations[] entry of the exact current git type whose body carries the
// verified-commit-hash capability marker — decoded straight out of a
// statement's predicate.
//
// Both halves are required, from the SAME entry. The type alone would grant
// the SHA-1 commit arm retroactively to legacy evidence that shares the type
// string but was signed before the producer verified commit hashes
// (computeVerifiedCommitHash); the marker alone, under a non-git or unknown
// type, is a producer-controlled key on an attestation nothing here vouches
// for. Legacy witness.dev types and unknown future git versions yield false —
// fail closed, exactly the derivation CollectionEnvelope.SubjectMatchScope
// makes from the typed collection. One predicate, two readers.
//
// It is a json.Unmarshaler rather than an inline struct field because the
// predicate is NOT always a collection. SearchByPredicateType runs bare
// predicates through the same guard — SLSA provenance, a VSA, a cosign
// attestation — and against those an inline `attestations` field is a type
// mismatch. payloadMatchesSubjects fails CLOSED on a decode error, so that
// would reject every external attestation outright: a guard widening into an
// outage. Here a predicate of any other shape simply yields false — no git
// claim, no SHA-1 arm, subjects checked exactly as before.
//
// It also costs nothing to read: encoding/json hands UnmarshalJSON a SUBSLICE
// of the payload, so the predicate body is never copied (#7572).
type gitAttestedClaim bool

func (g *gitAttestedClaim) UnmarshalJSON(predicate []byte) error {
	// RESET AT ENTRY. encoding/json calls this once per `predicate` key, and a
	// statement with DUPLICATE predicate keys (git-shaped first, non-git second)
	// would otherwise leave the flag latched true from the first call even though
	// the effective — last — predicate is non-git. Normal statement decoding is
	// last-wins, so this must be too, or the matcher grants the SHA-1 arm to a
	// statement whose real predicate attests no git. Zeroing here makes each call
	// reflect only its own predicate; the last one wins.
	*g = false
	var collection struct {
		Attestations []struct {
			Type        string                 `json:"type"`
			Attestation gitVerifiedMarkerClaim `json:"attestation"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(predicate, &collection); err != nil {
		// Not collection-shaped. The CLAIM fails closed (no git arm); the
		// statement does not, because the subject check is the point.
		return nil //nolint:nilerr // swallowing IS the contract: a bare predicate (SLSA, VSA, cosign) is not a decode failure of the statement, and propagating it would make payloadMatchesSubjects reject every external attestation
	}
	for _, att := range collection.Attestations {
		if cryptoutil.IsHardenedGitAttestationType(att.Type) && bool(att.Attestation) {
			*g = true
			return nil
		}
	}
	return nil
}

// gitVerifiedMarkerClaim is "this attestation body carries the
// verified-commit-hash capability marker", decoded from one
// attestations[].attestation entry of the narrow scope decode above.
//
// It is a json.Unmarshaler for the same two reasons gitAttestedClaim is: an
// attestation body is arbitrary producer JSON (a RawAttestation body can be an
// array, a string, null), and an inline struct field would turn any such body
// into a decode error that fails the WHOLE collection claim — including for
// hardened git evidence sitting next to it. A body of any other shape simply
// yields false: no marker, no SHA-1 arm (fail closed, per entry). And
// encoding/json hands it a SUBSLICE of the payload, so large sibling bodies
// (sboms, scan reports) are scanned in place, never copied (#7572).
//
// Duplicate keys inside one entry stay last-wins: each call resets the flag
// before reading its own body, mirroring gitAttestedClaim's entry reset.
type gitVerifiedMarkerClaim bool

func (m *gitVerifiedMarkerClaim) UnmarshalJSON(body []byte) error {
	*m = gitVerifiedMarkerClaim(cryptoutil.HasGitCommitVerifiedMarker(body))
	return nil
}

// subjectsMatchDigests reports whether the subject list attests at least one of
// the requested subject digests. An EMPTY request matches any statement (a
// subject-agnostic query — whole-policy walks, probes). A NON-EMPTY request
// requires the statement to actually carry one of the digests. Mirrors
// MemorySource's index-build digest matchability filter. Only call this on
// subjects decoded from signature-verified bytes, with a scope decoded from
// those same bytes (see payloadMatchesSubjects).
func subjectsMatchDigests(scope cryptoutil.SubjectMatchScope, subjects []intoto.Subject, subjectDigests []string) bool {
	if len(subjectDigests) == 0 {
		return true
	}
	have := make(map[string]struct{})
	for _, sub := range subjects {
		for algorithm, digest := range sub.Digest {
			if !scope.IsMatchableSubjectDigest(sub.Name, algorithm, digest) {
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

// CanonicalOrderSourcer is implemented by a source that guarantees its search
// results are yielded in a STABLE, CONTENT-DERIVED order — the same order, for
// the same corpus and the same query, on every call, in every process, on every
// replica.
//
// It exists for the minimum-witness stop-at-first-pass
// (policy.WithLazyStepSatisfaction). Stopping at the first passing collection
// makes StepResult.Passed — and therefore the SIGNED policy-verification
// attestation built from it — a function of DELIVERY ORDER. That is only
// acceptable if delivery order is itself a function of the corpus, which is a
// promise only the source can make.
//
// The bar is deliberately high, and "stable" is not enough on its own:
//
//   - Ordering by an unindexed column, or leaving it to the query planner, is
//     NOT canonical. judge-api's EntSource shipped with no ORDER BY at all,
//     which let Postgres return rows in any order it liked.
//   - Ordering by a value derived from ingestion (row id, insertion time) is
//     stable within one database but differs across replicas and re-imports,
//     so it is not content-derived and does not qualify.
//   - Ordering chosen by a REMOTE server is that server's contract, not this
//     source's. ArchivistaSource deliberately does not implement this.
//
// A source that does not implement this interface, or that returns false, is
// excluded from the lazy stop and verifies exhaustively. Failing to declare
// costs performance; declaring falsely costs determinism of a signed artifact,
// so the default is the safe one.
type CanonicalOrderSourcer interface {
	CanonicalStreamOrder() bool
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

// CanonicalStreamOrder FORWARDS the wrapped Sourcer's declaration. VerifiedSource
// never reorders: the streaming path yields in the underlying stream's order and
// the fallback path replays Search's slice in order, so its ordering guarantee is
// exactly whatever it wraps — no stronger, and no weaker.
//
// Forwarding is what makes the declaration reach the policy engine at all: the
// engine holds a VerifiedSourcer, and in production that is always a
// *VerifiedSource wrapping the real source (EntSource, ArchivistaSource, …).
// Without this, no production source could ever qualify for the lazy stop.
func (s *VerifiedSource) CanonicalStreamOrder() bool {
	c, ok := s.source.(CanonicalOrderSourcer)
	return ok && c.CanonicalStreamOrder()
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
		started := time.Now()
		results := make([]CollectionVerificationResult, 0)
		streamErr := streamer.SearchStream(ctx, collectionName, subjectDigests, attestations, func(toVerify CollectionEnvelope) error {
			results = append(results, s.verifyCandidate(toVerify, subjectDigests))
			return nil
		})
		if streamErr != nil {
			return nil, streamErr
		}
		fmt.Fprintln(os.Stderr, searchSummary(collectionName, "streamed", len(subjectDigests), len(results), verifiedOKCount(results), started))
		return results, nil
	}

	started := time.Now()
	candidates, err := s.source.Search(ctx, collectionName, subjectDigests, attestations)
	if err != nil {
		return nil, err
	}

	results := make([]CollectionVerificationResult, 0)
	// These envelopes are candidates matched by subject/attestation — their
	// signatures are checked below; "candidate" (not "unverified") avoids reading
	// as a verdict when it just means "fetched, pending verification".
	for _, toVerify := range candidates {
		results = append(results, s.verifyCandidate(toVerify, subjectDigests))
	}
	fmt.Fprintln(os.Stderr, searchSummary(collectionName, "slice", len(subjectDigests), len(candidates), verifiedOKCount(results), started))

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
		started := time.Now()
		count, okCount := 0, 0
		err := streamer.SearchStream(ctx, collectionName, subjectDigests, attestations, func(toVerify CollectionEnvelope) error {
			count++
			r := s.verifyCandidate(toVerify, subjectDigests)
			if len(r.Errors) == 0 {
				okCount++
			}
			return yield(r)
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, searchSummary(collectionName, "interleaved", len(subjectDigests), count, okCount, started))
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
