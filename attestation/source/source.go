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

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

type CollectionEnvelope struct {
	Envelope   dsse.Envelope
	Statement  intoto.Statement
	Collection attestation.Collection
	Reference  string
	// PayloadDigests is the digest set of the exact signed Envelope.Payload
	// bytes, recorded by VerifiedSource before it releases those bytes from
	// the result (see VerifiedSource.WithEvidenceHashes). It preserves the
	// evidence identity the VSA's inputAttestations must carry after the
	// payload itself is gone. Empty when the producing source was not
	// configured to record it.
	PayloadDigests cryptoutil.DigestSet
}

// SubjectMatchScope returns the scope in which THIS envelope's subjects may be
// judged matchable (cryptoutil.SubjectMatchScope).
//
// It is a method on the envelope, not a free function over a type list, so the
// fact and the subjects it qualifies can only be read off the same object.
// Both halves come from Envelope.Payload — EnvelopeToCollectionEnvelope decodes
// Statement and Collection from those same bytes — so a source cannot
// contribute subjects from the signed payload while contributing the
// git-attested claim from somewhere else.
//
// Callers on the VERIFIED path must not use this: they have to read the claim
// out of the signature-verified payload itself, for the same reason
// payloadMatchesSubjects reads subjects there rather than from Statement.
func (ce CollectionEnvelope) SubjectMatchScope() cryptoutil.SubjectMatchScope {
	// The git arm (a SHA-1 commit subject) is claimable ONLY by an attestation
	// COLLECTION. A non-collection statement whose predicate merely decodes into
	// a Collection shape (an attestations[] a hand-crafted external predicate can
	// carry) must NOT get it, or the SHA-1 restriction is bypassed — so gate on
	// the statement's own predicateType, in agreement with the verified path.
	if !isCollectionPredicateType(ce.Statement.PredicateType) {
		return cryptoutil.SubjectMatchScope{}
	}
	for _, att := range ce.Collection.Attestations {
		// The scope needs BOTH halves of the hardened-git fact: the exact
		// current git type AND the verified-commit-hash marker inside the
		// attestation body. Type alone would grant the SHA-1 arm
		// retroactively to legacy evidence that shares the type string but
		// never received the producer-side verification.
		if !cryptoutil.IsHardenedGitAttestationType(att.Type) {
			continue
		}
		// Re-marshal the entry to read the marker uniformly: a typed
		// *git.Attestor round-trips its commithashverified field, and a
		// RawAttestation (no factory registered) returns the exact decoded
		// bytes — both are the same bytes EnvelopeToCollectionEnvelope took
		// from Envelope.Payload, so the claim and the subjects still come
		// from one object. Any marshal failure, or a nil/absent body, fails
		// CLOSED: no marker, no SHA-1 arm.
		body, err := json.Marshal(att.Attestation)
		if err != nil {
			continue
		}
		if cryptoutil.HasGitCommitVerifiedMarker(body) {
			return cryptoutil.SubjectMatchScope{HardenedGitAttested: true}
		}
	}
	return cryptoutil.SubjectMatchScope{}
}

// isCollectionPredicateType reports whether a statement's outer predicateType is
// rookery's attestation-collection type (current or legacy). The git subject arm
// is bound to this: only a signed collection may make a SHA-1 commit subject
// matchable. Read from the SIGNED statement's predicateType, never inferred from
// the predicate body — the body is what an attacker shapes.
func isCollectionPredicateType(predicateType string) bool {
	return predicateType == attestation.CollectionType || predicateType == attestation.LegacyCollectionType
}

// StreamingSourcer is an optional extension of Sourcer: it yields matching
// candidates ONE AT A TIME instead of materializing the whole matching set.
// VerifiedSource prefers this path when available, verifying and releasing
// each candidate's raw bytes before the next is fetched, so peak memory is
// O(largest envelope) instead of O(matching corpus) (#7572).
//
// Contract: yield is called once per candidate, in the same order Search
// would have returned them; a yield error aborts the iteration and must be
// returned unwrapped enough to surface, and the source must NOT mark aborted
// candidates as seen (retry semantics identical to Search's all-or-nothing
// seen-marking).
type StreamingSourcer interface {
	SearchStream(ctx context.Context, collectionName string, subjectDigests, attestations []string, yield func(CollectionEnvelope) error) error
}

// StatementEnvelope carries a non-Collection DSSE envelope (bare predicate)
// returned by Sourcer.SearchByPredicateType. Attestor is either a typed
// attestor produced by the registered factory for Statement.PredicateType,
// or an *attestation.RawAttestation wrapping the raw predicate JSON when no
// factory is registered. See issue #39.
type StatementEnvelope struct {
	Envelope  dsse.Envelope
	Statement intoto.Statement
	Attestor  attestation.Attestor
	Verifiers []cryptoutil.Verifier
	Reference string
	Errors    []error
}

// Sourcer fetches DSSE envelopes from a backing store.
//
// Search returns attestation Collections (existing behavior).
//
// SearchByPredicateType returns bare-predicate statements (e.g. SLSA
// provenance, VSA, cosign attestations) whose predicateType is in
// predicateTypes AND whose statement subjects intersect subjectDigests.
// Implementations MUST NOT add those additional subjects to the policy's
// running subject-digest set — external attestations are verified without
// participating in Collection subject-graph traversal.
type Sourcer interface {
	Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error)
	SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error)
}

// EnvelopeToCollectionEnvelope decodes a DSSE envelope into a
// CollectionEnvelope: the in-toto Statement out of the envelope payload, and
// the attestation Collection out of the Statement predicate.
//
// Exported so callers outside this package can decode envelopes the same way
// its own Sourcers do, instead of maintaining a parallel copy that drifts
// (judge-api's EntSource previously hand-copied this and lost the empty
// payload / empty predicateType guards below).
//
// It validates before decoding: an empty payload and an empty or
// non-collection predicateType are rejected with a named error rather than
// producing a zero-valued Collection that later reads as "a collection with
// no attestations".
func EnvelopeToCollectionEnvelope(reference string, env dsse.Envelope) (CollectionEnvelope, error) {
	if len(env.Payload) == 0 {
		return CollectionEnvelope{}, fmt.Errorf("envelope %s has empty payload", reference)
	}

	statement := intoto.Statement{}
	if err := json.Unmarshal(env.Payload, &statement); err != nil {
		return CollectionEnvelope{}, fmt.Errorf("envelope %s: failed to unmarshal statement (payload length %d, first 50 bytes: %q): %w",
			reference, len(env.Payload), truncate(env.Payload, 50), err)
	}

	if statement.PredicateType == "" {
		return CollectionEnvelope{}, fmt.Errorf("envelope %s: statement has empty predicateType (payload length %d)", reference, len(env.Payload))
	}

	collection := attestation.Collection{}
	if err := json.Unmarshal(statement.Predicate, &collection); err != nil {
		return CollectionEnvelope{}, fmt.Errorf("envelope %s: failed to unmarshal collection: %w", reference, err)
	}

	return CollectionEnvelope{
		Reference:  reference,
		Envelope:   env,
		Statement:  statement,
		Collection: collection,
	}, nil
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
