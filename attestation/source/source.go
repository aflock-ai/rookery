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

func envelopeToCollectionEnvelope(reference string, env dsse.Envelope) (CollectionEnvelope, error) {
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
