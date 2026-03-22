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
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

type CollectionEnvelope struct {
	Envelope   dsse.Envelope
	Statement  intoto.Statement
	Collection attestation.Collection
	Reference  string
}

type Sourcer interface {
	Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error)
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
