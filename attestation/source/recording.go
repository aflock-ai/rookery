// Copyright 2026 TestifySec, Inc.
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
	"sync"

	"github.com/aflock-ai/rookery/attestation/dsse"
)

// RecordingSource wraps another Sourcer and captures every envelope it
// returns, deduplicated by reference. Used by `cilock verify --output-bundle`
// so the final tarball contains everything that was actually consulted —
// including envelopes pulled from Archivista at verify time.
//
// Safe for concurrent use.
type RecordingSource struct {
	inner Sourcer
	// sink is shared with every Fork, so a bundle holds what any run consulted.
	sink *recordingSink
}

type recordingSink struct {
	mu        sync.Mutex
	seen      map[string]struct{}
	envelopes []dsse.Envelope
}

func NewRecordingSource(inner Sourcer) *RecordingSource {
	return &RecordingSource{
		inner: inner,
		sink:  &recordingSink{seen: make(map[string]struct{})},
	}
}

func (r *RecordingSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	out, err := r.inner.Search(ctx, collectionName, subjectDigests, attestations)
	if err != nil {
		return out, err
	}
	r.sink.mu.Lock()
	defer r.sink.mu.Unlock()
	for _, ce := range out {
		if _, ok := r.sink.seen[ce.Reference]; ok {
			continue
		}
		r.sink.seen[ce.Reference] = struct{}{}
		r.sink.envelopes = append(r.sink.envelopes, ce.Envelope)
	}
	return out, nil
}

func (r *RecordingSource) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error) {
	return r.SearchByPredicateTypeWithOptions(ctx, predicateTypes, subjectDigests, PredicateSearchOptions{})
}

// SearchByPredicateTypeWithOptions forwards the options to the inner source
// when it accepts them, and records what came back either way.
func (r *RecordingSource) SearchByPredicateTypeWithOptions(ctx context.Context, predicateTypes []string, subjectDigests []string, opts PredicateSearchOptions) ([]StatementEnvelope, error) {
	out, err := searchPredicateWithOptions(ctx, r.inner, predicateTypes, subjectDigests, opts)
	if err != nil {
		return out, err
	}
	r.sink.mu.Lock()
	defer r.sink.mu.Unlock()
	for _, se := range out {
		if _, ok := r.sink.seen[se.Reference]; ok {
			continue
		}
		r.sink.seen[se.Reference] = struct{}{}
		r.sink.envelopes = append(r.sink.envelopes, se.Envelope)
	}
	return out, nil
}

// Envelopes returns a copy of every envelope captured so far.
func (r *RecordingSource) Envelopes() []dsse.Envelope {
	r.sink.mu.Lock()
	defer r.sink.mu.Unlock()
	out := make([]dsse.Envelope, len(r.sink.envelopes))
	copy(out, r.sink.envelopes)
	return out
}
