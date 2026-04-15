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

package source

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	intoto "github.com/aflock-ai/rookery/attestation/intoto"
)

func TestLoadEnvelope(t *testing.T) {
	// Marshal the attestation.Collection into a JSON byte array
	predicate, err := json.Marshal(attestation.Collection{})
	if err != nil {
		t.Fatalf("failed to marshal predicate, err = %v", err)
	}

	// Define the test cases
	tests := []struct {
		name                  string
		reference             string
		intotoStatment        intoto.Statement
		mSource               *MemorySource
		attCol                attestation.Collection
		wantLoadEnvelopeErr   bool
		wantPredicateErr      bool
		wantMemorySourceErr   bool
		wantReferenceExistErr bool
	}{
		{
			name:      "Valid intotoStatment",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://aflock.ai/attestation-collection/v0.1",
				Predicate:     json.RawMessage(predicate),
			},
			attCol:  attestation.Collection{},
			mSource: NewMemorySource(),
		},
		{
			name:                "Empty intotoStatment",
			reference:           "ref",
			intotoStatment:      intoto.Statement{},
			mSource:             NewMemorySource(),
			attCol:              attestation.Collection{},
			wantLoadEnvelopeErr: true, // empty predicateType is now rejected
			wantPredicateErr:    true,
			wantMemorySourceErr: true,
		},
		{
			name:      "Invalid intotoStatment Predicate",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://aflock.ai/attestation-collection/v0.1",
				Predicate:     json.RawMessage("invalid-predicate"),
			},
			attCol:              attestation.Collection{},
			mSource:             NewMemorySource(),
			wantLoadEnvelopeErr: true,
			wantMemorySourceErr: true,
		},
		{
			name:      "Valid intotoStatment",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://aflock.ai/attestation-collection/v0.1",
				Predicate:     json.RawMessage(predicate),
			},
			mSource:               NewMemorySource(),
			wantLoadEnvelopeErr:   true,
			wantReferenceExistErr: true,
		},
	}

	// Run the test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal the intoto.Statement into a JSON byte array
			statementBytes, _ := json.Marshal(tt.intotoStatment)

			// Create a new dsse.Envelope with the marshalled intoto.Statement as the payload
			envelope := dsse.Envelope{
				Payload:     statementBytes,
				PayloadType: "application/vnd.in-toto+json",
			}

			// Initialize a new MemorySource
			memorySource := NewMemorySource()
			if tt.wantReferenceExistErr {
				collEnv, err := envelopeToCollectionEnvelope(tt.reference, envelope)
				if err != nil {
					t.Fatalf("Invalid intotoStatment, err = %v", err)
				}
				// since this envelope is not in the MemorySource, we can add the collection envelope into the map
				memorySource.envelopesByReference[tt.reference] = collEnv
			}

			// Load the dsse.Envelope into the MemorySource
			err = memorySource.LoadEnvelope(tt.reference, envelope)
			if err != nil {
				// if we did not want the error
				if !tt.wantLoadEnvelopeErr {
					t.Fatalf("LoadEnvelope() error = %v, wantErr %v", err, tt.wantLoadEnvelopeErr)
				}
				return

			}

			// Check if the loaded envelope matches the expected CollectionEnvelope

			expectedCollectionEnvelope := CollectionEnvelope{
				Envelope:   envelope,
				Statement:  tt.intotoStatment,
				Collection: tt.attCol,
				Reference:  tt.reference,
			}
			if !reflect.DeepEqual(memorySource.envelopesByReference[tt.reference], expectedCollectionEnvelope) != tt.wantMemorySourceErr {
				t.Fatalf("Mismatch or non-existence of collection envelope for reference in envelopesByReference map.")
			}
			// Verify if the subjects and attestations are present in the loaded envelope
			for _, sub := range tt.intotoStatment.Subject {
				for _, digest := range sub.Digest {
					if _, ok := memorySource.subjectDigestsByReference[tt.reference][digest]; !ok != tt.wantMemorySourceErr {
						t.Fatalf("memorySource does not contain passed in digest = %v", digest)
					}
				}
			}
			for _, att := range tt.attCol.Attestations {
				if _, ok := memorySource.attestationsByReference[tt.reference][att.Attestation.Type()]; !ok != tt.wantMemorySourceErr {
					t.Fatalf("memorySource does not contain passed in attestation = %v", att.Attestation.Name())
				}
			}
		})
	}
}

func TestSearch(t *testing.T) {
	// Marshal the attestation.Collection into a JSON byte array
	validPredicate, err := json.Marshal(attestation.Collection{Name: "t"})
	if err != nil {
		t.Fatalf("failed to marshal predicate, err = %v", err)
	}

	// Define the arguments for the test cases
	type args struct {
		ctx            context.Context
		collectionName string
		subDigest      []string
		attestations   []string
	}
	// Define the test cases
	tests := []struct {
		name           string
		statements     []intoto.Statement
		searchQuery    args
		wantReferences map[string]struct{}
		wantErr        bool
	}{
		{
			name: "all match given query",
			statements: []intoto.Statement{
				{
					Type:          "1",
					Subject:       []intoto.Subject{{Name: "example1", Digest: map[string]string{"a": "exampledigest", "b": "exampledigest2", "c": "exampledigest3"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
				{
					Type:          "2",
					Subject:       []intoto.Subject{{Name: "example2", Digest: map[string]string{"a": "exampledigest", "b": "exampledigest2"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
				{
					Type:          "3",
					Subject:       []intoto.Subject{{Name: "example3", Digest: map[string]string{"a": "exampledigest"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
			},
			searchQuery: args{
				collectionName: "t",
				subDigest:      []string{"exampledigest", "notincluded"},
				attestations:   []string{},
			},
			wantReferences: map[string]struct{}{"ref0": {}, "ref1": {}, "ref2": {}},
			wantErr:        false,
		},
		{
			name: "some match",
			statements: []intoto.Statement{
				{
					Type:          "1",
					Subject:       []intoto.Subject{{Name: "example1", Digest: map[string]string{"a": "exampledigest", "b": "exampledigest2", "c": "exampledigest3"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
				{
					Type:          "2",
					Subject:       []intoto.Subject{{Name: "example2", Digest: map[string]string{"a": "exampledigest", "b": "exampledigest2"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
				{
					Type:          "3",
					Subject:       []intoto.Subject{{Name: "example3", Digest: map[string]string{"a": "exampledigest"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
				{
					Type:          "4",
					Subject:       []intoto.Subject{{Name: "example1", Digest: map[string]string{"a": "not included"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
			},
			searchQuery: args{
				collectionName: "t",
				subDigest:      []string{"exampledigest"},
				attestations:   []string{},
			},
			wantReferences: map[string]struct{}{"ref0": {}, "ref1": {}, "ref2": {}},
			wantErr:        false,
		},
		{
			name: "no matches",
			statements: []intoto.Statement{
				{
					Type:          "1",
					Subject:       []intoto.Subject{{Name: "example1", Digest: map[string]string{"a": "exampledigest", "b": "exampledigest2", "c": "exampledigest3"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
				{
					Type:          "2",
					Subject:       []intoto.Subject{{Name: "example2", Digest: map[string]string{"a": "exampledigest", "b": "exampledigest2"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
				{
					Type:          "3",
					Subject:       []intoto.Subject{{Name: "example3", Digest: map[string]string{"a": "exampledigest"}}},
					PredicateType: "https://aflock.ai/attestation-collection/v0.1",
					Predicate:     json.RawMessage(validPredicate),
				},
			},
			searchQuery: args{
				collectionName: "t",
				subDigest:      []string{},
				attestations:   []string{},
			},
			wantReferences: map[string]struct{}{},
			wantErr:        false,
		},
	}

	// Run the test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize a new MemorySource
			s := NewMemorySource()
			expectedResult := []CollectionEnvelope{}
			for i := range tt.statements {
				// Marshal the intoto.Statement into a JSON byte array
				payload, _ := json.Marshal(tt.statements[i])
				// Create a new dsse.Envelope with the marshalled intoto.Statement as the payload
				dsseEnv := dsse.Envelope{
					Payload:     payload,
					PayloadType: "application/vnd.in-toto+json",
				}
				// Load the dsse.Envelope into the MemorySource
				err := s.LoadEnvelope("ref"+fmt.Sprint(i), dsseEnv)
				if err != nil {
					t.Fatalf("invalid intoto statement, err = %v", err)
				}

				if _, ok := tt.wantReferences["ref"+fmt.Sprint(i)]; ok {
					collEnv, _ := envelopeToCollectionEnvelope("ref"+fmt.Sprint(i), dsseEnv)
					expectedResult = append(expectedResult, collEnv)
				}
			}

			// Run the search query on the MemorySource
			got, err := s.Search(tt.searchQuery.ctx, tt.searchQuery.collectionName, tt.searchQuery.subDigest, tt.searchQuery.attestations)
			if (err != nil) != tt.wantErr {
				t.Fatalf("MemorySource.Search() error = %v, wantErr %v", err, tt.wantErr)
			}
			// Check if the search results match the expected results
			if !reflect.DeepEqual(got, expectedResult) {
				t.Fatalf("MemorySource.Search() = %v, want %v", got, expectedResult)
			}
		})
	}
}

// TestSearchByPredicateType_HappyPath is the scaffold test for issue #39: a
// synthetic SLSA-v1 envelope loaded into MemorySource must be returned by
// SearchByPredicateType when the predicate type AND a subject digest match.
// The full 16-case matrix described in the issue is intentionally deferred
// to the follow-up PR once the verification flow is wired in.
func TestSearchByPredicateType_HappyPath(t *testing.T) {
	const (
		slsaV1PredicateType = "https://slsa.dev/provenance/v1"
		matchingDigest      = "deadbeefcafebabe"
	)

	// Synthetic SLSA provenance v1 predicate — just enough shape for the
	// statement parser; the scaffold does not exercise typed SLSA decoding.
	predicate := json.RawMessage(`{
        "buildDefinition": {"buildType": "https://example.com/build/v1"},
        "runDetails": {"builder": {"id": "https://example.com/builder"}}
    }`)

	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: slsaV1PredicateType,
		Subject: []intoto.Subject{
			{Name: "pkg:example/artifact", Digest: map[string]string{"sha256": matchingDigest}},
		},
		Predicate: predicate,
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	env := dsse.Envelope{Payload: payload, PayloadType: "application/vnd.in-toto+json"}

	s := NewMemorySource()
	if err := s.LoadEnvelope("ref-slsa-v1", env); err != nil {
		t.Fatalf("LoadEnvelope: %v", err)
	}

	// Also load a non-matching envelope (wrong predicate type) to confirm
	// filtering actually happens instead of returning everything.
	otherStmt := stmt
	otherStmt.PredicateType = "https://example.com/other/v1"
	otherPayload, err := json.Marshal(otherStmt)
	if err != nil {
		t.Fatalf("marshal other statement: %v", err)
	}
	if err := s.LoadEnvelope("ref-other", dsse.Envelope{Payload: otherPayload, PayloadType: "application/vnd.in-toto+json"}); err != nil {
		t.Fatalf("LoadEnvelope other: %v", err)
	}

	got, err := s.SearchByPredicateType(context.Background(), []string{slsaV1PredicateType}, []string{matchingDigest})
	if err != nil {
		t.Fatalf("SearchByPredicateType: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	if got[0].Reference != "ref-slsa-v1" {
		t.Errorf("Reference = %q, want %q", got[0].Reference, "ref-slsa-v1")
	}
	if got[0].Statement.PredicateType != slsaV1PredicateType {
		t.Errorf("PredicateType = %q, want %q", got[0].Statement.PredicateType, slsaV1PredicateType)
	}
	if got[0].Attestor == nil {
		t.Fatal("Attestor should be non-nil (RawAttestation fallback when no factory is registered)")
	}
	if got[0].Attestor.Type() != slsaV1PredicateType {
		t.Errorf("Attestor.Type() = %q, want %q", got[0].Attestor.Type(), slsaV1PredicateType)
	}

	// Subject digest must not match → zero results.
	got, err = s.SearchByPredicateType(context.Background(), []string{slsaV1PredicateType}, []string{"notamatch"})
	if err != nil {
		t.Fatalf("SearchByPredicateType (no-match subject): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 matches for non-matching subject digest, got %d", len(got))
	}
}
