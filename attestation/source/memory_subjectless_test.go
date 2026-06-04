// Copyright 2025 The Aflock Authors
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
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	intoto "github.com/aflock-ai/rookery/attestation/intoto"
)

// loadSubjectlessCollection loads a CollectionType envelope with NO subjects
// (as produced by an env-only / SBOM-only step, or a step that errored before
// recording any product) into a fresh MemorySource under collection name "build".
func loadSubjectlessCollection(t *testing.T) *MemorySource {
	t.Helper()
	predicate, err := json.Marshal(attestation.Collection{Name: "build"})
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       nil, // SUBJECTLESS
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	src := NewMemorySource()
	if err := src.LoadEnvelope("env-only.json", dsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
	}); err != nil {
		t.Fatalf("LoadEnvelope: %v", err)
	}
	return src
}

// TestSearch_SubjectlessCollectionDoesNotMatchSpecificArtifact pins a fail-OPEN:
// a signed collection with NO subjects must NOT satisfy a query for a SPECIFIC
// artifact digest. Otherwise that collection can "verify" an artifact it never
// attested (artifact substitution / replay) — e.g. an attacker reuses a
// legitimately-signed env-only collection to pass `cilock verify --artifactfile
// some-other-binary`. Today matchesSubjects returns true for subjectless
// collections regardless of the query, so this test fails until that is closed.
func TestSearch_SubjectlessCollectionDoesNotMatchSpecificArtifact(t *testing.T) {
	src := loadSubjectlessCollection(t)

	matches, err := src.Search(context.Background(), "build",
		[]string{"sha256:attacker-artifact-that-was-never-attested"}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("FAIL-OPEN: a subjectless collection matched a specific artifact digest "+
			"it never attested (got %d matches, want 0). A subjectless collection must not "+
			"satisfy a specific-artifact query, or it enables artifact substitution.", len(matches))
	}
}

// TestSearch_SubjectlessCollectionMatchesSubjectAgnosticQuery pins the
// LEGITIMATE behavior the fix MUST preserve: when the caller asks for no
// specific artifact (empty subjectDigests — e.g. verifying a step that has no
// products, or a whole-policy walk), a subjectless collection should still be
// found. The fix must distinguish "no artifact requested" (match) from "this
// specific artifact requested" (require a real subject match).
func TestSearch_SubjectlessCollectionMatchesSubjectAgnosticQuery(t *testing.T) {
	src := loadSubjectlessCollection(t)

	matches, err := src.Search(context.Background(), "build", nil, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("a subject-agnostic query (no specific artifact) must still find the "+
			"subjectless collection (got %d matches, want 1)", len(matches))
	}
}
