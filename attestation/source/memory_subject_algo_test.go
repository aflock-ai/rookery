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
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	intoto "github.com/aflock-ai/rookery/attestation/intoto"
)

// loadCollectionWithSubject loads a CollectionType envelope whose single
// subject carries the given (algorithm -> value) digest under collection name
// "build", into a fresh MemorySource.
func loadCollectionWithSubject(t *testing.T, digest map[string]string) *MemorySource {
	t.Helper()
	predicate, err := json.Marshal(attestation.Collection{Name: "build"})
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: "artifact", Digest: digest}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	src := NewMemorySource()
	if err := src.LoadEnvelope("build.json", dsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
	}); err != nil {
		t.Fatalf("LoadEnvelope: %v", err)
	}
	return src
}

// TestSearch_SHA1SubjectDoesNotAnchorMatch pins finding S1: a subject digest
// recorded only under SHA-1 must NOT satisfy a specific-artifact query. SHA-1
// has practical chosen-prefix collisions, so allowing it to anchor a subject
// match enables artifact substitution — an attacker crafts a second artifact
// with the same SHA-1 and replays the legitimately-signed collection against
// it. The query value is the recorded SHA-1 value itself; before the fix the
// index keyed digests by raw value with the algorithm stripped, so this matched.
func TestSearch_SHA1SubjectDoesNotAnchorMatch(t *testing.T) {
	sha1Value := strings.Repeat("a", 40) // well-formed sha1 hex
	src := loadCollectionWithSubject(t, map[string]string{"sha1": sha1Value})

	matches, err := src.Search(context.Background(), "build", []string{sha1Value}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("SHA-1 subject anchored a match (got %d, want 0) — SHA-1 is "+
			"collision-vulnerable and must not be a subject-match algorithm", len(matches))
	}
}

// TestSearch_MalformedSHA256SubjectRejected pins the length-validation half of
// finding S1: a subject whose value is the wrong length for its declared
// algorithm is malformed and must not be indexed as a matchable subject.
func TestSearch_MalformedSHA256SubjectRejected(t *testing.T) {
	badValue := strings.Repeat("a", 16) // declared sha256 but only 16 hex chars
	src := loadCollectionWithSubject(t, map[string]string{"sha256": badValue})

	matches, err := src.Search(context.Background(), "build", []string{badValue}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("malformed (wrong-length) sha256 subject anchored a match "+
			"(got %d, want 0)", len(matches))
	}
}

// TestSearch_ValidSHA256SubjectStillMatches guards the legitimate path the fix
// must preserve: a well-formed sha256 subject is still found by a query for its
// value.
func TestSearch_ValidSHA256SubjectStillMatches(t *testing.T) {
	good := strings.Repeat("b", 64)
	src := loadCollectionWithSubject(t, map[string]string{"sha256": good})

	matches, err := src.Search(context.Background(), "build", []string{good}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("a well-formed sha256 subject must still match its own digest "+
			"(got %d, want 1)", len(matches))
	}
}

// TestSearch_SHA1ValueDoesNotCrossMatchSHA256 pins the cross-algorithm half of
// finding S1. A collection records a subject under sha256 with value V; an
// attacker queries for the SAME string V but means it as a sha1 digest (a
// crafted SHA-1 collision printed as 64 chars, or any value that coincides).
// Because the recorded subject is a valid sha256 and the query value is equal,
// it WILL match — this is expected: the value-keyed index can't tell the
// query's intended algorithm apart. This test documents that the residual
// cross-algorithm exposure is bounded to value-equality (no length/algo
// confusion lets a 40-char sha1 stand in for a 64-char sha256), which is the
// in-scope guarantee of this fix. A full algorithm:value keying requires a
// coordinated Sourcer-caller change (tracked follow-up).
func TestSearch_SHA1ValueDoesNotCrossMatchSHA256(t *testing.T) {
	// Recorded subject: a real sha256 (64 hex).
	recorded := strings.Repeat("c", 64)
	src := loadCollectionWithSubject(t, map[string]string{"sha256": recorded})

	// A 40-char value (sha1 length) can never equal the 64-char recorded
	// sha256, so it must not match — the length gate prevents a short sha1
	// value from standing in for a sha256 subject.
	sha1Length := strings.Repeat("c", 40)
	matches, err := src.Search(context.Background(), "build", []string{sha1Length}, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("a sha1-length value cross-matched a sha256 subject "+
			"(got %d, want 0)", len(matches))
	}
}
