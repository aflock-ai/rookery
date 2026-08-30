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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// memoEnvelope builds a valid collection envelope (mirrors the audit-tagged
// makeTestEnvelope, which normal builds cannot see).
func memoEnvelope(t *testing.T, collectionName string, subjectDigests map[string]string) dsse.Envelope {
	t.Helper()
	predicate, err := json.Marshal(attestation.Collection{Name: collectionName})
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       []intoto.Subject{{Name: "test", Digest: subjectDigests}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	return dsse.Envelope{Payload: payload, PayloadType: "application/vnd.in-toto+json"}
}

// The policy depth loop re-searches every step on every iteration. When a
// step's inputs did not change, the repeat query returns nothing new by
// construction — every match is already in the ExcludeGitoids set — yet it
// still costs a GraphQL round trip and the server-side candidate sieve, the
// dominant consumer of the platform's database. The search memo skips repeats
// this source has already fully processed.
//
// The pinned semantics change: evidence uploaded between two IDENTICAL
// searches of one verify surfaces on the next verify, not on the repeat — the
// same outcome as that upload landing a moment after the verify finished.

// memoServer serves a fixed set of envelopes and counts search queries.
func memoServer(t *testing.T, envelopesByGitoid map[string][]byte, searchCalls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/query" {
			atomic.AddInt32(searchCalls, 1)
			edges := make([]map[string]any, 0, len(envelopesByGitoid))
			for gid := range envelopesByGitoid {
				edges = append(edges, map[string]any{"node": map[string]any{"gitoidSha256": gid}})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"dsses": map[string]any{"edges": edges}},
			})
			return
		}
		for gid, body := range envelopesByGitoid {
			if r.URL.Path == "/download/"+gid {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestArchivistaSource_RepeatedIdenticalSearchSkipsTheQuery(t *testing.T) {
	env := memoEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	envJSON, _ := json.Marshal(env)
	gid := envelopeGitoid(t, envJSON)

	var searchCalls int32
	srv := memoServer(t, map[string][]byte{gid: envJSON}, &searchCalls)
	defer srv.Close()

	src := NewArchivistaSource(archivista.New(srv.URL))

	first, err := src.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("first search: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("precondition: first search must yield the corpus, got %d", len(first))
	}

	repeat, err := src.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("repeat search: %v", err)
	}
	if len(repeat) != 0 {
		t.Errorf("an identical repeat must yield nothing (all seen), got %d", len(repeat))
	}
	if got := atomic.LoadInt32(&searchCalls); got != 1 {
		t.Errorf("the identical repeat must be served from the memo without a search query: got %d queries, want 1", got)
	}

	// A GROWN digest set is a different search and must query again — the
	// depth loop's whole purpose.
	if _, err := src.Search(context.Background(), "step1", []string{"abc", "def"}, nil); err != nil {
		t.Fatalf("grown search: %v", err)
	}
	if got := atomic.LoadInt32(&searchCalls); got != 2 {
		t.Errorf("a grown digest set must reach the server: got %d queries, want 2", got)
	}
}

// A yield error aborts the batch and marks nothing seen; the memo must follow
// the same all-or-nothing rule or the retry the abort semantics promise would
// silently become a no-op.
func TestArchivistaSource_AbortedBatchIsNotMemoized(t *testing.T) {
	env := memoEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	envJSON, _ := json.Marshal(env)
	gid := envelopeGitoid(t, envJSON)

	var searchCalls int32
	srv := memoServer(t, map[string][]byte{gid: envJSON}, &searchCalls)
	defer srv.Close()

	src := NewArchivistaSource(archivista.New(srv.URL))

	abort := context.DeadlineExceeded
	if err := src.SearchStream(context.Background(), "step1", []string{"abc"}, nil, func(CollectionEnvelope) error {
		return abort
	}); err == nil {
		t.Fatal("precondition: an aborting yield must error the stream")
	}

	got, err := src.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("retry after abort: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("the retry after an aborted batch must re-query and re-yield: got %d envelopes", len(got))
	}
	if calls := atomic.LoadInt32(&searchCalls); calls != 2 {
		t.Errorf("an aborted batch must not be memoized: got %d queries, want 2", calls)
	}
}

// The fingerprint must be INJECTIVE: no two distinct searches may share one,
// or completing the first silently suppresses the second (a correctness bug,
// not a perf bug). These pin the concrete collision classes a separator-join
// encoding admits.
func TestSearchFingerprint_IsInjective(t *testing.T) {
	if searchFingerprint("c", []string{"a", "b"}, nil) == searchFingerprint("c", []string{"a\x01b"}, nil) {
		t.Error("element content imitating the old separator must not collide: [a b] vs [a\\x01b]")
	}
	if searchFingerprint("c", []string{"a"}, []string{"b"}) == searchFingerprint("c", []string{"a", "b"}, nil) {
		t.Error("a value must not migrate across the digest/attestation boundary")
	}
	if searchFingerprint("c\x00x", nil, nil) == searchFingerprint("c", []string{"x"}, nil) {
		t.Error("collection-name content must not bleed into the digest list")
	}
	if searchFingerprint("c", []string{"1:a"}, nil) == searchFingerprint("c", []string{"1", ":a"}, nil) {
		t.Error("length-prefix look-alikes inside elements must not collide")
	}
	// The canonicalization property the memo depends on survives: caller
	// order does not distinguish identical searches.
	if searchFingerprint("c", []string{"b", "a"}, []string{"y", "x"}) != searchFingerprint("c", []string{"a", "b"}, []string{"x", "y"}) {
		t.Error("sorted canonicalization must make order-permuted identical searches equal")
	}
}
