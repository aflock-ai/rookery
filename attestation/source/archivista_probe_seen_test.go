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
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/archivista"
)

// THE DEFECT (testifysec/judge#7592). ArchivistaSource excluded and marked
// seenGitoids on EVERY search, the unfiltered diagnostic probe included. The
// probe matches every collection for a step name, so one diagnostic consumed
// the step's whole corpus; a later depth iteration — which is where evidence
// reached only through a back-referenced subject digest first becomes
// searchable — then had it excluded, the step went unsatisfied, and a policy
// that should PASS failed.
//
// These tests exercise the SOURCE end to end against a fake Archivista that
// applies gitoidSha256NotIn and the subject-digest filter SERVER-SIDE, the way
// the real one does. That fidelity is the whole point: a fake that ignores
// excludeGitoids passes whether or not the guard exists, because the exclusion
// never removes anything. probeCorpusServer below refuses to be that fake.

// probeCorpusEntry is one envelope in the fake server's corpus, indexed the
// way Archivista indexes it: by collection name and subject digest.
type probeCorpusEntry struct {
	gitoid         string
	body           []byte
	collectionName string
	subjectDigest  string
}

// probeSearchVars mirrors the variables block SearchGitoids sends.
type probeSearchVars struct {
	SubjectDigests []string `json:"subjectDigests"`
	CollectionName string   `json:"collectionName"`
	Attestations   []string `json:"attestations"`
	ExcludeGitoids []string `json:"excludeGitoids"`
	PredicateTypes []string `json:"predicateTypes"`
}

// probeCorpusServer serves a fixed corpus and — crucially — HONOURS the three
// filters the real server applies: collectionName, subjectDigests (empty means
// "no subject filter", exactly like the GraphQL `valueIn: null`), and
// excludeGitoids. searchVars records every variables block it was sent so a
// test can assert on the query the source actually issued, not just on what
// came back.
type probeCorpusServer struct {
	*httptest.Server
	mu         sync.Mutex
	searchVars []probeSearchVars
}

// lastSearchVars returns the variables block of the most recent /query, under
// the lock: the handler runs on the server's goroutine and the race detector
// does not follow the happens-before edge through the socket.
func (s *probeCorpusServer) lastSearchVars(t *testing.T) probeSearchVars {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.searchVars) == 0 {
		t.Fatal("no search reached the server")
	}
	return s.searchVars[len(s.searchVars)-1]
}

func newProbeCorpusServer(t *testing.T, corpus []probeCorpusEntry) *probeCorpusServer {
	t.Helper()
	s := &probeCorpusServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Variables probeSearchVars `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.searchVars = append(s.searchVars, req.Variables)
		s.mu.Unlock()

		excluded := make(map[string]struct{}, len(req.Variables.ExcludeGitoids))
		for _, g := range req.Variables.ExcludeGitoids {
			excluded[g] = struct{}{}
		}
		wanted := make(map[string]struct{}, len(req.Variables.SubjectDigests))
		for _, d := range req.Variables.SubjectDigests {
			wanted[d] = struct{}{}
		}

		edges := make([]map[string]any, 0, len(corpus))
		for _, e := range corpus {
			if _, skip := excluded[e.gitoid]; skip {
				continue
			}
			if req.Variables.CollectionName != "" && req.Variables.CollectionName != e.collectionName {
				continue
			}
			// An empty digest list is NO subject filter, matching the
			// GraphQL `valueIn: $subjectDigests` with a null binding.
			if len(wanted) > 0 {
				if _, ok := wanted[e.subjectDigest]; !ok {
					continue
				}
			}
			edges = append(edges, map[string]any{"node": map[string]any{"gitoidSha256": e.gitoid}})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"dsses": map[string]any{"edges": edges}},
		})
	})

	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		for _, e := range corpus {
			if r.URL.Path == "/download/"+e.gitoid {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(e.body)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// probeCorpus builds a one-collection corpus: collection `name`, subject
// digest `digest`, content-addressed the way the client re-hashes it.
func probeCorpus(t *testing.T, name, digest string) []probeCorpusEntry {
	t.Helper()
	env := memoEnvelope(t, name, map[string]string{"sha256": digest})
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return []probeCorpusEntry{{
		gitoid:         envelopeGitoid(t, body),
		body:           body,
		collectionName: name,
		subjectDigest:  digest,
	}}
}

// PRECONDITION for every test below: the fake must actually apply the
// exclusion. Without this control, "the filtered search returned the
// collection" proves nothing — it would hold against a server that ignores
// excludeGitoids entirely, which is exactly the fake that let this defect
// survive.
func TestProbeCorpusServer_AppliesTheExclusionServerSide(t *testing.T) {
	corpus := probeCorpus(t, "build", "abc")
	srv := newProbeCorpusServer(t, corpus)
	client := archivista.New(srv.URL)

	all, err := client.SearchGitoids(context.Background(), archivista.SearchGitoidVariables{CollectionName: "build"})
	if err != nil {
		t.Fatalf("unfiltered search: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("control: the corpus must be visible without an exclusion, got %d", len(all))
	}

	none, err := client.SearchGitoids(context.Background(), archivista.SearchGitoidVariables{
		CollectionName: "build",
		ExcludeGitoids: []string{corpus[0].gitoid},
	})
	if err != nil {
		t.Fatalf("excluded search: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("control: the fake must honour excludeGitoids server-side, got %d", len(none))
	}
}

// THE RED TEST for #7592: a diagnostic probe must not bury the evidence a
// later digest-filtered search depends on.
//
// Against the unguarded source the probe marks the collection seen and this
// fails with 0 collections on the second search — the verdict flip described
// in the issue, reproduced at the source boundary.
func TestArchivistaSource_ProbeDoesNotBuryEvidenceFromALaterFilteredSearch(t *testing.T) {
	corpus := probeCorpus(t, "build", "abc")
	srv := newProbeCorpusServer(t, corpus)
	src := NewArchivistaSource(archivista.New(srv.URL))
	ctx := context.Background()

	// Depth 0: the step is not yet reachable, the filtered search comes back
	// empty, and diagnoseEmptyCollectionResult probes with a NIL digest set.
	probe, err := src.Search(ctx, "build", nil, nil)
	if err != nil {
		t.Fatalf("probe search: %v", err)
	}
	if len(probe) != 1 {
		t.Fatalf("precondition: the probe must see the corpus it is asked to describe, got %d", len(probe))
	}

	// Depth N: back-reference discovery has added the collection's subject
	// digest to the seed set. The evidence must still be adjudicable.
	filtered, err := src.Search(ctx, "build", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("filtered search: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("a diagnostic probe buried the step's evidence: the later digest-filtered search returned %d collections, want 1 — "+
			"the probe marked the corpus seen and the exclusion removed it, so the step goes unsatisfied and a passing policy fails", len(filtered))
	}
	if filtered[0].Reference != corpus[0].gitoid {
		t.Errorf("filtered search returned %q, want the corpus gitoid %q", filtered[0].Reference, corpus[0].gitoid)
	}
}

// The OTHER half of the gate, which fails differently and so needs its own
// test: a probe must not have the exclusion APPLIED to it either. If it did,
// the probe would answer about the unseen remainder rather than the corpus and
// diagnoseEmptyCollectionResult would report ErrNoCollections for a step whose
// collections exist and were merely already returned.
func TestArchivistaSource_ProbeIsNotFilteredByTheSeenSet(t *testing.T) {
	corpus := probeCorpus(t, "build", "abc")
	srv := newProbeCorpusServer(t, corpus)
	src := NewArchivistaSource(archivista.New(srv.URL))
	ctx := context.Background()

	first, err := src.Search(ctx, "build", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("filtered search: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("precondition: the filtered search must return the corpus and mark it seen, got %d", len(first))
	}

	probe, err := src.Search(ctx, "build", nil, nil)
	if err != nil {
		t.Fatalf("probe search: %v", err)
	}
	if len(probe) != 1 {
		t.Errorf("the probe answered about the UNSEEN REMAINDER, not the corpus: got %d collections, want 1 — "+
			"a probe with the exclusion applied reports ErrNoCollections for evidence that exists and was merely already returned", len(probe))
	}
	// And it must be side-effect free in the other direction too: the probe
	// must not have told the server to skip anything.
	last := srv.lastSearchVars(t)
	if len(last.ExcludeGitoids) != 0 {
		t.Errorf("the probe sent %d excludeGitoids; a diagnostic must query the whole corpus", len(last.ExcludeGitoids))
	}
}

// NO REGRESSION to the #7572 re-download fix: a DIGEST-FILTERED search must
// still exclude what this source already returned, and must still mark. Uses a
// GROWN digest set so the search memo cannot short-circuit the second query —
// otherwise this would pass on the memo alone and say nothing about the
// exclusion.
func TestArchivistaSource_FilteredSearchStillExcludesAndMarks(t *testing.T) {
	corpus := probeCorpus(t, "build", "abc")
	srv := newProbeCorpusServer(t, corpus)
	src := NewArchivistaSource(archivista.New(srv.URL))
	ctx := context.Background()

	first, err := src.Search(ctx, "build", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("first search: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("precondition: first search must yield the corpus, got %d", len(first))
	}

	grown, err := src.Search(ctx, "build", []string{"abc", "def"}, nil)
	if err != nil {
		t.Fatalf("grown search: %v", err)
	}
	if len(grown) != 0 {
		t.Errorf("a digest-filtered search must exclude what this source already returned: got %d, want 0 — "+
			"without the exclusion every depth iteration re-downloads the corpus", len(grown))
	}
	last := srv.lastSearchVars(t)
	if len(last.ExcludeGitoids) != 1 || last.ExcludeGitoids[0] != corpus[0].gitoid {
		t.Errorf("the filtered search must carry the seen gitoid as excludeGitoids, got %v", last.ExcludeGitoids)
	}
}

// SearchByPredicateType is the sibling instance of the same mechanism: it
// shares this source's one seen-set, and on main it excluded and marked on
// every call regardless of whether a subject filter was supplied. The rule is
// the source's, not one method's — an unfiltered search neither consults nor
// updates the seen set.
func TestArchivistaSource_UnfilteredPredicateSearchIsSeenNeutral(t *testing.T) {
	corpus := probeCorpus(t, "build", "abc")
	srv := newProbeCorpusServer(t, corpus)
	src := NewArchivistaSource(archivista.New(srv.URL))
	ctx := context.Background()

	if _, err := src.SearchByPredicateType(ctx, []string{"https://slsa.dev/provenance/v1"}, nil); err != nil {
		t.Fatalf("unfiltered predicate search: %v", err)
	}
	if last := srv.lastSearchVars(t); len(last.ExcludeGitoids) != 0 {
		t.Errorf("an unfiltered predicate search sent %d excludeGitoids; it must query the whole corpus", len(last.ExcludeGitoids))
	}

	filtered, err := src.Search(ctx, "build", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("filtered search: %v", err)
	}
	if len(filtered) != 1 {
		t.Errorf("an unfiltered predicate search consumed the corpus: the later digest-filtered search returned %d collections, want 1", len(filtered))
	}
}
