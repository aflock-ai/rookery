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

// THE DEFECT (testifysec/judge#7592). ArchivistaSource excluded and marked its
// seen-set on EVERY search, the unfiltered diagnostic probe included. The
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
// way Archivista indexes it: by collection name, statement predicate type and
// subject digest. One envelope carries all three, because one envelope really
// does: a collection DSSE has a collection name AND a predicate type, so both
// search kinds can reach it — which is what makes one kind's exclusion leaking
// into the other observable at all.
type probeCorpusEntry struct {
	gitoid         string
	body           []byte
	collectionName string
	predicateType  string
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

// probeCorpusServer serves a fixed corpus and — crucially — HONOURS the four
// filters the real server applies: collectionName, predicateTypes,
// subjectDigests (empty means "no subject filter", exactly like the GraphQL
// `valueIn: null`), and excludeGitoids. searchVars records every variables
// block it was sent so a test can assert on the query the source actually
// issued, not just on what came back.
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

// searchCount is how many /query requests this server has answered. A test
// that asserts on lastSearchVars needs it: when a search never reaches the
// server (the SearchStream memo short-circuits an identical repeat),
// lastSearchVars silently returns the PREVIOUS search's variables and every
// assertion about "the query this search issued" becomes a claim about a
// different query.
func (s *probeCorpusServer) searchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.searchVars)
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
		wantedPredicates := make(map[string]struct{}, len(req.Variables.PredicateTypes))
		for _, p := range req.Variables.PredicateTypes {
			wantedPredicates[p] = struct{}{}
		}

		edges := make([]map[string]any, 0, len(corpus))
		for _, e := range corpus {
			if _, skip := excluded[e.gitoid]; skip {
				continue
			}
			if req.Variables.CollectionName != "" && req.Variables.CollectionName != e.collectionName {
				continue
			}
			// An absent predicate list is NO predicate filter: the
			// collection query (SearchGitoids) has no predicateTypes
			// variable at all, while the predicate query
			// (SearchGitoidsByPredicate) always sends a non-empty one.
			if len(wantedPredicates) > 0 {
				if _, ok := wantedPredicates[e.predicateType]; !ok {
					continue
				}
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

// collectionPredicateType is the predicate type memoEnvelope stamps on a
// collection statement. Naming it here lets a predicate-type search reach the
// same corpus entry a collection search reaches, which is the precondition for
// observing one search kind's exclusions inside the other's results.
const collectionPredicateType = "https://aflock.ai/attestation-collection/v0.1"

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
		predicateType:  collectionPredicateType,
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

// PRECONDITION for every predicate-type test: the fake must actually apply the
// predicate filter. Without this control a predicate search "matching" the
// corpus proves nothing — it would match against a fake that ignores
// predicateTypes and hands back everything, so a test could assert on results
// the real server would never have returned.
func TestProbeCorpusServer_AppliesThePredicateFilterServerSide(t *testing.T) {
	corpus := probeCorpus(t, "build", "abc")
	srv := newProbeCorpusServer(t, corpus)
	client := archivista.New(srv.URL)

	hit, err := client.SearchGitoidsByPredicate(context.Background(), archivista.SearchGitoidByPredicateVariables{
		PredicateTypes: []string{collectionPredicateType},
	})
	if err != nil {
		t.Fatalf("matching predicate search: %v", err)
	}
	if len(hit) != 1 {
		t.Fatalf("control: the corpus entry must be reachable by its own predicate type, got %d", len(hit))
	}

	miss, err := client.SearchGitoidsByPredicate(context.Background(), archivista.SearchGitoidByPredicateVariables{
		PredicateTypes: []string{"https://slsa.dev/provenance/v1"},
	})
	if err != nil {
		t.Fatalf("non-matching predicate search: %v", err)
	}
	if len(miss) != 0 {
		t.Fatalf("control: the fake must honour predicateTypes server-side, got %d", len(miss))
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

// SearchByPredicateType is the sibling instance of the same mechanism: on main
// it excluded and marked on every call regardless of whether a subject filter
// was supplied. The rule is the source's, not one method's — an unfiltered
// search neither consults nor updates the seen set — and since the two search
// kinds now keep SEPARATE seen sets, the rule has to hold PER KIND. So both
// halves below are exercised WITHIN the predicate kind: a probe that only
// looked harmless because its marks landed in some other kind's set would be a
// probe-gate regression this test must still catch.
//
// The orthogonal property — that a predicate search's marks never reach the
// collection kind's set — is swept in archivista_seen_isolation_test.go.
func TestArchivistaSource_UnfilteredPredicateSearchIsSeenNeutral(t *testing.T) {
	corpus := probeCorpus(t, "build", "abc")
	srv := newProbeCorpusServer(t, corpus)
	src := NewArchivistaSource(archivista.New(srv.URL))
	ctx := context.Background()

	probe, err := src.SearchByPredicateType(ctx, []string{collectionPredicateType}, nil)
	if err != nil {
		t.Fatalf("unfiltered predicate search: %v", err)
	}
	if len(probe) != 1 {
		t.Fatalf("precondition: the unfiltered predicate search must see the corpus it is asked about, got %d", len(probe))
	}
	if last := srv.lastSearchVars(t); len(last.ExcludeGitoids) != 0 {
		t.Errorf("an unfiltered predicate search sent %d excludeGitoids; it must query the whole corpus", len(last.ExcludeGitoids))
	}

	filtered, err := src.SearchByPredicateType(ctx, []string{collectionPredicateType}, []string{"abc"})
	if err != nil {
		t.Fatalf("filtered predicate search: %v", err)
	}
	if len(filtered) != 1 {
		t.Errorf("an unfiltered predicate search consumed the corpus: the later digest-filtered predicate search returned %d envelopes, want 1", len(filtered))
	}
}
