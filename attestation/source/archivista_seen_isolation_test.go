// jade:ring local
//
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
	"reflect"
	"testing"

	"github.com/aflock-ai/rookery/attestation/archivista"
)

// THE DEFECT (testifysec/judge#8976, part 2). ArchivistaSource kept ONE
// seenGitoids slice and both of its search paths read and appended to it.
// SearchStream searches COLLECTIONS by name; SearchByPredicateType searches
// bare DSSE statements by predicate type. They are different queries over
// different result spaces, so one kind's exclusions suppressed the other
// kind's results: a collection search that returned an envelope made a later
// predicate search over that same envelope come back empty, and vice versa.
// The external-attestation flow (SLSA provenance, VSAs, cosign attestations)
// then found nothing, for a reason nothing in the logs explains.
//
// THE PROPERTY, stated over the whole set rather than one direction: every
// search kind carries its OWN exclusion set, containing exactly the gitoids
// that kind processed and never another kind's. That is a claim about a
// PRODUCT — kinds × kinds — so the test below is a sweep of that product, not
// an instance. The diagonal (a kind against itself) is not filler: it is the
// anti-vacuity control. Deleting the exclusion mechanism outright would
// satisfy every off-diagonal cell, and only the diagonal notices.
//
// Completeness of the enumeration is itself checked, in
// TestSearchKinds_CoverEverySearchEntryPoint.

// searchKind is one of ArchivistaSource's search entry points, reduced to what
// the sweep needs: a way to issue one search and read back the gitoids it
// yielded.
type searchKind struct {
	name string
	// methods are the exported methods this kind is reached through. The
	// closure guard compares the union of these against the type's real
	// method set, so the sweep cannot silently stop covering the type.
	methods []string
	// run issues one search of this kind against src, restricted to the
	// given subject digests, and returns the gitoids it yielded.
	run func(t *testing.T, src *ArchivistaSource, subjectDigests []string) []string
}

// seenSweepCollection is the corpus's collection name, and
// collectionPredicateType (archivista_probe_seen_test.go) its predicate type.
// ONE envelope answers to both, which is the only way a leak between the two
// kinds' sets is observable at the source boundary.
const seenSweepCollection = "build"

func searchKinds() []searchKind {
	return []searchKind{
		{
			name:    "collection",
			methods: []string{"Search", "SearchStream"},
			run: func(t *testing.T, src *ArchivistaSource, subjectDigests []string) []string {
				t.Helper()
				envs, err := src.Search(context.Background(), seenSweepCollection, subjectDigests, nil)
				if err != nil {
					t.Fatalf("collection search: %v", err)
				}
				got := make([]string, 0, len(envs))
				for _, e := range envs {
					got = append(got, e.Reference)
				}
				return got
			},
		},
		{
			name:    "predicate",
			methods: []string{"SearchByPredicateType"},
			run: func(t *testing.T, src *ArchivistaSource, subjectDigests []string) []string {
				t.Helper()
				envs, err := src.SearchByPredicateType(context.Background(), []string{collectionPredicateType}, subjectDigests)
				if err != nil {
					t.Fatalf("predicate search: %v", err)
				}
				got := make([]string, 0, len(envs))
				for _, e := range envs {
					got = append(got, e.Reference)
				}
				return got
			},
		},
	}
}

// TestArchivistaSource_EachSearchKindKeepsItsOwnExclusionSet sweeps the full
// product of search kinds. For every ordered pair (producer, consumer) it runs
// a real digest-filtered search of each kind against a fake Archivista that
// applies excludeGitoids SERVER-SIDE, and asserts on the excludeGitoids the
// server was actually sent — the observable that proves what the source asked
// for, rather than what some local variable happened to hold.
//
//   - producer == consumer: the exclusion MUST be carried. Without this the
//     sweep would pass against a source with no exclusion at all.
//   - producer != consumer: the exclusion MUST NOT be carried, and the
//     consumer must still see the whole corpus.
func TestArchivistaSource_EachSearchKindKeepsItsOwnExclusionSet(t *testing.T) {
	kinds := searchKinds()
	for _, producer := range kinds {
		for _, consumer := range kinds {
			t.Run(producer.name+"_then_"+consumer.name, func(t *testing.T) {
				corpus := probeCorpus(t, seenSweepCollection, "abc")
				gitoid := corpus[0].gitoid
				srv := newProbeCorpusServer(t, corpus)
				src := NewArchivistaSource(archivista.New(srv.URL))

				first := producer.run(t, src, []string{"abc"})
				if len(first) != 1 || first[0] != gitoid {
					t.Fatalf("precondition: the %s search must yield the corpus gitoid %q, got %v", producer.name, gitoid, first)
				}

				// A GROWN digest set, so the SearchStream memo cannot
				// short-circuit the consumer: a repeat with an identical
				// fingerprint never reaches the server, and then every
				// assertion below would be about the producer's query.
				before := srv.searchCount()
				second := consumer.run(t, src, []string{"abc", "def"})
				if got := srv.searchCount(); got != before+1 {
					t.Fatalf("anti-vacuity: the %s consumer search must reach the server, got %d queries, want %d", consumer.name, got, before+1)
				}
				sent := srv.lastSearchVars(t)

				if producer.name == consumer.name {
					// The diagonal. Same kind, so the exclusion is the
					// point: this is what stops every depth iteration
					// re-downloading the corpus (#7572).
					if len(sent.ExcludeGitoids) != 1 || sent.ExcludeGitoids[0] != gitoid {
						t.Errorf("a repeat %s search must carry its own seen gitoid as excludeGitoids, got %v — "+
							"without it the exclusion mechanism is gone and the off-diagonal cells prove nothing", consumer.name, sent.ExcludeGitoids)
					}
					if len(second) != 0 {
						t.Errorf("a repeat %s search must not re-yield what that kind already returned, got %v", consumer.name, second)
					}
					return
				}

				if len(sent.ExcludeGitoids) != 0 {
					t.Errorf("a %s search excluded %v, gitoids only the %s search processed — "+
						"the two kinds share one seen set, so one kind's results silently suppress the other's",
						consumer.name, sent.ExcludeGitoids, producer.name)
				}
				if len(second) != 1 || second[0] != gitoid {
					t.Errorf("a %s search hid the corpus from a later %s search: got %v, want [%s] — "+
						"the evidence exists and was merely already returned to a DIFFERENT kind of query",
						producer.name, consumer.name, second, gitoid)
				}
			})
		}
	}
}

// notASearchKind classifies the exported methods of *ArchivistaSource that are
// NOT search entry points. It is empty today because every exported method is
// one; it exists so the guard below can be exhaustive over the type rather
// than over a name prefix.
var notASearchKind = map[string]string{}

// TestSearchKinds_CoverEverySearchEntryPoint is what makes the sweep above a
// SWEEP rather than two hand-picked cases: it checks that searchKinds()
// enumerates the source's entire search surface.
//
// The check is exhaustive over the type's exported methods and FAILS CLOSED —
// a newly added method is unclassified, and unclassified is a failure, so a
// third search kind cannot appear without either joining the sweep or being
// explicitly declared not to be one. A name-prefix heuristic ("everything
// called Search*") would have let a differently-named entry point through,
// which is the whole failure mode this guards.
func TestSearchKinds_CoverEverySearchEntryPoint(t *testing.T) {
	covered := map[string]bool{}
	for _, k := range searchKinds() {
		for _, m := range k.methods {
			covered[m] = true
		}
	}

	typ := reflect.TypeOf(&ArchivistaSource{})
	real := map[string]bool{}
	for i := range typ.NumMethod() {
		name := typ.Method(i).Name
		real[name] = true
		if covered[name] {
			continue
		}
		if _, declared := notASearchKind[name]; declared {
			continue
		}
		t.Errorf("exported method %s.%s is classified neither as a search kind (searchKinds) nor as a non-search method (notASearchKind): "+
			"if it is a search, the seen-set isolation sweep does not cover it", typ.Elem().Name(), name)
	}

	// And the reverse, so the table cannot drift into naming methods that no
	// longer exist and quietly claim coverage of nothing.
	for m := range covered {
		if !real[m] {
			t.Errorf("searchKinds names method %s, which %s does not have", m, typ.Elem().Name())
		}
	}
	for m := range notASearchKind {
		if !real[m] {
			t.Errorf("notASearchKind names method %s, which %s does not have", m, typ.Elem().Name())
		}
	}
}
