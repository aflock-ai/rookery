//go:build audit

package source

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// --- Test helpers ---

// makeTestEnvelope creates a valid collection envelope for testing.
func makeTestEnvelope(t *testing.T, collectionName string, subjectDigests map[string]string) dsse.Envelope {
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

	return dsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
	}
}

// errSourcer is a source that always returns an error.
type errSourcer struct {
	err error
}

func (s *errSourcer) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	return nil, s.err
}

func (s *errSourcer) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error) {
	return nil, s.err
}

// delaySourcer is a source that blocks until its channel is closed, then returns results.
type delaySourcer struct {
	gate    chan struct{}
	results []CollectionEnvelope
}

func (s *delaySourcer) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	<-s.gate
	return s.results, nil
}

func (s *delaySourcer) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error) {
	<-s.gate
	return nil, nil
}

// --- MemorySource adversarial tests ---

// TestMemorySource_DuplicateReference verifies that loading the same reference
// twice returns ErrDuplicateReference.
func TestMemorySource_DuplicateReference(t *testing.T) {
	ms := NewMemorySource()
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc123"})

	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("first LoadEnvelope failed: %v", err)
	}

	err := ms.LoadEnvelope("ref1", env)
	if err == nil {
		t.Errorf("BUG: second LoadEnvelope with same reference should fail")
	} else {
		var dupErr ErrDuplicateReference
		if errors.As(err, &dupErr) {
			t.Logf("OK: correctly returned ErrDuplicateReference: %v", err)
		} else {
			t.Errorf("BUG: expected ErrDuplicateReference, got %T: %v", err, err)
		}
	}
}

// TestMemorySource_SearchWithNilContext verifies behavior with nil context.
func TestMemorySource_SearchWithNilContext(t *testing.T) {
	ms := NewMemorySource()
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})

	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	// MemorySource.Search doesn't use context at all, so nil should work.
	// This documents the contract mismatch: the interface requires context
	// but MemorySource ignores it.
	//nolint:staticcheck // testing nil context deliberately
	results, err := ms.Search(nil, "step1", []string{"abc"}, nil)
	if err != nil {
		t.Errorf("BUG: MemorySource.Search with nil context failed: %v", err)
	} else {
		t.Logf("OK: MemorySource.Search ignores context (nil works), found %d results", len(results))
	}
}

// TestMemorySource_SearchEmptySubjectDigests verifies that empty subject
// digests returns no matches (not all matches).
func TestMemorySource_SearchEmptySubjectDigests(t *testing.T) {
	ms := NewMemorySource()
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})

	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	results, err := ms.Search(context.Background(), "step1", []string{}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("BUG: empty subject digests should return no matches, got %d", len(results))
	} else {
		t.Logf("OK: empty subject digests correctly returns no matches")
	}
}

// TestMemorySource_SearchNilAttestations verifies that nil attestations list
// means "match any attestations" (vacuously true).
func TestMemorySource_SearchNilAttestations(t *testing.T) {
	ms := NewMemorySource()
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})

	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	results, err := ms.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("BUG: nil attestations filter should match everything, got %d results", len(results))
	} else {
		t.Logf("OK: nil attestations acts as 'match any', found %d result(s)", len(results))
	}
}

// TestMemorySource_SearchWrongCollectionName verifies collection name filtering.
func TestMemorySource_SearchWrongCollectionName(t *testing.T) {
	ms := NewMemorySource()
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})

	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	results, err := ms.Search(context.Background(), "wrong-name", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("BUG: wrong collection name should return no matches, got %d", len(results))
	} else {
		t.Logf("OK: wrong collection name correctly returns no matches")
	}
}

// TestMemorySource_InvalidEnvelopePayload verifies behavior with invalid JSON payload.
func TestMemorySource_InvalidEnvelopePayload(t *testing.T) {
	ms := NewMemorySource()

	env := dsse.Envelope{
		Payload:     []byte("not-valid-json"),
		PayloadType: "application/vnd.in-toto+json",
	}

	err := ms.LoadEnvelope("ref1", env)
	if err == nil {
		t.Errorf("BUG: LoadEnvelope should fail with invalid JSON payload")
	} else {
		t.Logf("OK: invalid JSON payload correctly rejected: %v", err)
	}
}

// TestMemorySource_ConcurrentSearchAndLoad documents that MemorySource has
// no synchronization. Concurrent LoadEnvelope and Search calls will cause
// "concurrent map writes" fatal panics or data races.
//
// NOTE: We cannot actually run concurrent map access here because it causes
// a non-recoverable runtime panic (fatal error: concurrent map writes).
// This has been verified empirically -- concurrent LoadEnvelope calls crash
// with a panic in memory.go:88 (envelopesByReference map write).
//
// To reproduce the crash:
//
//	go test -run TestMemorySource_ConcurrentSearchAndLoad -count=1 ./source/
//
// with the concurrent goroutines uncommented below.
func TestMemorySource_ConcurrentSearchAndLoad(t *testing.T) {
	// FIXED: MemorySource now uses sync.RWMutex to protect all map operations.
	// Verify concurrent access is safe by running LoadEnvelope and Search concurrently.
	src := NewMemorySource()

	var wg sync.WaitGroup
	const n = 10
	for i := 0; i < n; i++ {
		wg.Add(2)
		ref := fmt.Sprintf("ref-%d", i)
		env := makeTestEnvelope(t, fmt.Sprintf("step%d", i), map[string]string{"sha256": fmt.Sprintf("digest%d", i)})
		go func() {
			defer wg.Done()
			_ = src.LoadEnvelope(ref, env)
		}()
		go func() {
			defer wg.Done()
			_, _ = src.Search(context.Background(), fmt.Sprintf("step%d", i), []string{fmt.Sprintf("digest%d", i)}, nil)
		}()
	}
	wg.Wait()
	t.Log("FIXED: MemorySource concurrent access completed without panic or race")
}

// --- ArchivistaSource adversarial tests ---

// TestArchivistaSource_PartialDownloadFailure tests what happens when
// SearchGitoids returns multiple gitoids but downloading one of them fails.
func TestArchivistaSource_PartialDownloadFailure(t *testing.T) {
	// Build test envelopes for the server to serve
	env1 := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	env1JSON, _ := json.Marshal(env1)

	downloadCount := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query":
			// Return 3 gitoids
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"dsses": map[string]interface{}{
						"edges": []map[string]interface{}{
							{"node": map[string]interface{}{"gitoidSha256": "gitoid-1"}},
							{"node": map[string]interface{}{"gitoidSha256": "gitoid-2"}},
							{"node": map[string]interface{}{"gitoidSha256": "gitoid-3"}},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/download/gitoid-1":
			atomic.AddInt32(&downloadCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write(env1JSON)

		case r.URL.Path == "/download/gitoid-2":
			// Simulate failure on the second download
			atomic.AddInt32(&downloadCount, 1)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))

		case r.URL.Path == "/download/gitoid-3":
			atomic.AddInt32(&downloadCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Write(env1JSON)
		}
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	results, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err == nil {
		t.Errorf("BUG: Search should have returned error when one download fails, but returned %d results", len(results))
	} else {
		t.Logf("OK: Search correctly returned error on partial download failure: %v", err)
	}

	// KEY BUG: When download of gitoid-2 fails, we get partial results
	// AND gitoid-1 is added to seenGitoids. On a retry, gitoid-1 would be
	// excluded even though the overall Search failed.
	if len(results) > 0 {
		t.Errorf("BUG: partial results returned (%d envelopes) despite error. "+
			"ArchivistaSource.Search returns partial envelopes slice when a download in the middle fails. "+
			"This is because `return envelopes, err` returns the accumulated slice.", len(results))
	}

	// Check seenGitoids state
	if len(source.seenGitoids) > 0 {
		t.Errorf("BUG: seenGitoids was partially updated (%v) despite Search returning an error. "+
			"On retry, gitoid-1 will be excluded even though the caller didn't get a successful result. "+
			"This breaks the retry semantics.", source.seenGitoids)
	}
}

// TestArchivistaSource_SeenGitoidsAccumulate verifies that seenGitoids
// persists across calls, filtering already-seen results.
func TestArchivistaSource_SeenGitoidsAccumulate(t *testing.T) {
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	envJSON, _ := json.Marshal(env)

	callCount := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query":
			c := atomic.AddInt32(&callCount, 1)
			var edges []map[string]interface{}
			if c == 1 {
				edges = []map[string]interface{}{
					{"node": map[string]interface{}{"gitoidSha256": "gitoid-1"}},
				}
			}
			// Second call: return empty because gitoid-1 is excluded
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"dsses": map[string]interface{}{
						"edges": edges,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/download/gitoid-1":
			w.Header().Set("Content-Type", "application/json")
			w.Write(envJSON)
		}
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	// First search
	results1, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("first Search failed: %v", err)
	}
	if len(results1) != 1 {
		t.Fatalf("expected 1 result from first search, got %d", len(results1))
	}

	// Second search - gitoid-1 should be in ExcludeGitoids
	results2, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("second Search failed: %v", err)
	}
	if len(results2) != 0 {
		t.Errorf("BUG: second search should return 0 (gitoid-1 excluded), got %d", len(results2))
	} else {
		t.Logf("OK: seenGitoids correctly excludes already-seen gitoids on second search")
	}
}

// TestArchivistaSource_ConcurrentSearch verifies that concurrent Search calls
// on the same ArchivistaSource will race on seenGitoids.
func TestArchivistaSource_ConcurrentSearch(t *testing.T) {
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	envJSON, _ := json.Marshal(env)

	requestCount := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query":
			n := atomic.AddInt32(&requestCount, 1)
			edges := []map[string]interface{}{
				{"node": map[string]interface{}{"gitoidSha256": fmt.Sprintf("gitoid-%d", n)}},
			}
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"dsses": map[string]interface{}{
						"edges": edges,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write(envJSON)
		}
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = source.Search(context.Background(), "step1", []string{"abc"}, nil)
		}()
	}
	wg.Wait()

	// FIXED: ArchivistaSource.Search now uses a mutex to protect seenGitoids.
	// The race detector should not flag any issues.
	source.mu.Lock()
	t.Logf("FIXED: ArchivistaSource concurrent access completed without race. seenGitoids has %d entries.", len(source.seenGitoids))
	source.mu.Unlock()
}

// TestArchivistaSource_EmptyGitoidResults verifies behavior when the GraphQL
// query returns no gitoids.
func TestArchivistaSource_EmptyGitoidResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"dsses": map[string]interface{}{
					"edges": []interface{}{},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	results, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Errorf("BUG: Search with no results should not error, got: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("BUG: expected 0 results, got %d", len(results))
	} else {
		t.Logf("OK: empty gitoid results returns empty slice without error")
	}
}

// --- MultiSource adversarial tests ---

// TestMultiSource_OneSourceErrors verifies that if one source errors,
// the entire MultiSource returns an error and discards results from
// the successful source.
func TestMultiSource_OneSourceErrors(t *testing.T) {
	sentinel := errors.New("source failed")

	ms := NewMemorySource()
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	multi := NewMultiSource(
		ms,
		&errSourcer{err: sentinel},
	)

	results, err := multi.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err == nil {
		t.Errorf("BUG: MultiSource.Search should return error when one source fails")
	} else {
		t.Logf("OK: MultiSource correctly propagates error from failing source: %v", err)
	}

	// MultiSource discards all results when any source errors
	if results != nil && len(results) > 0 {
		t.Errorf("BUG: expected nil results when error occurs, got %d results", len(results))
	} else {
		t.Logf("OK: results are nil/empty on error")
	}
}

// TestMultiSource_AllSourcesError verifies behavior when all sources fail.
func TestMultiSource_AllSourcesError(t *testing.T) {
	multi := NewMultiSource(
		&errSourcer{err: errors.New("error-1")},
		&errSourcer{err: errors.New("error-2")},
	)

	_, err := multi.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err == nil {
		t.Errorf("BUG: expected error when all sources fail")
	} else {
		// Only the first error is returned, which loses the second error
		t.Logf("OK: MultiSource returns error when all sources fail: %v", err)
		t.Logf("NOTE: only the first error is returned; other errors are silently dropped")
	}
}

// TestMultiSource_EmptySources verifies behavior with no sources.
func TestMultiSource_EmptySources(t *testing.T) {
	multi := NewMultiSource()

	results, err := multi.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Errorf("BUG: empty MultiSource should not error, got: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("BUG: expected 0 results from empty MultiSource, got %d", len(results))
	} else {
		t.Logf("OK: empty MultiSource returns empty results without error")
	}
}

// TestMultiSource_ContextCancellation verifies that MultiSource respects
// context cancellation (passed through to underlying sources).
func TestMultiSource_ContextCancellation(t *testing.T) {
	gate := make(chan struct{})
	slow := &delaySourcer{gate: gate, results: nil}

	multi := NewMultiSource(slow)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// The delaySourcer blocks on gate, but the goroutine in MultiSource
	// is already running. Since the source doesn't check context, this will
	// block until gate is closed.
	go func() {
		// Let it run for a moment, then unblock
		close(gate)
	}()

	results, err := multi.Search(ctx, "step1", []string{"abc"}, nil)
	if err != nil {
		t.Logf("OK: MultiSource propagated error on cancelled context: %v", err)
	} else {
		t.Logf("OK: MultiSource returned %d results (underlying source doesn't check ctx). "+
			"NOTE: MultiSource itself does not check context cancellation; it relies on sources to do so.", len(results))
	}
}

// --- VerifiedSource adversarial tests ---

// TestVerifiedSource_NoVerifiersPass verifies that when an envelope has no
// signatures, the VerifiedSource still returns a result but with an error
// in the Errors field.
func TestVerifiedSource_NoVerifiersPass(t *testing.T) {
	ms := NewMemorySource()
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	// No verifiers provided -- envelope has no signatures either
	vs := NewVerifiedSource(ms)

	results, err := vs.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("VerifiedSource.Search failed: %v", err)
	}

	if len(results) == 0 {
		t.Errorf("BUG: expected at least one result (even if verification failed)")
	} else {
		r := results[0]
		if len(r.Errors) == 0 {
			t.Errorf("BUG: expected verification errors for unsigned envelope")
		} else {
			t.Logf("OK: unsigned envelope correctly has verification errors: %v", r.Errors)
		}
		if len(r.Verifiers) != 0 {
			t.Errorf("BUG: expected no valid verifiers, got %d", len(r.Verifiers))
		}
	}
}

// TestVerifiedSource_UnderlyingSourceError verifies error propagation.
func TestVerifiedSource_UnderlyingSourceError(t *testing.T) {
	sentinel := errors.New("underlying source error")
	vs := NewVerifiedSource(&errSourcer{err: sentinel})

	_, err := vs.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err == nil {
		t.Errorf("BUG: expected error propagation from underlying source")
	} else if !errors.Is(err, sentinel) {
		t.Errorf("BUG: expected sentinel error, got: %v", err)
	} else {
		t.Logf("OK: underlying source error correctly propagated")
	}
}

// =============================================================================
// MemorySource race condition and concurrency tests
// =============================================================================

// TestRace_MemorySource_ConcurrentLoadAndSearch runs many concurrent LoadEnvelope
// and Search calls against the same MemorySource to exercise the RWMutex
// protection. With -race, this will flag any remaining data races.
func TestRace_MemorySource_ConcurrentLoadAndSearch(t *testing.T) {
	src := NewMemorySource()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		ref := fmt.Sprintf("ref-%d", i)
		collName := fmt.Sprintf("step-%d", i%5) // intentional overlap on collection names
		digest := fmt.Sprintf("digest-%d", i)
		env := makeTestEnvelope(t, collName, map[string]string{"sha256": digest})

		go func() {
			defer wg.Done()
			_ = src.LoadEnvelope(ref, env)
		}()

		go func() {
			defer wg.Done()
			// Search for the same collection name that other goroutines are loading into
			_, _ = src.Search(context.Background(), collName, []string{digest}, nil)
		}()
	}

	wg.Wait()
	t.Log("OK: 50 concurrent Load + 50 concurrent Search completed without race")
}

// TestRace_MemorySource_ConcurrentSearchPartialState verifies that Search never
// observes a partially-loaded envelope. The envelope should either be fully
// visible or not visible at all.
func TestRace_MemorySource_ConcurrentSearchPartialState(t *testing.T) {
	src := NewMemorySource()
	const iterations = 100

	env := makeTestEnvelope(t, "step1", map[string]string{
		"sha256": "deadbeef",
	})

	// Pre-load one envelope so searches have something to find
	if err := src.LoadEnvelope("baseline", env); err != nil {
		t.Fatalf("baseline LoadEnvelope failed: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan string, iterations)

	for i := 0; i < iterations; i++ {
		wg.Add(2)
		ref := fmt.Sprintf("ref-%d", i)
		env := makeTestEnvelope(t, "step1", map[string]string{
			"sha256": fmt.Sprintf("digest-%d", i),
		})

		go func() {
			defer wg.Done()
			_ = src.LoadEnvelope(ref, env)
		}()

		go func() {
			defer wg.Done()
			results, err := src.Search(context.Background(), "step1", []string{"deadbeef"}, nil)
			if err != nil {
				errCh <- fmt.Sprintf("Search returned error: %v", err)
				return
			}
			// Each result must have a valid Reference and non-nil Collection
			for _, r := range results {
				if r.Reference == "" {
					errCh <- "BUG: Search returned result with empty Reference (partial state visible)"
				}
				if r.Collection.Name == "" {
					errCh <- "BUG: Search returned result with empty Collection.Name (partial state visible)"
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for msg := range errCh {
		t.Error(msg)
	}
	t.Log("OK: no partial state observed during concurrent Search + Load")
}

// TestAdversarial_MemorySource_StoreSameCollectionTwice verifies that loading
// two different envelopes with the same collection name (but different references)
// works correctly and both are returned by Search.
func TestAdversarial_MemorySource_StoreSameCollectionTwice(t *testing.T) {
	src := NewMemorySource()

	env1 := makeTestEnvelope(t, "shared-step", map[string]string{"sha256": "digest-a"})
	env2 := makeTestEnvelope(t, "shared-step", map[string]string{"sha256": "digest-b"})

	if err := src.LoadEnvelope("ref-1", env1); err != nil {
		t.Fatalf("first LoadEnvelope failed: %v", err)
	}
	if err := src.LoadEnvelope("ref-2", env2); err != nil {
		t.Fatalf("second LoadEnvelope failed: %v", err)
	}

	// Search for digest-a should find ref-1
	results, err := src.Search(context.Background(), "shared-step", []string{"digest-a"}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("BUG: expected 1 result for digest-a, got %d", len(results))
	} else if results[0].Reference != "ref-1" {
		t.Errorf("BUG: expected ref-1, got %s", results[0].Reference)
	}

	// Search for digest-b should find ref-2
	results, err = src.Search(context.Background(), "shared-step", []string{"digest-b"}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("BUG: expected 1 result for digest-b, got %d", len(results))
	} else if results[0].Reference != "ref-2" {
		t.Errorf("BUG: expected ref-2, got %s", results[0].Reference)
	}

	// Search for either digest should find both
	results, err = src.Search(context.Background(), "shared-step", []string{"digest-a", "digest-b"}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("BUG: expected 2 results for both digests, got %d", len(results))
	}

	t.Log("OK: same collection name with different references both indexed and searchable")
}

// TestAdversarial_MemorySource_LoadBytesInvalidJSON verifies LoadBytes rejects garbled data.
func TestAdversarial_MemorySource_LoadBytesInvalidJSON(t *testing.T) {
	src := NewMemorySource()

	err := src.LoadBytes("ref1", []byte("{truncated"))
	if err == nil {
		t.Error("BUG: LoadBytes should reject invalid JSON")
	} else {
		t.Logf("OK: LoadBytes rejected invalid JSON: %v", err)
	}
}

// TestAdversarial_MemorySource_LoadEnvelopeWithValidPayloadButInvalidPredicate
// verifies that a valid intoto.Statement with an invalid predicate (not a
// valid Collection) fails at load time.
func TestAdversarial_MemorySource_LoadEnvelopeWithValidPayloadButInvalidPredicate(t *testing.T) {
	src := NewMemorySource()

	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(`"this is a string, not a collection object"`),
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	env := dsse.Envelope{
		Payload:     payload,
		PayloadType: intoto.PayloadType,
	}

	err = src.LoadEnvelope("ref1", env)
	if err == nil {
		t.Error("BUG: LoadEnvelope should reject envelope with invalid predicate (string instead of Collection object)")
	} else {
		t.Logf("OK: invalid predicate correctly rejected: %v", err)
	}
}

// =============================================================================
// ArchivistaSource edge case tests
// =============================================================================

// TestAdversarial_ArchivistaSource_MalformedGraphQLResponse verifies behavior
// when the GraphQL response has unexpected structure (missing "data" field).
func TestAdversarial_ArchivistaSource_MalformedGraphQLResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return valid JSON but missing the expected "data.dsses.edges" path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": {"unexpected": "shape"}}`))
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	results, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Logf("OK: malformed GraphQL response returned error: %v", err)
	} else if len(results) == 0 {
		// The JSON unmarshaler will just produce zero-value fields (empty edges),
		// so we get 0 results with no error. This is arguably a bug: the server
		// returned garbage, but we silently treated it as "no results".
		t.Log("CONCERN: malformed GraphQL response silently returned 0 results instead of an error. " +
			"The ArchivistaSource/Client does not validate the response schema. " +
			"A misconfigured server or MITM could silently suppress all results.")
	} else {
		t.Errorf("BUG: unexpected results from malformed response: %d", len(results))
	}
}

// TestAdversarial_ArchivistaSource_GraphQLErrorResponse verifies that GraphQL-level
// errors (inside the response body, not HTTP errors) are propagated.
func TestAdversarial_ArchivistaSource_GraphQLErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": null, "errors": [{"message": "rate limit exceeded"}]}`))
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	_, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err == nil {
		t.Error("BUG: GraphQL error response should propagate as error")
	} else {
		t.Logf("OK: GraphQL error correctly propagated: %v", err)
	}
}

// TestAdversarial_ArchivistaSource_DownloadMalformedEnvelope verifies behavior
// when the downloaded envelope is valid JSON but doesn't match dsse.Envelope schema.
func TestAdversarial_ArchivistaSource_DownloadMalformedEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query":
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"dsses": map[string]interface{}{
						"edges": []map[string]interface{}{
							{"node": map[string]interface{}{"gitoidSha256": "gitoid-1"}},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/download/gitoid-1":
			// Return valid JSON that represents a DSSE envelope, but whose
			// payload is not a valid intoto.Statement
			w.Header().Set("Content-Type", "application/json")
			env := dsse.Envelope{
				Payload:     []byte(`{"not": "an intoto statement"}`),
				PayloadType: "application/vnd.in-toto+json",
			}
			json.NewEncoder(w).Encode(env)
		}
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	_, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err == nil {
		t.Error("BUG: download of envelope with invalid intoto statement payload should fail")
	} else {
		t.Logf("OK: malformed envelope payload correctly rejected: %v", err)
	}

	// Verify seenGitoids was NOT updated since the search failed
	source.mu.Lock()
	seen := len(source.seenGitoids)
	source.mu.Unlock()
	if seen > 0 {
		t.Errorf("BUG: seenGitoids updated (%d) despite failed search; retry will skip these gitoids", seen)
	} else {
		t.Log("OK: seenGitoids not updated on failed search")
	}
}

// TestAdversarial_ArchivistaSource_EmptyGitoidString verifies behavior when
// the server returns an empty string gitoid.
func TestAdversarial_ArchivistaSource_EmptyGitoidString(t *testing.T) {
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	envJSON, _ := json.Marshal(env)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query":
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"dsses": map[string]interface{}{
						"edges": []map[string]interface{}{
							{"node": map[string]interface{}{"gitoidSha256": ""}},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/download/":
			// The empty gitoid becomes /download/ path
			w.Header().Set("Content-Type", "application/json")
			w.Write(envJSON)
		}
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	results, err := source.Search(context.Background(), "step1", []string{"abc"}, nil)
	if err != nil {
		t.Logf("OK: empty gitoid returned error: %v", err)
	} else if len(results) > 0 {
		// The empty gitoid "" is used as the reference for the CollectionEnvelope.
		// This is dubious: an empty string is a valid Go map key, so it could
		// silently collide with other empty-gitoid results.
		t.Logf("CONCERN: empty gitoid string was accepted as valid (reference=%q). "+
			"ArchivistaSource does not validate gitoid values. An empty gitoid "+
			"will add an empty string to seenGitoids, and if the server returns "+
			"multiple empty gitoids they will all get the same reference.", results[0].Reference)
	} else {
		t.Log("OK: empty gitoid returned 0 results")
	}
}

// TestAdversarial_ArchivistaSource_ContextCancelledDuringDownload verifies
// that context cancellation mid-download does not corrupt seenGitoids state.
func TestAdversarial_ArchivistaSource_ContextCancelledDuringDownload(t *testing.T) {
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	envJSON, _ := json.Marshal(env)

	queryHandled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query":
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"dsses": map[string]interface{}{
						"edges": []map[string]interface{}{
							{"node": map[string]interface{}{"gitoidSha256": "gitoid-1"}},
							{"node": map[string]interface{}{"gitoidSha256": "gitoid-2"}},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			close(queryHandled) // signal that query has been served

		case r.URL.Path == "/download/gitoid-1":
			w.Header().Set("Content-Type", "application/json")
			w.Write(envJSON)

		case r.URL.Path == "/download/gitoid-2":
			// Block indefinitely to simulate a slow download
			<-r.Context().Done()
		}
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context after query is handled but during download phase
	go func() {
		<-queryHandled
		cancel()
	}()

	_, err := source.Search(ctx, "step1", []string{"abc"}, nil)
	if err == nil {
		t.Error("BUG: expected error when context is cancelled during download")
	} else {
		t.Logf("OK: context cancellation during download returned error: %v", err)
	}

	// Verify seenGitoids was not partially updated
	source.mu.Lock()
	seen := len(source.seenGitoids)
	source.mu.Unlock()
	if seen > 0 {
		t.Errorf("BUG: seenGitoids partially updated (%d entries) despite cancelled search; "+
			"retry will skip already-processed gitoids", seen)
	} else {
		t.Log("OK: seenGitoids not updated on cancelled search")
	}
}

// TestRace_ArchivistaSource_ConcurrentSearchMutexCorrectness runs many concurrent
// searches and verifies no duplicates appear in seenGitoids (each gitoid should
// appear exactly once).
func TestRace_ArchivistaSource_ConcurrentSearchMutexCorrectness(t *testing.T) {
	env := makeTestEnvelope(t, "step1", map[string]string{"sha256": "abc"})
	envJSON, _ := json.Marshal(env)

	var counter int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query":
			n := atomic.AddInt32(&counter, 1)
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"dsses": map[string]interface{}{
						"edges": []map[string]interface{}{
							{"node": map[string]interface{}{"gitoidSha256": fmt.Sprintf("gitoid-%d", n)}},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write(envJSON)
		}
	}))
	defer srv.Close()

	client := archivista.New(srv.URL)
	source := NewArchivistaSource(client)

	const concurrency = 30
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			_, _ = source.Search(context.Background(), "step1", []string{"abc"}, nil)
		}()
	}
	wg.Wait()

	// Check for duplicates in seenGitoids
	source.mu.Lock()
	seen := make(map[string]int)
	for _, g := range source.seenGitoids {
		seen[g]++
	}
	source.mu.Unlock()

	for gitoid, count := range seen {
		if count > 1 {
			t.Errorf("BUG: gitoid %q appears %d times in seenGitoids (should be 1). "+
				"This means the same gitoid was processed by multiple concurrent searches. "+
				"The seenGitoids snapshot is taken before downloads start, so two concurrent "+
				"searches can both see the same gitoid as 'not yet excluded'.", gitoid, count)
		}
	}
	t.Logf("OK: %d unique gitoids in seenGitoids after %d concurrent searches", len(seen), concurrency)
}

// =============================================================================
// intoto Statement construction adversarial tests
// =============================================================================

// TestAdversarial_IntotoStatement_EmptySubjects verifies that NewStatement
// rejects an empty subjects map.
func TestAdversarial_IntotoStatement_EmptySubjects(t *testing.T) {
	_, err := intoto.NewStatement(
		"https://example.com/predicate/v1",
		[]byte(`{"key": "value"}`),
		map[string]cryptoutil.DigestSet{},
	)
	if err == nil {
		t.Error("BUG: NewStatement should reject empty subjects map")
	} else {
		t.Logf("OK: empty subjects correctly rejected: %v", err)
	}
}

// TestAdversarial_IntotoStatement_InvalidPredicate verifies that NewStatement
// rejects predicates that are not valid JSON.
func TestAdversarial_IntotoStatement_InvalidPredicate(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"artifact.tar.gz": {
			{Hash: crypto.SHA256}: "deadbeef",
		},
	}

	_, err := intoto.NewStatement(
		"https://example.com/predicate/v1",
		[]byte(`{truncated`),
		subjects,
	)
	if err == nil {
		t.Error("BUG: NewStatement should reject invalid JSON predicate")
	} else {
		t.Logf("OK: invalid JSON predicate correctly rejected: %v", err)
	}
}

// TestAdversarial_IntotoStatement_SubjectNameWithPathTraversal verifies that
// subject names with path traversal characters are accepted (the intoto spec
// does not restrict subject names, but consumers should be aware).
func TestAdversarial_IntotoStatement_SubjectNameWithPathTraversal(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"../../../etc/passwd": {
			{Hash: crypto.SHA256}: "deadbeef",
		},
		"/absolute/path": {
			{Hash: crypto.SHA256}: "cafebabe",
		},
		"path/with/../traversal/../../escape": {
			{Hash: crypto.SHA256}: "12345678",
		},
	}

	stmt, err := intoto.NewStatement(
		"https://example.com/predicate/v1",
		[]byte(`{}`),
		subjects,
	)
	if err != nil {
		t.Fatalf("NewStatement failed: %v", err)
	}

	// Verify the path traversal names are stored as-is
	foundTraversal := false
	for _, s := range stmt.Subject {
		if s.Name == "../../../etc/passwd" {
			foundTraversal = true
		}
	}
	if foundTraversal {
		t.Log("CONCERN: intoto.NewStatement accepts subject names with path traversal " +
			"characters (../../../etc/passwd). The in-toto spec does not restrict names, " +
			"but downstream consumers that use subject names as file paths without " +
			"sanitization are vulnerable to directory traversal attacks. " +
			"File: attestation/intoto/statement.go:42 (NewStatement)")
	} else {
		t.Error("BUG: path traversal subject name was not preserved")
	}
}

// TestAdversarial_IntotoStatement_LargeSubjectCount verifies that NewStatement
// handles a very large number of subjects without issues.
func TestAdversarial_IntotoStatement_LargeSubjectCount(t *testing.T) {
	const numSubjects = 10000
	subjects := make(map[string]cryptoutil.DigestSet, numSubjects)
	for i := 0; i < numSubjects; i++ {
		subjects[fmt.Sprintf("artifact-%05d.bin", i)] = cryptoutil.DigestSet{
			{Hash: crypto.SHA256}: fmt.Sprintf("%064d", i),
		}
	}

	stmt, err := intoto.NewStatement(
		"https://example.com/predicate/v1",
		[]byte(`{}`),
		subjects,
	)
	if err != nil {
		t.Fatalf("NewStatement with %d subjects failed: %v", numSubjects, err)
	}

	if len(stmt.Subject) != numSubjects {
		t.Errorf("BUG: expected %d subjects, got %d", numSubjects, len(stmt.Subject))
	}

	// Verify subjects are sorted (deterministic output)
	for i := 1; i < len(stmt.Subject); i++ {
		if stmt.Subject[i].Name < stmt.Subject[i-1].Name {
			t.Errorf("BUG: subjects not sorted at index %d: %q > %q",
				i, stmt.Subject[i-1].Name, stmt.Subject[i].Name)
			break
		}
	}

	t.Logf("OK: %d subjects created and sorted correctly", numSubjects)
}

// TestAdversarial_IntotoStatement_DeterministicSerialization verifies that
// the same inputs always produce the same JSON output (critical for DSSE
// signing -- non-deterministic output = different signatures for same input).
func TestAdversarial_IntotoStatement_DeterministicSerialization(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"z-artifact.bin": {
			{Hash: crypto.SHA256}: "aaaa",
		},
		"a-artifact.bin": {
			{Hash: crypto.SHA256}: "bbbb",
		},
		"m-artifact.bin": {
			{Hash: crypto.SHA256}: "cccc",
		},
	}

	predicate := []byte(`{"build": "data"}`)

	// Create the statement 100 times and verify identical JSON
	var firstJSON []byte
	for i := 0; i < 100; i++ {
		stmt, err := intoto.NewStatement("https://example.com/v1", predicate, subjects)
		if err != nil {
			t.Fatalf("iteration %d: NewStatement failed: %v", i, err)
		}

		data, err := json.Marshal(stmt)
		if err != nil {
			t.Fatalf("iteration %d: Marshal failed: %v", i, err)
		}

		if firstJSON == nil {
			firstJSON = data
		} else if string(data) != string(firstJSON) {
			t.Errorf("BUG: non-deterministic serialization at iteration %d.\n"+
				"First:   %s\n"+
				"Current: %s\n"+
				"This means the same inputs produce different JSON, which will "+
				"cause different DSSE signatures for identical content.",
				i, string(firstJSON), string(data))
			break
		}
	}
	t.Log("OK: 100 iterations produced identical JSON serialization")
}

// TestAdversarial_IntotoStatement_NilPredicate verifies behavior with nil predicate.
func TestAdversarial_IntotoStatement_NilPredicate(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"artifact.bin": {
			{Hash: crypto.SHA256}: "deadbeef",
		},
	}

	_, err := intoto.NewStatement("https://example.com/v1", nil, subjects)
	if err == nil {
		t.Error("BUG: NewStatement should reject nil predicate (json.Valid(nil) returns false)")
	} else {
		t.Logf("OK: nil predicate correctly rejected: %v", err)
	}
}

// TestAdversarial_IntotoStatement_EmptyPredicate verifies behavior with empty
// byte slice predicate.
func TestAdversarial_IntotoStatement_EmptyPredicate(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"artifact.bin": {
			{Hash: crypto.SHA256}: "deadbeef",
		},
	}

	_, err := intoto.NewStatement("https://example.com/v1", []byte{}, subjects)
	if err == nil {
		t.Error("BUG: NewStatement should reject empty predicate")
	} else {
		t.Logf("OK: empty predicate correctly rejected: %v", err)
	}
}

// TestAdversarial_IntotoStatement_NilSubjects verifies that nil subjects map is rejected.
func TestAdversarial_IntotoStatement_NilSubjects(t *testing.T) {
	_, err := intoto.NewStatement("https://example.com/v1", []byte(`{}`), nil)
	if err == nil {
		t.Error("BUG: NewStatement should reject nil subjects map")
	} else {
		t.Logf("OK: nil subjects correctly rejected: %v", err)
	}
}

// TestAdversarial_IntotoStatement_SubjectWithEmptyDigestSet verifies behavior
// when a subject has an empty DigestSet.
func TestAdversarial_IntotoStatement_SubjectWithEmptyDigestSet(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"artifact.bin": {}, // empty DigestSet
	}

	stmt, err := intoto.NewStatement("https://example.com/v1", []byte(`{}`), subjects)
	if err != nil {
		t.Logf("OK: empty DigestSet correctly rejected: %v", err)
		return
	}

	// If it succeeds, verify the subject has an empty digest map.
	// This is potentially dangerous: a subject with no digests cannot be
	// meaningfully verified.
	if len(stmt.Subject) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(stmt.Subject))
	}
	if len(stmt.Subject[0].Digest) != 0 {
		t.Errorf("BUG: expected empty digest map, got %v", stmt.Subject[0].Digest)
	} else {
		t.Log("CONCERN: intoto.NewStatement accepts subjects with empty DigestSet. " +
			"A subject with no digests cannot be verified by policy evaluation. " +
			"An attacker could craft a statement with empty-digest subjects that " +
			"match any policy check that doesn't validate digest presence. " +
			"File: attestation/intoto/statement.go:67-75 (no check for empty DigestSet)")
	}
}

// TestAdversarial_IntotoStatement_SubjectNameEmptyString verifies behavior
// when a subject name is the empty string.
func TestAdversarial_IntotoStatement_SubjectNameEmptyString(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"": {
			{Hash: crypto.SHA256}: "deadbeef",
		},
	}

	stmt, err := intoto.NewStatement("https://example.com/v1", []byte(`{}`), subjects)
	if err != nil {
		t.Logf("OK: empty subject name rejected: %v", err)
		return
	}

	if len(stmt.Subject) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(stmt.Subject))
	}
	if stmt.Subject[0].Name != "" {
		t.Errorf("BUG: expected empty name, got %q", stmt.Subject[0].Name)
	} else {
		t.Log("CONCERN: intoto.NewStatement accepts subjects with empty name. " +
			"The in-toto spec requires subject names to be non-empty. " +
			"File: attestation/intoto/statement.go:42 (no name validation)")
	}
}

// =============================================================================
// Collection serialization round-trip tests
// =============================================================================

// TestAdversarial_CollectionEnvelope_JSONRoundTrip verifies that marshaling and
// unmarshaling a CollectionEnvelope produces an equivalent result.
func TestAdversarial_CollectionEnvelope_JSONRoundTrip(t *testing.T) {
	// Build a complete envelope
	predicate, err := json.Marshal(attestation.Collection{
		Name: "build-step",
		Attestations: []attestation.CollectionAttestation{
			{Type: "https://aflock.ai/attestation/git/v0.1"},
			{Type: "https://aflock.ai/attestation/environment/v0.1"},
		},
	})
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}

	stmt := intoto.Statement{
		Type: intoto.StatementType,
		Subject: []intoto.Subject{
			{Name: "binary.exe", Digest: map[string]string{"sha256": "aabbccdd"}},
			{Name: "config.yaml", Digest: map[string]string{"sha256": "11223344", "sha1": "aabb"}},
		},
		PredicateType: attestation.CollectionType,
		Predicate:     json.RawMessage(predicate),
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	originalEnv := dsse.Envelope{
		Payload:     payload,
		PayloadType: intoto.PayloadType,
	}

	// Round-trip through JSON
	envJSON, err := json.Marshal(originalEnv)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	var restored dsse.Envelope
	if err := json.Unmarshal(envJSON, &restored); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	// Verify payloads match
	if string(originalEnv.Payload) != string(restored.Payload) {
		t.Errorf("BUG: payload mismatch after JSON round-trip.\n"+
			"Original: %s\n"+
			"Restored: %s", string(originalEnv.Payload), string(restored.Payload))
	}

	if originalEnv.PayloadType != restored.PayloadType {
		t.Errorf("BUG: PayloadType mismatch: %q vs %q", originalEnv.PayloadType, restored.PayloadType)
	}

	// Now verify that envelopeToCollectionEnvelope produces the same result
	ce1, err1 := envelopeToCollectionEnvelope("ref1", originalEnv)
	ce2, err2 := envelopeToCollectionEnvelope("ref2", restored)
	if err1 != nil {
		t.Fatalf("envelopeToCollectionEnvelope(original) failed: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("envelopeToCollectionEnvelope(restored) failed: %v", err2)
	}

	if ce1.Collection.Name != ce2.Collection.Name {
		t.Errorf("BUG: collection name mismatch: %q vs %q", ce1.Collection.Name, ce2.Collection.Name)
	}

	if len(ce1.Statement.Subject) != len(ce2.Statement.Subject) {
		t.Errorf("BUG: subject count mismatch: %d vs %d", len(ce1.Statement.Subject), len(ce2.Statement.Subject))
	}

	t.Log("OK: JSON round-trip preserves envelope fidelity")
}

// TestAdversarial_CollectionEnvelope_NilAttestationInCollection verifies behavior
// when a collection has an attestation with nil Attestation field.
func TestAdversarial_CollectionEnvelope_NilAttestationInCollection(t *testing.T) {
	// Build a collection with a nil attestation (Attestation field is nil)
	coll := attestation.Collection{
		Name: "test-step",
		Attestations: []attestation.CollectionAttestation{
			{Type: "https://aflock.ai/attestation/git/v0.1", Attestation: nil},
		},
	}

	predicate, err := json.Marshal(coll)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}

	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
		PredicateType: attestation.CollectionType,
		Predicate:     json.RawMessage(predicate),
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	env := dsse.Envelope{
		Payload:     payload,
		PayloadType: intoto.PayloadType,
	}

	// Load it into MemorySource
	src := NewMemorySource()
	err = src.LoadEnvelope("ref1", env)
	if err != nil {
		t.Logf("OK: envelope with nil attestation rejected at load time: %v", err)
		return
	}

	// If it loaded, verify we can search for it
	results, err := src.Search(context.Background(), "test-step", []string{"abc"}, nil)
	if err != nil {
		t.Errorf("BUG: search failed after loading envelope with nil attestation: %v", err)
	} else {
		t.Logf("OK: envelope with nil attestation loaded and searchable (%d results). "+
			"NOTE: the attestation with nil Attestation field is preserved as a "+
			"CollectionAttestation with Type set but Attestation nil.", len(results))
	}
}

// TestAdversarial_CollectionEnvelope_DuplicateAttestationTypes verifies behavior
// when a collection has multiple attestations of the same type.
func TestAdversarial_CollectionEnvelope_DuplicateAttestationTypes(t *testing.T) {
	coll := attestation.Collection{
		Name: "test-step",
		Attestations: []attestation.CollectionAttestation{
			{Type: "https://aflock.ai/attestation/git/v0.1"},
			{Type: "https://aflock.ai/attestation/git/v0.1"}, // duplicate type
			{Type: "https://aflock.ai/attestation/environment/v0.1"},
		},
	}

	predicate, err := json.Marshal(coll)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}

	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
		PredicateType: attestation.CollectionType,
		Predicate:     json.RawMessage(predicate),
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	env := dsse.Envelope{
		Payload:     payload,
		PayloadType: intoto.PayloadType,
	}

	src := NewMemorySource()
	err = src.LoadEnvelope("ref1", env)
	if err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	// Search with the git attestation type
	results, err := src.Search(context.Background(), "test-step", []string{"abc"},
		[]string{"https://aflock.ai/attestation/git/v0.1"})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("BUG: expected 1 result, got %d", len(results))
	}

	// Verify the collection has 3 attestations (2 duplicates + 1)
	if len(results) > 0 && len(results[0].Collection.Attestations) != 3 {
		t.Errorf("BUG: expected 3 attestations (including duplicates), got %d",
			len(results[0].Collection.Attestations))
	}

	t.Log("OK: duplicate attestation types are preserved in collection. " +
		"The MemorySource index (attestationsByReference) deduplicates types " +
		"in its set, so searching works correctly even with duplicates.")
}

// TestAdversarial_EnvelopeToCollectionEnvelope_EmptyPayload verifies behavior
// with an empty payload.
func TestAdversarial_EnvelopeToCollectionEnvelope_EmptyPayload(t *testing.T) {
	env := dsse.Envelope{
		Payload:     []byte{},
		PayloadType: intoto.PayloadType,
	}

	_, err := envelopeToCollectionEnvelope("ref1", env)
	if err == nil {
		t.Error("BUG: empty payload should be rejected by envelopeToCollectionEnvelope")
	} else {
		t.Logf("OK: empty payload correctly rejected: %v", err)
	}
}

// TestAdversarial_EnvelopeToCollectionEnvelope_NullPredicate verifies behavior
// when the statement's predicate is JSON null.
func TestAdversarial_EnvelopeToCollectionEnvelope_NullPredicate(t *testing.T) {
	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
		PredicateType: attestation.CollectionType,
		Predicate:     json.RawMessage(`null`),
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	env := dsse.Envelope{
		Payload:     payload,
		PayloadType: intoto.PayloadType,
	}

	ce, err := envelopeToCollectionEnvelope("ref1", env)
	if err != nil {
		t.Logf("OK: null predicate rejected: %v", err)
	} else {
		// json.Unmarshal of null into a struct is valid -- it produces zero values
		t.Logf("CONCERN: null predicate accepted. Collection name is %q (empty). "+
			"An attacker could craft envelopes with null predicates that parse as "+
			"empty Collections. The collection name would be empty string, which "+
			"could match policy evaluations that don't validate collection name presence. "+
			"File: attestation/source/source.go:44", ce.Collection.Name)
	}
}

// =============================================================================
// MemorySource index correctness tests
// =============================================================================

// TestAdversarial_MemorySource_AttestationSearchWithLegacyURI verifies that
// the MemorySource attestation index includes both modern and legacy URIs.
func TestAdversarial_MemorySource_AttestationSearchWithLegacyURI(t *testing.T) {
	// Create a collection with a modern URI
	coll := attestation.Collection{
		Name: "test-step",
		Attestations: []attestation.CollectionAttestation{
			{Type: "https://aflock.ai/attestation/git/v0.1"},
		},
	}

	predicate, err := json.Marshal(coll)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}

	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       []intoto.Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
		PredicateType: attestation.CollectionType,
		Predicate:     json.RawMessage(predicate),
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	env := dsse.Envelope{
		Payload:     payload,
		PayloadType: intoto.PayloadType,
	}

	src := NewMemorySource()
	if err := src.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	// Search with the modern URI
	results, err := src.Search(context.Background(), "test-step", []string{"abc"},
		[]string{"https://aflock.ai/attestation/git/v0.1"})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("BUG: expected 1 result with modern URI, got %d", len(results))
	}

	// Search with the legacy URI (if one exists)
	legacyURI := attestation.LegacyAlternate("https://aflock.ai/attestation/git/v0.1")
	if legacyURI != "" {
		results, err = src.Search(context.Background(), "test-step", []string{"abc"},
			[]string{legacyURI})
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}
		if len(results) != 1 {
			t.Errorf("BUG: expected 1 result with legacy URI %q, got %d. "+
				"The MemorySource should index both modern and legacy URIs "+
				"(see memory.go:109-111).", legacyURI, len(results))
		} else {
			t.Logf("OK: legacy URI %q correctly matches modern attestation", legacyURI)
		}
	} else {
		t.Log("OK: no legacy alternate for this URI")
	}
}

// TestAdversarial_MemorySource_MultipleDigestAlgorithms verifies that
// subjects with multiple digest algorithms are all indexed.
func TestAdversarial_MemorySource_MultipleDigestAlgorithms(t *testing.T) {
	env := makeTestEnvelope(t, "step1", map[string]string{
		"sha256": "aaaa",
		"sha1":   "bbbb",
	})

	src := NewMemorySource()
	if err := src.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	// Search by sha256 digest
	results, err := src.Search(context.Background(), "step1", []string{"aaaa"}, nil)
	if err != nil {
		t.Fatalf("Search by sha256 failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("BUG: expected 1 result for sha256 digest, got %d", len(results))
	}

	// Search by sha1 digest
	results, err = src.Search(context.Background(), "step1", []string{"bbbb"}, nil)
	if err != nil {
		t.Fatalf("Search by sha1 failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("BUG: expected 1 result for sha1 digest, got %d", len(results))
	}

	// Search by non-existent digest
	results, err = src.Search(context.Background(), "step1", []string{"cccc"}, nil)
	if err != nil {
		t.Fatalf("Search by missing digest failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("BUG: expected 0 results for non-existent digest, got %d", len(results))
	}

	t.Log("OK: all digest algorithms are indexed and searchable")
}
