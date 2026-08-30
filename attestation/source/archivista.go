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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/intoto"
	log "github.com/sirupsen/logrus"
)

// ArchivistaSource implements Sourcer backed by an Archivista server.
type ArchivistaSource struct {
	client      *archivista.Client
	mu          sync.Mutex
	seenGitoids []string
	// completedSearches memoizes fully-processed digest-filtered searches by
	// input fingerprint. The policy depth loop re-searches every step on
	// every iteration; when a step's inputs did not change, the repeat
	// query's whole result is already excluded by seenGitoids — the memo
	// skips the GraphQL round trip (and the server-side candidate sieve, the
	// dominant consumer of the platform's database) whose empty answer is
	// known. Marked only after a batch completes and marks its gitoids seen,
	// so an aborted batch stays fully retryable. The one semantics change —
	// evidence uploaded mid-verify no longer surfaces on an identical repeat
	// within the same verify — is pinned in archivista_memo_test.go: a
	// verify is a snapshot evaluation. Guarded by mu.
	completedSearches map[string]struct{}
}

// NewArchivistaSource creates a new source backed by an Archivista client.
func NewArchivistaSource(client *archivista.Client) *ArchivistaSource {
	return &ArchivistaSource{
		client:      client,
		seenGitoids: make([]string, 0),
	}
}

// NewArchvistSource is a deprecated alias preserved for backward compatibility
// with go-witness. Use NewArchivistaSource instead.
//
// Deprecated: Use NewArchivistaSource.
func NewArchvistSource(client *archivista.Client) *ArchivistaSource {
	return NewArchivistaSource(client)
}

func (s *ArchivistaSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	envelopes := make([]CollectionEnvelope, 0)
	err := s.SearchStream(ctx, collectionName, subjectDigests, attestations, func(ce CollectionEnvelope) error {
		envelopes = append(envelopes, ce)
		return nil
	})
	if err != nil {
		return []CollectionEnvelope{}, err
	}
	return envelopes, nil
}

// SearchStream is the streaming form of Search (source.StreamingSourcer):
// each matching envelope is downloaded, parsed and yielded one at a time, so
// a caller that compacts candidates as they arrive (VerifiedSource) never
// holds the whole matching corpus in memory at once — Search's accumulated
// []CollectionEnvelope was the verify-path heap peak against a large corpus
// (#7572). Search delegates here; there is one download/parse implementation.
// ArchivistaDecodeWorkers bounds the download+decode pipeline behind
// SearchStream. Per-candidate fetch+parse is the serial critical path of a
// large verify (the crypto and policy gate consume candidates faster than one
// goroutine can download and JSON-decode them, #7572 wall-time follow-up), so
// up to this many candidates are fetched and decoded concurrently while the
// YIELD ORDER — and therefore every downstream verification outcome — remains
// exactly the serial order. The window also caps decoded-but-not-yet-consumed
// envelopes, keeping the streaming path's peak O(workers × largest envelope),
// not O(corpus).
//
// Tuning (338-envelope prod hot-set harness, judge-api/pkg/policybench,
// GOMAXPROCS=8): W=1 wall ~29.6s peak 52.6 MiB · W=2 16.5s / 91.4 MiB ·
// W=3 11.4s / 107 MiB. W=2 holds the #7673 one-turn peak budget (≤~100 MiB);
// raise only with a re-measured peak.
const ArchivistaDecodeWorkers = 2

// decodedSlot is one candidate's decode outcome. ok=false is a SKIP (see
// fetchCollectionEnvelope), never an error — the zero value is a skipped slot.
type decodedSlot struct {
	env CollectionEnvelope
	ok  bool
}

// drainInOrder consumes the decode window strictly in candidate order, so the
// caller observes exactly the sequence the serial loop produced regardless of
// the order workers finished in. Slot i is awaited before i+1 is looked at.
//
// Once yield returns an error no further yields happen, but the remaining slots
// are still drained: their workers must be allowed to finish so the pool can be
// joined. `aborted` short-circuits those remaining downloads, which is a waste
// optimisation only — every candidate is still reported as processed, and the
// caller marks NOTHING seen on a yield error, keeping a failed batch fully
// retryable.
func drainInOrder(
	gitoids []string,
	results []chan decodedSlot,
	window chan struct{},
	yield func(CollectionEnvelope) error,
	aborted *atomic.Bool,
) ([]string, error) {
	processed := make([]string, 0, len(gitoids))
	var yieldErr error
	for i := range gitoids {
		r := <-results[i]
		processed = append(processed, gitoids[i])
		if yieldErr == nil && r.ok {
			if yieldErr = yield(r.env); yieldErr != nil {
				aborted.Store(true)
			}
		}
		<-window
	}
	return processed, yieldErr
}

// fetchCollectionEnvelope downloads one gitoid and converts it into a
// collection envelope. Both failure modes are SKIPS rather than errors, which
// is the serial loop's original semantics: a gitoid that will not download, and
// a DSSE that is not a collection (policy envelopes, VSAs), are each logged and
// dropped so one bad candidate cannot fail the batch.
//
// Split out of SearchStream's worker so the concurrency there reads as the
// pipeline it is; folded back inline it also pushes the function past the
// cognitive-complexity gate.
func (s *ArchivistaSource) fetchCollectionEnvelope(ctx context.Context, gitoid string) (CollectionEnvelope, bool) {
	env, err := s.client.Download(ctx, gitoid)
	if err != nil {
		log.Debugf("archivista source: skipping gitoid %s: download failed: %v", gitoid, err)
		return CollectionEnvelope{}, false
	}
	collectionEnv, err := EnvelopeToCollectionEnvelope(gitoid, env)
	if err != nil {
		log.Debugf("archivista source: skipping gitoid %s: %v", gitoid, err)
		return CollectionEnvelope{}, false
	}
	return collectionEnv, true
}

// NOTE ON CANONICAL ORDERING. ArchivistaSource deliberately does NOT implement
// source.CanonicalOrderSourcer. drainInOrder faithfully preserves the order of
// client.SearchGitoids, but that order is chosen by a REMOTE server's query
// plan — it is that server's contract, not this source's, and this client
// cannot promise it is stable, let alone content-derived. Not declaring costs
// only performance: verifies through this source run the step gate
// exhaustively instead of stopping at the first passing collection. Declaring
// falsely would cost determinism of a SIGNED artifact. See
// source.CanonicalOrderSourcer.
func (s *ArchivistaSource) SearchStream(ctx context.Context, collectionName string, subjectDigests, attestations []string, yield func(CollectionEnvelope) error) error {
	// A digest-filtered search this source already fully processed yields
	// nothing new by construction (see completedSearches) — skip the round
	// trip outright. Searches with an empty digest set are diagnostics and
	// never consult the memo.
	fingerprint := searchFingerprint(collectionName, subjectDigests, attestations)
	s.mu.Lock()
	if _, done := s.completedSearches[fingerprint]; done && len(subjectDigests) > 0 {
		s.mu.Unlock()
		return nil
	}
	excludeGitoids := make([]string, len(s.seenGitoids))
	copy(excludeGitoids, s.seenGitoids)
	s.mu.Unlock()

	gitoids, err := s.client.SearchGitoids(ctx, archivista.SearchGitoidVariables{
		CollectionName: collectionName,
		SubjectDigests: subjectDigests,
		Attestations:   attestations,
		ExcludeGitoids: excludeGitoids,
	})
	if err != nil {
		return err
	}

	// Bounded parallel download+decode, strictly ordered yield. The feeder
	// admits at most ArchivistaDecodeWorkers candidates into the window; the
	// consumer yields candidate i only after i-1, so results are identical
	// to the serial loop this replaces. Failed candidates keep the serial
	// skip semantics (logged, marked processed, never yielded). A yield
	// error stops further yields; the remaining in-flight slots are drained
	// (bounded waste) and NOTHING is marked seen, preserving the
	// all-or-nothing retry semantics of a failed batch.
	results := make([]chan decodedSlot, len(gitoids))
	for i := range results {
		results[i] = make(chan decodedSlot, 1)
	}
	window := make(chan struct{}, ArchivistaDecodeWorkers)
	jobs := make(chan int)
	// aborted flips once the consumer sees a yield error: workers then
	// short-circuit their remaining slots without downloading. Invisible to
	// semantics — the abort path marks NOTHING as seen regardless — it only
	// stops the drain from fetching a potentially huge remaining candidate
	// list nobody will consume.
	var aborted atomic.Bool
	var wg sync.WaitGroup
	for k := 0; k < ArchivistaDecodeWorkers; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if aborted.Load() {
					results[i] <- decodedSlot{}
					continue
				}
				env, ok := s.fetchCollectionEnvelope(ctx, gitoids[i])
				results[i] <- decodedSlot{env: env, ok: ok}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range gitoids {
			window <- struct{}{}
			jobs <- i
		}
	}()

	processedGitoids, yieldErr := drainInOrder(gitoids, results, window, yield, &aborted)
	wg.Wait()
	if yieldErr != nil {
		// Aborted mid-iteration: mark NOTHING as seen, exactly like a
		// failed batch — the next search must be able to retry the run.
		return yieldErr
	}

	// Only mark gitoids as seen after ALL were successfully processed.
	// This prevents partial updates that break retry semantics: if a
	// download fails mid-batch, no gitoids are excluded on the next search.
	s.mu.Lock()
	s.seenGitoids = append(s.seenGitoids, processedGitoids...)
	// The memo follows the same all-or-nothing rule: a batch that reached
	// this point marked every candidate seen, so its identical repeat is
	// provably empty and the query can be skipped.
	if len(subjectDigests) > 0 {
		if s.completedSearches == nil {
			s.completedSearches = make(map[string]struct{})
		}
		s.completedSearches[fingerprint] = struct{}{}
	}
	s.mu.Unlock()

	return nil
}

// searchFingerprint canonicalizes a search's inputs into an INJECTIVE
// encoding: sorted copies, so the caller's slice order (which the policy
// depth loop does not guarantee) cannot make identical searches look
// distinct, and every element length-prefixed (netstring-style), so element
// content can never imitate a separator — ["a", "b"] and ["a\x01b"] must not
// share a fingerprint, or completing the first search would silently
// suppress the second. The digest count is encoded too, so a value cannot
// migrate across the digest/attestation boundary.
func searchFingerprint(collectionName string, subjectDigests, attestations []string) string {
	digests := append([]string(nil), subjectDigests...)
	atts := append([]string(nil), attestations...)
	sort.Strings(digests)
	sort.Strings(atts)
	var b strings.Builder
	writeField := func(v string) {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	writeField(collectionName)
	writeField(strconv.Itoa(len(digests)))
	for _, d := range digests {
		writeField(d)
	}
	for _, a := range atts {
		writeField(a)
	}
	return b.String()
}

// SearchByPredicateType queries Archivista for DSSE envelopes whose statement
// predicateType is in predicateTypes AND whose subjects intersect
// subjectDigests. Each matched envelope is downloaded, parsed into an
// intoto.Statement, and wrapped in a StatementEnvelope with either a typed
// attestor (from the registered factory) or a RawAttestation fallback.
//
// No DSSE signature verification happens here — verification is the caller's
// responsibility via Functionary.Validate on StatementEnvelope.Verifiers.
// This implementation returns an empty Verifiers slice; the policy engine's
// external-attestation flow performs its own verification.
//
// See issue #39.
func (s *ArchivistaSource) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error) {
	s.mu.Lock()
	excludeGitoids := make([]string, len(s.seenGitoids))
	copy(excludeGitoids, s.seenGitoids)
	s.mu.Unlock()

	gitoids, err := s.client.SearchGitoidsByPredicate(ctx, archivista.SearchGitoidByPredicateVariables{
		PredicateTypes: predicateTypes,
		SubjectDigests: subjectDigests,
		ExcludeGitoids: excludeGitoids,
	})
	if err != nil {
		return nil, err
	}

	envelopes := make([]StatementEnvelope, 0, len(gitoids))
	processedGitoids := make([]string, 0, len(gitoids))
	for _, gitoid := range gitoids {
		env, err := s.client.Download(ctx, gitoid)
		if err != nil {
			log.Debugf("archivista source: SearchByPredicateType skipping gitoid %s: download failed: %v", gitoid, err)
			processedGitoids = append(processedGitoids, gitoid)
			continue
		}

		se := StatementEnvelope{
			Envelope:  env,
			Reference: gitoid,
		}

		if len(env.Payload) == 0 {
			se.Errors = append(se.Errors, fmt.Errorf("envelope %s has empty payload", gitoid))
			envelopes = append(envelopes, se)
			processedGitoids = append(processedGitoids, gitoid)
			continue
		}

		stmt := intoto.Statement{}
		if err := json.Unmarshal(env.Payload, &stmt); err != nil {
			se.Errors = append(se.Errors, fmt.Errorf("envelope %s: failed to unmarshal statement: %w", gitoid, err))
			envelopes = append(envelopes, se)
			processedGitoids = append(processedGitoids, gitoid)
			continue
		}

		se.Statement = stmt

		if factory, ok := attestation.FactoryByType(stmt.PredicateType); ok {
			typed := factory()
			if err := json.Unmarshal(stmt.Predicate, typed); err != nil {
				se.Errors = append(se.Errors, fmt.Errorf("typed factory unmarshal failed for %s, falling back to raw: %w", stmt.PredicateType, err))
				se.Attestor = attestation.NewRawAttestation(stmt.PredicateType, stmt.Predicate)
			} else {
				se.Attestor = typed
			}
		} else {
			se.Attestor = attestation.NewRawAttestation(stmt.PredicateType, stmt.Predicate)
		}

		envelopes = append(envelopes, se)
		processedGitoids = append(processedGitoids, gitoid)
	}

	s.mu.Lock()
	s.seenGitoids = append(s.seenGitoids, processedGitoids...)
	s.mu.Unlock()

	return envelopes, nil
}
