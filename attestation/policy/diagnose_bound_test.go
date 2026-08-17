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

package policy

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The BOUND on the empty-collection diagnostic re-probe.
//
// Verdict invariance is pinned separately, in diagnose_invariance_test.go,
// which compiles against both the bounded and unbounded trees. This file pins
// the bound itself: that it fires, where it fires, and — the load-bearing
// half — that it CANNOT fire anywhere else.
// ---------------------------------------------------------------------------

// legacyDiagnoseEmptyCollectionResult is the pre-bound implementation,
// verbatim. It is the differential oracle: for any corpus at or below the
// bound the bounded diagnostic must produce a BYTE-IDENTICAL error string, and
// above the bound it must still agree on everything except the length of the
// observed-subject list.
//
// It deliberately does NOT call observedCollectionSubjects. An oracle that
// shares the code under test cannot detect a change to that code: a reversed
// sort or a dropped digest pair would move both sides equally and the
// comparison would stay green. The rendering below is a standalone copy of the
// pre-change body.
func legacyDiagnoseEmptyCollectionResult(ctx context.Context, src source.VerifiedSourcer, stepName string, suppliedDigests, attestations []string) error {
	allForStep, err := src.Search(ctx, stepName, nil, attestations)
	if err != nil || len(allForStep) == 0 {
		return ErrNoCollections{Step: stepName}
	}
	return ErrSubjectDigestMismatch{
		Step:             stepName,
		SuppliedDigests:  append([]string(nil), suppliedDigests...),
		ObservedSubjects: legacyObservedCollectionSubjects(allForStep),
	}
}

// legacyObservedCollectionSubjects is the pre-change rendering, copied.
func legacyObservedCollectionSubjects(results []source.CollectionVerificationResult) []string {
	seen := make(map[string]struct{})
	for _, r := range results {
		for _, subj := range r.Statement.Subject {
			repr := subj.Name
			for algo, dig := range subj.Digest {
				repr = fmt.Sprintf("%s (%s:%s)", subj.Name, algo, dig)
				break
			}
			seen[repr] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// boundedProbeCorpus builds n collections for "build", each carrying one
// uniquely-named subject so the rendered observed-subject list has exactly one
// entry per collection. That 1:1 mapping is what lets the assertions below
// count collections by counting subjects.
func boundedProbeCorpus(n int) *diagCorpus {
	corpus := newDiagCorpus()
	all := make([]source.CollectionVerificationResult, 0, n)
	for i := 0; i < n; i++ {
		all = append(all, diagCollection(nil, fmt.Sprintf("c-%d", i), "build",
			diagSubject(fmt.Sprintf("file:app-%d", i), fmt.Sprintf("%064x", i))))
	}
	corpus.byStep["build"] = all
	return corpus
}

// observedFrom returns ObservedSubjects AS RENDERED — it does not re-sort, so
// callers that compare against a literal also pin the ordering contract.
func observedFrom(t *testing.T, err error) []string {
	t.Helper()
	var mm ErrSubjectDigestMismatch
	require.True(t, errors.As(err, &mm), "want ErrSubjectDigestMismatch, got %T: %v", err, err)
	return mm.ObservedSubjects
}

// truncatedFrom returns the sample-truncation flag the hint selection reads.
// It is asserted separately from ObservedSubjects because the two can disagree
// in exactly the way that matters: a COMPLETE observation wrongly marked
// truncated hedges a hint that should have been definite, and a TRUNCATED one
// wrongly marked complete states an absence it never established.
func truncatedFrom(t *testing.T, err error) bool {
	t.Helper()
	var mm ErrSubjectDigestMismatch
	require.True(t, errors.As(err, &mm), "want ErrSubjectDigestMismatch, got %T: %v", err, err)
	return mm.ObservedTruncated
}

// TestProbeBound_ObservedSubjectsAreSortedAndDeduped pins the stability
// contract the error type documents ("a sorted, deduplicated rendering"). The
// bound moved this rendering behind a shared helper; without an explicit
// assertion, reversing the sort passes every other test in this file because
// the differential oracle would move with it.
//
// NOT VACUOUS: the fixture emits collections in DESCENDING name order and
// repeats one subject across two collections, so an implementation that
// preserved source order, or failed to dedupe, produces a different literal.
func TestProbeBound_ObservedSubjectsAreSortedAndDeduped(t *testing.T) {
	shared := diagSubject("file:shared", "ffff")
	corpus := newDiagCorpus()
	corpus.byStep["build"] = []source.CollectionVerificationResult{
		diagCollection(nil, "c-0", "build", diagSubject("zzz:last", "0003"), shared),
		diagCollection(nil, "c-1", "build", diagSubject("mmm:middle", "0002"), shared),
		diagCollection(nil, "c-2", "build", diagSubject("aaa:first", "0001")),
	}

	got := observedFrom(t, diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{corpus}, "build", []string{"nope"}, nil))

	assert.Equal(t, []string{
		"aaa:first (sha256:0001)",
		"file:shared (sha256:ffff)",
		"mmm:middle (sha256:0002)",
		"zzz:last (sha256:0003)",
	}, got, "observed subjects must be sorted and deduplicated")
	assert.True(t, sort.StringsAreSorted(got))
}

// ---------------------------------------------------------------------------
// 1. The bound fires on a streaming source: the corpus is not drained.
// ---------------------------------------------------------------------------

// NOT VACUOUS: the control assertion at the end drives the SAME fixture
// through a full unfiltered Search and requires all 50 candidates back, so a
// fixture that could only ever yield 4 would fail there. 50 is deliberately
// more than ten times the bound.
func TestProbeBound_StreamingSourceStopsAtTheBound(t *testing.T) {
	require.Greater(t, 50, maxDiagnosticProbeCollections, "fixture must exceed the bound or the test proves nothing")
	corpus := boundedProbeCorpus(50)

	err := diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{corpus}, "build", []string{"nope"}, nil)

	// EXACTLY bound+1, asserted tight rather than as an upper limit. The probe
	// reads one past the bound on purpose — that extra collection is what
	// distinguishes "there were exactly N" from "there were more than N" — and
	// it is never rendered. A tight equality reddens in both directions: at
	// bound it means the truncation flag went back to guessing, and above
	// bound+1 it means the abort stopped working and a 806-envelope corpus
	// gets drained to build an error string.
	assert.Equal(t, maxDiagnosticProbeCollections+1, corpus.probeYields,
		"the bounded probe must stop one past the bound, not drain the corpus")
	assert.Len(t, observedFrom(t, err), maxDiagnosticProbeCollections,
		"the collection read past the bound proves truncation but is never rendered")
	assert.True(t, truncatedFrom(t, err),
		"50 collections behind a bound of 4 is a sample and must say so")

	// Control: the same fixture yields everything when nobody aborts it.
	control := boundedProbeCorpus(50)
	all, serr := control.Search(context.Background(), "build", nil, nil)
	require.NoError(t, serr)
	require.Len(t, all, 50, "fixture must be capable of yielding the whole corpus")
}

// ---------------------------------------------------------------------------
// 2. A non-streaming source cannot be aborted, so the bound saves no fetch —
//    and therefore must not cap the rendering either.
// ---------------------------------------------------------------------------

// This test previously asserted the OPPOSITE (it was named
// ...TruncatesTheSample and required exactly maxDiagnosticProbeCollections
// subjects). That contract was the defect: the slice arm already holds every
// collection in memory, so truncating bought nothing and cost correctness —
// see TestProbeBound_TreeSubjectBeyondTheBoundStillSteersTheHint below for
// what it actually broke.
func TestProbeBound_NonStreamingSourceRendersTheCompleteUnion(t *testing.T) {
	corpus := boundedProbeCorpus(50)

	err := diagnoseEmptyCollectionResult(context.Background(), diagBatchSource{corpus}, "build", []string{"nope"}, nil)

	assert.Equal(t, 50, corpus.probeYields,
		"a non-streaming source hands back the whole slice — the bound cannot save the fetch here")
	assert.Len(t, observedFrom(t, err), 50,
		"the fetch already paid for every collection, so the union must be complete")
	assert.False(t, truncatedFrom(t, err),
		"nothing was withheld, so the message must not hedge as if it were a sample")
}

// TestProbeBound_TreeSubjectBeyondTheBoundStillSteersTheHint is the regression
// for the bug the old truncate-the-sample contract caused, and it is the reason
// that contract had to go rather than merely being relaxed.
//
// ObservedSubjects is NOT decoration: ErrSubjectDigestMismatch.Error scans it
// for a "tree:" subject to pick between two mutually exclusive remediations —
// "your file was modified after attestation" versus "you need an inclusion
// proof". Truncating to the first four collections made a tree: subject in the
// fifth invisible, and the operator was confidently sent after the wrong cause.
//
// NOT VACUOUS: the tree: subject sits at index 9, well past the bound of 4, so
// a re-introduced truncation reddens this immediately. The paired sub-test
// proves the hedge is not merely always-on.
func TestProbeBound_TreeSubjectBeyondTheBoundStillSteersTheHint(t *testing.T) {
	corpusWithTreeAt := func(n, idx int) *diagCorpus {
		corpus := boundedProbeCorpus(n)
		corpus.byStep["build"][idx] = diagCollection(nil, fmt.Sprintf("c-%d", idx), "build",
			diagSubject("tree:products", fmt.Sprintf("%064x", idx)))
		return corpus
	}
	require.Greater(t, 9, maxDiagnosticProbeCollections,
		"the tree: subject must sit past the bound or this proves nothing")

	t.Run("batch source sees it and commits to the inclusion-proof hint", func(t *testing.T) {
		err := diagnoseEmptyCollectionResult(context.Background(),
			diagBatchSource{corpusWithTreeAt(50, 9)}, "build", []string{"nope"}, nil)

		assert.Contains(t, err.Error(), "inclusion proof",
			"a tree: subject past the bound must still select the Merkle-tree remediation")
		assert.False(t, truncatedFrom(t, err),
			"the slice arm observed everything — it must state the cause, not hedge")
	})

	t.Run("streamed source cannot see it and says so instead of guessing", func(t *testing.T) {
		err := diagnoseEmptyCollectionResult(context.Background(),
			diagStreamSource{corpusWithTreeAt(50, 9)}, "build", []string{"nope"}, nil)

		// The stream genuinely stopped before index 9, so the honest answer is
		// "unknown" — NOT the confident modified-file hint the old code gave.
		assert.True(t, truncatedFrom(t, err), "the stream stopped early; the sample is incomplete")
		assert.Contains(t, err.Error(), "a sample of this step's collections",
			"absence of tree: in a SAMPLE must be reported as unknown, not as absence")
	})
}

// ---------------------------------------------------------------------------
// 3. Off-by-one around the bound.
// ---------------------------------------------------------------------------

// seenNote is the message on the seen-set assertion. It is spelled out because
// a bare count mismatch here reads like a bug in the bound, and it is not: the
// probe is seen-neutral exactly where its abort fires.
const seenNote = "the probe is seen-neutral exactly where the abort fires (n > bound); at or below the bound the stream ends on its own, the source commits what it delivered, and that is what main did at every size"

// NOT VACUOUS: the table walks every corpus size from 0 to bound+2 and asserts
// an exact count at each, so `>` vs `>=` and `n` vs `n-1` all redden. The
// seen-set column is asserted the same way, and its expectation was derived by
// running the strict form (0 everywhere) and reading which sizes disagreed —
// not by copying what the code happens to do.
func TestProbeBound_ExactBoundary(t *testing.T) {
	for n := 0; n <= maxDiagnosticProbeCollections+2; n++ {
		t.Run(fmt.Sprintf("corpus=%d", n), func(t *testing.T) {
			// The streamed arm renders at most the bound; the slice arm already
			// paid for the whole fetch and renders all of it.
			bounded := n
			if bounded > maxDiagnosticProbeCollections {
				bounded = maxDiagnosticProbeCollections
			}
			// The stream reads ONE PAST the bound to prove truncation, so it
			// yields min(n, bound+1) — and is truncated exactly when it had to
			// stop, i.e. when n actually exceeds the bound. n == bound must NOT
			// report truncation: stopping because the source ran out is not the
			// same as stopping because the bound bit.
			streamYields := n
			if streamYields > maxDiagnosticProbeCollections+1 {
				streamYields = maxDiagnosticProbeCollections + 1
			}
			// SEEN-SET STATE, stated exactly rather than aspirationally.
			//
			// The abort is what makes the probe non-mutating, so the probe is
			// non-mutating exactly where the abort fires: above the bound. At
			// or below it the stream simply runs out, SearchStream returns nil,
			// and a seen-tracking source commits everything it delivered —
			// which is what an unbounded probe did at EVERY size before this
			// change. So n <= bound is inherited behaviour, asserted below
			// against the legacy oracle, not a regression this bound
			// introduces. Closing it belongs in the source (judge-api's
			// EntSource already refuses to mark from a probe; ArchivistaSource
			// has no such guard) and is tracked in testifysec/judge#8026.
			streamSeen := n
			if n > maxDiagnosticProbeCollections {
				streamSeen = 0
			}

			for _, arm := range []struct {
				name string
				src  func(*diagCorpus) source.VerifiedSourcer
				// yields is what the SOURCE hands over, which the streaming
				// arm bounds and the slice arm cannot.
				yields int
				// rendered is what reaches ObservedSubjects.
				rendered  int
				truncated bool
				// seen is how many collections a seen-tracking source has
				// marked by the time the probe returns. See seenNote below
				// for why this is not 0 everywhere.
				seen int
			}{
				{"streamed", func(c *diagCorpus) source.VerifiedSourcer { return diagStreamSource{c} },
					streamYields, bounded, n > maxDiagnosticProbeCollections, streamSeen},
				{"batch", func(c *diagCorpus) source.VerifiedSourcer { return diagBatchSource{c} },
					n, n, false, n},
			} {
				t.Run(arm.name, func(t *testing.T) {
					corpus := boundedProbeCorpus(n)
					corpus.trackSeen = true
					err := diagnoseEmptyCollectionResult(context.Background(), arm.src(corpus), "build", []string{"nope"}, nil)

					assert.Len(t, corpus.seen, arm.seen, seenNote)

					// INHERITED, NOT INTRODUCED. Where the bound does not bite,
					// this probe consumes exactly what the unbounded probe on
					// main consumed — the bound only ever removes mutation, it
					// never adds any. Comparing against the legacy oracle makes
					// that an executable claim rather than a comment, so a
					// future change that makes the small-corpus case WORSE than
					// main reddens here.
					legacyCorpus := boundedProbeCorpus(n)
					legacyCorpus.trackSeen = true
					_ = legacyDiagnoseEmptyCollectionResult(context.Background(), arm.src(legacyCorpus), "build", []string{"nope"}, nil)
					assert.LessOrEqual(t, len(corpus.seen), len(legacyCorpus.seen),
						"the bounded probe must never consume MORE than the unbounded one it replaced")
					if n <= maxDiagnosticProbeCollections {
						assert.Len(t, legacyCorpus.seen, arm.seen,
							"at or below the bound the legacy probe consumes the same set — this case is inherited from main, not caused by the bound")
					}

					if n == 0 {
						var nc ErrNoCollections
						require.True(t, errors.As(err, &nc), "empty corpus must diagnose ErrNoCollections, got %T", err)
						assert.Equal(t, 0, corpus.probeYields)
						return
					}
					assert.Len(t, observedFrom(t, err), arm.rendered)
					assert.Equal(t, arm.yields, corpus.probeYields)
					assert.Equal(t, arm.truncated, truncatedFrom(t, err),
						"truncation must track whether the source actually had more, not whether the bound was reached")
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. Differential against the legacy implementation.
// ---------------------------------------------------------------------------

// TestProbeBound_MessageIdenticalToLegacyAtOrBelowBound is the byte-identity
// half: for every corpus the bound does not bite, the operator sees exactly
// the string they saw before.
//
// NOT VACUOUS: it compares full Error() strings, so a change to subject
// rendering, ordering, dedup, the supplied-digest list or the hint selection
// reddens it — the legacy oracle is a literal copy of the old body, not a
// re-derivation of the new one.
func TestProbeBound_MessageIdenticalToLegacyAtOrBelowBound(t *testing.T) {
	for n := 1; n <= maxDiagnosticProbeCollections; n++ {
		t.Run(fmt.Sprintf("corpus=%d", n), func(t *testing.T) {
			supplied := []string{"abc123notinenvelope", "def456"}

			legacy := legacyDiagnoseEmptyCollectionResult(context.Background(), diagBatchSource{boundedProbeCorpus(n)}, "build", supplied, nil)
			streamed := diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{boundedProbeCorpus(n)}, "build", supplied, nil)
			batch := diagnoseEmptyCollectionResult(context.Background(), diagBatchSource{boundedProbeCorpus(n)}, "build", supplied, nil)

			assert.Equal(t, legacy.Error(), streamed.Error(), "streamed arm must be byte-identical to legacy at or below the bound")
			assert.Equal(t, legacy.Error(), batch.Error(), "slice arm must be byte-identical to legacy at or below the bound")
		})
	}
}

// TestProbeBound_AgreesWithLegacyAboveBoundExceptSampleSize pins what the
// bound is ALLOWED to change above the bound, and everything it is not.
func TestProbeBound_AgreesWithLegacyAboveBoundExceptSampleSize(t *testing.T) {
	const corpusSize = 40
	supplied := []string{"abc123notinenvelope", "def456"}

	legacyErr := legacyDiagnoseEmptyCollectionResult(context.Background(), diagBatchSource{boundedProbeCorpus(corpusSize)}, "build", supplied, nil)
	boundedErr := diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{boundedProbeCorpus(corpusSize)}, "build", supplied, nil)

	var legacy, bounded ErrSubjectDigestMismatch
	require.True(t, errors.As(legacyErr, &legacy))
	require.True(t, errors.As(boundedErr, &bounded))

	assert.Equal(t, legacy.Step, bounded.Step, "Step must not change")
	assert.Equal(t, legacy.SuppliedDigests, bounded.SuppliedDigests, "SuppliedDigests must not change")
	require.Len(t, legacy.ObservedSubjects, corpusSize, "oracle sanity: legacy renders the whole corpus")
	assert.Len(t, bounded.ObservedSubjects, maxDiagnosticProbeCollections)
	assert.Subset(t, legacy.ObservedSubjects, bounded.ObservedSubjects,
		"the bounded sample must be a subset of what legacy observed — never an invented subject")
}

// ---------------------------------------------------------------------------
// 5. Diagnostic quality survives the bound.
// ---------------------------------------------------------------------------

// NOT VACUOUS: every assertion names a specific substring the operator needs,
// and the corpus is 40 collections (ten times the bound), so a bound that
// rendered nothing would fail on the subject-name and digest assertions rather
// than passing a "message is non-empty" check.
func TestProbeBound_DiagnosticQualityPreserved(t *testing.T) {
	corpus := boundedProbeCorpus(40)
	err := diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{corpus}, "build", []string{"abc123notinenvelope"}, nil)
	msg := err.Error()

	assert.Contains(t, msg, "not present in any subject", "must still explain the real problem")
	assert.Contains(t, msg, `step "build"`, "must still name the step")
	assert.Contains(t, msg, "abc123notinenvelope", "must still echo what the operator supplied")
	assert.Contains(t, msg, "file:app-0", "must still name an observed subject")
	assert.Contains(t, msg, "(sha256:", "must still show the digest the operator would need to match")
	assert.Contains(t, msg, "the file was likely modified after it was", "must still carry the fail-closed hint")
	assert.NotContains(t, msg, "no collections found", "must not regress to the misleading no-collections phrasing")

	// The rendered list stays readable rather than dumping the corpus.
	assert.Less(t, len(msg), 1000, "the bounded message must stay operator-readable; got %d bytes", len(msg))
}

// TestProbeBound_TreeSubjectHintStillReachable pins that the "tree:" hint —
// which is selected by scanning ObservedSubjects — still fires when a sampled
// collection carries a Merkle-tree subject.
func TestProbeBound_TreeSubjectHintStillReachable(t *testing.T) {
	corpus := newDiagCorpus()
	all := []source.CollectionVerificationResult{
		diagCollection(nil, "c-0", "build", diagSubject("tree:products", "aa")),
	}
	for i := 1; i < 40; i++ {
		all = append(all, diagCollection(nil, fmt.Sprintf("c-%d", i), "build",
			diagSubject(fmt.Sprintf("file:app-%d", i), fmt.Sprintf("%064x", i))))
	}
	corpus.byStep["build"] = all

	err := diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{corpus}, "build", []string{"nope"}, nil)
	assert.Contains(t, err.Error(), "Merkle tree", "a sampled tree: subject must still select the inclusion-proof hint")
}

// ---------------------------------------------------------------------------
// 6. The abort sentinel must never be mistaken for a source failure, and a
//    real source failure must never be mistaken for the abort.
// ---------------------------------------------------------------------------

// erroringStreamSource yields `yieldFirst` candidates and then fails with a
// genuine source error.
type erroringStreamSource struct {
	yieldFirst int
	failWith   error
}

func (s erroringStreamSource) Search(_ context.Context, _ string, _, _ []string) ([]source.CollectionVerificationResult, error) {
	return nil, s.failWith
}

func (s erroringStreamSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

func (s erroringStreamSource) SearchStream(_ context.Context, stepName string, _, _ []string, yield func(source.CollectionVerificationResult) error) error {
	for i := 0; i < s.yieldFirst; i++ {
		if err := yield(diagCollection(nil, fmt.Sprintf("c-%d", i), stepName, diagSubject(fmt.Sprintf("file:app-%d", i), "aa"))); err != nil {
			return err
		}
	}
	return s.failWith
}

func TestProbeBound_SentinelNeverEscapesAndRealErrorsStillCollapse(t *testing.T) {
	realErr := errors.New("archivista: connection reset")

	t.Run("bound reached before any source error: digest mismatch", func(t *testing.T) {
		src := erroringStreamSource{yieldFirst: maxDiagnosticProbeCollections + 3, failWith: realErr}
		err := diagnoseEmptyCollectionResult(context.Background(), src, "build", []string{"nope"}, nil)

		var mm ErrSubjectDigestMismatch
		require.True(t, errors.As(err, &mm), "the abort sentinel must be swallowed, got %T: %v", err, err)
		assert.False(t, errors.Is(err, errDiagnosticProbeSatisfied), "the sentinel must never reach a caller")
		assert.NotContains(t, err.Error(), "sample bound reached")
	})

	t.Run("genuine source error before the bound: collapses to ErrNoCollections", func(t *testing.T) {
		src := erroringStreamSource{yieldFirst: maxDiagnosticProbeCollections - 2, failWith: realErr}
		err := diagnoseEmptyCollectionResult(context.Background(), src, "build", []string{"nope"}, nil)

		var nc ErrNoCollections
		require.True(t, errors.As(err, &nc), "a real source error must collapse to ErrNoCollections, got %T: %v", err, err)
	})

	t.Run("source that wraps the sentinel is still handled", func(t *testing.T) {
		src := wrappingStreamSource{}
		err := diagnoseEmptyCollectionResult(context.Background(), src, "build", []string{"nope"}, nil)
		var mm ErrSubjectDigestMismatch
		require.True(t, errors.As(err, &mm), "errors.Is must see through a source that wraps the abort, got %T: %v", err, err)
	})
}

// wrappingStreamSource returns the yield error wrapped, which the
// StreamingSourcer contract permits ("unwrapped enough to surface").
type wrappingStreamSource struct{}

func (wrappingStreamSource) Search(_ context.Context, _ string, _, _ []string) ([]source.CollectionVerificationResult, error) {
	return nil, nil
}

func (wrappingStreamSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

func (wrappingStreamSource) SearchStream(_ context.Context, stepName string, _, _ []string, yield func(source.CollectionVerificationResult) error) error {
	for i := 0; ; i++ {
		if err := yield(diagCollection(nil, fmt.Sprintf("c-%d", i), stepName, diagSubject(fmt.Sprintf("file:app-%d", i), "aa"))); err != nil {
			return fmt.Errorf("source aborted iteration: %w", err)
		}
		if i > 1000 {
			return errors.New("probe never aborted")
		}
	}
}

// ---------------------------------------------------------------------------
// 7. The deliberate behavioural delta: the probe is now seen-NEUTRAL.
// ---------------------------------------------------------------------------

// TestProbeBound_AbortLeavesSeenSetUntouched pins the one intentional change
// this bound makes to an ArchivistaSource-shaped source.
//
// Before the bound, the probe drained the stream to completion, so the source
// marked every collection for the step as SEEN — and a seen collection is
// excluded from every later search on that instance. A diagnostic therefore
// hid the step's legitimate evidence from every later depth iteration. That is
// precisely the failure judge-api's EntSource guards against explicitly
// ("MARKING from a probe is worse ... a diagnostic must not mutate what the
// search can still find"); ArchivistaSource had no such guard.
//
// Aborting the stream restores that contract for free: StreamingSourcer marks
// nothing seen on an aborted iteration.
//
// NOT VACUOUS: the control run below drains the same fixture without a bound
// and asserts the seen set DOES fill, so the fixture genuinely models
// seen-tracking rather than never recording anything.
func TestProbeBound_AbortLeavesSeenSetUntouched(t *testing.T) {
	corpus := boundedProbeCorpus(40)
	corpus.trackSeen = true

	err := diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{corpus}, "build", []string{"nope"}, nil)
	var mm ErrSubjectDigestMismatch
	require.True(t, errors.As(err, &mm))

	assert.Empty(t, corpus.seen, "an aborted diagnostic probe must mark nothing seen")

	// The evidence is still fully discoverable afterwards.
	after, serr := corpus.Search(context.Background(), "build", nil, nil)
	require.NoError(t, serr)
	assert.Len(t, after, 40, "the probe must not have consumed the corpus")

	// Control: the legacy, unbounded probe DOES consume it.
	control := boundedProbeCorpus(40)
	control.trackSeen = true
	_ = legacyDiagnoseEmptyCollectionResult(context.Background(), diagStreamSource{control}, "build", []string{"nope"}, nil)
	assert.Len(t, control.seen, 40, "control: the unbounded probe marks the whole corpus seen")
	remaining, serr := control.Search(context.Background(), "build", nil, nil)
	require.NoError(t, serr)
	assert.Empty(t, remaining, "control: after the unbounded probe the corpus is invisible to later searches")
}

// ---------------------------------------------------------------------------
// 8. STRUCTURAL CONTAINMENT — the bound must be unreachable from verification.
// ---------------------------------------------------------------------------

// parsePolicyPackage parses the package's NON-TEST Go files.
func parsePolicyPackage(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		require.NoError(t, perr, "parsing %s", name)
		files = append(files, f)
	}
	require.NotEmpty(t, files, "found no non-test sources to analyse — the containment check would be vacuous")
	return fset, files
}

// TestBoundedProbeIsStructurallyContained fails if the bounded path becomes
// reachable from anywhere other than the diagnostic.
//
// It walks every top-level function in the package's non-test sources and
// records which ones mention the bound, the abort sentinel, or the bounded
// probe. Production code may name those three identifiers from exactly two
// places: the probe itself, and the one diagnostic that calls it. A new caller
// on the verification path — or a "just cap it here too" edit inside
// verifySteps or verifyStepStreamed — reddens this test.
//
// NOT VACUOUS: the test first requires that it FOUND the two expected
// functions and a non-zero number of top-level function declarations, so a
// parse that matched nothing fails loudly instead of passing empty.
func TestBoundedProbeIsStructurallyContained(t *testing.T) {
	_, files := parsePolicyPackage(t)

	guarded := map[string]bool{
		"maxDiagnosticProbeCollections": true,
		"errDiagnosticProbeSatisfied":   true,
		"probeStepEvidence":             true,
	}

	referencedBy := map[string]map[string]bool{}
	totalFuncs := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			totalFuncs++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok || !guarded[id.Name] {
					return true
				}
				if referencedBy[fn.Name.Name] == nil {
					referencedBy[fn.Name.Name] = map[string]bool{}
				}
				referencedBy[fn.Name.Name][id.Name] = true
				return true
			})
		}
	}

	require.Greater(t, totalFuncs, 20, "the AST walk found almost no functions — it is not analysing the package")

	got := make([]string, 0, len(referencedBy))
	for name := range referencedBy {
		got = append(got, name)
	}
	sort.Strings(got)

	assert.Equal(t, []string{"diagnoseEmptyCollectionResult", "probeStepEvidence"}, got,
		"the diagnostic bound leaked outside the diagnostic path: %v", referencedBy)

	// And the two that ARE allowed must genuinely be there, so the equality
	// above cannot be satisfied by a rename that silently removed the bound.
	require.Contains(t, referencedBy, "probeStepEvidence")
	assert.True(t, referencedBy["probeStepEvidence"]["maxDiagnosticProbeCollections"],
		"probeStepEvidence no longer applies the bound")
	assert.True(t, referencedBy["probeStepEvidence"]["errDiagnosticProbeSatisfied"],
		"probeStepEvidence no longer aborts the stream")
	assert.True(t, referencedBy["diagnoseEmptyCollectionResult"]["probeStepEvidence"],
		"the diagnostic no longer goes through the bounded probe")
}

// TestBoundedProbeReturnsNoEvidence is the type-level half of containment: the
// bounded probe's signature must not be able to hand a collection back. As
// long as it returns only (bool, []string, error), a truncated probe result
// cannot become — or silently shrink — the evidence a policy is judged on,
// whoever calls it.
//
// NOT VACUOUS: it locates the declaration by name and fails if absent, then
// asserts the exact rendered result list, so widening the signature to return
// []source.CollectionVerificationResult reddens it.
func TestBoundedProbeReturnsNoEvidence(t *testing.T) {
	fset, files := parsePolicyPackage(t)

	var decl *ast.FuncDecl
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if ok && fn.Name.Name == "probeStepEvidence" {
				decl = fn
			}
		}
	}
	require.NotNil(t, decl, "probeStepEvidence not found — containment check would be vacuous")

	results := make([]string, 0, 3)
	for _, field := range decl.Type.Results.List {
		var buf strings.Builder
		require.NoError(t, printer.Fprint(&buf, fset, field.Type))
		n := len(field.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			results = append(results, buf.String())
		}
	}

	// Still an EXACT pin, not a growing allow-list. The added bool reports
	// whether the subject sample was truncated; it is a scalar fact ABOUT the
	// probe, not a channel for evidence — no CollectionVerificationResult,
	// envelope, statement or verifier can travel through it. Widening this to
	// "anything scalar is fine" would be the inverted guard; changing the pin
	// once, deliberately, with the reason recorded, is not.
	assert.Equal(t, []string{"bool", "[]string", "bool", "error"}, results,
		"the bounded probe must not be able to return evidence")
}

// TestOnlyTheDiagnosticIssuesAnUnfilteredSearch pins the complementary fact
// the containment argument leans on: in the whole package, the only search
// issued with a nil subject-digest set is the diagnostic probe. Verification
// searches always pass vo.subjectDigests, which checkVerifyOpts guarantees is
// non-empty.
//
// NOT VACUOUS: the walk requires that it found at least the three known search
// call sites before judging them.
func TestOnlyTheDiagnosticIssuesAnUnfilteredSearch(t *testing.T) {
	_, files := parsePolicyPackage(t)

	type callSite struct{ fn, method, digestArg string }
	var sites []callSite

	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name != "Search" && sel.Sel.Name != "SearchStream" {
					return true
				}
				// arg 0 is ctx, 1 is the collection name, 2 is the digest set.
				if len(call.Args) < 3 {
					return true
				}
				digest := "<expr>"
				if id, ok := call.Args[2].(*ast.Ident); ok {
					digest = id.Name
				} else if selArg, ok := call.Args[2].(*ast.SelectorExpr); ok {
					digest = selArg.Sel.Name
				}
				sites = append(sites, callSite{fn.Name.Name, sel.Sel.Name, digest})
				return true
			})
		}
	}

	require.GreaterOrEqual(t, len(sites), 3, "expected to find the engine's search call sites; found %v", sites)

	for _, s := range sites {
		if s.digestArg == "nil" {
			assert.Equal(t, "probeStepEvidence", s.fn,
				"%s issues an UNFILTERED %s — only the bounded diagnostic probe may do that", s.fn, s.method)
			continue
		}
		assert.Equal(t, "subjectDigests", s.digestArg,
			"%s.%s passes an unexpected digest argument %q; verification searches must pass vo.subjectDigests",
			s.fn, s.method, s.digestArg)
	}
}
