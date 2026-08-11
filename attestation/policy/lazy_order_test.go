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
	"fmt"
	"math/rand"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// WITNESS DETERMINISM (Codex, #7958 second review round).
//
// Stop-at-first-pass makes StepResult.Passed depend on WHICH passing collection
// arrives first. Verdicts are unaffected — any witness proves the same verdict —
// but Passed is copied verbatim into the SIGNED policy-verification attestation
// (plugins/attestors/policyverify/policyverify.go:232-286). So two verifies over
// an identical corpus, differing only in the order the source happened to
// deliver rows, produce DIFFERENT SIGNED ARTIFACTS.
//
// That is not acceptable for a signed artifact, and it is not hypothetical:
// judge-api's EntSource issued its gitoid query with NO ORDER BY, so Postgres
// was free to return rows in any order at all.
//
// THE CONTRACT. The witness is defined as "the first passing collection in
// CANONICAL STREAM ORDER", and canonical order is a property the SOURCE must
// declare (source.CanonicalOrderSourcer). A source that does not declare it is
// contractually excluded from the lazy stop — the same shape as the fan-out
// exclusion — so the witness is always a pure function of (corpus, policy,
// trust) and never of delivery timing.
// ---------------------------------------------------------------------------

// lazyOrderedSource yields its candidates sorted by Reference and DECLARES
// canonical order. It models judge-api's EntSource with its ORDER BY: whatever
// order rows arrive in underneath, the stream the policy engine consumes is a
// pure function of the corpus.
// The sort happens inside the QUERY (lazySource.ordered), not by buffering the
// stream — buffering would defeat the whole point by paying for every candidate
// before the consumer gets a chance to stop.
type lazyOrderedSource struct{ *lazySource }

func newLazyOrderedSource(s *lazySource) lazyOrderedSource {
	s.ordered = true
	return lazyOrderedSource{s}
}

// CanonicalStreamOrder declares the contract.
func (s lazyOrderedSource) CanonicalStreamOrder() bool { return true }

// lazyUnorderedSource yields in whatever order it was handed and declares
// NOTHING. It models ArchivistaSource, whose ordering is a remote server's
// choice, and pre-ORDER-BY EntSource, whose ordering was the planner's.
//
// The inner source is a NAMED FIELD, never embedded: *lazySource declares
// CanonicalStreamOrder, and embedding would PROMOTE that declaration, quietly
// turning this fixture into a canonical source and making every test below
// pass for the wrong reason.
type lazyUnorderedSource struct{ inner *lazySource }

func (s lazyUnorderedSource) Search(ctx context.Context, stepName string, subjectDigests, attestations []string) ([]source.CollectionVerificationResult, error) {
	return s.inner.Search(ctx, stepName, subjectDigests, attestations)
}

func (s lazyUnorderedSource) SearchStream(ctx context.Context, stepName string, subjectDigests, attestations []string, yield func(source.CollectionVerificationResult) error) error {
	return s.inner.SearchStream(ctx, stepName, subjectDigests, attestations, yield)
}

func (s lazyUnorderedSource) SearchByPredicateType(ctx context.Context, pts []string, sd []string) ([]source.StatementEnvelope, error) {
	return s.inner.SearchByPredicateType(ctx, pts, sd)
}

var (
	_ source.StreamingVerifiedSourcer = lazyOrderedSource{}
	_ source.CanonicalOrderSourcer    = lazyOrderedSource{}
	_ source.StreamingVerifiedSourcer = lazyUnorderedSource{}
)

// The negative assertion the compiler cannot make: lazyUnorderedSource must NOT
// satisfy CanonicalOrderSourcer. If a future edit embeds the inner source, the
// declaration is promoted, the fixture silently becomes canonical, and
// TestLazyWitness_UndeclaredSourceOrderCannotMoveTheWitness starts proving
// nothing.
func TestLazyOrderFixtures_UndeclaredSourceReallyDeclaresNothing(t *testing.T) {
	var s source.VerifiedSourcer = lazyUnorderedSource{inner: newLazySource(nil)}
	_, declares := s.(source.CanonicalOrderSourcer)
	assert.False(t, declares,
		"lazyUnorderedSource must NOT satisfy source.CanonicalOrderSourcer — it is the fixture for a source that cannot promise ordering")

	var ordered source.VerifiedSourcer = newLazyOrderedSource(newLazySource(nil))
	c, declares := ordered.(source.CanonicalOrderSourcer)
	require.True(t, declares, "lazyOrderedSource must satisfy source.CanonicalOrderSourcer")
	assert.True(t, c.CanonicalStreamOrder(), "and must declare TRUE, or the payoff test can never reach the lazy stop")
}

// lazyOrderCorpus builds one step with `n` passing candidates, delivered in the
// order given by perm. Every candidate satisfies the step on its own, so the
// witness is decided purely by which one arrives first.
func lazyOrderCorpus(t testing.TB, verifier cryptoutil.Verifier, keyID string, perm []int) (Policy, *lazySource) {
	t.Helper()
	corpus := make([]source.CollectionVerificationResult, 0, len(perm))
	for _, i := range perm {
		corpus = append(corpus, lazyPlain(verifier, fmt.Sprintf("cand-%02d", i), "build", ""))
	}
	return lazyPolicy(keyID, lazyStep("build", keyID)),
		newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": corpus})
}

// lazyPermutations returns n shuffled orderings of 0..size-1, seeded so a
// failure reproduces.
func lazyPermutations(size, n int) [][]int {
	rng := rand.New(rand.NewSource(20260810)) //nolint:gosec // deterministic test input
	out := make([][]int, 0, n)
	for k := 0; k < n; k++ {
		p := make([]int, size)
		for i := range p {
			p[i] = i
		}
		rng.Shuffle(size, func(i, j int) { p[i], p[j] = p[j], p[i] })
		out = append(out, p)
	}
	return out
}

// ---------------------------------------------------------------------------
// THE PERMUTATION TEST. Same candidate set, many delivery orders, a source that
// declares NOTHING about its ordering. The witness must not move.
//
// RED against the first implementation: lazy truncated at whichever candidate
// happened to arrive first, so each permutation produced a different Passed set
// and therefore a different signed attestation.
//
// GREEN under the contract: an undeclared source is excluded from the lazy stop
// entirely, so the step verifies exhaustively and the witness is the whole
// passing set — identical for every permutation.
// ---------------------------------------------------------------------------
func TestLazyWitness_UndeclaredSourceOrderCannotMoveTheWitness(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	const candidates = 6
	var first []string
	var firstExamined int

	for k, perm := range lazyPermutations(candidates, 8) {
		pol, src := lazyOrderCorpus(t, verifier, keyID, perm)
		pass, results, err := pol.Verify(context.Background(),
			WithVerifiedSource(lazyUnorderedSource{inner: src}),
			WithSubjectDigests([]string{"sha256:seed"}),
			WithSearchDepth(1),
			WithLazyStepSatisfaction(true),
		)
		require.NoError(t, err)
		require.True(t, pass)

		witness := lazyPassedRefs(results)["build"]
		if k == 0 {
			first, firstExamined = witness, src.yielded
			continue
		}
		assert.Equal(t, first, witness,
			"permutation %d produced a DIFFERENT witness (%v vs %v). Passed is copied verbatim into the signed "+
				"policy-verification attestation, so a delivery-order-dependent witness means the same corpus and "+
				"the same policy can be signed two different ways.", k, witness, first)
		assert.Equal(t, firstExamined, src.yielded,
			"permutation %d examined a different number of candidates (%d vs %d)", k, src.yielded, firstExamined)
	}

	// Non-vacuity: an UNDECLARED source must have been excluded from the stop,
	// so the witness is the whole passing set. If this were 1 the exclusion is
	// not firing and the test above is passing for the wrong reason.
	assert.Len(t, first, candidates,
		"an undeclared source must be excluded from the lazy stop, so every passing collection stays in the witness")
	assert.Equal(t, candidates, firstExamined,
		"an undeclared source must be examined exhaustively")
}

// ---------------------------------------------------------------------------
// THE PAYOFF, and the guard against a degenerate fix. Excluding every source
// would satisfy the test above by making the feature do nothing. A source that
// DOES declare canonical order must still get the O(1) stop — and must still
// produce the same witness no matter what order rows reached it in.
// ---------------------------------------------------------------------------
func TestLazyWitness_CanonicalSourceKeepsTheStopAndPinsTheWitness(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	const candidates = 6
	var first []string

	for k, perm := range lazyPermutations(candidates, 8) {
		pol, src := lazyOrderCorpus(t, verifier, keyID, perm)
		pass, results, err := pol.Verify(context.Background(),
			WithVerifiedSource(newLazyOrderedSource(src)),
			WithSubjectDigests([]string{"sha256:seed"}),
			WithSearchDepth(1),
			WithLazyStepSatisfaction(true),
		)
		require.NoError(t, err)
		require.True(t, pass)

		witness := lazyPassedRefs(results)["build"]
		require.Len(t, witness, 1,
			"a canonically-ordered source must still get the stop — the whole point of the feature. Witness: %v", witness)
		assert.Equal(t, []string{"cand-00"}, witness,
			"the witness must be the FIRST collection in canonical order, whatever order the rows arrived in")
		assert.Equal(t, 1, src.yielded,
			"permutation %d examined %d candidates; a canonical source must still stop at the first pass", k, src.yielded)

		if k == 0 {
			first = witness
			continue
		}
		assert.Equal(t, first, witness, "permutation %d moved the witness", k)
	}
}

// The engine must read the declaration, not assume it. A source that declares
// FALSE is as excluded as one that declares nothing.
func TestLazyWitness_SourceDeclaringFalseIsExcluded(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	pol, src := lazyOrderCorpus(t, verifier, keyID, []int{0, 1, 2, 3})
	_, results, err := pol.Verify(context.Background(),
		WithVerifiedSource(lazyDeclineOrderSource{src}),
		WithSubjectDigests([]string{"sha256:seed"}),
		WithSearchDepth(1),
		WithLazyStepSatisfaction(true),
	)
	require.NoError(t, err)
	assert.Len(t, lazyPassedRefs(results)["build"], 4,
		"a source whose CanonicalStreamOrder() returns FALSE must be excluded from the lazy stop, exactly like one that does not implement it at all")
}

// lazyDeclineOrderSource implements the interface but declines the contract.
type lazyDeclineOrderSource struct{ *lazySource }

func (s lazyDeclineOrderSource) CanonicalStreamOrder() bool { return false }

var _ source.CanonicalOrderSourcer = lazyDeclineOrderSource{}

// ---------------------------------------------------------------------------
// THE ENGINE'S OWN HALF OF DETERMINISM.
//
// A canonical source is necessary but NOT sufficient. The engine decides which
// digests it searches and in what order, and it built that order out of two Go
// MAPS — topologicalSort's queue seed and Collection.BackRefs(). Go randomizes
// map iteration, so the search frontier, and therefore the witness, moved from
// run to run even with a perfectly ordered source.
//
// Found by TestLazyWitness_PropertyDifferentialAgainstFrozenOracle at seed=866
// (three steps, candidates behind two different back-referenced nodes) — not by
// any hand-written case. Both maps are now sorted before use.
// ---------------------------------------------------------------------------

func TestPolicy_TopologicalSortIsDeterministic(t *testing.T) {
	_, keyID := earlyExitVerifier(t)

	// Independent steps: AttestationsFrom constrains nothing, so ONLY a
	// deliberate tie-break can make the order stable.
	independent := lazyPolicy(keyID,
		lazyStep("zulu", keyID), lazyStep("alpha", keyID),
		lazyStep("mike", keyID), lazyStep("bravo", keyID))

	first, err := independent.topologicalSort()
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "bravo", "mike", "zulu"}, first,
		"independent steps must sort by name — the only tie-break that is a function of the policy rather than of the run")

	// Go re-seeds map iteration per range, so repeating in-process is a real
	// test of the property, not a formality.
	for i := 0; i < 50; i++ {
		got, serr := independent.topologicalSort()
		require.NoError(t, serr)
		require.Equal(t, first, got, "iteration %d produced a different step order", i)
	}

	// Dependencies still win over the name tie-break.
	dependent := lazyStep("alpha", keyID)
	dependent.AttestationsFrom = []string{"zulu"}
	constrained := lazyPolicy(keyID, dependent, lazyStep("zulu", keyID))
	for i := 0; i < 20; i++ {
		got, serr := constrained.topologicalSort()
		require.NoError(t, serr)
		require.Equal(t, []string{"zulu", "alpha"}, got,
			"iteration %d: AttestationsFrom must still order the graph; the name sort is only a TIE-break", i)
	}
}

// The witness must be identical across repeated verifies of one corpus — the
// end-to-end form of the property above, on the shape that exposed it.
func TestLazyWitness_IsStableAcrossRepeatedVerifies(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	build := func() (Policy, *lazySource) {
		return lazyPolicy(keyID, lazyStep("alpha", keyID), lazyStep("bravo", keyID), lazyStep("charlie", keyID)),
			newLazySource(map[string][]source.CollectionVerificationResult{
				"sha256:seed": {
					lazyPlain(verifier, "alpha-1", "alpha", "sha256:hopA"),
					lazyPlain(verifier, "alpha-2", "alpha", "sha256:hopB"),
					lazyPlain(verifier, "bravo-1", "bravo", "sha256:hopB"),
				},
				// charlie is reachable from EITHER hop, so which one enters the
				// search set first decides which charlie becomes the witness.
				"sha256:hopA": {lazyPlain(verifier, "charlie-viaA", "charlie", "")},
				"sha256:hopB": {lazyPlain(verifier, "charlie-viaB", "charlie", "")},
			})
	}

	var first map[string][]string
	for i := 0; i < 30; i++ {
		pol, src := build()
		pass, results, err := pol.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:seed"}),
			WithSearchDepth(3),
			WithLazyStepSatisfaction(true),
		)
		require.NoError(t, err)
		require.True(t, pass)

		got := lazyPassedRefs(results)
		if i == 0 {
			first = got
			continue
		}
		require.Equal(t, first, got,
			"run %d produced a different witness. Passed is signed, so a witness that depends on Go's map seed means "+
				"the same corpus signs differently on every verify.", i)
	}
	t.Logf("stable witness across 30 verifies: %v", first)
}
