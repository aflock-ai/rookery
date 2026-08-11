// Copyright 2026 The Rookery Contributors
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

// These tests pin FAIL-path step_results CORRECTNESS and DETERMINISM in
// verifyArtifacts (docs/design/minimum-witness-verification.md §10.6).
//
// The defect: verifyArtifacts iterated p.Steps — a Go map — and CLEARS
// result.Passed for a step whose artifacts fail. A step whose artifactsFrom
// edge points at a cleared step therefore sees a different upstream depending
// on which one the map handed back first: with the upstream intact it compares
// digests and can be ACCEPTED; after the clear it fails with "has no passed
// collections". Same corpus, same verdict, different step_results on every run.
//
// Sorting the steps made that REPRODUCIBLE BUT NOT CORRECT, and the two are
// separate properties that need separate mechanisms:
//
//   - CORRECTNESS comes from the fixed point, converging at COLLECTION
//     granularity. Two distinct fail-opens live here:
//
//     (i) STEP ordering. Any single ordered pass is fail-OPEN whenever a
//     consumer is visited before its provider: it is accepted against the
//     provider's still-populated evidence and stays accepted after the
//     provider is rejected. A name sort only fixes WHICH policies lose —
//     every one whose lexical order opposes its artifactsFrom order.
//     Pinned by ...ConsumerRejectedWhenProviderRejectedLater.
//
//     (ii) SIBLING collections. A step-level accept keeps the whole Passed
//     set when just one collection is valid, so the INVALID siblings ride
//     along where a downstream artifactsFrom can match them — and since the
//     step's classification never changes, the fixed point never revisits
//     it. Each collection is therefore judged individually and pruned on its
//     own. Pinned by ...InvalidSiblingCollectionCannotSatisfyDownstream.
//
//     Over-rejection controls: ...ValidChainSurvivesFixedPoint (both lexical
//     orderings) and ...ValidSiblingStillSatisfiesDownstream.
//
//   - DETERMINISM still comes from the name sort, and is still needed: the
//     fixed point converges the passed/rejected CLASSIFICATION regardless of
//     order, but NOT the recorded REASON. A step that fails on its own digest
//     mismatch when evaluated early records "mismatched digests"; evaluated
//     after its provider is cleared it records "has no passed collections".
//     Pinned by TestVerifyArtifacts_FailPathStepResultsAreDeterministic, whose
//     corpus is built specifically to keep those reasons divergent (see
//     failShapedCorpus) — with a converging corpus that test would pass under a
//     map range and be vacuous.
//
// VERDICTS are unaffected by either mechanism: the AND over Analyze() forces
// FAIL either way, and the fixed point only ever clears MORE steps (a corpus
// with nothing to clear settles on the first pass and breaks). The
// verdict-invariance test below pins that, so neither change can be mistaken
// for a semantic one.
//
// Ordering choice — name sort, NOT topologicalSort. topologicalSort orders by
// AttestationsFrom only, while the edge that matters here is artifactsFrom,
// which is not cycle-checked at all (§10.5) — a mutually-referencing
// artifactsFrom pair is legal today and has no topological order. A total order
// over step names is always defined, and the fixed point's iteration cap —
// bounded by the TOTAL number of passed collections, since that is what shrinks
// — means even a cyclic artifactsFrom pair terminates.
//
// (Until #7958 there was a second reason: topologicalSort seeded its queue from
// a map range and was itself unstable. That is fixed, and
// TestVerifyArtifacts_TopologicalSortIsStable now pins the fix. The reason
// above is the one that survives, so the name sort stays.)
//
// SCOPE BOUNDARY — read before extending these tests. They pin verifyArtifacts
// and are driven by calling it DIRECTLY, so on their own they say nothing about
// end-to-end Verify().
//
// There WAS a residual there: verifySteps orders steps with topologicalSort, so
// while that was unstable the order in which two depth-0 steps contributed
// back-references varied, varying vo.subjectDigests and therefore the ORDER of
// a later-depth step's Passed slice. Measured with a three-step probe (two
// depth-0 steps each contributing one back-reference, a third reachable from
// both): 400 runs produced 2 distinct step_results renders (307/93 and 330/70
// across trials).
//
// #7958 closed it. The same probe re-measured on this tree: 400 runs, 1 render.
// The residual is documented rather than deleted because it explains why these
// tests were scoped the way they were — and because the probe is the cheapest
// way to re-check the property if verifySteps' ordering is ever touched again.

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// failShapedCorpus builds a three-step interdependent chain whose artifact
// verification FAILS, shaped so that the REASON recorded against step "c"
// depends on whether step "b" was processed before it:
//
//	a --(products lib.so@good)-->
//	b   artifactsFrom [a], consumes lib.so@BAD    => MISMATCH, b is cleared
//	    also products app.bin@good2
//	c   artifactsFrom [b], consumes app.bin@BAD3  => MISMATCH against b's product
//
// c fails either way, but for a DIFFERENT recorded reason:
//   - c evaluated while b still has evidence -> "mismatched digests for app.bin"
//   - c evaluated after b was cleared        -> "step \"b\" ... has no passed collections"
//
// The mismatch on c is deliberate and load-bearing. Once verifyArtifacts
// propagates to a fixed point, the passed/rejected CLASSIFICATION converges
// regardless of order — so a corpus where c's material MATCHES b's product can
// no longer distinguish an ordered pass from a map range, and the determinism
// test built on it would be vacuous. Divergent reasons are what remains
// order-sensitive at the fixed point, and therefore what the name sort still
// has to pin. (The converging classification case is owned by
// TestVerifyArtifacts_ConsumerRejectedWhenProviderRejectedLater.)
//
// The verdict is FAIL either way: b is always cleared, so the AND over
// Analyze() is always false.
func failShapedCorpus(verifier cryptoutil.Verifier, keyID string) (Policy, map[string]StepResult) {
	good := digest("aa")
	bad := digest("bb")
	good2 := digest("cc")
	bad3 := digest("dd")

	collA := artifactCollection(verifier, "a-1", "a",
		[]attestation.Attestor{productAttestor(map[string]cryptoutil.DigestSet{"lib.so": good})}, "")

	collB := artifactCollection(verifier, "b-1", "b", []attestation.Attestor{
		materialAttestor(map[string]cryptoutil.DigestSet{"lib.so": bad}),
		productAttestor(map[string]cryptoutil.DigestSet{"app.bin": good2}),
	}, "")

	collC := artifactCollection(verifier, "c-1", "c",
		[]attestation.Attestor{materialAttestor(map[string]cryptoutil.DigestSet{"app.bin": bad3})}, "")

	step := func(name string, artifactsFrom ...string) Step {
		return Step{
			Name:          name,
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			ArtifactsFrom: artifactsFrom,
		}
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			"a": step("a"),
			"b": step("b", "a"),
			"c": step("c", "b"),
		},
	}

	byStep := map[string]StepResult{
		"a": {Step: "a", Passed: []PassedCollection{{Collection: collA}}},
		"b": {Step: "b", Passed: []PassedCollection{{Collection: collB}}},
		"c": {Step: "c", Passed: []PassedCollection{{Collection: collC}}},
	}

	return p, byStep
}

// chainCorpus builds a three-step artifactsFrom chain root -> mid -> leaf with
// caller-chosen NAMES, so a test can put the consumer either before or after its
// provider in lexical (sort) order:
//
//	root            products lib.so@good
//	mid   artifactsFrom [root], consumes lib.so@<midConsumes>; products app.bin@good2
//	leaf  artifactsFrom [mid],  consumes app.bin@good2  (always MATCHES mid's product)
//
// midConsumes==good makes the whole chain valid; midConsumes==bad makes mid fail
// its own artifact check, which must then invalidate leaf transitively.
func chainCorpus(verifier cryptoutil.Verifier, keyID, root, mid, leaf string, midValid bool) (Policy, map[string]StepResult) {
	good := digest("aa")
	bad := digest("bb")
	good2 := digest("cc")

	midConsumes := bad
	if midValid {
		midConsumes = good
	}

	collRoot := artifactCollection(verifier, root+"-1", root,
		[]attestation.Attestor{productAttestor(map[string]cryptoutil.DigestSet{"lib.so": good})}, "")

	collMid := artifactCollection(verifier, mid+"-1", mid, []attestation.Attestor{
		materialAttestor(map[string]cryptoutil.DigestSet{"lib.so": midConsumes}),
		productAttestor(map[string]cryptoutil.DigestSet{"app.bin": good2}),
	}, "")

	collLeaf := artifactCollection(verifier, leaf+"-1", leaf,
		[]attestation.Attestor{materialAttestor(map[string]cryptoutil.DigestSet{"app.bin": good2})}, "")

	step := func(name string, artifactsFrom ...string) Step {
		return Step{
			Name:          name,
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			ArtifactsFrom: artifactsFrom,
		}
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			root: step(root),
			mid:  step(mid, root),
			leaf: step(leaf, mid),
		},
	}

	byStep := map[string]StepResult{
		root: {Step: root, Passed: []PassedCollection{{Collection: collRoot}}},
		mid:  {Step: mid, Passed: []PassedCollection{{Collection: collMid}}},
		leaf: {Step: leaf, Passed: []PassedCollection{{Collection: collLeaf}}},
	}

	return p, byStep
}

// ---------------------------------------------------------------------------
// Codex CHANGES_REQUESTED regression: reproducible is NOT the same as correct.
// ---------------------------------------------------------------------------

// A single ordered pass is fail-OPEN whenever a consumer sorts before its
// artifactsFrom provider. The consumer validates against the provider's
// still-populated Passed set, is accepted, and then STAYS accepted after the
// provider is subsequently rejected — leaving recorded evidence whose
// provenance chain is broken.
//
// Names are chosen so lexical order OPPOSES dependency order:
//
//	dependency: m (root) -> z (mid, FAILS) -> a (leaf)
//	lexical:    a, m, z          => the leaf "a" is evaluated FIRST
//
// The single-pass implementation leaves a with passed=1 even though its only
// provider z ends rejected. The fixed point must re-evaluate a and reject it.
//
// RED against a single ordered pass; MUTATION: drop the fixed-point loop and
// this reddens.
func TestVerifyArtifacts_ConsumerRejectedWhenProviderRejectedLater(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	p, byStep := chainCorpus(verifier, keyID, "m", "z", "a", false)

	// Premise: lexical order really does put the consumer before its provider.
	require.Less(t, "a", "z", "test premise: the consumer must sort before its provider")

	out, err := p.verifyArtifacts(context.Background(), &verifyOptions{}, byStep)
	require.NoError(t, err)

	// The provider fails its own artifact check.
	require.Empty(t, out["z"].Passed, "z consumes a mismatching digest and must be rejected")

	// The consumer must NOT survive on evidence from a rejected provider.
	require.Empty(t, out["a"].Passed,
		"FAIL-OPEN: a was accepted against z's collections and kept its passed set after z was rejected; artifact validity must propagate to a fixed point, not a single ordered pass")
	require.NotEmpty(t, out["a"].Rejected, "a must carry a rejection explaining why its chain is broken")
	require.Contains(t, out["a"].Rejected[len(out["a"].Rejected)-1].Reason.Error(), "z",
		"a's rejection must name the provider that invalidated it")

	// The untouched root is unaffected — the fixed point must not over-reject.
	require.Len(t, out["m"].Passed, 1, "m has no artifactsFrom edge and must survive")
}

// Inverse control: a fully VALID chain must survive the fixed point in BOTH
// orderings. Guards against the fixed point over-rejecting — the obvious way to
// make the regression above pass is to reject too much.
func TestVerifyArtifacts_ValidChainSurvivesFixedPoint(t *testing.T) {
	for _, tc := range []struct {
		name            string
		root, mid, leaf string
	}{
		// lexical AGREES with dependency order (a -> b -> c)
		{"lexical agrees with dependency order", "a", "b", "c"},
		// lexical OPPOSES dependency order (m -> z -> a): same shape as the
		// regression, but every artifact digest lines up.
		{"lexical opposes dependency order", "m", "z", "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, keyID := earlyExitVerifier(t)
			p, byStep := chainCorpus(verifier, keyID, tc.root, tc.mid, tc.leaf, true)

			out, err := p.verifyArtifacts(context.Background(), &verifyOptions{}, byStep)
			require.NoError(t, err)

			for _, name := range []string{tc.root, tc.mid, tc.leaf} {
				require.Len(t, out[name].Passed, 1, "step %q is valid end-to-end and must keep its passed collection", name)
				require.Empty(t, out[name].Rejected, "step %q must not be rejected", name)
			}
			require.True(t, allAnalyzed(out), "a fully valid chain must remain a PASS")
		})
	}
}

// ---------------------------------------------------------------------------
// Codex CHANGES_REQUESTED round 2: the fixed point must converge at COLLECTION
// granularity, not step granularity.
// ---------------------------------------------------------------------------

// multiCollectionCorpus builds the shape where a step keeps BOTH a valid and an
// invalid collection:
//
//	r          products base.o@good
//	s          artifactsFrom [r], TWO collections:
//	             s-valid   consumes base.o@good (MATCHES r)  -> products out1.bin@d1
//	             s-invalid consumes base.o@BAD  (mismatch)   -> products out2.bin@d2
//	d          artifactsFrom [s], consumes <consumesPath>@<consumesDigest>
//
// consumesPath selects WHICH sibling d can be satisfied by. compareArtifacts
// matches by PATH, so a path matching neither sibling fails on no-overlap and
// exercises nothing — the path, not just the digest, is what makes this corpus
// load-bearing.
//
// Lexical order is d, r, s — the consumer sorts first, so the fixed point has to
// do real work.
//
// With a step-level accept, s survives on s-valid while s-invalid STAYS in
// Passed, and d can then satisfy itself against s-invalid's products — evidence
// hanging off a collection whose own artifact chain is broken.
func multiCollectionCorpus(verifier cryptoutil.Verifier, keyID, consumesPath string, consumesDigest cryptoutil.DigestSet) (Policy, map[string]StepResult, map[string]PassedCollection) {
	good := digest("aa")
	bad := digest("bb")
	d1 := digest("cc")
	d2 := digest("dd")

	collR := artifactCollection(verifier, "r-1", "r",
		[]attestation.Attestor{productAttestor(map[string]cryptoutil.DigestSet{"base.o": good})}, "")

	// Valid sibling: its material matches r's product.
	collSValid := artifactCollection(verifier, "s-valid", "s", []attestation.Attestor{
		materialAttestor(map[string]cryptoutil.DigestSet{"base.o": good}),
		productAttestor(map[string]cryptoutil.DigestSet{"out1.bin": d1}),
	}, "")

	// Invalid sibling: its material does NOT match r's product.
	collSInvalid := artifactCollection(verifier, "s-invalid", "s", []attestation.Attestor{
		materialAttestor(map[string]cryptoutil.DigestSet{"base.o": bad}),
		productAttestor(map[string]cryptoutil.DigestSet{"out2.bin": d2}),
	}, "")

	collD := artifactCollection(verifier, "d-1", "d",
		[]attestation.Attestor{materialAttestor(map[string]cryptoutil.DigestSet{consumesPath: consumesDigest})}, "")

	step := func(name string, artifactsFrom ...string) Step {
		return Step{Name: name, Functionaries: []Functionary{{PublicKeyID: keyID}}, ArtifactsFrom: artifactsFrom}
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			"r": step("r"),
			"s": step("s", "r"),
			"d": step("d", "s"),
		},
	}

	pcValid := PassedCollection{Collection: collSValid}
	pcInvalid := PassedCollection{Collection: collSInvalid}

	byStep := map[string]StepResult{
		"r": {Step: "r", Passed: []PassedCollection{{Collection: collR}}},
		"s": {Step: "s", Passed: []PassedCollection{pcValid, pcInvalid}},
		"d": {Step: "d", Passed: []PassedCollection{{Collection: collD}}},
	}

	return p, byStep, map[string]PassedCollection{"valid": pcValid, "invalid": pcInvalid}
}

// (surviving collection references come from passedRefs in
// streamed_depth_guard_test.go — same package, same semantics.)

// A step-level accept is fail-OPEN for the step's SIBLINGS: one valid collection
// keeps the step accepted, and the invalid collections ride along inside Passed
// where downstream artifactsFrom can match against them. The step-level
// classification never changes, so the fixed point never revisits it.
//
// Here d's material corresponds ONLY to the INVALID sibling's product, so d can
// only be satisfied by evidence that should have been removed.
//
// RED against a step-level accept; MUTATION E restores that short-circuit and
// this reddens.
func TestVerifyArtifacts_InvalidSiblingCollectionCannotSatisfyDownstream(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	// out2.bin@dd is the INVALID sibling's product — the only thing d can match.
	p, byStep, sibs := multiCollectionCorpus(verifier, keyID, "out2.bin", digest("dd"))

	// §10.7 guard: two collections in ONE step is exactly the shape that
	// collapses if the fixtures share a statement.
	require.NotEqual(t, passedCollectionKeyOf(sibs["valid"]), passedCollectionKeyOf(sibs["invalid"]),
		"the two sibling fixtures must carry distinct merge identities or this corpus is not what it claims")

	out, err := p.verifyArtifacts(context.Background(), &verifyOptions{}, byStep)
	require.NoError(t, err)

	// THE finding, asserted first so its message is the one a reader sees: d can
	// only ever match the invalid sibling, so it must not survive.
	require.Empty(t, out["d"].Passed,
		"FAIL-OPEN: d satisfied its artifactsFrom against s's INVALID collection; individually-invalid collections must be removed from Passed even when a sibling keeps the step accepted")
	require.NotEmpty(t, out["d"].Rejected, "d must carry a rejection")

	// The mechanism behind it: the step itself is legitimately still accepted —
	// via its VALID sibling — but the invalid sibling is gone from Passed.
	require.Equal(t, []string{"s-valid"}, passedRefs(out["s"]),
		"s must keep the valid sibling and DROP the invalid one; keeping both is what let d pass")
	require.NotEmpty(t, out["s"].Rejected, "the dropped sibling must be recorded as rejected, not silently discarded")
}

// Inverse control: a downstream step matching the VALID sibling still passes, so
// the per-collection pruning is not simply rejecting everything.
func TestVerifyArtifacts_ValidSiblingStillSatisfiesDownstream(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	// out1.bin@cc is the VALID sibling's product.
	p, byStep, _ := multiCollectionCorpus(verifier, keyID, "out1.bin", digest("cc"))

	out, err := p.verifyArtifacts(context.Background(), &verifyOptions{}, byStep)
	require.NoError(t, err)

	require.Equal(t, []string{"s-valid"}, passedRefs(out["s"]), "s keeps exactly its valid sibling")
	require.Len(t, out["d"].Passed, 1,
		"d matches the VALID sibling's product and must still pass — the pruning must not over-reject")
	require.Empty(t, out["d"].Rejected, "d must not be rejected when its chain is sound")
	require.Len(t, out["r"].Passed, 1, "r is untouched")
}

// renderStepResults produces a canonical text form of the step results.
//
// It sorts the step names ITSELF, so the rendering can never leak map iteration
// order: any difference two renders show is a genuine CONTENT difference, not a
// formatting artifact. It includes each rejection's Reason text, which the JSON
// form does not (error has no MarshalJSON), making it strictly more sensitive
// than the marshal check that accompanies it.
func renderStepResults(byStep map[string]StepResult) string {
	names := make([]string, 0, len(byStep))
	for n := range byStep {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		r := byStep[n]
		fmt.Fprintf(&b, "step=%s passed=%d rejected=%d\n", n, len(r.Passed), len(r.Rejected))
		for _, pc := range r.Passed {
			fmt.Fprintf(&b, "  passed=%s\n", pc.Collection.Reference)
		}
		for _, rc := range r.Rejected {
			reason := "<nil>"
			if rc.Reason != nil {
				reason = rc.Reason.Error()
			}
			fmt.Fprintf(&b, "  rejected=%s\n", strings.ReplaceAll(reason, "\n", "\\n"))
		}
	}
	return b.String()
}

// The determinism test. verifyArtifacts must produce byte-identical
// step_results for a byte-identical FAIL corpus, run after run.
//
// Go randomizes map iteration order per range, so a fresh corpus per iteration
// samples the order space directly. 200 samples is well past what is needed:
// against a map range this test caught the divergence at run 3, 6 and 11 across
// trials, so the per-run detection probability is order 0.1-0.5 and the chance
// of 199 consecutive misses is negligible.
//
// What it pins is the recorded REASON, not the classification — the fixed point
// converges the latter on its own. See failShapedCorpus for why its step "c"
// carries a MISMATCHING material rather than a matching one; with a matching
// one this test passes under a map range and proves nothing.
//
// MUTATION: replace the fixed point's inner `for _, stepName := range stepNames`
// with `for _, step := range p.Steps` and this test reddens.
func TestVerifyArtifacts_FailPathStepResultsAreDeterministic(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	const runs = 200
	var firstRender, firstJSON string

	for i := 0; i < runs; i++ {
		p, byStep := failShapedCorpus(verifier, keyID)

		out, err := p.verifyArtifacts(context.Background(), &verifyOptions{}, byStep)
		require.NoError(t, err)

		render := renderStepResults(out)
		marshaled, err := json.Marshal(out)
		require.NoError(t, err)

		if i == 0 {
			firstRender, firstJSON = render, string(marshaled)
			continue
		}

		require.Equal(t, firstRender, render,
			"run %d produced different step_results content than run 0: verifyArtifacts must not depend on map iteration order", i)
		require.Equal(t, firstJSON, string(marshaled),
			"run %d marshaled step_results differ from run 0", i)
	}
}

// Verdict invariance on the SAME corpus. This is the guard that the ordering
// fix changed only WHICH of the previously-possible contents is produced, never
// the answer: the corpus must be FAIL before and after, for the same reason
// (step "b"'s artifact mismatch clears it, so the AND over Analyze() is false).
func TestVerifyArtifacts_FailCorpusVerdictIsInvariant(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	const runs = 200
	for i := 0; i < runs; i++ {
		p, byStep := failShapedCorpus(verifier, keyID)

		out, err := p.verifyArtifacts(context.Background(), &verifyOptions{}, byStep)
		require.NoError(t, err)

		// The engine's verdict is the AND over Analyze(). "b" is always cleared,
		// so the verdict is always FAIL — regardless of processing order.
		require.False(t, out["b"].Analyze(), "run %d: b's artifact mismatch must always clear it", i)
		require.False(t, allAnalyzed(out), "run %d: the corpus verdict must be FAIL", i)

		// "a" has no artifactsFrom edge, so nothing can ever clear it.
		require.True(t, out["a"].Analyze(), "run %d: a has no artifactsFrom edge and must always survive", i)
	}
}

func allAnalyzed(byStep map[string]StepResult) bool {
	for _, r := range byStep {
		if !r.Analyze() {
			return false
		}
	}
	return true
}

// topologicalSort is STABLE — #7958 gave it deterministic name tie-breaks
// (sort.Strings on both the initial queue and each newly-ready set).
//
// History, because this test was the inverse of itself one commit ago. It
// originally pinned topologicalSort's INSTABILITY: its queue was seeded from a
// map range, so equal-in-degree steps came out in random order, and that was
// one of the two reasons verifyArtifacts uses a name sort instead. #7958 fixed
// it, which correctly turned the old assertion red.
//
// The name sort in verifyArtifacts REMAINS, for the reason that never depended
// on topologicalSort being unstable:
//
//   - topologicalSort orders by AttestationsFrom. The edge that governs
//     artifact verification is artifactsFrom, which is NOT cycle-checked (the
//     DFS walks only AttestationsFrom), so a mutually-referencing artifactsFrom
//     pair is legal today and has no topological order at all.
//   - and the property being protected is REASON determinism, which needs only
//     SOME fixed total order, not a dependency-correct one. See
//     failShapedCorpus: step c records "mismatched digests for app.bin" when
//     evaluated while b still holds evidence, and "step \"b\" ... has no passed
//     collections" once b is cleared. The fixed point converges the
//     classification either way, but not that text. A name sort over the step
//     map keys is total, always defined, and cheaper than a topological walk.
//
// So this now guards the opposite direction: if topologicalSort ever regresses
// to an unstable order, that is a regression in #7958, not a reason to revisit
// the name sort.
func TestVerifyArtifacts_TopologicalSortIsStable(t *testing.T) {
	p := Policy{Steps: map[string]Step{
		"a": {Name: "a"},
		"b": {Name: "b"},
		"c": {Name: "c"},
		"d": {Name: "d"},
		"e": {Name: "e"},
	}}

	first, err := p.topologicalSort()
	require.NoError(t, err)

	for i := 1; i < 200; i++ {
		order, err := p.topologicalSort()
		require.NoError(t, err)
		require.Equal(t, first, order,
			"run %d: topologicalSort must return one stable order for equal-in-degree steps (#7958)", i)
	}

	// The tie-break is by name, so five independent roots come back sorted.
	require.Equal(t, []string{"a", "b", "c", "d", "e"}, first,
		"equal-in-degree steps must be ordered by name")
}

// Guards the fixtures themselves: the three collections must carry distinct
// merge identities (§10.7). They live in different steps here so
// mergePassedCollections never compares them, but a future edit that moves two
// into one step would otherwise silently lose one.
func TestVerifyArtifacts_FailCorpusFixturesAreDistinct(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	_, byStep := failShapedCorpus(verifier, keyID)

	keys := map[string]string{}
	for name, r := range byStep {
		require.Len(t, r.Passed, 1)
		k := passedCollectionKeyOf(r.Passed[0])
		if other, dup := keys[k]; dup {
			t.Fatalf("steps %q and %q share a merge key (§10.7 fixture collapse)", other, name)
		}
		keys[k] = name
	}

	refs := make([]string, 0, len(byStep))
	for _, r := range byStep {
		refs = append(refs, r.Passed[0].Collection.Reference)
	}
	sort.Strings(refs)
	require.Equal(t, []string{"a-1", "b-1", "c-1"}, refs)
}
