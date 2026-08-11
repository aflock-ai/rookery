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
	"sort"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// THE PROPERTY TEST — randomly generated reachability graphs, differentialled
// against the frozen eager oracle.
//
// WHY IT EXISTS. The hand-written shape table missed a whole CLASS of bug: the
// first demand valve bought its repair pass by extending the depth BUDGET,
// which silently extended REACHABILITY, and a policy whose satisfying evidence
// sat one hop past searchDepth flipped eager's FAIL into a lazy PASS. Every
// hand-written shape passed. A reviewer found it by construction.
//
// Enumerated shapes test the cases the author thought of. This tests the ones
// they did not: the interaction of search depth, graph shape, truncation point,
// candidate ordering and step count, all at once. It is the instrument for this
// class of defect, and the fix is not believed until it survives it.
//
// Every case is seeded deterministically and the seed is printed on failure, so
// a red is reproducible with `-run .../seed<N>`.
// ---------------------------------------------------------------------------

// lazyPropertyCases is the number of generated graphs. Each runs two full
// verifies (frozen oracle + live lazy), so this is the knob to turn if the
// package's runtime budget changes.
const lazyPropertyCases = 1500

// lazyGraph is one generated policy + corpus + search depth.
type lazyGraph struct {
	seed        int64
	policy      Policy
	source      *lazySource
	searchDepth int
	fanout      int
	// describe renders the graph for a failure message. A property-test red is
	// useless if the reader cannot see the counterexample.
	describe string
}

// generateLazyGraph builds one random case.
//
// The digest graph is a DAG over node indices (edges only point FORWARD, i<j),
// so reachability depth is well defined and the generator cannot accidentally
// build a cycle whose behaviour differs between arms for uninteresting reasons.
// Node 0 is the seed.
func generateLazyGraph(seed int64, v cryptoutil.Verifier, keyID string) lazyGraph {
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test input, not crypto

	nNodes := 1 + rng.Intn(6) // 1..6
	nSteps := 1 + rng.Intn(3) // 1..3
	depth := 1 + rng.Intn(5)  // 1..5 — the range the reachability bug lived in
	useFanout := rng.Intn(8) == 0
	useAttestationsFrom := rng.Intn(6) == 0
	useArtifactsFrom := nSteps >= 2 && rng.Intn(3) == 0

	node := func(i int) string { return fmt.Sprintf("sha256:n%02d", i) }
	stepName := func(i int) string { return fmt.Sprintf("step%d", i) }

	byDigest := map[string][]source.CollectionVerificationResult{}
	desc := fmt.Sprintf("seed=%d nodes=%d steps=%d depth=%d fanout=%v attFrom=%v artFrom=%v\n",
		seed, nNodes, nSteps, depth, useFanout, useAttestationsFrom, useArtifactsFrom)

	// A small digest pool for the artifactsFrom chain, so producer/consumer
	// digests sometimes match and sometimes do not.
	chainPool := []cryptoutil.DigestSet{lazyDigest("c0"), lazyDigest("c1"), lazyDigest("c2")}

	for s := 0; s < nSteps; s++ {
		// At least one candidate per step. A step with ZERO candidates fails
		// unconditionally and drags the whole verify to FAIL, which starves the
		// generator of the PASSING verifies the lazy stop actually fires on —
		// measured, it was two thirds of the budget. The non-vacuity floors at
		// the bottom of the test are what keep this bias honest.
		nCandidates := 1 + rng.Intn(4) // 1..4
		for c := 0; c < nCandidates; c++ {
			// Bias placement toward the seed node so evidence is reachable
			// often enough to produce passes, while still generating the
			// multi-hop graphs the reachability bug lived in.
			at := 0
			if rng.Intn(2) == 0 {
				at = rng.Intn(nNodes)
			}
			ref := fmt.Sprintf("s%d-c%d@n%02d", s, c, at)

			// Back-reference: forward edges only, so the graph stays a DAG.
			backRef := ""
			if at+1 < nNodes && rng.Intn(2) == 0 {
				to := at + 1 + rng.Intn(nNodes-at-1)
				backRef = node(to)
				desc += fmt.Sprintf("  %s: backref n%02d->n%02d\n", ref, at, to)
			}

			var cvr source.CollectionVerificationResult
			switch kind := rng.Intn(10); {
			case kind < 6: // passing
				attestors := []attestation.Attestor{&lazyAttestor{AttName: ref, AttType: lazyAttType}}
				if useArtifactsFrom {
					// Producers carry a product, consumers a material; both are
					// drawn from the same small pool so the edge is satisfiable
					// only sometimes.
					pick := chainPool[rng.Intn(len(chainPool))]
					if s == 0 {
						attestors = append(attestors, &lazyAttestor{
							AttName: ref + "-prod", AttType: lazyChainAttType, inline: true,
							products: map[string]attestation.Product{"app.bin": {Digest: pick}},
						})
					} else {
						attestors = append(attestors, &lazyAttestor{
							AttName: ref + "-mat", AttType: lazyChainAttType, inline: true,
							materials: map[string]cryptoutil.DigestSet{"app.bin": pick},
						})
					}
				}
				cvr = lazyCollection(v, ref, stepName(s), backRef, attestors...)
				desc += fmt.Sprintf("  %s: PASS at n%02d\n", ref, at)
			case kind < 8: // signature failure — dropped at functionary triage
				cvr = lazyBadSig(ref, stepName(s))
				desc += fmt.Sprintf("  %s: BADSIG at n%02d\n", ref, at)
			default: // authorized but GATE-rejected (wrong attestation type)
				cvr = lazyCollection(v, ref, stepName(s), backRef,
					&lazyAttestor{AttName: ref, AttType: lazyTaintedAttType})
				desc += fmt.Sprintf("  %s: GATEREJECT at n%02d\n", ref, at)
			}
			byDigest[node(at)] = append(byDigest[node(at)], cvr)
		}
	}

	steps := make([]Step, 0, nSteps)
	for s := 0; s < nSteps; s++ {
		st := lazyStep(stepName(s), keyID)
		if useArtifactsFrom && s > 0 {
			st.ArtifactsFrom = []string{stepName(0)}
			desc += fmt.Sprintf("  %s.artifactsFrom = [%s]\n", stepName(s), stepName(0))
		}
		if useAttestationsFrom && s > 0 {
			st.AttestationsFrom = []string{stepName(0)}
			desc += fmt.Sprintf("  %s.attestationsFrom = [%s]\n", stepName(s), stepName(0))
		}
		steps = append(steps, st)
	}

	fanout := 0
	if useFanout {
		fanout = 1 + rng.Intn(3)
	}

	return lazyGraph{
		seed:        seed,
		policy:      lazyPolicy(keyID, steps...),
		source:      newLazySource(byDigest),
		searchDepth: depth,
		fanout:      fanout,
		describe:    desc,
	}
}

// runLazyGraph verifies one generated graph on one arm, with a FRESH source.
func runLazyGraph(t testing.TB, g lazyGraph, mode lazyMode, v cryptoutil.Verifier, keyID string) lazyRun {
	t.Helper()
	// Rebuild from the seed: the source carries counters and the engine mutates
	// vo.subjectDigests, so the two arms must never share one.
	fresh := generateLazyGraph(g.seed, v, keyID)

	opts := []VerifyOption{
		WithVerifiedSource(fresh.source),
		WithSubjectDigests([]string{"sha256:n00"}),
		WithSearchDepth(fresh.searchDepth),
	}
	if fresh.fanout > 0 {
		opts = append(opts, WithMaxSubjectFanout(fresh.fanout))
	}

	pass, results, err := mode.run(fresh.policy, context.Background(), opts...)
	require.NoError(t, err, "seed=%d: %s arm errored\n%s", g.seed, mode.name, g.describe)

	return lazyRun{
		pass:     pass,
		passed:   lazyPassedRefs(results),
		rejected: rejectionReasons(results),
		yielded:  fresh.source.yielded,
		examined: fresh.source.examined(),
	}
}

func TestLazyWitness_PropertyDifferentialAgainstFrozenOracle(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	var (
		passCases   int
		failCases   int
		savedCases  int // lazy examined FEWER candidates — the win
		replayCases int // lazy examined MORE — the valve's re-scan
		deepCases   int // the graph actually reached logical depth >= 2
		divergences int
	)

	for i := 0; i < lazyPropertyCases; i++ {
		seed := int64(i) + 1
		g := generateLazyGraph(seed, verifier, keyID)

		oracle := runLazyGraph(t, g, lazyOracleMode(), verifier, keyID)
		lazy := runLazyGraph(t, g, lazyLazyMode(), verifier, keyID)

		if oracle.pass {
			passCases++
		} else {
			failCases++
		}
		switch {
		case lazy.yielded < oracle.yielded:
			savedCases++
		case lazy.yielded > oracle.yielded:
			replayCases++
		}
		if g.searchDepth >= 2 && len(oracle.examined) > 0 {
			deepCases++
		}

		// THE PROPERTY. Verdicts change for no one.
		if oracle.pass != lazy.pass {
			divergences++
			t.Errorf("VERDICT DIVERGENCE at seed=%d: lazy=%v oracle=%v\n%s\n"+
				"lazy examined %v\noracle examined %v",
				seed, lazy.pass, oracle.pass, g.describe, lazy.examined, oracle.examined)
			continue
		}

		// The witness may only ever SHRINK. A passed collection lazy has and
		// the oracle does not means evidence was admitted that a full search
		// would have demoted — the manufacture-a-pass direction, and the exact
		// shape the fan-out exclusion exists to prevent.
		for step, refs := range lazy.passed {
			for _, ref := range refs {
				if !containsString(oracle.passed[step], ref) {
					t.Errorf("WITNESS GREW at seed=%d: step %q passed %q under lazy but not under the oracle\n%s",
						seed, step, ref, g.describe)
				}
			}
		}

		// Candidates lazy examined must be a SUBSET of the ones eager examined:
		// lazy searches a depth-bounded view of a digest set that is itself a
		// subset of eager's at the same logical depth. Anything outside that is
		// evidence eager could not reach — which is how the reachability bug
		// presented.
		for _, ref := range lazy.examined {
			if !containsString(oracle.examined, ref) {
				t.Errorf("REACHED TOO FAR at seed=%d: lazy examined %q, which eager never reached\n%s",
					seed, ref, g.describe)
			}
		}

		// On a FAILING verify the demand valve must have pulled everything
		// back: a FAIL is only allowed after exhaustion.
		if !oracle.pass && !equalStrings(oracle.examined, lazy.examined) {
			t.Errorf("INCOMPLETE FAIL at seed=%d: the verify FAILED but lazy did not examine every candidate\n%s\nlazy %v\noracle %v",
				seed, g.describe, lazy.examined, oracle.examined)
		}

		// WITNESS IDENTITY. The witness is what gets SIGNED, so it must be a
		// pure function of (corpus, policy) — never of the order rows happened
		// to arrive in. Re-run the same case through a source that sorts its
		// query results (the EntSource shape) and confirm the witness is
		// unchanged. Under a canonical source the two runs consume the same
		// sequence, so any difference means the witness depends on something
		// outside the corpus.
		again := runLazyGraph(t, g, lazyLazyMode(), verifier, keyID)
		if !equalWitness(lazy.passed, again.passed) {
			t.Errorf("WITNESS NOT REPRODUCIBLE at seed=%d: two runs over the identical corpus produced different witnesses\n%s\nrun1 %v\nrun2 %v",
				seed, g.describe, lazy.passed, again.passed)
		}

		if t.Failed() {
			// One counterexample is enough to act on, and a property test that
			// prints 1500 of them is unreadable.
			t.Fatalf("stopping at the first counterexample (seed=%d)", seed)
		}
	}

	t.Logf("property differential: %d cases — %d PASS / %d FAIL, %d cheaper under lazy, %d paid a valve re-scan, %d at depth>=2, %d divergences",
		lazyPropertyCases, passCases, failCases, savedCases, replayCases, deepCases, divergences)

	// ---------------------------------------------------------------------
	// NON-VACUITY. A property test that generates 1500 trivially-identical
	// runs proves nothing. Each of these floors names a behaviour the suite
	// must actually be exercising; if the generator drifts and stops producing
	// one of them, this reddens rather than silently going quiet.
	// ---------------------------------------------------------------------
	require.Greater(t, passCases, lazyPropertyCases/20,
		"too few PASSING verifies generated — the lazy stop only fires on a passing step, so a corpus of failures exercises almost nothing")
	require.Greater(t, failCases, lazyPropertyCases/20,
		"too few FAILING verifies generated — the exhaustiveness and demand-valve paths would go untested")
	require.Greater(t, savedCases, lazyPropertyCases/50,
		"the lazy stop never actually saved work in %d cases — it is not firing, and every verdict comparison is between two identical runs", lazyPropertyCases)
	require.Greater(t, replayCases, 0,
		"the demand valve never re-scanned in %d cases — the repair path is untested by this generator", lazyPropertyCases)
	require.Greater(t, deepCases, lazyPropertyCases/10,
		"too few multi-hop graphs — the reachability bug this test exists for lives at depth >= 2")
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// equalWitness compares two per-step passed-collection sets — the content the
// signed policy-verification attestation is built from.
func equalWitness(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for step, refs := range a {
		other, ok := b[step]
		if !ok || !equalStrings(refs, other) {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
