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
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lazyLazyMode is the LIVE engine with the minimum-witness option ON. It lives
// here — not in lazy_shapes_test.go — so the shape table and the invariance
// suite stay compilable against the PRE-change tree.
func lazyLazyMode() lazyMode {
	return lazyMode{name: "lazy", run: func(p Policy, ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, error) {
		return p.Verify(ctx, append(opts, WithLazyStepSatisfaction(true))...)
	}}
}

// ---------------------------------------------------------------------------
// THE DIFFERENTIAL. Lazy verdicts must equal the FROZEN ORACLE's, shape by
// shape. Witnesses may shrink; verdicts may not move.
// ---------------------------------------------------------------------------
func TestLazyWitnessIsVerdictInvariantAgainstFrozenOracle(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, shape := range lazyShapes() {
		t.Run(shape.name, func(t *testing.T) {
			oracle := runLazyShape(t, shape, lazyOracleMode(), verifier, keyID)
			lazy := runLazyShape(t, shape, lazyLazyMode(), verifier, keyID)

			require.Equal(t, shape.wantVerdict, oracle.pass,
				"%s: the shape no longer produces the verdict it was written to produce; it has stopped testing its case", shape.desc)

			assert.Equal(t, oracle.pass, lazy.pass,
				"VERDICT DIVERGENCE — %s: lazy=%v oracle=%v. Phase 1's whole contract is that verdicts change for no one.",
				shape.desc, lazy.pass, oracle.pass)

			// A PASS must be witnessed by evidence the oracle also passed:
			// lazy's Passed is a SUBSET of eager's, never a superset. A
			// superset means an exclusion leaked and the fan-out guard (or
			// another non-monotone component) manufactured evidence.
			for step, refs := range lazy.passed {
				for _, ref := range refs {
					assert.Contains(t, oracle.passed[step], ref,
						"%s: step %q passed collection %q under lazy that the frozen oracle did NOT pass — lazy must only ever SHRINK the witness", shape.desc, step, ref)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EXAMINATION BOUNDS — the exhaustiveness pin and the inertness pin, plus the
// honest accounting of what the coarse valve COSTS.
//
// Three contracts, declared per shape (lazyExamExpectation):
//
//	Fewer       the stop fired and the verify settled: strictly cheaper.
//	Inert       identical candidates, one for one — an exclusion fired, or the
//	            step never passed so there was nothing to stop at. This is the
//	            EXHAUSTIVENESS PIN judge's readiness classifier depends on.
//	CompleteSet the valve demanded the truncated step back: the examined SET is
//	            identical (nothing goes unexamined) but the COUNT is higher,
//	            because the truncated pass is paid for twice.
//
// The CompleteSet row is the one that must not be quietly dropped: on these
// shapes Phase 1 is a net COST, not a saving. Stating it here is what keeps
// the benchmark's "806 → 1" from being read as a universal claim.
// ---------------------------------------------------------------------------
func TestLazyWitness_ExaminationBounds(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, shape := range lazyShapes() {
		t.Run(shape.name, func(t *testing.T) {
			oracle := runLazyShape(t, shape, lazyOracleMode(), verifier, keyID)
			lazy := runLazyShape(t, shape, lazyLazyMode(), verifier, keyID)

			switch shape.wantExam {
			case lazyExamInert:
				assert.Equal(t, oracle.yielded, lazy.yielded,
					"%s: lazy must be INERT on this shape — it examined %d candidates against eager's %d. An exclusion is not firing, or a failing step stopped early.",
					shape.desc, lazy.yielded, oracle.yielded)
				assert.Equal(t, oracle.examined, lazy.examined,
					"%s: lazy must examine the identical candidate SET on this shape", shape.desc)
				// The §6.1 consumer contract, stated directly: judge's
				// readiness classifier (errors.As over every Rejected[].Reason)
				// and findTrustMismatch both need a FAILING step's rejection
				// list to be complete. On an inert shape it must be byte-equal.
				assert.Equal(t, oracle.rejected, lazy.rejected,
					"%s: the REJECTED set must be identical — judge's readiness classifier discriminates PENDING from terminal FAILED by walking exactly these reasons", shape.desc)

			case lazyExamFewer:
				assert.Less(t, lazy.yielded, oracle.yielded,
					"%s: the stop must have fired and settled — lazy examined %d candidates against eager's %d",
					shape.desc, lazy.yielded, oracle.yielded)

			case lazyExamCompleteSet:
				assert.Equal(t, oracle.examined, lazy.examined,
					"%s: the demand valve must have pulled every candidate back; the examined SET must be identical to eager's — a missing candidate is unexamined evidence", shape.desc)
				// The COUNT may land either side of eager's and that is not a
				// defect: the truncated pass is paid twice, but it also skipped
				// candidates the eager pass fetched, and a later exhaustive
				// pass over a wider digest set covers them once. What must
				// hold is the bound — a runaway means the valve is re-marking
				// in a loop rather than monotonically.
				assert.LessOrEqual(t, lazy.yielded, 3*oracle.yielded,
					"%s: the valve's re-scan overhead must stay bounded (lazy %d vs eager %d)", shape.desc, lazy.yielded, oracle.yielded)
				t.Logf("valve re-scan accounting for %q: lazy examined %d candidates, eager %d (identical SET of %d)", shape.name, lazy.yielded, oracle.yielded, len(lazy.examined))
			}
		})
	}
}

// The valve terminates. Marks are monotone and each firing buys exactly one
// extra depth iteration, so the loop can add at most one iteration per step —
// never spin. Measured directly as the search count the source observed.
func TestLazyWitness_ValveTerminatesWithinItsBudget(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, shape := range lazyShapes() {
		t.Run(shape.name, func(t *testing.T) {
			pol, src := shape.build(t, verifier, keyID)
			opts := []VerifyOption{
				WithVerifiedSource(src),
				WithSubjectDigests(append([]string(nil), shape.seeds...)),
				WithSearchDepth(shape.depth),
				WithLazyStepSatisfaction(true),
			}
			if shape.fanout > 0 {
				opts = append(opts, WithMaxSubjectFanout(shape.fanout))
			}
			_, _, err := pol.Verify(context.Background(), opts...)
			require.NoError(t, err)

			// searchDepth + len(steps) iterations, each searching every step,
			// is the analytic bound on the extended loop.
			maxSearches := (shape.depth + len(pol.Steps)) * len(pol.Steps)
			assert.LessOrEqual(t, src.searches, maxSearches,
				"%s: the demand valve extended the depth loop past its bound (%d searches, bound %d) — marks must be monotone and each firing must buy exactly one iteration",
				shape.desc, src.searches, maxSearches)
		})
	}
}

// ---------------------------------------------------------------------------
// THE VALVE, named directly. Not "the verdict came out right" — the valve must
// be OBSERVABLY responsible: with the valve's marking disabled the depth-1
// upstream shape FAILs. This test states the mechanism so the mutation ledger
// has a single named RED to point at.
// ---------------------------------------------------------------------------
func TestLazyWitness_DemandValveRescuesTheUpstreamEdge(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, name := range []string{"artifactsfrom-second-upstream-candidate", "artifactsfrom-upstream-at-depth1"} {
		shape := lazyShapeByName(t, name)
		t.Run(name, func(t *testing.T) {
			lazy := runLazyShape(t, shape, lazyLazyMode(), verifier, keyID)
			require.True(t, lazy.pass,
				"%s: the demand valve must un-truncate the upstream step and reach PASS; a naive stop-at-first-pass FAILs here", shape.desc)

			// Non-vacuity: the witness that carried the PASS must be the
			// upstream collection the FIRST stop skipped. If "source-right"
			// were the first candidate the shape would pass without the valve.
			assert.Contains(t, lazy.passed["source"], "source-right",
				"%s: the rescuing upstream collection must be in the final witness", shape.desc)
		})
	}
}

// ---------------------------------------------------------------------------
// NON-VACUITY for the AttestationsFrom shape. This one nearly shipped broken:
// the first draft's Rego module was written in v1 syntax, OPA's parser rejected
// it, and EVERY collection was denied with a parse error. The shape "failed"
// under both arms, the exemption looked load-bearing, and it proved nothing.
//
// So the shape must prove three things, not one:
//
//  1. the eager FAIL is the DENY RULE firing, not a module that will not parse;
//  2. removing the tainted upstream candidate makes the same policy PASS — the
//     deny is CONDITIONAL on the upstream set;
//  3. therefore truncating the upstream WOULD manufacture a pass, which is
//     exactly what the exemption exists to prevent.
//
// ---------------------------------------------------------------------------
func TestLazyWitness_AttestationsFromShapeDeniesForTheRightReason(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	shape := lazyShapeByName(t, "attestationsfrom-manufacture-a-pass")

	oracle := runLazyShape(t, shape, lazyOracleMode(), verifier, keyID)
	require.False(t, oracle.pass, "the shape must FAIL eagerly")

	joined := strings.Join(oracle.rejected["check"], "\n")
	assert.Contains(t, joined, "tainted upstream attestation present",
		"the eager FAIL must be the deny RULE firing. Rejections were: %s", joined)
	assert.NotContains(t, joined, "rego_parse_error",
		"the Rego module must PARSE. A parse error denies every collection unconditionally, "+
			"which makes this whole shape vacuous — the exemption would look load-bearing while proving nothing.")

	// Condition 2: the same policy WITHOUT the tainted upstream candidate must
	// PASS. That is precisely the state a truncated upstream leaves the engine
	// in, so this is the manufactured pass, demonstrated directly.
	clean := lazyCollection(verifier, "source-clean", "source", "",
		&lazyAttestor{AttName: "source-clean", AttType: lazyAttType})
	check := Step{
		Name:             "check",
		Functionaries:    []Functionary{{PublicKeyID: keyID}},
		AttestationsFrom: []string{"source"},
		Attestations: []Attestation{{
			Type:         lazyAttType,
			RegoPolicies: []RegoPolicy{{Module: lazyDenyOnTaintedUpstream, Name: "lazy-deny-tainted.rego"}},
		}},
	}
	pass, _, err := lazyPolicy(keyID, lazyStep("source", keyID), check).Verify(context.Background(),
		WithVerifiedSource(newLazySource(map[string][]source.CollectionVerificationResult{
			"sha256:seed": {clean, lazyCollection(verifier, "check-one", "check", "", &lazyAttestor{AttName: "check-one", AttType: lazyAttType})},
		})),
		WithSubjectDigests([]string{"sha256:seed"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)
	assert.True(t, pass,
		"with the tainted upstream candidate absent the policy must PASS — that is the state a truncated "+
			"upstream produces, and it is why lazy must be INERT on AttestationsFrom shapes")
}

// The upstream candidate order is load-bearing for shapes 4 and 5: if the
// SATISFYING collection were yielded first, a naive stop would pass and the
// valve would never be exercised. Pin the order.
func TestLazyWitness_ValveShapesYieldTheWrongUpstreamFirst(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, name := range []string{"artifactsfrom-second-upstream-candidate", "artifactsfrom-upstream-at-depth1"} {
		shape := lazyShapeByName(t, name)
		t.Run(name, func(t *testing.T) {
			_, src := shape.build(t, verifier, keyID)
			first := ""
			for _, cvr := range src.byDigest["sha256:seed"] {
				if cvr.Collection.Name == "source" {
					first = cvr.Reference
					break
				}
			}
			require.Equal(t, "source-wrong", first,
				"the first upstream candidate must be the NON-satisfying one, or the valve is never exercised and the test passes vacuously")
		})
	}
}

func lazyShapeByName(t testing.TB, name string) lazyShape {
	t.Helper()
	for _, s := range lazyShapes() {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no lazy shape named %q", name)
	return lazyShape{}
}

// ---------------------------------------------------------------------------
// FIXTURE TRAP (design doc §10.7). passedCollectionKey hashes only the
// Statement plus the verified key IDs. Fixtures built the obvious way — same
// statement for every candidate — COLLAPSE inside mergePassedCollections, and
// every count this suite measures silently becomes 1.
//
// This asserts non-collapse WITH A COUNT, and asserts the opposite for the
// deliberately-identical control so the check cannot itself be vacuous.
// ---------------------------------------------------------------------------
func TestLazyFixtures_DistinctStatementsDoNotCollapse(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	const n = 7
	corpus := make([]source.CollectionVerificationResult, 0, n)
	for i := 0; i < n; i++ {
		corpus = append(corpus, lazyPlain(verifier, fmt.Sprintf("distinct-%02d", i), "build", ""))
	}
	src := newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": corpus})

	pass, results, err := lazyPolicy(keyID, lazyStep("build", keyID)).Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:seed"}),
		WithSearchDepth(1),
	)
	require.NoError(t, err)
	require.True(t, pass)
	assert.Len(t, results["build"].Passed, n,
		"the %d fixture collections must survive mergePassedCollections as %d distinct entries; if this is 1 the fixtures share a Statement and every candidate count in this file is meaningless", n, n)

	// CONTROL — the trap has to be real, or the assertion above measures
	// nothing. mergePassedCollections is the mechanism (it is what runs across
	// depth iterations), so the control drives it directly: collections that
	// share a Statement and a signer set MUST collapse to one entry.
	same := make([]PassedCollection, 0, n)
	for i := 0; i < n; i++ {
		cvr := lazyPlain(verifier, fmt.Sprintf("same-%02d", i), "build", "")
		cvr.Statement = lazyStatement("shared")
		cvr.ValidFunctionaries = cvr.Verifiers
		same = append(same, PassedCollection{Collection: cvr})
	}
	assert.Len(t, mergePassedCollections(nil, same), 1,
		"collections sharing a Statement and signer set must collapse to ONE entry in mergePassedCollections — that is the trap (design doc §10.7) the distinct-statement fixtures exist to avoid")

	distinct := make([]PassedCollection, 0, n)
	for i := 0; i < n; i++ {
		cvr := lazyPlain(verifier, fmt.Sprintf("distinct-%02d", i), "build", "")
		cvr.ValidFunctionaries = cvr.Verifiers
		distinct = append(distinct, PassedCollection{Collection: cvr})
	}
	assert.Len(t, mergePassedCollections(nil, distinct), n,
		"the distinct-statement fixtures must survive the same merge as %d entries", n)
}

// ---------------------------------------------------------------------------
// NON-VACUITY: the fixtures must select the arm they claim. Every measurement
// above assumes the STREAMED arm — the arm every production verify takes. A
// fixture that silently took the batch arm could never stop early, and the
// whole file would pass by doing nothing.
// ---------------------------------------------------------------------------
func TestLazyFixtures_SelectTheStreamedArm(t *testing.T) {
	base := newLazySource(nil)

	_, streams := source.VerifiedSourcer(base).(source.StreamingVerifiedSourcer)
	assert.True(t, streams,
		"lazySource must satisfy StreamingVerifiedSourcer; if it does not, every run in this file takes the batch arm and can never reach the lazy stop")

	_, batchStreams := source.VerifiedSourcer(lazyBatchSource{inner: base}).(source.StreamingVerifiedSourcer)
	assert.False(t, batchStreams,
		"lazyBatchSource must NOT satisfy StreamingVerifiedSourcer, or the batch control below is not a control")
}

// The BATCH arm must be untouched by the option: Search materializes every
// candidate before the engine sees one, so there is nothing to stop, and the
// option must not pretend otherwise.
func TestLazyWitness_BatchArmIsUnaffected(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	run := func(lazy bool) (bool, int) {
		corpus := make([]source.CollectionVerificationResult, 0, 6)
		for i := 0; i < 6; i++ {
			corpus = append(corpus, lazyPlain(verifier, fmt.Sprintf("build-%02d", i), "build", ""))
		}
		src := newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": corpus})
		opts := []VerifyOption{
			WithVerifiedSource(lazyBatchSource{inner: src}),
			WithSubjectDigests([]string{"sha256:seed"}),
			WithSearchDepth(1),
		}
		if lazy {
			opts = append(opts, WithLazyStepSatisfaction(true))
		}
		pass, _, err := lazyPolicy(keyID, lazyStep("build", keyID)).Verify(context.Background(), opts...)
		require.NoError(t, err)
		return pass, src.yielded
	}

	offPass, offCount := run(false)
	onPass, onCount := run(true)
	assert.Equal(t, offPass, onPass, "the batch arm's verdict must not depend on the lazy option")
	assert.Equal(t, offCount, onCount,
		"the batch arm must examine the same candidate count with the option on: Search has already materialized everything, so a 'saving' here would be a lie")
}

// ---------------------------------------------------------------------------
// The option must be OFF by default — the whole point of landing dark.
// ---------------------------------------------------------------------------
func TestLazyWitness_DefaultsOff(t *testing.T) {
	vo := &verifyOptions{}
	assert.False(t, vo.lazyStepSatisfaction, "the zero verifyOptions must have the lazy stop disabled")

	WithLazyStepSatisfaction(true)(vo)
	assert.True(t, vo.lazyStepSatisfaction, "WithLazyStepSatisfaction(true) must enable it")

	WithLazyStepSatisfaction(false)(vo)
	assert.False(t, vo.lazyStepSatisfaction, "WithLazyStepSatisfaction(false) must disable it again")
}

// lazyWitnessEligible is an AND over three independent preconditions: the
// option, the policy SHAPE, and the source's ORDERING declaration. This walks
// the whole truth table so no one of them can quietly stop being consulted —
// the failure mode being that lazy silently applies where an exclusion should
// have stopped it.
func TestLazyWitness_EligibilityRequiresOptionShapeAndCanonicalSource(t *testing.T) {
	_, keyID := earlyExitVerifier(t)

	withAF := lazyStep("check", keyID)
	withAF.AttestationsFrom = []string{"source"}

	monotone := lazyPolicy(keyID, lazyStep("build", keyID))
	nonMonotone := lazyPolicy(keyID, lazyStep("source", keyID), withAF)

	canonical := newLazySource(nil)                              // declares true
	undeclared := lazyUnorderedSource{inner: newLazySource(nil)} // declares nothing

	cases := []struct {
		name   string
		pol    Policy
		option bool
		src    source.VerifiedSourcer
		want   bool
	}{
		{"all-three-satisfied", monotone, true, canonical, true},
		{"option-off", monotone, false, canonical, false},
		{"shape-has-attestationsfrom", nonMonotone, true, canonical, false},
		{"source-does-not-declare-order", monotone, true, undeclared, false},
		{"nothing-satisfied", nonMonotone, false, undeclared, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vo := &verifyOptions{lazyStepSatisfaction: tc.option, verifiedSource: tc.src}
			assert.Equal(t, tc.want, tc.pol.lazyWitnessEligible(vo))
		})
	}

	// The SHAPE half must stay exactly searchExpansionIsMonotone — the same
	// whole-policy AttestationsFrom test the depth loop's early break uses. If
	// the two ever diverge, one of them is wrong.
	for _, pol := range []Policy{monotone, nonMonotone} {
		vo := &verifyOptions{lazyStepSatisfaction: true, verifiedSource: canonical}
		assert.Equal(t, pol.searchExpansionIsMonotone(), pol.lazyWitnessEligible(vo),
			"with the option on and a canonical source, eligibility must reduce to searchExpansionIsMonotone")
	}
}
