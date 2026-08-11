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
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MINIMUM-WITNESS PHASE 1 — frozen-oracle differential.
//
// The contract: verdicts change for NO ONE. The oracle is
// frozenEagerVerifyWithExternals (lazy_frozen_oracle_test.go), a verbatim copy
// of the pre-lazy engine that contains none of the code Phase 1 adds, so no
// Phase 1 mutation can move oracle and subject together.
//
// Every shape below is run in THREE modes:
//
//	oracle : the frozen pre-change engine                (the truth)
//	eager  : the live engine, flag OFF                   (anti-rot: must equal oracle)
//	lazy   : the live engine, flag ON                    (the differential: must equal oracle)
//
// "eager == oracle" is the invariance suite. It is what makes the frozen copy
// trustworthy, and it is the test that reddens if someone edits eager
// verification without re-freezing.
// ---------------------------------------------------------------------------

// lazyShape is one generated policy shape + corpus.
type lazyShape struct {
	name string
	// desc says what the shape is FOR, so a failure reads as a finding.
	desc string
	// build returns a fresh policy and a fresh source for one run. Fresh per
	// run is mandatory: the source carries counters and the digest set is
	// mutated by the depth loop.
	build func(t testing.TB, verifier cryptoutil.Verifier, keyID string) (Policy, *lazySource)
	// seeds are the policy's seed subject digests.
	seeds []string
	// depth is the search depth for this shape.
	depth int
	// fanout, when > 0, activates the subject fan-out guard for this shape.
	fanout int
	// wantExam is the shape's candidate-examination contract. See
	// lazyExamExpectation.
	wantExam lazyExamExpectation
	// wantVerdict is the pre-change verdict, written as a literal so a shape
	// that silently stops exercising its case is caught rather than
	// self-confirming.
	wantVerdict bool
}

// lazyExamExpectation is what a shape claims about how many candidates the
// lazy arm examines relative to the eager arm. Stating it per shape — rather
// than asserting a blanket "lazy is cheaper" — is what makes the COST of the
// coarse Phase 1 valve visible instead of hidden.
type lazyExamExpectation int

const (
	// lazyExamFewer: the stop fired and the verify settled on the witness, so
	// lazy examined STRICTLY fewer candidates. This is the win.
	lazyExamFewer lazyExamExpectation = iota

	// lazyExamInert: lazy examined the IDENTICAL candidates, one for one.
	// Either an exclusion suppressed the stop (AttestationsFrom shape, fan-out
	// guard active) or the step never passed, so there was nothing to stop at
	// (the exhaustiveness pin).
	lazyExamInert

	// lazyExamCompleteSet: the verify did not settle on the first witness, so
	// the demand valve pulled the truncated step back and re-ran it
	// exhaustively. The examined SET must equal eager's exactly — nothing goes
	// unexamined — but the COUNT is higher, because the truncated pass is paid
	// for twice. That re-scan is the honest price of a valve with no
	// per-candidate cursor (cursors are Phase 2).
	lazyExamCompleteSet
)

// lazyShapes is the generated cross-product this suite runs. Each entry names
// the specific soundness question it exists to answer.
func lazyShapes() []lazyShape {
	return []lazyShape{
		// -------------------------------------------------------------------
		// 1. The headline case: one step, many candidates, the first passes.
		//    This is the 806-verify shape in miniature.
		// -------------------------------------------------------------------
		{
			name:        "single-step-satisfied",
			wantExam:    lazyExamFewer,
			desc:        "one step with 12 passing candidates: the witness is the first one; the other 11 are pure waste",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: true,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				corpus := make([]source.CollectionVerificationResult, 0, 12)
				for i := 0; i < 12; i++ {
					corpus = append(corpus, lazyPlain(v, fmt.Sprintf("build-%02d", i), "build", ""))
				}
				return lazyPolicy(keyID, lazyStep("build", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": corpus})
			},
		},

		// -------------------------------------------------------------------
		// 2. THE EXHAUSTIVENESS PIN. A failing step has no passing collection
		//    to stop at, so the lazy arm must examine every candidate — which
		//    is what keeps judge's readiness classifier and findTrustMismatch
		//    sound (design doc §6.1).
		// -------------------------------------------------------------------
		{
			name:        "single-step-fail-exhaustive",
			wantExam:    lazyExamInert,
			desc:        "one step, 12 candidates, ALL bad-signature: FAIL must examine every candidate, exactly as eager",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: false,
			build: func(_ testing.TB, _ cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				corpus := make([]source.CollectionVerificationResult, 0, 12)
				for i := 0; i < 12; i++ {
					corpus = append(corpus, lazyBadSig(fmt.Sprintf("build-bad-%02d", i), "build"))
				}
				return lazyPolicy(keyID, lazyStep("build", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": corpus})
			},
		},

		// -------------------------------------------------------------------
		// 2b. THE EXHAUSTIVENESS PIN, GATE-rejection flavour — and the one that
		//     actually reaches the stop.
		//
		//     Shape 2's candidates are dropped by triageOne, which returns from
		//     the stream callback BEFORE the lazy stop is evaluated at all. So
		//     shape 2 can never detect a stop that fires on the wrong verdict:
		//     measured, a mutation replacing `lazyStop && verdict == passed`
		//     with bare `lazyStop` left the entire suite GREEN.
		//
		//     Here the candidates are functionary-AUTHORIZED — correct signer,
		//     correct step name — and the STEP GATE rejects them for carrying
		//     the wrong attestation type, so every one reaches the stop's guard
		//     carrying streamedGateRejected.
		//
		//     This is what pins "stop ONLY at a gate PASS". Without it a stop
		//     that truncated on any authorized candidate would pass the suite,
		//     and a FAILING step would silently stop reporting the rejection
		//     reasons judge's readiness classifier uses to discriminate PENDING
		//     from terminal FAILED (design doc §6.1).
		// -------------------------------------------------------------------
		{
			name:        "single-step-gate-rejected-exhaustive",
			wantExam:    lazyExamInert,
			desc:        "one step, 12 AUTHORIZED candidates the GATE rejects: every one must still be examined and reported",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: false,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				corpus := make([]source.CollectionVerificationResult, 0, 12)
				for i := 0; i < 12; i++ {
					ref := fmt.Sprintf("build-wrongtype-%02d", i)
					corpus = append(corpus, lazyCollection(v, ref, "build", "",
						&lazyAttestor{AttName: ref, AttType: lazyTaintedAttType}))
				}
				return lazyPolicy(keyID, lazyStep("build", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": corpus})
			},
		},

		// -------------------------------------------------------------------
		// 3. Mixed corpus in a FAILING verify: the passing step's stream is
		//    truncated, then DEMANDED back by the valve because the verify
		//    never settles. The examined SET must still be complete.
		// -------------------------------------------------------------------
		{
			name:        "multi-step-partially-satisfied",
			wantExam:    lazyExamCompleteSet,
			desc:        "build satisfiable, audit has no evidence: the dominant prod cost shape; the truncated step must be demanded back",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: false,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				corpus := []source.CollectionVerificationResult{
					lazyPlain(v, "build-a", "build", "sha256:hop"),
					lazyPlain(v, "build-b", "build", ""),
					lazyBadSig("build-bad", "build"),
				}
				return lazyPolicy(keyID, lazyStep("build", keyID), lazyStep("audit", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{
						"sha256:seed": corpus,
						"sha256:hop":  {lazyPlain(v, "build-hop", "build", "")},
					})
			},
		},

		// -------------------------------------------------------------------
		// 4. THE VALVE CASE, depth 0. build.artifactsFrom=[source]; source's
		//    FIRST passing candidate does not satisfy the edge, its second
		//    does. A naive stop-at-first-pass FAILs here; the valve must
		//    un-truncate and reach PASS.
		// -------------------------------------------------------------------
		{
			name:        "artifactsfrom-second-upstream-candidate",
			wantExam:    lazyExamCompleteSet,
			desc:        "the upstream witness the lazy stop picks fails the artifactsFrom edge; the valve must re-run the step exhaustively",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: true,
			build:       lazyArtifactsFromDepth0,
		},

		// -------------------------------------------------------------------
		// 5. THE VALVE CASE, depth 1 — the design doc's execution-proven
		//    counterexample (§3): the satisfying upstream collection is only
		//    reachable through a BackRef discovered at depth 1.
		// -------------------------------------------------------------------
		{
			name:        "artifactsfrom-upstream-at-depth1",
			wantExam:    lazyExamCompleteSet,
			desc:        "the satisfying upstream collection is discovered only at depth 1 (doc §3 counterexample): must still PASS",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: true,
			build:       lazyArtifactsFromDepth1,
		},

		// -------------------------------------------------------------------
		// 6. THE ATTESTATIONSFROM EXEMPTION. A downstream Rego rule DENIES on
		//    the presence of a second upstream attestation type. Truncating
		//    the upstream removes the denial input — a MANUFACTURED PASS, the
		//    one direction the valve structurally cannot catch (it fires on
		//    artifact-edge failure, and here nothing fails). Lazy must be
		//    inert on this shape.
		// -------------------------------------------------------------------
		{
			name:        "attestationsfrom-manufacture-a-pass",
			wantExam:    lazyExamInert,
			desc:        "downstream rego denies when a second upstream attestation type is present; truncating upstream would MANUFACTURE a pass",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: false,
			build:       lazyAttestationsFromShape,
		},

		// -------------------------------------------------------------------
		// 7. THE FAN-OUT EXCLUSION. With the guard active, a truncated stream
		//    sees a smaller hub set and would admit a candidate the full
		//    stream demotes — again FAIL→PASS. Lazy must be inert.
		// -------------------------------------------------------------------
		{
			name:     "fanout-guard-active",
			wantExam: lazyExamInert,
			desc:     "the subject fan-out guard demotes every candidate at full stream; a truncated stream would not see the hub",
			// A REAL 64-hex digest: the guard only counts subject digests that
			// pass cryptoutil.IsMatchableSubjectDigest, so the symbolic
			// "sha256:seed" the other shapes use would be invisible to it and
			// this shape would prove nothing.
			seeds:       []string{lazyHubDigest},
			depth:       1,
			fanout:      3,
			wantVerdict: false,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				// 5 candidates all connected to the closure only through the
				// single seed digest. With maxFanout=3 the seed digest is a hub
				// (5 > 3) and every candidate is hub-only ⇒ FAIL. A stream
				// truncated at candidate 1 would see a count of 1, no hub, and
				// admit it: PASS. That is the divergence the exclusion prevents.
				corpus := make([]source.CollectionVerificationResult, 0, 5)
				for i := 0; i < 5; i++ {
					cvr := lazyPlain(v, fmt.Sprintf("hub-%02d", i), "build", "")
					cvr.Statement.Subject = append(cvr.Statement.Subject,
						intoto.Subject{Name: "hub", Digest: map[string]string{"sha256": lazyHubDigest}})
					corpus = append(corpus, cvr)
				}
				return lazyPolicy(keyID, lazyStep("build", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{lazyHubDigest: corpus})
			},
		},

		// -------------------------------------------------------------------
		// 8. BackRef frontier. The passing step's LATER candidates carry the
		//    back-reference the downstream step's evidence hangs off. A stop
		//    that never harvested them would strand the second step — the
		//    valve has to catch this too, and it is NOT an artifact edge.
		// -------------------------------------------------------------------
		{
			name:        "backref-frontier-behind-second-candidate",
			wantExam:    lazyExamCompleteSet,
			desc:        "the digest that reaches step two is a BackRef of the FIRST step's second candidate; truncation would strand it",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: true,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				return lazyPolicy(keyID, lazyStep("build", keyID), lazyStep("audit", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{
						"sha256:seed": {
							// First candidate passes but carries NO frontier.
							lazyPlain(v, "build-first", "build", ""),
							// Second candidate carries the only route to audit.
							lazyPlain(v, "build-second", "build", "sha256:hop"),
						},
						"sha256:hop": {lazyPlain(v, "audit-only", "audit", "")},
					})
			},
		},

		// -------------------------------------------------------------------
		// 9. Depth-1 satisfaction with a truncatable step at depth 0, at the
		//    TIGHTEST search depth the option allows. searchDepth=2 is where a
		//    valve that only extends the budget "when already at the end"
		//    silently loses an iteration and FAILs.
		// -------------------------------------------------------------------
		{
			name:        "backref-frontier-at-search-depth-2",
			wantExam:    lazyExamCompleteSet,
			desc:        "same frontier shape at searchDepth=2: the valve must buy back the iteration the truncated pass under-used",
			seeds:       []string{"sha256:seed"},
			depth:       2,
			wantVerdict: true,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				return lazyPolicy(keyID, lazyStep("build", keyID), lazyStep("audit", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{
						"sha256:seed": {
							lazyPlain(v, "build-first", "build", ""),
							lazyPlain(v, "build-second", "build", "sha256:hop"),
						},
						"sha256:hop": {lazyPlain(v, "audit-only", "audit", "")},
					})
			},
		},

		// -------------------------------------------------------------------
		// 9b. THE REACHABILITY REGRESSION (Codex, #7958 review). The first
		//     implementation of the valve bought its extra pass by bumping the
		//     depth BUDGET, which is wrong: the budget counts ITERATIONS, but
		//     what bounds a verify is REACHABILITY. An extra iteration runs
		//     against the whole accumulated subject graph, so it searches
		//     digests one hop FURTHER OUT than searchDepth allows.
		//
		//     The chain, at searchDepth=2:
		//
		//	    seed --build-first--> A --build-hop--> B --> audit-deep
		//	         (logical 0)     (1)              (2)     (3)
		//
		//     EAGER searches logical levels 0 and 1 — i.e. {seed} then
		//     {seed, A}. It discovers B but never searches it, so audit-deep
		//     is unreachable and the verify FAILS.
		//
		//     The budget-bumping valve granted a third iteration that searched
		//     {seed, A, B}, found audit-deep, and PASSED. A clean FAIL→PASS
		//     divergence — the manufacture-a-pass direction.
		//
		//     The fix tracks per-digest LOGICAL depth: a repair pass REPLAYS
		//     its logical level instead of advancing it, so it re-searches the
		//     frontier the truncated pass under-used without reaching past
		//     eager's horizon.
		// -------------------------------------------------------------------
		{
			name:        "valve-must-not-extend-reachability",
			wantExam:    lazyExamCompleteSet,
			desc:        "a valve repair pass must REPLAY its logical depth, not advance it: reaching one hop past searchDepth turns eager's FAIL into a PASS",
			seeds:       []string{"sha256:seed"},
			depth:       2,
			wantVerdict: false,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				return lazyPolicy(keyID, lazyStep("build", keyID), lazyStep("audit", keyID)),
					newLazySource(map[string][]source.CollectionVerificationResult{
						// The truncated pass stops here and harvests A. The
						// second candidate is what it SKIPS, so the shape is a
						// real truncation and not just a one-candidate stream.
						"sha256:seed": {
							lazyPlain(v, "build-first", "build", "sha256:A"),
							lazyPlain(v, "build-extra", "build", ""),
						},
						// Logical depth 1: reachable, and searched by eager.
						"sha256:A": {lazyPlain(v, "build-hop", "build", "sha256:B")},
						// Logical depth 2: DISCOVERED by eager but never
						// SEARCHED, so this evidence must stay unreachable.
						"sha256:B": {lazyPlain(v, "audit-deep", "audit", "")},
					})
			},
		},

		// -------------------------------------------------------------------
		// 10. Empty-step diagnosis interaction: the #7572 depth guard fires on
		//     a step with no evidence at all while a sibling step truncates.
		// -------------------------------------------------------------------
		{
			name:        "truncated-sibling-with-diagnosed-empty-step",
			wantExam:    lazyExamCompleteSet,
			desc:        "one step truncates while a sibling is diagnosed empty: the once-per-verify probe guard must not be perturbed",
			seeds:       []string{"sha256:seed"},
			depth:       3,
			wantVerdict: false,
			build: func(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
				src := newLazySource(map[string][]source.CollectionVerificationResult{
					"sha256:seed": {
						lazyPlain(v, "build-x", "build", ""),
						lazyPlain(v, "build-y", "build", ""),
					},
				}).withUnfiltered(map[string][]source.CollectionVerificationResult{
					"audit": {lazyPlain(v, "audit-unreachable", "audit", "")},
				})
				return lazyPolicy(keyID, lazyStep("build", keyID), lazyStep("audit", keyID)), src
			},
		},
	}
}

// lazyHubDigest is a syntactically valid sha256 hex digest — 64 characters —
// so cryptoutil.IsMatchableSubjectDigest accepts it and the subject fan-out
// guard actually counts it.
var lazyHubDigest = strings.Repeat("ab", 32)

// lazyArtifactsFromDepth0 builds build.artifactsFrom=[source] where source's
// FIRST passing candidate produces the wrong artifact and its SECOND produces
// the one build consumed.
func lazyArtifactsFromDepth0(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
	consumed := lazyDigest("aa11")
	other := lazyDigest("bb22")

	build := lazyCollection(v, "build-one", "build", "",
		&lazyAttestor{AttName: "build-one", AttType: lazyAttType},
		&lazyAttestor{
			AttName:   "build-mat",
			AttType:   lazyChainAttType,
			materials: map[string]cryptoutil.DigestSet{"app.bin": consumed},
			inline:    true,
		})
	srcWrong := lazyCollection(v, "source-wrong", "source", "",
		&lazyAttestor{AttName: "source-wrong", AttType: lazyAttType},
		&lazyAttestor{AttName: "source-wrong-prod", AttType: lazyChainAttType,
			products: map[string]attestation.Product{"other.bin": {Digest: other}}, inline: true})
	srcRight := lazyCollection(v, "source-right", "source", "",
		&lazyAttestor{AttName: "source-right", AttType: lazyAttType},
		&lazyAttestor{AttName: "source-right-prod", AttType: lazyChainAttType,
			products: map[string]attestation.Product{"app.bin": {Digest: consumed}}, inline: true})

	buildStep := lazyStep("build", keyID)
	buildStep.ArtifactsFrom = []string{"source"}

	return lazyPolicy(keyID, buildStep, lazyStep("source", keyID)),
		newLazySource(map[string][]source.CollectionVerificationResult{
			"sha256:seed": {build, srcWrong, srcRight},
		})
}

// lazyArtifactsFromDepth1 is the design doc's §3 counterexample: the
// satisfying upstream collection hangs off a digest that only enters the
// search set as a BackRef of the downstream collection, at depth 1.
func lazyArtifactsFromDepth1(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
	consumed := lazyDigest("aa11")
	other := lazyDigest("bb22")

	build := lazyCollection(v, "build-one", "build", "sha256:hop",
		&lazyAttestor{AttName: "build-one", AttType: lazyAttType},
		&lazyAttestor{
			AttName:   "build-mat",
			AttType:   lazyChainAttType,
			materials: map[string]cryptoutil.DigestSet{"app.bin": consumed},
			inline:    true,
		})
	srcWrong := lazyCollection(v, "source-wrong", "source", "",
		&lazyAttestor{AttName: "source-wrong", AttType: lazyAttType},
		&lazyAttestor{AttName: "source-wrong-prod", AttType: lazyChainAttType,
			products: map[string]attestation.Product{"other.bin": {Digest: other}}, inline: true})
	srcRight := lazyCollection(v, "source-right", "source", "",
		&lazyAttestor{AttName: "source-right", AttType: lazyAttType},
		&lazyAttestor{AttName: "source-right-prod", AttType: lazyChainAttType,
			products: map[string]attestation.Product{"app.bin": {Digest: consumed}}, inline: true})

	buildStep := lazyStep("build", keyID)
	buildStep.ArtifactsFrom = []string{"source"}

	return lazyPolicy(keyID, buildStep, lazyStep("source", keyID)),
		newLazySource(map[string][]source.CollectionVerificationResult{
			"sha256:seed": {build, srcWrong},
			"sha256:hop":  {srcRight},
		})
}

// lazyDenyOnTaintedUpstream denies whenever the cross-step context carries the
// tainted attestation type. Under eager verification BOTH upstream candidates
// are in Passed, so the type IS in the context and the step is denied. Under a
// (wrongly) lazy upstream the second candidate is never examined, the type is
// absent, and the deny does not fire — that is the manufactured pass.
var lazyDenyOnTaintedUpstream = []byte(`package lazywitness

deny[msg] {
	input.steps.source["` + lazyTaintedAttType + `"]
	msg := "tainted upstream attestation present"
}
`)

func lazyAttestationsFromShape(_ testing.TB, v cryptoutil.Verifier, keyID string) (Policy, *lazySource) {
	clean := lazyCollection(v, "source-clean", "source", "",
		&lazyAttestor{AttName: "source-clean", AttType: lazyAttType})
	tainted := lazyCollection(v, "source-tainted", "source", "",
		&lazyAttestor{AttName: "source-tainted", AttType: lazyAttType},
		&lazyAttestor{AttName: "tainted-marker", AttType: lazyTaintedAttType})

	check := Step{
		Name:             "check",
		Functionaries:    []Functionary{{PublicKeyID: keyID}},
		AttestationsFrom: []string{"source"},
		Attestations: []Attestation{{
			Type:         lazyAttType,
			RegoPolicies: []RegoPolicy{{Module: lazyDenyOnTaintedUpstream, Name: "lazy-deny-tainted.rego"}},
		}},
	}

	return lazyPolicy(keyID, lazyStep("source", keyID), check),
		newLazySource(map[string][]source.CollectionVerificationResult{
			"sha256:seed": {
				clean,
				tainted,
				lazyCollection(v, "check-one", "check", "", &lazyAttestor{AttName: "check-one", AttType: lazyAttType}),
			},
		})
}

// ---------------------------------------------------------------------------
// lazyRun executes one shape in one mode and returns everything the
// differential compares.
// ---------------------------------------------------------------------------
type lazyRun struct {
	pass     bool
	passed   map[string][]string
	rejected map[string][]string
	yielded  int
	examined []string
}

// lazyMode names one verification arm. The lazy arm is defined in
// lazy_differential_test.go, deliberately: this file and lazy_invariance_test.go
// must stay compilable against the PRE-change tree, where no lazy API exists.
// That is what lets the invariance suite be run BEFORE the change.
type lazyMode struct {
	name string
	run  func(p Policy, ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, error)
}

// lazyOracleMode is the frozen pre-change engine — the truth this suite
// compares everything against.
func lazyOracleMode() lazyMode {
	return lazyMode{name: "oracle", run: func(p Policy, ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, error) {
		pass, results, _, err := frozenEagerVerifyWithExternals(p, ctx, opts...)
		return pass, results, err
	}}
}

// lazyEagerMode is the LIVE engine with the option unset.
func lazyEagerMode() lazyMode {
	return lazyMode{name: "eager", run: func(p Policy, ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, error) {
		return p.Verify(ctx, opts...)
	}}
}

func runLazyShape(t testing.TB, shape lazyShape, mode lazyMode, verifier cryptoutil.Verifier, keyID string) lazyRun {
	t.Helper()
	pol, src := shape.build(t, verifier, keyID)

	opts := []VerifyOption{
		WithVerifiedSource(src),
		WithSubjectDigests(append([]string(nil), shape.seeds...)),
		WithSearchDepth(shape.depth),
	}
	if shape.fanout > 0 {
		opts = append(opts, WithMaxSubjectFanout(shape.fanout))
	}

	pass, results, err := mode.run(pol, context.Background(), opts...)
	require.NoError(t, err, "%s/%s: verification must not error", shape.name, mode.name)

	return lazyRun{
		pass:     pass,
		passed:   lazyPassedRefs(results),
		rejected: rejectionReasons(results),
		yielded:  src.yielded,
		examined: src.examined(),
	}
}

func lazyPassedRefs(results map[string]StepResult) map[string][]string {
	out := make(map[string][]string, len(results))
	for step, sr := range results {
		refs := make([]string, 0, len(sr.Passed))
		for _, pc := range sr.Passed {
			refs = append(refs, pc.Collection.Reference)
		}
		sort.Strings(refs)
		out[step] = refs
	}
	return out
}
