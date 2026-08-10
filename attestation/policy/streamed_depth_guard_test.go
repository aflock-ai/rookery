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
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// #7572, STREAMED ARM — the depth-repeat guard on the empty-collection
// diagnostic lived only on the batch arm. Prod takes the streamed arm: every
// production verify wraps its source in *source.VerifiedSource
// (plugins/attestors/policyverify/policyverify.go and
// judge-api/cmd/server/cmd/handlers_policy.go), and VerifiedSource ALWAYS
// implements StreamingVerifiedSourcer — when the underlying Sourcer does not
// stream, SearchStream replays the materialized Search result
// (attestation/source/verified.go). So the type assertion in verifySteps
// always succeeds in production and the batch arm is a test-and-legacy path.
//
// Measured on the fixtures below, PRE-change: batch fired the unfiltered
// diagnostic probe ONCE per verify, streamed fired it once per DEPTH (3 at the
// default searchDepth of 3). On a prod source that probe is a full unfiltered
// re-fetch of the step's history — 806 candidate envelopes in the incident
// that opened #7572.
//
// The two arms also diverged in CONTENT, but only for one of the two
// diagnoses. ErrNoCollections renders identically at every depth, so the
// existing cross-depth content de-dup (mergeRejectedCollections) already
// collapsed the streamed arm's three copies to one. ErrSubjectDigestMismatch
// embeds SuppliedDigests, and the depth loop APPENDS to vo.subjectDigests
// (policy.go), so each depth rendered a different message, hashed to a
// different rejectedCollectionKey, and survived the merge — three entries on
// the streamed arm versus one on the batch arm.
// ---------------------------------------------------------------------------

// depthGuardSource models judge-api's EntSource: no seen-envelope exclusion,
// so the same collection is handed back on EVERY search whose digest set
// reaches it. It is deliberately a BATCH-ONLY VerifiedSourcer — the streaming
// presentation is a separate wrapper type below, so a single fixture can be
// fed to both arms unchanged.
type depthGuardSource struct {
	// byDigest maps a subject digest to the collections reachable from it.
	// This is what a DIGEST-FILTERED search sees.
	byDigest map[string][]source.CollectionVerificationResult
	// unfiltered is what the DIAGNOSTIC PROBE sees. The probe searches with
	// subjectDigests == nil, which on a real source means "every collection
	// ever recorded under this step name, whatever its subjects" — the
	// expensive query the guard exists to stop repeating.
	unfiltered map[string][]source.CollectionVerificationResult

	// probes counts unfiltered searches (subjectDigests == nil). The depth
	// loop always searches with a non-empty digest set, so every probe is a
	// diagnoseEmptyCollectionResult call.
	probes int
	// searches counts digest-filtered searches.
	searches int
}

func (s *depthGuardSource) Search(_ context.Context, stepName string, subjectDigests, _ []string) ([]source.CollectionVerificationResult, error) {
	if len(subjectDigests) == 0 {
		s.probes++
		return append([]source.CollectionVerificationResult(nil), s.unfiltered[stepName]...), nil
	}
	s.searches++

	out := make([]source.CollectionVerificationResult, 0)
	seen := map[string]struct{}{}
	for _, d := range subjectDigests {
		for _, cvr := range s.byDigest[d] {
			if cvr.Collection.Name != stepName {
				continue
			}
			// De-duplicate within ONE call (a real query returns a row once)
			// but deliberately NOT across calls — that is EntSource's
			// behavior, and it is what makes the depth loop re-adjudicate.
			if _, dup := seen[cvr.Reference]; dup {
				continue
			}
			seen[cvr.Reference] = struct{}{}
			out = append(out, cvr)
		}
	}
	return out, nil
}

func (s *depthGuardSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// streamedDepthGuardSource presents the SAME depthGuardSource through
// StreamingVerifiedSourcer. SearchStream replays Search exactly as
// (*source.VerifiedSource).SearchStream does when its underlying Sourcer does
// not stream (attestation/source/verified.go), so the candidate SEQUENCE the
// two arms consume is identical by construction: the only variable between a
// batch run and a streamed run of the same fixture is which arm verifySteps
// dispatches to.
type streamedDepthGuardSource struct{ *depthGuardSource }

func (s streamedDepthGuardSource) SearchStream(ctx context.Context, stepName string, subjectDigests, attestations []string, yield func(source.CollectionVerificationResult) error) error {
	results, err := s.Search(ctx, stepName, subjectDigests, attestations)
	if err != nil {
		return err
	}
	for i := range results {
		if err := yield(results[i]); err != nil {
			return err
		}
	}
	return nil
}

var (
	_ source.VerifiedSourcer          = (*depthGuardSource)(nil)
	_ source.VerifiedSourcer          = streamedDepthGuardSource{}
	_ source.StreamingVerifiedSourcer = streamedDepthGuardSource{}
)

// depthGuardArm names one of the two verifySteps dispatch arms and knows how
// to present a fixture so that arm is the one taken.
type depthGuardArm struct {
	name string
	// present wraps the fixture in the type whose interface set selects this
	// arm. Every test below runs its whole table through BOTH.
	present func(*depthGuardSource) source.VerifiedSourcer
}

var depthGuardArms = []depthGuardArm{
	{name: "batch", present: func(s *depthGuardSource) source.VerifiedSourcer { return s }},
	{name: "streamed", present: func(s *depthGuardSource) source.VerifiedSourcer { return streamedDepthGuardSource{s} }},
}

// depthGuardShape is one corpus shape. All three use the same two-step policy
// (dupPolicy: "build" and "audit", from rejected_dedup_test.go) so the only
// thing that varies is what the source holds for "audit".
type depthGuardShape struct {
	name string
	// desc records which diagnosis the shape drives the engine into.
	desc  string
	build func(t *testing.T, verifier cryptoutil.Verifier) *depthGuardSource
	// wantProbes is the number of unfiltered probes ONE verify may issue,
	// independent of searchDepth. It is a LITERAL, not a value derived from
	// the code under test: "diagnose a step's absence once per verify" is the
	// specification, and 1 is what it means.
	wantProbes int
	// wantDiagnoses is the number of diagnostic rejections the step carries
	// after the verify.
	wantDiagnoses int
	// diagStep is the step the diagnosis lands on.
	diagStep string
}

// depthGuardShapes: the two diagnosable shapes plus a control that must never
// probe at all.
//
//   - "missing"   — "audit" has no evidence anywhere, so the probe finds
//     nothing and the diagnosis is ErrNoCollections.
//   - "mismatch"  — "audit" HAS evidence, but none of it hangs off a reachable
//     digest, so filtered searches return nothing while the unfiltered probe
//     returns collections: ErrSubjectDigestMismatch, whose message embeds the
//     (growing) supplied digest set.
//   - "satisfied" — both steps are satisfied, so no search is ever empty and
//     the diagnostic must not run. This is the control that keeps the guard
//     honest: a guard that fired unconditionally would still pass the two
//     shapes above.
func depthGuardShapes() []depthGuardShape {
	return []depthGuardShape{
		{
			name:          "missing",
			desc:          "audit step has no evidence at all -> ErrNoCollections",
			wantProbes:    1,
			wantDiagnoses: 1,
			diagStep:      "audit",
			build: func(t *testing.T, v cryptoutil.Verifier) *depthGuardSource {
				t.Helper()
				return &depthGuardSource{byDigest: map[string][]source.CollectionVerificationResult{
					"sha256:binary":   {dupCollection(v, "build-current", "build", "sha256:pipeline")},
					"sha256:pipeline": {dupCollection(v, "build-hop", "build", "sha256:commit")},
				}}
			},
		},
		{
			name:          "mismatch",
			desc:          "audit step has evidence the supplied digests never reach -> ErrSubjectDigestMismatch",
			wantProbes:    1,
			wantDiagnoses: 1,
			diagStep:      "audit",
			build: func(t *testing.T, v cryptoutil.Verifier) *depthGuardSource {
				t.Helper()
				return &depthGuardSource{
					byDigest: map[string][]source.CollectionVerificationResult{
						"sha256:binary":   {dupCollection(v, "build-current", "build", "sha256:pipeline")},
						"sha256:pipeline": {dupCollection(v, "build-hop", "build", "sha256:commit")},
					},
					// Reachable from NO digest the search ever holds, so only
					// the unfiltered probe can see it.
					unfiltered: map[string][]source.CollectionVerificationResult{
						"audit": {dupCollection(v, "audit-unreachable", "audit", "")},
					},
				}
			},
		},
		{
			name:          "satisfied",
			desc:          "every step satisfied -> the diagnostic must never run",
			wantProbes:    0,
			wantDiagnoses: 0,
			diagStep:      "audit",
			build: func(t *testing.T, v cryptoutil.Verifier) *depthGuardSource {
				t.Helper()
				return &depthGuardSource{byDigest: map[string][]source.CollectionVerificationResult{
					"sha256:binary": {
						dupCollection(v, "build-current", "build", "sha256:pipeline"),
						dupCollection(v, "audit-current", "audit", ""),
					},
					"sha256:pipeline": {dupCollection(v, "build-hop", "build", "sha256:commit")},
				}}
			},
		},
	}
}

// ---------------------------------------------------------------------------
// NON-VACUITY GATE for this whole file.
//
// Every test below distinguishes the two arms purely by the fixture's
// interface set. If the "batch" fixture accidentally satisfied
// StreamingVerifiedSourcer (say a future embedded field promoted a
// SearchStream method), every "batch" run would silently take the streamed
// arm, the parity tests would compare the streamed arm with itself and pass
// vacuously, and the probe-count tests would lose the control they measure
// against. This asserts the dispatch predicate verifySteps itself uses.
// ---------------------------------------------------------------------------
func TestDepthGuardFixtures_SelectTheArmsTheyClaim(t *testing.T) {
	base := &depthGuardSource{}

	_, batchStreams := source.VerifiedSourcer(base).(source.StreamingVerifiedSourcer)
	assert.False(t, batchStreams,
		"the batch fixture must NOT satisfy StreamingVerifiedSourcer; if it does, every \"batch\" row below takes the streamed arm and this file's comparisons are vacuous")

	_, streamedStreams := source.VerifiedSourcer(streamedDepthGuardSource{base}).(source.StreamingVerifiedSourcer)
	assert.True(t, streamedStreams,
		"the streamed fixture must satisfy StreamingVerifiedSourcer; if it does not, every \"streamed\" row below takes the batch arm and can never reach the code this file exists to test")
}

// ---------------------------------------------------------------------------
// The guard itself: one unfiltered probe per verify, on BOTH arms, at every
// search depth.
//
// PRE-CHANGE this is RED for arm=streamed on shapes "missing" and "mismatch"
// (3 probes at depth 3, 4 at depth 4) and GREEN for arm=batch — which is the
// asymmetry, stated as a test.
// ---------------------------------------------------------------------------
func TestVerify_EmptyResultDiagnosedOncePerVerify(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, shape := range depthGuardShapes() {
		for _, arm := range depthGuardArms {
			for _, depth := range []int{1, 2, 3, 4} {
				t.Run(fmt.Sprintf("%s/%s/depth%d", shape.name, arm.name, depth), func(t *testing.T) {
					src := shape.build(t, verifier)

					_, results, err := dupPolicy(keyID).Verify(context.Background(),
						WithVerifiedSource(arm.present(src)),
						WithSubjectDigests([]string{"sha256:binary"}),
						WithSearchDepth(depth),
					)
					require.NoError(t, err)

					assert.Equal(t, shape.wantProbes, src.probes,
						"%s: the unfiltered diagnostic probe re-fetches the step's whole history; it must run at most once per verify, never once per depth",
						shape.desc)

					assert.Equal(t, shape.wantDiagnoses, countDiagnoses(results[shape.diagStep]),
						"%s: the step must carry exactly one diagnostic rejection per verify", shape.desc)
				})
			}
		}
	}
}

// countDiagnoses counts the rejections produced by the empty-collection
// diagnostic — either of its two error classes. Classification is by
// errors.As on the typed errors, the same way judge-api's readiness
// classifier reads them (pkg/workflow/activities/cilock/readiness.go), so
// this counts what a real consumer counts.
func countDiagnoses(sr StepResult) int {
	n := 0
	for _, rc := range sr.Rejected {
		if rc.Reason == nil {
			continue
		}
		var noColl ErrNoCollections
		var mismatch ErrSubjectDigestMismatch
		if errors.As(rc.Reason, &noColl) || errors.As(rc.Reason, &mismatch) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// VERDICT INVARIANCE — the load-bearing invariant. De-duplicating a
// DIAGNOSTIC must never change whether a policy passes or fails, nor which
// collections passed, at any depth, on either arm.
//
// The expectations are LITERALS captured by running this table on the
// PRE-change tree. They deliberately share no code with the guard: a mutation
// that moves the guard cannot move the oracle with it, which is the failure
// mode that makes a differential test report a false GREEN (a mutation to a
// helper both sides call moves both sides equally).
// ---------------------------------------------------------------------------
func TestVerify_DepthGuardIsVerdictInvariant(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	// want maps shape/depth to the verdict and the exact set of collection
	// references that PASSED each step. Captured on the pre-change tree; must
	// be identical after the guard is ported, on both arms.
	want := map[string]struct {
		pass   bool
		passed map[string][]string
	}{
		"missing/1":   {pass: false, passed: map[string][]string{"build": {"build-current"}, "audit": {}}},
		"missing/2":   {pass: false, passed: map[string][]string{"build": {"build-current", "build-hop"}, "audit": {}}},
		"missing/3":   {pass: false, passed: map[string][]string{"build": {"build-current", "build-hop"}, "audit": {}}},
		"missing/4":   {pass: false, passed: map[string][]string{"build": {"build-current", "build-hop"}, "audit": {}}},
		"mismatch/1":  {pass: false, passed: map[string][]string{"build": {"build-current"}, "audit": {}}},
		"mismatch/2":  {pass: false, passed: map[string][]string{"build": {"build-current", "build-hop"}, "audit": {}}},
		"mismatch/3":  {pass: false, passed: map[string][]string{"build": {"build-current", "build-hop"}, "audit": {}}},
		"mismatch/4":  {pass: false, passed: map[string][]string{"build": {"build-current", "build-hop"}, "audit": {}}},
		"satisfied/1": {pass: true, passed: map[string][]string{"build": {"build-current"}, "audit": {"audit-current"}}},
		"satisfied/2": {pass: true, passed: map[string][]string{"build": {"build-current"}, "audit": {"audit-current"}}},
		"satisfied/3": {pass: true, passed: map[string][]string{"build": {"build-current"}, "audit": {"audit-current"}}},
		"satisfied/4": {pass: true, passed: map[string][]string{"build": {"build-current"}, "audit": {"audit-current"}}},
	}

	for _, shape := range depthGuardShapes() {
		for _, arm := range depthGuardArms {
			for _, depth := range []int{1, 2, 3, 4} {
				key := fmt.Sprintf("%s/%d", shape.name, depth)
				t.Run(fmt.Sprintf("%s/%s", key, arm.name), func(t *testing.T) {
					exp, ok := want[key]
					require.True(t, ok, "no recorded pre-change expectation for %s", key)

					src := shape.build(t, verifier)
					pass, results, err := dupPolicy(keyID).Verify(context.Background(),
						WithVerifiedSource(arm.present(src)),
						WithSubjectDigests([]string{"sha256:binary"}),
						WithSearchDepth(depth),
					)
					require.NoError(t, err)

					assert.Equal(t, exp.pass, pass,
						"the verdict must equal the pre-change verdict recorded for %s", key)
					for step, refs := range exp.passed {
						assert.Equal(t, refs, passedRefs(results[step]),
							"step %q: the passed-collection set must equal the pre-change set recorded for %s", step, key)
					}
				})
			}
		}
	}
}

// passedRefs returns the sorted references of a step's passed collections —
// the verdict-bearing content of a StepResult.
func passedRefs(sr StepResult) []string {
	out := make([]string, 0, len(sr.Passed))
	for _, pc := range sr.Passed {
		out = append(out, pc.Collection.Reference)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// ARM PARITY on the rejection list. verifyStepStreamed's contract says it
// "produces the same StepResult as the batch path" (policy.go). For the
// empty-result diagnosis it did not.
//
// PRE-CHANGE this is RED for shape "mismatch" (streamed 3 entries vs batch 1)
// and GREEN for "missing" — because ErrNoCollections renders identically at
// every depth and mergeRejectedCollections already collapsed it. That the
// content divergence hid on one of the two shapes is exactly why the probe
// count, not the entry count, is the primary assertion above.
// ---------------------------------------------------------------------------
func TestVerify_StreamedAndBatchArmsAgreeOnRejections(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	for _, shape := range depthGuardShapes() {
		for _, depth := range []int{1, 2, 3, 4} {
			t.Run(fmt.Sprintf("%s/depth%d", shape.name, depth), func(t *testing.T) {
				run := func(arm depthGuardArm) map[string][]string {
					src := shape.build(t, verifier)
					_, results, err := dupPolicy(keyID).Verify(context.Background(),
						WithVerifiedSource(arm.present(src)),
						WithSubjectDigests([]string{"sha256:binary"}),
						WithSearchDepth(depth),
					)
					require.NoError(t, err)
					return rejectionReasons(results)
				}
				assert.Equal(t, run(depthGuardArms[0]), run(depthGuardArms[1]),
					"the streamed arm must produce the same rejection list as the batch arm (%s)", shape.desc)
			})
		}
	}
}

// rejectionReasons renders every step's rejection reasons, sorted, so two
// runs can be compared as data.
func rejectionReasons(results map[string]StepResult) map[string][]string {
	out := make(map[string][]string, len(results))
	for step, sr := range results {
		reasons := make([]string, 0, len(sr.Rejected))
		for _, rc := range sr.Rejected {
			if rc.Reason == nil {
				reasons = append(reasons, "")
				continue
			}
			reasons = append(reasons, rc.Reason.Error())
		}
		sort.Strings(reasons)
		out[step] = reasons
	}
	return out
}

// ---------------------------------------------------------------------------
// STRUCTURAL CONTAINMENT. The bug was not a wrong guard, it was a MISSING one
// on a second call site — and nothing in the code made the second site
// visible. This makes the un-guarded probe unreachable: the depth guard lives
// inside diagnoseEmptyResultOnce, and diagnoseEmptyResultOnce is the only
// production caller of diagnoseEmptyCollectionResult. A future third arm
// cannot re-introduce the asymmetry without failing this test.
//
// Not vacuous: it fails if the call graph has ZERO calls as readily as if it
// has two, and TestDepthGuardContainment_DetectsAnUnguardedCaller below runs
// the same analyzer over a synthetic package that HAS a second caller and
// asserts it is rejected.
// ---------------------------------------------------------------------------
func TestDiagnosticProbeIsReachableOnlyThroughTheDepthGuard(t *testing.T) {
	callers := callersOfInPackage(t, ".", "diagnoseEmptyCollectionResult")
	assert.Equal(t, []string{"diagnoseEmptyResultOnce"}, callers,
		"diagnoseEmptyCollectionResult must have exactly one production caller — the guarded wrapper. "+
			"A direct call from anywhere else is an un-depth-guarded probe: on a prod source that is a full "+
			"unfiltered re-fetch of the step's history, once per depth (#7572).")
}

func TestDepthGuardContainment_DetectsAnUnguardedCaller(t *testing.T) {
	dir := t.TempDir()
	src := `package p
func diagnoseEmptyCollectionResult() {}
func diagnoseEmptyResultOnce() { diagnoseEmptyCollectionResult() }
func someNewArm() { diagnoseEmptyCollectionResult() }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o600))
	callers := callersOfInPackage(t, dir, "diagnoseEmptyCollectionResult")
	assert.Equal(t, []string{"diagnoseEmptyResultOnce", "someNewArm"}, callers,
		"the analyzer must see a second caller; if it cannot, TestDiagnosticProbeIsReachableOnlyThroughTheDepthGuard passes vacuously")
}

// callersOfInPackage returns the sorted, deduplicated names of the top-level
// functions in dir's NON-TEST Go files that call fn.
func callersOfInPackage(t *testing.T, dir, fn string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	seen := map[string]struct{}{}
	parsed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, perr)
		parsed++
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != fn {
					return true
				}
				if fd.Name.Name == fn {
					return true // recursion, not an external caller
				}
				seen[fd.Name.Name] = struct{}{}
				return true
			})
		}
	}
	require.NotZero(t, parsed, "parsed no non-test Go files in %s", dir)
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Benchmark: probes per verify, on a probe corpus the size of the one that
// opened #7572 (806 collections for the step name). ReportMetric surfaces
// probes/verify directly so before/after is readable without arithmetic.
// ---------------------------------------------------------------------------
func BenchmarkVerify_StreamedEmptyStepDiagnosis(b *testing.B) {
	verifier, keyID := earlyExitVerifierB(b)

	corpus := make([]source.CollectionVerificationResult, 0, 806)
	for i := 0; i < 806; i++ {
		corpus = append(corpus, dupCollection(verifier, fmt.Sprintf("audit-hist-%d", i), "audit", ""))
	}

	totalProbes := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := &depthGuardSource{
			byDigest: map[string][]source.CollectionVerificationResult{
				"sha256:binary":   {dupCollection(verifier, "build-current", "build", "sha256:pipeline")},
				"sha256:pipeline": {dupCollection(verifier, "build-hop", "build", "sha256:commit")},
			},
			unfiltered: map[string][]source.CollectionVerificationResult{"audit": corpus},
		}
		pass, _, err := dupPolicy(keyID).Verify(context.Background(),
			WithVerifiedSource(streamedDepthGuardSource{src}),
			WithSubjectDigests([]string{"sha256:binary"}),
			WithSearchDepth(3),
		)
		if err != nil || pass {
			b.Fatalf("expected clean FAIL verdict, got pass=%v err=%v", pass, err)
		}
		totalProbes += src.probes
	}
	b.StopTimer()
	b.ReportMetric(float64(totalProbes)/float64(b.N), "probes/verify")
}
