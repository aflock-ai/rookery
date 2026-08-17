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
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// VERDICT INVARIANCE for the empty-collection diagnostic re-probe.
//
// Every assertion in this file is written against HARD-CODED expected values,
// never values recomputed from the run. That is deliberate: the file is run
// UNCHANGED against the tree before and after the diagnostic probe is bounded,
// so a green result on both trees is the byte-identity evidence. If the bound
// ever moved a verdict or an evidence set, these goldens go red.
//
// It uses only symbols that exist on BOTH trees — nothing from the bounded
// probe itself. The bound's own behaviour is pinned in diagnose_bound_test.go.
// ---------------------------------------------------------------------------

// diagCorpus is the instrumented backing store shared by the batch and
// streaming fixture sources below. It separates the two populations the
// diagnostic conflates:
//
//   - byDigest — what a DIGEST-FILTERED search (the real verification path)
//     returns. The engine only ever issues filtered searches; checkVerifyOpts
//     rejects a Verify with no subject digests outright.
//   - byStep — what an UNFILTERED (nil-digest) search sees. In the whole
//     engine the ONLY caller that issues one is diagnoseEmptyCollectionResult.
//
// Collections that exist in byStep but in no byDigest bucket are the probe's
// exclusive population: if one of them ever reaches StepResult.Passed, the
// diagnostic leaked evidence into verification.
type diagCorpus struct {
	byDigest map[string][]source.CollectionVerificationResult
	byStep   map[string][]source.CollectionVerificationResult

	realCalls   int
	realYields  int
	probeCalls  int
	probeYields int

	// trackSeen models ArchivistaSource.seenGitoids: a candidate already handed
	// back is excluded from every later search on the same instance. Off by
	// default, which models judge-api's EntSource (the prod verify path).
	trackSeen bool
	seen      map[string]struct{}
}

func newDiagCorpus() *diagCorpus {
	return &diagCorpus{
		byDigest: map[string][]source.CollectionVerificationResult{},
		byStep:   map[string][]source.CollectionVerificationResult{},
		seen:     map[string]struct{}{},
	}
}

// candidates resolves a search WITHOUT recording anything, so the streaming
// fixture can decide per-candidate whether it was actually delivered.
func (c *diagCorpus) candidates(stepName string, subjectDigests []string) []source.CollectionVerificationResult {
	out := make([]source.CollectionVerificationResult, 0)
	emitted := map[string]struct{}{}
	add := func(cvr source.CollectionVerificationResult) {
		if cvr.Collection.Name != stepName {
			return
		}
		if _, dup := emitted[cvr.Reference]; dup {
			return
		}
		if c.trackSeen {
			if _, gone := c.seen[cvr.Reference]; gone {
				return
			}
		}
		emitted[cvr.Reference] = struct{}{}
		out = append(out, cvr)
	}

	if len(subjectDigests) == 0 {
		for _, cvr := range c.byStep[stepName] {
			add(cvr)
		}
		return out
	}
	for _, d := range subjectDigests {
		for _, cvr := range c.byDigest[d] {
			add(cvr)
		}
	}
	return out
}

func (c *diagCorpus) noteCall(subjectDigests []string) {
	if len(subjectDigests) == 0 {
		c.probeCalls++
		return
	}
	c.realCalls++
}

func (c *diagCorpus) noteYield(subjectDigests []string, n int) {
	if len(subjectDigests) == 0 {
		c.probeYields += n
		return
	}
	c.realYields += n
}

func (c *diagCorpus) markSeen(delivered []source.CollectionVerificationResult) {
	if !c.trackSeen {
		return
	}
	for _, cvr := range delivered {
		c.seen[cvr.Reference] = struct{}{}
	}
}

func (c *diagCorpus) Search(_ context.Context, stepName string, subjectDigests, _ []string) ([]source.CollectionVerificationResult, error) {
	c.noteCall(subjectDigests)
	out := c.candidates(stepName, subjectDigests)
	c.noteYield(subjectDigests, len(out))
	c.markSeen(out)
	return out, nil
}

func (c *diagCorpus) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// diagBatchSource exposes ONLY the VerifiedSourcer surface, so the policy
// engine takes its batch arm and the diagnostic takes its slice arm.
type diagBatchSource struct{ *diagCorpus }

// diagStreamSource additionally implements StreamingVerifiedSourcer, which is
// the arm production takes: *source.VerifiedSource implements it
// unconditionally.
//
// Its SearchStream reproduces ArchivistaSource's contract faithfully, which is
// what makes it a usable oracle: candidates are delivered one at a time, a
// yield error stops delivery, and an aborted iteration marks NOTHING as seen.
type diagStreamSource struct{ *diagCorpus }

func (s diagStreamSource) SearchStream(_ context.Context, stepName string, subjectDigests, _ []string, yield func(source.CollectionVerificationResult) error) error {
	s.noteCall(subjectDigests)
	cands := s.candidates(stepName, subjectDigests)
	delivered := make([]source.CollectionVerificationResult, 0, len(cands))
	for _, cvr := range cands {
		s.noteYield(subjectDigests, 1)
		delivered = append(delivered, cvr)
		if err := yield(cvr); err != nil {
			// Aborted: mark nothing seen, exactly like ArchivistaSource.
			return err
		}
	}
	s.markSeen(delivered)
	return nil
}

// diagCollection is earlyExitCollection plus a real subject list, which the
// diagnostic renders into ErrSubjectDigestMismatch.ObservedSubjects.
func diagCollection(verifier cryptoutil.Verifier, ref, stepName string, subjects ...intoto.Subject) source.CollectionVerificationResult {
	cvr := earlyExitCollection(verifier, ref, stepName, "")
	cvr.Statement = intoto.Statement{
		PredicateType: attestation.CollectionType,
		Subject:       subjects,
	}
	return cvr
}

func diagSubject(name, digest string) intoto.Subject {
	return intoto.Subject{Name: name, Digest: map[string]string{"sha256": digest}}
}

// diagPolicy is a single-step policy over the shared noop attestation type.
func diagPolicy(keyID string, stepNames ...string) Policy {
	steps := map[string]Step{}
	for _, name := range stepNames {
		steps[name] = Step{
			Name:          name,
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: noopStepAttType}},
		}
	}
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps:   steps,
	}
}

// stepRejectionReasons renders one step's rejection reasons in result order.
// Distinct from rejectionReasons in streamed_depth_guard_test.go, which renders
// every step of a result map.
func stepRejectionReasons(sr StepResult) []string {
	out := make([]string, 0, len(sr.Rejected))
	for _, rc := range sr.Rejected {
		if rc.Reason == nil {
			out = append(out, "")
			continue
		}
		out = append(out, rc.Reason.Error())
	}
	return out
}

func hasRejectionOfType[T error](sr StepResult) bool {
	for _, rc := range sr.Rejected {
		var target T
		if errors.As(rc.Reason, &target) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The outermost structural fact: the verification path can never issue an
// unfiltered search, so a bound applied to unfiltered searches can never
// truncate verification.
//
// NOT VACUOUS: the assertion names the exact typed error and the option it
// blames; a Verify that silently accepted nil digests would return (false,
// nil, nil) and fail the require.Error below.
// ---------------------------------------------------------------------------

func TestVerify_RejectsUnfilteredSearch_NoSubjectDigests(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	corpus := newDiagCorpus()
	corpus.byStep["build"] = []source.CollectionVerificationResult{
		diagCollection(verifier, "c0", "build", diagSubject("file:dist/app", "aaaa")),
	}

	for _, tc := range []struct {
		name    string
		digests []string
	}{
		{"nil digests", nil},
		{"empty digests", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := diagPolicy(keyID, "build").Verify(context.Background(),
				WithVerifiedSource(diagStreamSource{corpus}),
				WithSubjectDigests(tc.digests),
			)
			require.Error(t, err)
			var opt ErrInvalidOption
			require.True(t, errors.As(err, &opt), "want ErrInvalidOption, got %T: %v", err, err)
			assert.Equal(t, "subject digests", opt.Option)
		})
	}

	// The rejection happens before any search: the engine never reached the
	// source at all.
	assert.Equal(t, 0, corpus.realCalls, "a rejected Verify must not search")
	assert.Equal(t, 0, corpus.probeCalls, "a rejected Verify must not probe")
}

// ---------------------------------------------------------------------------
// The verdict + evidence golden. Same table, both arms of the engine.
// ---------------------------------------------------------------------------

type diagVerdictCase struct {
	name string
	// reachable is the collection refs a digest-filtered search can return for
	// "build" from the seed digest.
	reachable int
	// probeOnly is the number of extra collections visible ONLY to an
	// unfiltered probe. They are the diagnostic's exclusive population.
	probeOnly int
	// wantPass / wantPassedRefs are the frozen verdict + evidence set.
	wantPass       bool
	wantPassedRefs []string
	// wantNoCollections / wantDigestMismatch pin WHICH diagnosis fires.
	wantNoCollections  bool
	wantDigestMismatch bool
}

func diagVerdictCases() []diagVerdictCase {
	return []diagVerdictCase{
		{
			name:              "empty collection: nothing loaded for the step at all",
			reachable:         0,
			probeOnly:         0,
			wantPass:          false,
			wantPassedRefs:    []string{},
			wantNoCollections: true,
		},
		{
			name:           "single match",
			reachable:      1,
			probeOnly:      0,
			wantPass:       true,
			wantPassedRefs: []string{"reach-0"},
		},
		{
			name:           "many matches, below the diagnostic bound",
			reachable:      3,
			probeOnly:      0,
			wantPass:       true,
			wantPassedRefs: []string{"reach-0", "reach-1", "reach-2"},
		},
		{
			name:      "many matches, far above the diagnostic bound",
			reachable: 12,
			probeOnly: 0,
			wantPass:  true,
			wantPassedRefs: []string{
				"reach-0", "reach-1", "reach-10", "reach-11", "reach-2", "reach-3",
				"reach-4", "reach-5", "reach-6", "reach-7", "reach-8", "reach-9",
			},
		},
		{
			name:               "digest mismatch: corpus present but unreachable, below the bound",
			reachable:          0,
			probeOnly:          2,
			wantPass:           false,
			wantPassedRefs:     []string{},
			wantDigestMismatch: true,
		},
		{
			name:               "digest mismatch: corpus present but unreachable, far above the bound",
			reachable:          0,
			probeOnly:          40,
			wantPass:           false,
			wantPassedRefs:     []string{},
			wantDigestMismatch: true,
		},
		{
			name:               "mixed: reachable evidence AND a large unreachable corpus",
			reachable:          2,
			probeOnly:          40,
			wantPass:           true,
			wantPassedRefs:     []string{"reach-0", "reach-1"},
			wantDigestMismatch: false,
		},
	}
}

func buildDiagCorpus(verifier cryptoutil.Verifier, tc diagVerdictCase) *diagCorpus {
	corpus := newDiagCorpus()
	all := make([]source.CollectionVerificationResult, 0, tc.reachable+tc.probeOnly)
	reachable := make([]source.CollectionVerificationResult, 0, tc.reachable)
	for i := 0; i < tc.reachable; i++ {
		cvr := diagCollection(verifier, fmt.Sprintf("reach-%d", i), "build",
			diagSubject(fmt.Sprintf("file:reach-%d", i), fmt.Sprintf("%064x", i)))
		reachable = append(reachable, cvr)
		all = append(all, cvr)
	}
	for i := 0; i < tc.probeOnly; i++ {
		cvr := diagCollection(verifier, fmt.Sprintf("probe-only-%d", i), "build",
			diagSubject(fmt.Sprintf("file:probe-only-%d", i), fmt.Sprintf("%064x", 1000+i)))
		all = append(all, cvr)
	}
	corpus.byDigest["sha256:seed"] = reachable
	corpus.byStep["build"] = all
	return corpus
}

func runDiagVerdictCase(t *testing.T, tc diagVerdictCase, streaming bool) {
	t.Helper()
	verifier, keyID := earlyExitVerifier(t)
	corpus := buildDiagCorpus(verifier, tc)

	var src source.VerifiedSourcer = diagBatchSource{corpus}
	if streaming {
		src = diagStreamSource{corpus}
	}

	pass, results, err := diagPolicy(keyID, "build").Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:seed"}),
	)
	require.NoError(t, err)

	assert.Equal(t, tc.wantPass, pass, "VERDICT changed")
	require.Contains(t, results, "build")
	assert.Equal(t, tc.wantPassedRefs, passedRefs(results["build"]), "EVIDENCE SET changed")

	// The probe's exclusive population must never become evidence.
	for _, ref := range passedRefs(results["build"]) {
		assert.NotContains(t, ref, "probe-only-",
			"a collection only an unfiltered probe can see reached StepResult.Passed — the diagnostic leaked evidence into verification")
	}

	assert.Equal(t, tc.wantNoCollections, hasRejectionOfType[ErrNoCollections](results["build"]),
		"ErrNoCollections presence changed; reasons=%v", stepRejectionReasons(results["build"]))
	assert.Equal(t, tc.wantDigestMismatch, hasRejectionOfType[ErrSubjectDigestMismatch](results["build"]),
		"ErrSubjectDigestMismatch presence changed; reasons=%v", stepRejectionReasons(results["build"]))
}

// TestVerify_VerdictAndEvidence_Golden freezes the pass/fail verdict, the
// evidence set and WHICH diagnosis fires, for both engine arms.
//
// NOT VACUOUS: wantPassedRefs is an exact slice equality against literal
// values, so a truncation anywhere in the verification path (say a bound
// leaking into the filtered search) drops refs and reddens the case with 12
// reachable collections — 12 is deliberately three times the diagnostic bound.
func TestVerify_VerdictAndEvidence_Golden(t *testing.T) {
	for _, tc := range diagVerdictCases() {
		t.Run("streamed/"+tc.name, func(t *testing.T) { runDiagVerdictCase(t, tc, true) })
		t.Run("batch/"+tc.name, func(t *testing.T) { runDiagVerdictCase(t, tc, false) })
	}
}

// TestVerify_MultiStep_OneStepHasNoAttestations pins the "a step legitimately
// has no attestations" case inside a policy where the OTHER step passes: the
// satisfied step keeps its exact evidence, the starved step gets exactly the
// no-collections diagnosis, and the policy fails.
//
// NOT VACUOUS: it asserts the passing step's evidence set by literal value, so
// a change that starved it too would redden here rather than silently
// degrading to "policy still fails".
func TestVerify_MultiStep_OneStepHasNoAttestations(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	corpus := newDiagCorpus()

	built := make([]source.CollectionVerificationResult, 0, 9)
	for i := 0; i < 9; i++ {
		built = append(built, diagCollection(verifier, fmt.Sprintf("build-%d", i), "build",
			diagSubject(fmt.Sprintf("file:build-%d", i), fmt.Sprintf("%064x", i))))
	}
	corpus.byDigest["sha256:seed"] = built
	corpus.byStep["build"] = built
	// "test" has no collections at all, in either population.

	pass, results, err := diagPolicy(keyID, "build", "test").Verify(context.Background(),
		WithVerifiedSource(diagStreamSource{corpus}),
		WithSubjectDigests([]string{"sha256:seed"}),
	)
	require.NoError(t, err)

	assert.False(t, pass)
	assert.Equal(t, []string{
		"build-0", "build-1", "build-2", "build-3", "build-4",
		"build-5", "build-6", "build-7", "build-8",
	}, passedRefs(results["build"]))
	assert.Empty(t, passedRefs(results["test"]))
	assert.True(t, hasRejectionOfType[ErrNoCollections](results["test"]),
		"a step with no collections in either population must get ErrNoCollections; reasons=%v",
		stepRejectionReasons(results["test"]))
	assert.False(t, hasRejectionOfType[ErrSubjectDigestMismatch](results["test"]))
}

// TestVerify_DiagnosticNeverAddsPassedEvidence is the containment assertion
// stated positively over the whole matrix: across every shape, the count of
// passed collections equals the count of REACHABLE collections. The probe
// population never contributes, however large it is.
//
// NOT VACUOUS: the two large-probe-corpus cases have 40 probe-only
// collections against 0 and 2 reachable ones, so a leak of even one would
// break the equality.
func TestVerify_DiagnosticNeverAddsPassedEvidence(t *testing.T) {
	for _, tc := range diagVerdictCases() {
		t.Run(tc.name, func(t *testing.T) {
			verifier, keyID := earlyExitVerifier(t)
			corpus := buildDiagCorpus(verifier, tc)
			_, results, err := diagPolicy(keyID, "build").Verify(context.Background(),
				WithVerifiedSource(diagStreamSource{corpus}),
				WithSubjectDigests([]string{"sha256:seed"}),
			)
			require.NoError(t, err)
			assert.Len(t, results["build"].Passed, tc.reachable,
				"passed evidence must equal the REACHABLE population exactly (probe-only population = %d)", tc.probeOnly)
		})
	}
}
