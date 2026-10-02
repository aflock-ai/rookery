// jade:ring local
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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// External attestations: one verdict per input.
//
// A step reads an external as input.external.<name>, one passed candidate.
// Sources return candidates in no fixed order, so when several pass the
// external's own policy and the step's Rego accepts one and denies another,
// the verdict must not depend on which one the source returned first.
//
// The rule these tests pin: the verdict is PASS iff some choice of one passed
// candidate per external (the same choice for every step that reads it) makes
// the whole policy pass. Equivalently, PASS iff taking the candidates in some
// row order, first-candidate-only, would pass. Every test here drives a source that returns candidates in a
// FIXED order and runs every order it cares about, so a RED result never
// depends on luck.
// ---------------------------------------------------------------------------

const (
	detScanType   = "https://example.com/det-scan/v1"
	detOtherType  = "https://example.com/det-other/v1"
	detBuildType  = "https://example.com/det-build/v1"
	detDeployType = "https://example.com/det-deploy/v1"
	detSeed       = "sha256:artifact"
)

// orderedExternalSource returns each predicate type's candidates in exactly
// the order the test gave them.
type orderedExternalSource struct {
	byStep      map[string][]source.CollectionVerificationResult
	byPredicate map[string][]source.StatementEnvelope
}

func (s *orderedExternalSource) Search(_ context.Context, stepName string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	return s.byStep[stepName], nil
}

func (s *orderedExternalSource) SearchByPredicateType(_ context.Context, predicateTypes []string, _ []string) ([]source.StatementEnvelope, error) {
	n := 0
	for _, pt := range predicateTypes {
		n += len(s.byPredicate[pt])
	}
	out := make([]source.StatementEnvelope, 0, n)
	for _, pt := range predicateTypes {
		out = append(out, s.byPredicate[pt]...)
	}
	return out, nil
}

// ForkVerified: the source keeps no search state, so it is its own fresh copy.
func (s *orderedExternalSource) ForkVerified() (source.VerifiedSourcer, bool) { return s, true }

// seenExcludingSource behaves like EntSource and ArchivistaSource within one
// verify: a repeat Search returns only collections it has not returned
// before. Re-running the step loop over the SAME instance would therefore see
// nothing on the second run; each run must get a fork.
type seenExcludingSource struct {
	inner    *orderedExternalSource
	seen     map[string]bool
	forkable bool
	forks    *int
}

func newSeenExcludingSource(inner *orderedExternalSource, forkable bool) *seenExcludingSource {
	return &seenExcludingSource{inner: inner, seen: map[string]bool{}, forkable: forkable, forks: new(int)}
}

func (s *seenExcludingSource) Search(ctx context.Context, step string, digests, atts []string) ([]source.CollectionVerificationResult, error) {
	all, err := s.inner.Search(ctx, step, digests, atts)
	if err != nil {
		return nil, err
	}
	var out []source.CollectionVerificationResult
	for _, c := range all {
		if s.seen[c.Reference] {
			continue
		}
		s.seen[c.Reference] = true
		out = append(out, c)
	}
	return out, nil
}

func (s *seenExcludingSource) SearchByPredicateType(ctx context.Context, pts []string, digests []string) ([]source.StatementEnvelope, error) {
	return s.inner.SearchByPredicateType(ctx, pts, digests)
}

func (s *seenExcludingSource) ForkVerified() (source.VerifiedSourcer, bool) {
	if !s.forkable {
		return nil, false
	}
	*s.forks++
	return &seenExcludingSource{inner: s.inner, seen: map[string]bool{}, forkable: true, forks: s.forks}, true
}

// detCandidate is one external candidate with a JSON body and a reference.
func detCandidate(t *testing.T, v cryptoutil.Verifier, predicateType, ref string, body map[string]any) source.StatementEnvelope {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	env := mkExternalEnvelope(t, predicateType, raw, v)
	env.Reference = ref
	return env
}

func detCollection(v cryptoutil.Verifier, step, attType string) source.CollectionVerificationResult {
	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{v},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference: step + "-collection",
			Collection: attestation.Collection{
				Name: step,
				Attestations: []attestation.CollectionAttestation{
					{Type: attType, Attestation: &dummyAttestor{name: step, typeStr: attType}},
				},
			},
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
}

func detExternal(keyID, name, predicateType string, required bool) ExternalAttestation {
	return ExternalAttestation{
		Name: name, PredicateType: predicateType, Required: required,
		Functionaries: []Functionary{{PublicKeyID: keyID}},
	}
}

func detStep(keyID, name, attType string, externals []string, module string) Step {
	return Step{
		Name:          name,
		Functionaries: []Functionary{{PublicKeyID: keyID}},
		ExternalFrom:  externals,
		Attestations: []Attestation{{
			Type:         attType,
			RegoPolicies: []RegoPolicy{{Name: name + ".rego", Module: []byte(module)}},
		}},
	}
}

// detBuildRego denies a scan with findings; its message names the scan it saw.
const detBuildRego = `package detbuild
import rego.v1
deny contains msg if {
	input.external.scan.findings > 0
	msg := sprintf("scan %v has %v findings", [input.external.scan.id, input.external.scan.findings])
}
deny contains msg if {
	not input.external.scan
	msg := "no scan"
}
`

type detRun struct {
	accepted  bool
	steps     map[string]StepResult
	externals map[string]ExternalResult
	err       error
}

func detVerify(p Policy, src source.VerifiedSourcer, opts ...VerifyOption) detRun {
	accepted, steps, externals, err := p.VerifyWithExternals(context.Background(),
		append([]VerifyOption{WithVerifiedSource(src), WithSubjectDigests([]string{detSeed})}, opts...)...)
	return detRun{accepted: accepted, steps: steps, externals: externals, err: err}
}

// permutations returns every ordering of in.
func permutations[T any](in []T) [][]T {
	if len(in) <= 1 {
		return [][]T{append([]T(nil), in...)}
	}
	var out [][]T
	for i := range in {
		rest := make([]T, 0, len(in)-1)
		rest = append(rest, in[:i]...)
		rest = append(rest, in[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]T{in[i]}, p...))
		}
	}
	return out
}

func refsOf(envs []source.StatementEnvelope) string {
	refs := make([]string, 0, len(envs))
	for _, e := range envs {
		refs = append(refs, e.Reference)
	}
	return strings.Join(refs, ",")
}

func detScanPolicy(keyID string) Policy {
	return Policy{
		Expires:              futureExpiry(),
		Steps:                map[string]Step{"build": detStep(keyID, "build", detBuildType, []string{"scan"}, detBuildRego)},
		ExternalAttestations: map[string]ExternalAttestation{"scan": detExternal(keyID, "scan", detScanType, true)},
	}
}

func detScanSource(v cryptoutil.Verifier, scans []source.StatementEnvelope) *orderedExternalSource {
	return &orderedExternalSource{
		byStep:      map[string][]source.CollectionVerificationResult{"build": {detCollection(v, "build", detBuildType)}},
		byPredicate: map[string][]source.StatementEnvelope{detScanType: scans},
	}
}

// Two of C's scans pass the external's own policy; the step accepts the clean
// one. The verdict must not depend on which one the source returned first.
func TestExternalDeterminism_VerdictIndependentOfCandidateOrder(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	clean := detCandidate(t, v, detScanType, "scan-clean", map[string]any{"id": "clean", "findings": 0})
	dirty := detCandidate(t, v, detScanType, "scan-dirty", map[string]any{"id": "dirty", "findings": 3})

	for _, order := range permutations([]source.StatementEnvelope{clean, dirty}) {
		run := detVerify(detScanPolicy(keyID), detScanSource(v, order))
		require.NoError(t, run.err, "order %s", refsOf(order))
		assert.True(t, run.accepted, "order %s: a clean scan of C passes build whatever the row order; build rejected=%v",
			refsOf(order), run.steps["build"].Rejected)
		assert.Len(t, run.externals["scan"].Passed, 2, "order %s: both scans pass the external itself", refsOf(order))
	}
}

// A source that remembers what it returned (EntSource, ArchivistaSource) is
// forked for every run after the first, so the second assignment sees the
// same evidence a fresh verify would. A source that cannot fork gets one run
// over the canonical order: the same outcome in every row order (a PASS, or a
// refusal when the first canonical candidate fails; external_fork_refusal_test.go).
func TestExternalDeterminism_StatefulSourceIsForked(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	clean := detCandidate(t, v, detScanType, "scan-clean", map[string]any{"id": "clean", "findings": 0})
	dirty := detCandidate(t, v, detScanType, "scan-dirty", map[string]any{"id": "dirty", "findings": 3})

	for _, order := range permutations([]source.StatementEnvelope{clean, dirty}) {
		src := newSeenExcludingSource(detScanSource(v, order), true)
		run := detVerify(detScanPolicy(keyID), src)
		require.NoError(t, run.err)
		assert.True(t, run.accepted, "order %s: the clean scan's run must see build's collection again", refsOf(order))
	}

	type outcome struct{ accepted, refused bool }
	outcomes := make([]outcome, 0, 2)
	for _, order := range permutations([]source.StatementEnvelope{clean, dirty}) {
		src := newSeenExcludingSource(detScanSource(v, order), false)
		run := detVerify(detScanPolicy(keyID), src)
		var bound ErrExternalAssignmentsExceedBound
		refused := errors.As(run.err, &bound)
		if !refused {
			require.NoError(t, run.err)
		}
		assert.Zero(t, *src.forks)
		outcomes = append(outcomes, outcome{accepted: run.accepted, refused: refused})
	}
	assert.Equal(t, outcomes[0], outcomes[1], "an unforkable source still gives one outcome whatever the row order")
}

// Any passing candidate satisfies, in every one of the 6 orders of 3.
func TestExternalDeterminism_AnyPassingCandidateSatisfies(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	scans := []source.StatementEnvelope{
		detCandidate(t, v, detScanType, "scan-a", map[string]any{"id": "a", "findings": 1}),
		detCandidate(t, v, detScanType, "scan-b", map[string]any{"id": "b", "findings": 0}),
		detCandidate(t, v, detScanType, "scan-c", map[string]any{"id": "c", "findings": 7}),
	}
	for _, order := range permutations(scans) {
		run := detVerify(detScanPolicy(keyID), detScanSource(v, order))
		require.NoError(t, run.err)
		assert.True(t, run.accepted, "order %s", refsOf(order))
	}
}

// Every step that reads an external sees the SAME candidate, as it always did.
// e1 is clean for SAST but has a license problem; e2 the reverse. Build needs
// a clean SAST, deploy a clean license. No single scan satisfies the policy,
// so it fails in every order (a per-step choice would pass it). With e3, which
// satisfies both, it passes in every order.
func TestExternalDeterminism_StepsShareOneCandidate(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	const buildRego = `package detsast
import rego.v1
deny contains msg if {
	input.external.scan.sast > 0
	msg := sprintf("scan %v: sast findings", [input.external.scan.id])
}
`
	const deployRego = `package detlicense
import rego.v1
deny contains msg if {
	input.external.scan.license != "ok"
	msg := sprintf("scan %v: license problem", [input.external.scan.id])
}
`
	pol := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build":  detStep(keyID, "build", detBuildType, []string{"scan"}, buildRego),
			"deploy": detStep(keyID, "deploy", detDeployType, []string{"scan"}, deployRego),
		},
		ExternalAttestations: map[string]ExternalAttestation{"scan": detExternal(keyID, "scan", detScanType, true)},
	}
	src := func(scans []source.StatementEnvelope) *orderedExternalSource {
		return &orderedExternalSource{
			byStep: map[string][]source.CollectionVerificationResult{
				"build":  {detCollection(v, "build", detBuildType)},
				"deploy": {detCollection(v, "deploy", detDeployType)},
			},
			byPredicate: map[string][]source.StatementEnvelope{detScanType: scans},
		}
	}
	e1 := detCandidate(t, v, detScanType, "e1", map[string]any{"id": "e1", "sast": 0, "license": "bad"})
	e2 := detCandidate(t, v, detScanType, "e2", map[string]any{"id": "e2", "sast": 2, "license": "ok"})
	e3 := detCandidate(t, v, detScanType, "e3", map[string]any{"id": "e3", "sast": 0, "license": "ok"})

	for _, order := range permutations([]source.StatementEnvelope{e1, e2}) {
		run := detVerify(pol, src(order))
		require.NoError(t, run.err)
		assert.False(t, run.accepted, "order %s: no single scan satisfies both steps", refsOf(order))
	}
	for _, order := range permutations([]source.StatementEnvelope{e1, e2, e3}) {
		run := detVerify(pol, src(order))
		require.NoError(t, run.err)
		assert.True(t, run.accepted, "order %s: e3 satisfies both steps", refsOf(order))
	}
}

// Two externals read jointly: the step requires a.x == b.x, and only (a2, b1)
// matches. Every order of both lists passes.
func TestExternalDeterminism_TwoExternalsJointRule(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	const joint = `package detjoint
import rego.v1
deny contains msg if {
	input.external.a.x != input.external.b.x
	msg := sprintf("a.x=%v b.x=%v", [input.external.a.x, input.external.b.x])
}
`
	pol := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"build": detStep(keyID, "build", detBuildType, []string{"a", "b"}, joint)},
		ExternalAttestations: map[string]ExternalAttestation{
			"a": detExternal(keyID, "a", detScanType, true),
			"b": detExternal(keyID, "b", detOtherType, true),
		},
	}
	as := []source.StatementEnvelope{
		detCandidate(t, v, detScanType, "a1", map[string]any{"x": 1}),
		detCandidate(t, v, detScanType, "a2", map[string]any{"x": 2}),
	}
	bs := []source.StatementEnvelope{
		detCandidate(t, v, detOtherType, "b1", map[string]any{"x": 2}),
		detCandidate(t, v, detOtherType, "b2", map[string]any{"x": 3}),
	}
	for _, ao := range permutations(as) {
		for _, bo := range permutations(bs) {
			src := &orderedExternalSource{
				byStep:      map[string][]source.CollectionVerificationResult{"build": {detCollection(v, "build", detBuildType)}},
				byPredicate: map[string][]source.StatementEnvelope{detScanType: ao, detOtherType: bo},
			}
			run := detVerify(pol, src)
			require.NoError(t, run.err)
			assert.True(t, run.accepted, "a=%s b=%s: (a2, b1) satisfies the joint rule", refsOf(ao), refsOf(bo))
		}
	}
}

// When no candidate passes, the verdict is FAILED and its reasons are the
// same in every order.
func TestExternalDeterminism_NoPassingCandidateFailsWithStableReasons(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	scans := []source.StatementEnvelope{
		detCandidate(t, v, detScanType, "scan-a", map[string]any{"id": "a", "findings": 1}),
		detCandidate(t, v, detScanType, "scan-b", map[string]any{"id": "b", "findings": 2}),
		detCandidate(t, v, detScanType, "scan-c", map[string]any{"id": "c", "findings": 3}),
	}
	var first string
	for i, order := range permutations(scans) {
		run := detVerify(detScanPolicy(keyID), detScanSource(v, order))
		require.NoError(t, run.err)
		require.False(t, run.accepted)
		var reasons []string
		for _, r := range run.steps["build"].Rejected {
			reasons = append(reasons, r.Reason.Error())
		}
		got := strings.Join(reasons, "\n")
		require.NotEmpty(t, got)
		if i == 0 {
			first = got
			continue
		}
		assert.Equal(t, first, got, "order %s: the deny reasons must not depend on row order", refsOf(order))
	}
}

// detKey is the canonical order key the design names: sha256 of the attestor
// JSON a step's Rego reads.
func detKey(t *testing.T, env source.StatementEnvelope) string {
	t.Helper()
	b, err := json.Marshal(env.Attestor)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// k = 1 has no cap and no refusal: 65 and 200 candidates, where the only one
// the step accepts sorts LAST in canonical order, must PASS in both source
// orders. A bound applied to k = 1 would never reach it.
func TestExternalDeterminism_SingleExternalHasNoBound(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	for _, n := range []int{65, 200} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			dirty := make([]source.StatementEnvelope, 0, n-1)
			maxKey := ""
			for i := 0; i < n-1; i++ {
				e := detCandidate(t, v, detScanType, fmt.Sprintf("dirty-%03d", i), map[string]any{"id": fmt.Sprintf("d%03d", i), "findings": 1})
				if k := detKey(t, e); k > maxKey {
					maxKey = k
				}
				dirty = append(dirty, e)
			}
			// Grind the clean scan's free field until it sorts after every dirty one.
			var clean source.StatementEnvelope
			for salt := 0; ; salt++ {
				clean = detCandidate(t, v, detScanType, "clean", map[string]any{"id": "clean", "findings": 0, "salt": salt})
				if detKey(t, clean) > maxKey {
					break
				}
			}
			for _, order := range [][]source.StatementEnvelope{append([]source.StatementEnvelope{clean}, dirty...), append(append([]source.StatementEnvelope(nil), dirty...), clean)} {
				run := detVerify(detScanPolicy(keyID), detScanSource(v, order))
				require.NoError(t, run.err, "k = 1 is never refused")
				assert.True(t, run.accepted, "the clean scan satisfies build wherever it sorts")
			}
		})
	}
}

// k >= 2 is capped at 64 assignments. 9 x 9 = 81 with no passing assignment
// is a refusal, not a signed FAILED; 8 x 8 = 64 with none is a plain FAILED;
// 9 x 9 where every assignment passes is a PASS.
func TestExternalDeterminism_ProductBound(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	const joint = `package detproduct
import rego.v1
deny contains msg if {
	input.external.a.x + input.external.b.x != 1000
	msg := "no match"
}
`
	pol := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"build": detStep(keyID, "build", detBuildType, []string{"a", "b"}, joint)},
		ExternalAttestations: map[string]ExternalAttestation{
			"a": detExternal(keyID, "a", detScanType, true),
			"b": detExternal(keyID, "b", detOtherType, true),
		},
	}
	build := func(n int, ax, bx func(int) int) *orderedExternalSource {
		var as, bs []source.StatementEnvelope
		for i := 0; i < n; i++ {
			as = append(as, detCandidate(t, v, detScanType, fmt.Sprintf("a%d", i), map[string]any{"x": ax(i), "i": i}))
			bs = append(bs, detCandidate(t, v, detOtherType, fmt.Sprintf("b%d", i), map[string]any{"x": bx(i), "i": i}))
		}
		return &orderedExternalSource{
			byStep:      map[string][]source.CollectionVerificationResult{"build": {detCollection(v, "build", detBuildType)}},
			byPredicate: map[string][]source.StatementEnvelope{detScanType: as, detOtherType: bs},
		}
	}
	never := func(i int) int { return i }

	t.Run("81 with no pass is refused", func(t *testing.T) {
		run := detVerify(pol, build(9, never, never))
		var bound ErrExternalAssignmentsExceedBound
		require.ErrorAs(t, run.err, &bound, "an unexplored assignment could have passed: refuse, do not sign FAILED")
		assert.False(t, run.accepted)
		assert.Equal(t, 81, bound.Assignments)
		assert.Equal(t, 64, bound.Bound)
	})
	t.Run("64 with no pass is FAILED", func(t *testing.T) {
		run := detVerify(pol, build(8, never, never))
		require.NoError(t, run.err)
		assert.False(t, run.accepted)
	})
	t.Run("81 where every assignment passes is PASS", func(t *testing.T) {
		run := detVerify(pol, build(9, func(int) int { return 500 }, func(int) int { return 500 }))
		require.NoError(t, run.err)
		assert.True(t, run.accepted)
	})
}

// scriptedAI answers every question with one response or error and counts calls.
type scriptedAI struct {
	mu    sync.Mutex
	calls int
	resp  AiResponse
	err   error
}

func (s *scriptedAI) Evaluate(_ context.Context, _ attestation.Attestor, pol AiPolicy, _ string) (AiResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	resp := s.resp
	if resp.Status != "" {
		resp.Model = pol.Model // a provider names the model that answered
	}
	return resp, s.err
}

// AI runs once per attestor, only after that attestor's Rego passed under the
// assignment being tried, and its answer holds under every assignment.
func TestExternalDeterminism_AIOncePerAttestor(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	pol := func() Policy {
		p := detScanPolicy(keyID)
		build := p.Steps["build"]
		build.Attestations[0].AiPolicies = []AiPolicy{{Name: "ai-gate", Prompt: "evaluate", Model: "test-model"}}
		p.Steps["build"] = build
		return p
	}
	clean := detCandidate(t, v, detScanType, "clean", map[string]any{"id": "clean", "findings": 0})
	cleanToo := detCandidate(t, v, detScanType, "clean-too", map[string]any{"id": "clean-too", "findings": 0})
	dirty := detCandidate(t, v, detScanType, "dirty", map[string]any{"id": "dirty", "findings": 3})
	dirtyToo := detCandidate(t, v, detScanType, "dirty-too", map[string]any{"id": "dirty-too", "findings": 4})

	t.Run("rego denies one, accepts the other, AI answers FAIL", func(t *testing.T) {
		for _, order := range permutations([]source.StatementEnvelope{clean, dirty}) {
			ai := &scriptedAI{resp: AiResponse{Status: AiStatusFail, Reason: "no"}}
			run := detVerify(pol(), detScanSource(v, order), WithAiProvider(ai))
			require.NoError(t, run.err)
			assert.False(t, run.accepted, "order %s: an AI FAIL rejects the collection under every assignment", refsOf(order))
			assert.Equal(t, 1, ai.calls, "order %s: the provider sees the attestor exactly once", refsOf(order))
		}
	})
	t.Run("every assignment denies: no inference", func(t *testing.T) {
		for _, order := range permutations([]source.StatementEnvelope{dirty, dirtyToo}) {
			ai := &scriptedAI{resp: AiResponse{Status: AiStatusPass}}
			run := detVerify(pol(), detScanSource(v, order), WithAiProvider(ai))
			require.NoError(t, run.err)
			assert.False(t, run.accepted)
			assert.Zero(t, ai.calls, "order %s: a predicate every assignment's Rego rejects never leaves for inference", refsOf(order))
		}
	})
	t.Run("AI refuses and rego passes only under one assignment: refused", func(t *testing.T) {
		for _, order := range permutations([]source.StatementEnvelope{clean, dirty}) {
			ai := &scriptedAI{err: ErrAIEvaluationRefused{Code: "provider_unavailable"}}
			run := detVerify(pol(), detScanSource(v, order), WithAiProvider(ai))
			var refused ErrAIEvaluationRefused
			require.ErrorAs(t, run.err, &refused, "order %s: an unanswered question is a refusal, not a signed FAILED", refsOf(order))
			assert.False(t, run.accepted)
		}
	})
	t.Run("rego passes under two assignments, AI FAIL: asked once", func(t *testing.T) {
		for _, order := range permutations([]source.StatementEnvelope{clean, cleanToo}) {
			ai := &scriptedAI{resp: AiResponse{Status: AiStatusFail, Reason: "no"}}
			run := detVerify(pol(), detScanSource(v, order), WithAiProvider(ai))
			require.NoError(t, run.err)
			assert.False(t, run.accepted)
			assert.Equal(t, 1, ai.calls, "order %s: one attestor, one question, whatever the assignment", refsOf(order))
		}
	})
}

// With several required externals missing, the error names the first by
// name, not a random one.
func TestExternalDeterminism_ErrorIndependentOfMapOrder(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	pol := Policy{
		Expires:              futureExpiry(),
		Steps:                map[string]Step{"noop": validNoopStep(keyID)},
		ExternalAttestations: map[string]ExternalAttestation{},
	}
	for _, name := range []string{"e", "c", "a", "d", "b"} {
		pol.ExternalAttestations[name] = detExternal(keyID, name, "https://example.com/missing/"+name, true)
	}
	src := &orderedExternalSource{byStep: map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(v)}}}
	for i := 0; i < 20; i++ {
		run := detVerify(pol, src)
		var missing ErrMissingExternalAttestation
		require.ErrorAs(t, run.err, &missing)
		require.Equal(t, "a", missing.Name, "run %d", i)
	}
}

// The recorded candidate order is the same whatever order a source returned
// them in and whatever references it gave them: a file path in the CLI, a
// gitoid in Judge.
func TestExternalDeterminism_RecordedOrderIndependentOfSource(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	pol := detScanPolicy(keyID)
	pol.Steps = map[string]Step{"noop": validNoopStep(keyID)}
	bodies := []map[string]any{
		{"id": "a", "findings": 0}, {"id": "b", "findings": 0}, {"id": "c", "findings": 0},
		{"id": "d", "findings": 5},
	}
	// The two sources name the same bodies with references that sort in
	// OPPOSITE orders, so an order taken from the reference is caught.
	withRefs := func(prefix string, reverse bool) []source.StatementEnvelope {
		out := make([]source.StatementEnvelope, 0, len(bodies))
		for i, b := range bodies {
			n := len(bodies) - i
			if reverse {
				n = i + 1
			}
			out = append(out, detCandidate(t, v, detScanType, fmt.Sprintf("%s-%d", prefix, n), b))
		}
		if reverse {
			for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
				out[i], out[j] = out[j], out[i]
			}
		}
		return out
	}
	ids := func(run detRun) string {
		out := make([]string, 0, len(run.externals["scan"].Passed))
		for _, p := range run.externals["scan"].Passed {
			b, err := json.Marshal(p.Envelope.Attestor)
			require.NoError(t, err)
			out = append(out, string(b))
		}
		return strings.Join(out, "|")
	}
	srcOf := func(scans []source.StatementEnvelope) *orderedExternalSource {
		return &orderedExternalSource{
			byStep:      map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(v)}},
			byPredicate: map[string][]source.StatementEnvelope{detScanType: scans},
		}
	}
	file := detVerify(pol, srcOf(withRefs("file:///evidence/scan", false)))
	gitoid := detVerify(pol, srcOf(withRefs("gitoid:sha256:ffff", true)))
	require.NoError(t, file.err)
	require.NoError(t, gitoid.err)
	require.Len(t, file.externals["scan"].Passed, 4)
	assert.Equal(t, ids(file), ids(gitoid), "the recorded order is a function of content, not of the source's order or references")
}

// ---------------------------------------------------------------------------
// A candidate that is not about the verify's subject is not evidence.
//
// An optional external is Skipped when nothing is found and fails when
// something is found and rejected. A candidate refused because it is not
// about the evaluated commit (the commit binding) or not about the requested
// subject at all (the verified source's substitution guard) must count as
// "nothing found", or evidence the engine itself declares irrelevant flips a
// passing verify to FAILED, and a source that matches subject digests by
// value (judge-api's EntSource) disagrees with one that does not
// (MemorySource) on the same envelopes.
// ---------------------------------------------------------------------------

// valueMatchSource hands back every statement of a predicate type whatever
// subjects were asked for, the way a by-value SQL digest match does when the
// value matches under another algorithm's key.
type valueMatchSource struct {
	*source.MemorySource
	bare []source.StatementEnvelope
}

func (s *valueMatchSource) SearchByPredicateType(_ context.Context, predicateTypes []string, _ []string) ([]source.StatementEnvelope, error) {
	var out []source.StatementEnvelope
	for _, e := range s.bare {
		for _, pt := range predicateTypes {
			if e.Statement.PredicateType == pt {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func unboundTestPolicy(keyID string, publicKeys map[string]PublicKey, required bool) Policy {
	fn := []Functionary{{Type: "publickey", PublicKeyID: keyID}}
	return Policy{
		Expires:    futureExpiry(),
		PublicKeys: publicKeys,
		ExternalAttestations: map[string]ExternalAttestation{
			"summary": {Name: "summary", PredicateType: vsaPredicateType, Functionaries: fn, Required: required},
		},
		Steps: map[string]Step{
			"build": {Name: "build", Functionaries: fn, Attestations: []Attestation{{Type: hsecBuildType}}},
		},
	}
}

func signBare(t *testing.T, key hsecKey, ref string, payload []byte) source.StatementEnvelope {
	t.Helper()
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
	require.NoError(t, err)
	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(payload, &stmt))
	return source.StatementEnvelope{
		Envelope: env, Statement: stmt, Reference: ref,
		Attestor: attestation.NewRawAttestation(stmt.PredicateType, stmt.Predicate),
	}
}

func TestExternalUnbound_OptionalExternalIsSkipped(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	sub := func(alg, value string) intoto.Subject {
		return intoto.Subject{Name: "https://example.com/commithash:" + value, Digest: map[string]string{alg: value}}
	}
	const c256 = "3333333333333333333333333333333333333333333333333333333333333333"

	type arm struct {
		name string
		src  func(build hsecSpec, bare source.StatementEnvelope) source.VerifiedSourcer
	}
	arms := []arm{
		{"memory source", func(build hsecSpec, bare source.StatementEnvelope) source.VerifiedSourcer {
			mem := source.NewMemorySource()
			require.NoError(t, mem.LoadEnvelope(build.ref, hsecSign(t, key, build)))
			require.NoError(t, mem.LoadEnvelope(bare.Reference, bare.Envelope))
			return source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))
		}},
		{"by-value source", func(build hsecSpec, bare source.StatementEnvelope) source.VerifiedSourcer {
			mem := source.NewMemorySource()
			require.NoError(t, mem.LoadEnvelope(build.ref, hsecSign(t, key, build)))
			return source.NewVerifiedSource(&valueMatchSource{MemorySource: mem, bare: []source.StatementEnvelope{bare}}, dsse.VerifyWithVerifiers(key.verifier))
		}},
	}

	cases := []struct {
		name  string
		seed  string
		build func() hsecSpec
		bare  []byte
		bind  bool
	}{
		// SHA-1: the summary's sha1 subject never anchors a bare predicate
		// (the substitution guard), bound or not.
		{"sha1 commit, unbound", hsecC, func() hsecSpec { return hsecCorpus["C-build"] }, bareStatement(t, "PASSED", sub("sha1", hsecC)), false},
		{"sha1 commit, bound", hsecC, func() hsecSpec { return hsecCorpus["C-build"] }, bareStatement(t, "PASSED", sub("sha1", hsecC)), true},
		// SHA-256: the summary is found, and the binding refuses a bare predicate.
		{"sha256 commit, bound", c256, func() hsecSpec {
			b := hsecCorpus["C-build"]
			b.gits = hsecGitOf(c256)
			b.treeRoot = c256
			return b
		}, bareStatement(t, "PASSED", sub("sha256", c256)), true},
	}
	for _, tc := range cases {
		for _, a := range arms {
			t.Run(tc.name+"/"+a.name, func(t *testing.T) {
				bare := signBare(t, key, "summary-for-c", tc.bare)
				var opts []VerifyOption
				if tc.bind {
					opts = append(opts, WithCommitBinding(tc.seed))
				}
				src := a.src(tc.build(), bare)
				accepted, steps, externals, err := unboundTestPolicy(key.keyID, pks, false).VerifyWithExternals(context.Background(),
					append([]VerifyOption{WithVerifiedSource(src), WithSubjectDigests([]string{tc.seed})}, opts...)...)
				require.NoError(t, err)
				require.True(t, steps["build"].HasPassed(), "control: build passes on C's own collection; rejected=%v", steps["build"].Rejected)
				er := externals["summary"]
				assert.Empty(t, er.Rejected, "a candidate not about the subject is not a rejection: %v", externalReasons(er))
				assert.True(t, er.Skipped, "an optional external with no candidate about the subject is Skipped")
				assert.True(t, accepted, "evidence that is not about C must not flip a passing verify to FAILED")

				// Required: the same candidates are "missing", never "rejected".
				_, _, _, err = unboundTestPolicy(key.keyID, pks, true).VerifyWithExternals(context.Background(),
					append([]VerifyOption{WithVerifiedSource(a.src(tc.build(), bare)), WithSubjectDigests([]string{tc.seed})}, opts...)...)
				var missing ErrMissingExternalAttestation
				require.ErrorAs(t, err, &missing)
				var rejected ErrExternalAttestationRejected
				assert.False(t, errors.As(err, &rejected))
			})
		}
	}
}

// Functionary, Rego and AI rejections still count: an optional external whose
// only candidate is about C and denied by its own Rego fails the policy.
func TestExternalUnbound_FoundButRejectedStillFails(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	const c256 = "3333333333333333333333333333333333333333333333333333333333333333"
	build := hsecCorpus["C-build"]
	build.gits = hsecGitOf(c256)
	build.treeRoot = c256
	pol := unboundTestPolicy(key.keyID, pks, false)
	ext := pol.ExternalAttestations["summary"]
	ext.RegoPolicies = []RegoPolicy{{Name: "passed-only", Module: regoVsaPassedOnly}}
	pol.ExternalAttestations["summary"] = ext
	bare := signBare(t, key, "summary-failed", bareStatement(t, "FAILED",
		intoto.Subject{Name: "x", Digest: map[string]string{"sha256": c256}}))
	mem := source.NewMemorySource()
	require.NoError(t, mem.LoadEnvelope(build.ref, hsecSign(t, key, build)))
	require.NoError(t, mem.LoadEnvelope(bare.Reference, bare.Envelope))
	accepted, _, externals, err := pol.VerifyWithExternals(context.Background(),
		WithVerifiedSource(source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))),
		WithSubjectDigests([]string{c256}))
	require.NoError(t, err)
	assert.False(t, accepted)
	assert.Len(t, externals["summary"].Rejected, 1)
	assert.False(t, externals["summary"].Skipped)
}
