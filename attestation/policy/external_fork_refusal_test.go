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
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A verdict from a partial search is not an answer.
//
// Every assignment after the first runs over a fork of the source (the state
// a fresh verify starts from). When no faithful fork can be had, because the
// source does not fork, refuses to, or hands back a value of another concrete
// type, the walk stops there. A PASS found among the assignments already
// tried is a real PASS: some assignment satisfies the policy. A FAILED is
// only an answer when every assignment was evaluated. Anything else is
// refused, the same way the k >= 2 bound is.
// ---------------------------------------------------------------------------

// detScansAroundClean returns nDirty scans the step denies and one clean scan
// it accepts, with the clean scan's free field ground until it sorts FIRST
// (cleanFirst) or LAST in canonical order.
func detScansAroundClean(t *testing.T, v cryptoutil.Verifier, nDirty int, cleanFirst bool) ([]source.StatementEnvelope, source.StatementEnvelope) {
	t.Helper()
	dirty := make([]source.StatementEnvelope, 0, nDirty)
	for i := 0; i < nDirty; i++ {
		dirty = append(dirty, detCandidate(t, v, detScanType, fmt.Sprintf("scan-dirty-%d", i), map[string]any{"id": fmt.Sprintf("dirty-%d", i), "findings": i + 1}))
	}
	for salt := 0; salt < 10000; salt++ {
		clean := detCandidate(t, v, detScanType, "scan-clean", map[string]any{"id": "clean", "findings": 0, "salt": salt})
		if sortsAround(t, clean, dirty, cleanFirst) {
			return dirty, clean
		}
	}
	t.Fatal("no salt put the clean scan where the test needs it")
	return nil, source.StatementEnvelope{}
}

func sortsAround(t *testing.T, clean source.StatementEnvelope, dirty []source.StatementEnvelope, first bool) bool {
	t.Helper()
	ck := detKey(t, clean)
	for _, d := range dirty {
		dk := detKey(t, d)
		if (first && ck >= dk) || (!first && ck <= dk) {
			return false
		}
	}
	return true
}

func withClean(dirty []source.StatementEnvelope, clean source.StatementEnvelope) []source.StatementEnvelope {
	return append(append([]source.StatementEnvelope(nil), dirty...), clean)
}

// The second canonical candidate passes and the source cannot fork, so it is
// never tried. FAILED would be a verdict from half the search: refuse.
func TestExternalFork_UnforkableSourceRefusesWhenALaterCandidateIsUntried(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	dirty, clean := detScansAroundClean(t, v, 1, false)
	for _, order := range permutations(withClean(dirty, clean)) {
		src := newSeenExcludingSource(detScanSource(v, order), false)
		run := detVerify(detScanPolicy(keyID), src)
		var bound ErrExternalAssignmentsExceedBound
		require.ErrorAs(t, run.err, &bound, "order %s: the clean scan was never tried; a FAILED here comes from a partial search", refsOf(order))
		assert.False(t, run.accepted)
		assert.Equal(t, 2, bound.Assignments)
		assert.Equal(t, 1, bound.Bound, "only the first canonical assignment could be tried")
		assert.Contains(t, bound.Error(), "fork")
		assert.Zero(t, *src.forks)
	}
}

// The first canonical candidate passes: some assignment satisfies the policy,
// so the PASS stands without a fork.
func TestExternalFork_UnforkableSourcePassesOnTheFirstCandidate(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	dirty, clean := detScansAroundClean(t, v, 1, true)
	for _, order := range permutations(withClean(dirty, clean)) {
		src := newSeenExcludingSource(detScanSource(v, order), false)
		run := detVerify(detScanPolicy(keyID), src)
		require.NoError(t, run.err, "order %s", refsOf(order))
		assert.True(t, run.accepted, "order %s: the first assignment tried passes", refsOf(order))
	}
}

// One distinct assignment in total (one candidate, or two with the same
// attestor JSON): evaluating it was the whole search, so its FAILED stands.
func TestExternalFork_UnforkableSourceWithOneAssignmentFails(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	dirty := detCandidate(t, v, detScanType, "scan-dirty", map[string]any{"id": "dirty", "findings": 3})
	twin := detCandidate(t, v, detScanType, "scan-dirty-twin", map[string]any{"id": "dirty", "findings": 3})
	for _, scans := range [][]source.StatementEnvelope{{dirty}, {dirty, twin}, {twin, dirty}} {
		src := newSeenExcludingSource(detScanSource(v, scans), false)
		run := detVerify(detScanPolicy(keyID), src)
		require.NoError(t, run.err, "%s: every assignment was evaluated", refsOf(scans))
		assert.False(t, run.accepted, "%s", refsOf(scans))
	}
}

// budgetForkSource forks faithfully until its budget runs out, then refuses:
// a source whose backing connection went away part-way through the walk.
type budgetForkSource struct {
	*orderedExternalSource
	budget *int
}

func (s budgetForkSource) ForkVerified() (source.VerifiedSourcer, bool) {
	if *s.budget == 0 {
		return nil, false
	}
	*s.budget--
	return budgetForkSource{orderedExternalSource: s.orderedExternalSource, budget: s.budget}, true
}

// A fork refused part-way through the walk leaves the later assignments
// untried: the same refusal, typed, never an untyped error or a FAILED.
func TestExternalFork_ForkRefusedMidWalkIsARefusal(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	dirty, clean := detScansAroundClean(t, v, 2, false)
	src := budgetForkSource{orderedExternalSource: detScanSource(v, withClean(dirty, clean)), budget: new(int)}
	*src.budget = 1
	run := detVerify(detScanPolicy(keyID), src)
	var bound ErrExternalAssignmentsExceedBound
	require.ErrorAs(t, run.err, &bound, "the clean scan (third) was never tried")
	assert.False(t, run.accepted)
	assert.Equal(t, 3, bound.Assignments)
	assert.Equal(t, 2, bound.Bound)
}

// ---------------------------------------------------------------------------
// A fork must keep the wrapper.
//
// A caller may wrap a real *source.VerifiedSource to narrow its searches (a
// tenant scope, a commit binding). If the wrapper does not define
// ForkVerified, the embedded one is promoted and returns the bare inner
// source: every assignment after the first would then read evidence the
// caller filtered out. The corpus below makes that visible. The only build
// collection is another tenant's, which the wrapper hides; with it hidden no
// assignment can pass, and with it visible the clean scan passes.
// ---------------------------------------------------------------------------

const forkSeed = "6666666666666666666666666666666666666666666666666666666666666666"

const hiddenBuildRef = "other-tenant-build"

// scopedVerifiedSource hides the collections in hidden from every collection
// search. It defines no ForkVerified.
type scopedVerifiedSource struct {
	*source.VerifiedSource
	hidden map[string]bool
}

func (s *scopedVerifiedSource) Search(ctx context.Context, name string, digests, atts []string) ([]source.CollectionVerificationResult, error) {
	all, err := s.VerifiedSource.Search(ctx, name, digests, atts)
	if err != nil {
		return nil, err
	}
	out := make([]source.CollectionVerificationResult, 0, len(all))
	for _, c := range all {
		if !s.hidden[c.Reference] {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *scopedVerifiedSource) SearchStream(ctx context.Context, name string, digests, atts []string, yield func(source.CollectionVerificationResult) error) error {
	return s.VerifiedSource.SearchStream(ctx, name, digests, atts, func(c source.CollectionVerificationResult) error {
		if s.hidden[c.Reference] {
			return nil
		}
		return yield(c)
	})
}

// forkingScopedSource keeps its scope on its first `faithful` forks, then
// hands back the embedded source's own fork with the scope dropped.
type forkingScopedSource struct {
	*scopedVerifiedSource
	faithful int
	forks    *int
}

func (s *forkingScopedSource) ForkVerified() (source.VerifiedSourcer, bool) {
	inner, ok := s.VerifiedSource.ForkVerified()
	if !ok {
		return nil, false
	}
	*s.forks++
	if *s.forks > s.faithful {
		return inner, true
	}
	vs, ok := inner.(*source.VerifiedSource)
	if !ok {
		return nil, false
	}
	return &forkingScopedSource{
		scopedVerifiedSource: &scopedVerifiedSource{VerifiedSource: vs, hidden: s.hidden},
		faithful:             s.faithful,
		forks:                s.forks,
	}, true
}

// scopedScan is a signed bare scan statement about forkSeed.
func scopedScan(t *testing.T, key hsecKey, ref string, predicate map[string]any) source.StatementEnvelope {
	t.Helper()
	body, err := json.Marshal(predicate)
	require.NoError(t, err)
	payload, err := json.Marshal(intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: detScanType,
		Subject:       []intoto.Subject{{Name: "artifact", Digest: map[string]string{"sha256": forkSeed}}},
		Predicate:     body,
	})
	require.NoError(t, err)
	return signBare(t, key, ref, payload)
}

// scopedCorpus loads the hidden build collection and nDirty dirty scans plus
// one clean scan that sorts LAST in canonical order, and returns the real
// verified source over them.
func scopedCorpus(t *testing.T, key hsecKey, nDirty int) *source.VerifiedSource {
	t.Helper()
	mem := source.NewMemorySource()
	require.NoError(t, mem.LoadEnvelope(hiddenBuildRef, hsecSign(t, key, hsecSpec{ref: hiddenBuildRef, step: "build", treeRoot: forkSeed})))
	dirty := make([]source.StatementEnvelope, 0, nDirty)
	for i := 0; i < nDirty; i++ {
		dirty = append(dirty, scopedScan(t, key, fmt.Sprintf("scan-dirty-%d", i), map[string]any{"id": fmt.Sprintf("dirty-%d", i), "findings": i + 1}))
	}
	var clean source.StatementEnvelope
	for salt := 0; ; salt++ {
		require.Less(t, salt, 10000, "no salt sorts the clean scan last")
		clean = scopedScan(t, key, "scan-clean", map[string]any{"id": "clean", "findings": 0, "salt": salt})
		if sortsAround(t, clean, dirty, false) {
			break
		}
	}
	for _, e := range withClean(dirty, clean) {
		require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))

	// The engine orders what the source returns, not what the test built.
	got, err := vs.SearchByPredicateType(context.Background(), []string{detScanType}, []string{forkSeed})
	require.NoError(t, err)
	require.Len(t, got, nDirty+1)
	var gotClean source.StatementEnvelope
	var gotDirty []source.StatementEnvelope
	for _, e := range got {
		if e.Reference == "scan-clean" {
			gotClean = e
		} else {
			gotDirty = append(gotDirty, e)
		}
	}
	require.True(t, sortsAround(t, gotClean, gotDirty, false), "the clean scan must be the LAST canonical candidate as the engine sees it")
	return vs
}

func scopedScanPolicy(key hsecKey) Policy {
	fn := []Functionary{{Type: "publickey", PublicKeyID: key.keyID}}
	return Policy{
		Expires:    futureExpiry(),
		PublicKeys: map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}},
		Steps: map[string]Step{"build": {
			Name: "build", Functionaries: fn, ExternalFrom: []string{"scan"},
			Attestations: []Attestation{{Type: hsecBuildType, RegoPolicies: []RegoPolicy{{Name: "build.rego", Module: []byte(detBuildRego)}}}},
		}},
		ExternalAttestations: map[string]ExternalAttestation{
			"scan": {Name: "scan", PredicateType: detScanType, Functionaries: fn, Required: true},
		},
	}
}

func scopedVerify(p Policy, src source.VerifiedSourcer) detRun {
	accepted, steps, externals, err := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(src), WithSubjectDigests([]string{forkSeed}))
	return detRun{accepted: accepted, steps: steps, externals: externals, err: err}
}

func hideOtherTenant(vs *source.VerifiedSource) *scopedVerifiedSource {
	return &scopedVerifiedSource{VerifiedSource: vs, hidden: map[string]bool{hiddenBuildRef: true}}
}

// Control: unscoped, the hidden build and the clean scan pass. Scoped, and
// forked faithfully, every assignment is tried and none passes: FAILED.
func TestExternalFork_FaithfulWrapperForkKeepsItsScope(t *testing.T) {
	key := newHsecKey(t)
	vs := scopedCorpus(t, key, 2)
	pol := scopedScanPolicy(key)

	unscoped := scopedVerify(pol, vs)
	require.NoError(t, unscoped.err)
	require.True(t, unscoped.accepted, "control: the other tenant's build passes with the clean scan when nothing hides it")

	forks := new(int)
	run := scopedVerify(pol, &forkingScopedSource{scopedVerifiedSource: hideOtherTenant(vs), faithful: 1 << 30, forks: forks})
	require.NoError(t, run.err, "a faithful fork lets every assignment be tried")
	assert.False(t, run.accepted, "under the scope no build collection exists, whatever scan is chosen")
	assert.GreaterOrEqual(t, *forks, 2, "the second and third assignments each ran over a fork")
}

// Forked once: the wrapper's promoted ForkVerified returns the bare verified
// source. That is not a fork of the wrapper, so the source is unforkable and
// the untried clean scan makes the verify a refusal, never a PASS on the
// other tenant's build.
func TestExternalFork_PromotedForkVerifiedDropsTheWrapper(t *testing.T) {
	key := newHsecKey(t)
	vs := scopedCorpus(t, key, 1)
	run := scopedVerify(scopedScanPolicy(key), hideOtherTenant(vs))
	assert.False(t, run.accepted, "a later assignment must not pass on evidence the wrapper filtered out")
	var bound ErrExternalAssignmentsExceedBound
	require.ErrorAs(t, run.err, &bound, "the clean scan could not be tried under the wrapper's scope")
	assert.Equal(t, 2, bound.Assignments)
	assert.Equal(t, 1, bound.Bound)
}

// Forked again: the first fork keeps the wrapper and the second does not. The
// check holds on every fork, so the third assignment is refused rather than
// run over the bare source.
func TestExternalFork_EveryForkMustKeepTheWrapper(t *testing.T) {
	key := newHsecKey(t)
	vs := scopedCorpus(t, key, 2)
	forks := new(int)
	run := scopedVerify(scopedScanPolicy(key), &forkingScopedSource{scopedVerifiedSource: hideOtherTenant(vs), faithful: 1, forks: forks})
	assert.False(t, run.accepted, "the third assignment must not run over a fork that dropped the scope")
	var bound ErrExternalAssignmentsExceedBound
	require.ErrorAs(t, run.err, &bound, "the clean scan (third) could not be tried under the wrapper's scope")
	assert.Equal(t, 3, bound.Assignments)
	assert.Equal(t, 2, bound.Bound)
}

// ---------------------------------------------------------------------------
// One search per predicate type.
//
// Two externals may share a predicate type (a SAST scan and a license scan,
// both attestation collections, told apart by their own Rego). ArchivistaSource
// returns each statement at most once per verify (its predicate seen-set), so
// a second search for the same type returned nothing and the second external
// was judged on an empty candidate set: missing when required, Skipped when
// optional, whatever the evidence said.
// ---------------------------------------------------------------------------

// seenPredicateSource returns each statement at most once, as
// ArchivistaSource's predicate search does within one verify.
type seenPredicateSource struct {
	*orderedExternalSource
	seen map[string]bool
}

func (s *seenPredicateSource) SearchByPredicateType(ctx context.Context, pts, digests []string) ([]source.StatementEnvelope, error) {
	all, err := s.orderedExternalSource.SearchByPredicateType(ctx, pts, digests)
	if err != nil {
		return nil, err
	}
	out := make([]source.StatementEnvelope, 0, len(all))
	for _, e := range all {
		if !s.seen[e.Reference] {
			s.seen[e.Reference] = true
			out = append(out, e)
		}
	}
	return out, nil
}

func TestExternalSearch_ExternalsSharingAPredicateTypeSeeTheSameCandidates(t *testing.T) {
	v, keyID := newECDSAVerifier(t)
	const both = `package detboth
import rego.v1
deny contains "no license scan" if not input.external.license
deny contains "no sast scan" if not input.external.sast
`
	pol := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"build": detStep(keyID, "build", detBuildType, []string{"license", "sast"}, both)},
		ExternalAttestations: map[string]ExternalAttestation{
			"license": detExternal(keyID, "license", detScanType, true),
			"sast":    detExternal(keyID, "sast", detScanType, true),
		},
	}
	scan := detCandidate(t, v, detScanType, "scan", map[string]any{"id": "scan", "findings": 0})
	src := &seenPredicateSource{orderedExternalSource: detScanSource(v, []source.StatementEnvelope{scan}), seen: map[string]bool{}}
	run := detVerify(pol, src)
	require.NoError(t, run.err, "both externals name the same evidence; the second must not be judged on an empty search")
	assert.True(t, run.accepted, "build rejected=%v", run.steps["build"].Rejected)
	assert.Len(t, run.externals["license"].Passed, 1)
	assert.Len(t, run.externals["sast"].Passed, 1)
}
