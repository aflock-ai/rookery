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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
// judge#7551 — the depth loop must stop expanding once further search cannot
// change the verdict.
//
// These tests model the shape of the cilock release gate, which is what made
// the cost visible: a two-step policy (source-git, build) verified against a
// binary digest, where source-git is only reachable through the build
// collection's back-reference. Measured on release-fanout run 30477171517, each
// artifact fetched 1110 candidate envelopes (2 + 10 + 9 at depths 0-1, then 786
// + 303 at depth 2) and took ~327s. Everything at depth 2 was noise: both steps
// were already satisfied at depth 1.
// ---------------------------------------------------------------------------

// reachableSource is a VerifiedSourcer that models a subject graph: a
// collection is returned only when the search's subject digests include the
// digest it hangs off. It counts Search calls and, more importantly, the number
// of candidate envelopes it hands back — that count is the direct analogue of
// the per-envelope Archivista downloads that dominate release-gate wall clock.
type reachableSource struct {
	// byDigest maps a subject digest to the collections reachable from it.
	byDigest map[string][]source.CollectionVerificationResult

	searches  int
	candidate int
	// returned mirrors ArchivistaSource.seenGitoids: an envelope already handed
	// back is excluded from every later search in the same process, so
	// `candidate` counts DISTINCT envelope downloads — the quantity that
	// dominates release-gate wall clock.
	returned map[string]struct{}
	// searchedDigests records every subject digest ever submitted to a search,
	// so a test can assert that a given depth's expansion never happened.
	searchedDigests map[string]struct{}
}

func (s *reachableSource) Search(_ context.Context, stepName string, subjectDigests, _ []string) ([]source.CollectionVerificationResult, error) {
	s.searches++
	if s.returned == nil {
		s.returned = map[string]struct{}{}
	}
	if s.searchedDigests == nil {
		s.searchedDigests = map[string]struct{}{}
	}

	out := make([]source.CollectionVerificationResult, 0)
	for _, d := range subjectDigests {
		s.searchedDigests[d] = struct{}{}
		for _, cvr := range s.byDigest[d] {
			if cvr.Collection.Name != stepName {
				continue
			}
			if _, dup := s.returned[cvr.Reference]; dup {
				continue
			}
			s.returned[cvr.Reference] = struct{}{}
			out = append(out, cvr)
		}
	}

	s.candidate += len(out)
	return out, nil
}

func (s *reachableSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// earlyExitCollection builds a passing collection for stepName carrying an
// optional back-reference, mirroring how the release policy's build collection
// points at the pipeline URL digest that the source-git collection shares.
func earlyExitCollection(verifier cryptoutil.Verifier, ref, stepName, backRef string) source.CollectionVerificationResult {
	coll := attestation.Collection{
		Name: stepName,
		Attestations: []attestation.CollectionAttestation{
			{Type: noopStepAttType, Attestation: &dummyAttestor{name: ref, typeStr: noopStepAttType}},
		},
	}
	if backRef != "" {
		coll.RecordedBackRefs = map[string]cryptoutil.DigestSet{"ref": newDigestSet(backRef)}
	}

	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference:  ref,
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
}

func earlyExitVerifier(t *testing.T) (cryptoutil.Verifier, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	return verifier, keyID
}

// releaseShapedSource builds the subject graph of the cilock release gate plus
// `noise` historical collections per step hanging off the depth-2 digest.
//
//	sha256:binary  --> build collection      (backref sha256:pipeline)
//	sha256:pipeline --> source-git collection (backref sha256:commit)
//	sha256:commit  --> `noise` unrelated build + source-git collections
func releaseShapedSource(verifier cryptoutil.Verifier, noise int) *reachableSource {
	src := &reachableSource{byDigest: map[string][]source.CollectionVerificationResult{}}

	src.byDigest["sha256:binary"] = []source.CollectionVerificationResult{
		earlyExitCollection(verifier, "build-current", "build", "sha256:pipeline"),
	}
	src.byDigest["sha256:pipeline"] = []source.CollectionVerificationResult{
		earlyExitCollection(verifier, "source-git-current", "source-git", "sha256:commit"),
	}

	historical := make([]source.CollectionVerificationResult, 0, noise*2)
	for i := 0; i < noise; i++ {
		historical = append(historical,
			earlyExitCollection(verifier, fmt.Sprintf("source-git-old-%d", i), "source-git", ""),
			earlyExitCollection(verifier, fmt.Sprintf("build-old-%d", i), "build", ""),
		)
	}
	src.byDigest["sha256:commit"] = historical

	return src
}

func releaseShapedPolicy(keyID string) Policy {
	step := func(name string) Step {
		return Step{
			Name:          name,
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: noopStepAttType}},
		}
	}
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			"source-git": step("source-git"),
			"build":      step("build"),
		},
	}
}

// Once every step is satisfied, the depth loop must stop. Before judge#7551 the
// loop ran a fixed 3 iterations and re-searched every step against the
// accumulated digest set, pulling in every historical collection reachable from
// the depth-1 back-references.
//
// Fails on revert: without the early exit the third depth iteration searches
// sha256:commit and the source hands back all 200 historical collections.
func TestEarlyExit_StopsExpandingOnceEveryStepIsSatisfied(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	const noisePerStep = 100
	src := releaseShapedSource(verifier, noisePerStep)
	p := releaseShapedPolicy(keyID)

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:binary"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)
	assert.True(t, pass, "both steps are satisfiable from the seed digest; the verdict must still be PASS")
	require.Len(t, results["build"].Passed, 1)
	require.Len(t, results["source-git"].Passed, 1)

	// build is found at depth 0, source-git at depth 1 via build's back-reference.
	// Both steps are then satisfied, so depth 2 — the one that would drag in the
	// 200 historical collections — must never run.
	assert.Equal(t, 2, src.candidate,
		"only the two collections the policy actually needs may be fetched; a third depth iteration would fetch all %d historical ones", noisePerStep*2)

	// The crisp invariant: source-git's own back-reference is added to the seed
	// set at the end of depth 1, but the policy is satisfied by then, so it must
	// never be submitted to a search.
	_, expanded := src.searchedDigests["sha256:commit"]
	assert.False(t, expanded,
		"the depth-2 digest must never be searched once every step is already satisfied")
}

// Verdict preservation: a step that is only reachable at depth 2 must still be
// found. This is the guard against "fixing" the fan-out by simply cutting the
// search short — the loop may only stop when the policy is ALREADY satisfied.
func TestEarlyExit_StillReachesEvidenceOnlyFoundAtDepthTwo(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	src := &reachableSource{byDigest: map[string][]source.CollectionVerificationResult{
		"sha256:binary": {earlyExitCollection(verifier, "build-current", "build", "sha256:pipeline")},
		// Nothing for source-git at depth 1 — only an intermediate hop that
		// carries the back-reference onward.
		"sha256:pipeline": {earlyExitCollection(verifier, "build-hop", "build", "sha256:commit")},
		"sha256:commit":   {earlyExitCollection(verifier, "source-git-current", "source-git", "")},
	}}

	pass, results, err := p7551Verify(t, releaseShapedPolicy(keyID), src)
	require.NoError(t, err)
	assert.True(t, pass, "source-git is only reachable at depth 2; the early exit must not cut the search before the policy is satisfied")
	assert.Len(t, results["source-git"].Passed, 1)
}

// A policy whose steps declare AttestationsFrom feeds upstream passed
// collections into Rego, and arbitrary Rego over that set is not monotone in
// the collection count. Such a policy must run the full search.
//
// Fails on revert of searchExpansionIsMonotone: the early exit would fire at
// depth 1 and the depth-2 historical collections would never be searched.
func TestEarlyExit_NotTakenWhenAPolicyUsesAttestationsFrom(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	const noisePerStep = 100
	src := releaseShapedSource(verifier, noisePerStep)

	p := releaseShapedPolicy(keyID)
	build := p.Steps["build"]
	build.AttestationsFrom = []string{"source-git"}
	p.Steps["build"] = build

	require.False(t, p.searchExpansionIsMonotone(),
		"a policy with AttestationsFrom must not be treated as monotone")

	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:binary"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	assert.Greater(t, src.candidate, 2,
		"a non-monotone policy must keep expanding; the full depth-2 search has to run")
}

// The unconditional half of the fix: an iteration that discovers no new digests
// means the next one would issue byte-identical queries.
func TestEarlyExit_StopsWhenNoNewDigestsAreDiscovered(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	// build is satisfied but source-git can never be: no collection named
	// source-git exists anywhere in the graph. The policy therefore never
	// becomes satisfied, so only the "no new digests" guard can stop the loop.
	src := &reachableSource{byDigest: map[string][]source.CollectionVerificationResult{
		"sha256:binary": {earlyExitCollection(verifier, "build-current", "build", "")},
	}}

	pass, _, err := p7551Verify(t, releaseShapedPolicy(keyID), src)
	require.NoError(t, err)
	assert.False(t, pass, "source-git has no evidence anywhere; the verdict must be FAIL")

	// One search per step for the single depth iteration, plus the one
	// empty-result diagnostic re-probe that source-git's zero-result search
	// triggers. A second depth iteration would add two more.
	assert.Equal(t, 3, src.searches,
		"the seed iteration discovered no back-references, so a second identical iteration must not run")
}

func p7551Verify(t *testing.T, p Policy, src *reachableSource) (bool, map[string]StepResult, error) {
	t.Helper()
	return p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:binary"}),
		WithSearchDepth(3),
	)
}
