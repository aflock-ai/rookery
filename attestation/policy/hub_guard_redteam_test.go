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
//
// ============================================================================
// RED TEAM: envelope explosion against the back-reference path.
//
// Verification follows only what the seed matches: relationship edges
// (BackRefs) are no longer followed, so no asserted back-reference, from a
// gate-passing collection or a gate-rejected one, ever enters the search
// frontier. These tests used to pin the bounds on the old expansion walk
// (the empty-tree guard, linear growth, the depth cap); they now pin the
// stronger property that replaced all three: the frontier is the seed set.
// WithMaxSubjectFanout (production default VERIFY_SUBJECT_FANOUT_LIMIT=32)
// remains the bound on hub digests inside the seed set.
// ============================================================================

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
)

// redTeamCanaryDigest is an ordinary, non-degenerate digest added to every
// red-team fixture. Under the old walk it always expanded; it must now never
// reach a search, which proves the fixture's collection passed its gate and
// its edges were still not followed.
const redTeamCanaryDigest = "c0ffee00000000000000000000000000000000000000000000000000deadbeef"

// countingSource records every digest the policy engine ever searches on, so a
// test can assert the FRONTIER's size rather than eyeballing reach.
type countingSource struct {
	results   []source.CollectionVerificationResult
	seen      map[string]struct{}
	perSearch []int
}

func (s *countingSource) Search(_ context.Context, _ string, subjectDigests []string, _ []string) ([]source.CollectionVerificationResult, error) {
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	for _, d := range subjectDigests {
		s.seen[d] = struct{}{}
	}
	s.perSearch = append(s.perSearch, len(subjectDigests))
	return s.results, nil
}

func (s *countingSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// redTeamVerify runs a one-step policy whose single collection asserts the
// supplied back-references, and reports every digest that entered the search.
func redTeamVerify(t *testing.T, backRefs map[string]cryptoutil.DigestSet, gatePasses bool) *countingSource {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	// CANARY: a always-unguarded real digest, added to every fixture. It
	// guarantees the depth loop keeps iterating even when every digest under
	// test is guarded away — so "the digest never reached a search" is a real
	// observation about that digest, not an artifact of the loop stopping.
	refs := map[string]cryptoutil.DigestSet{
		"https://example.com/attestations/canary/v1/ref:canary": newDigestSet(redTeamCanaryDigest),
	}
	for k, v := range backRefs {
		refs[k] = v
	}

	coll := attestation.Collection{Name: "attacker", RecordedBackRefs: refs}
	if gatePasses {
		coll.Attestations = []attestation.CollectionAttestation{{
			Type:        hubGuardAttType,
			Attestation: &dummyAttestor{name: "a", typeStr: hubGuardAttType},
		}}
	}

	src := &countingSource{results: []source.CollectionVerificationResult{{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}}}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			"attacker": {
				Name:          "attacker",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: hubGuardAttType}},
			},
			// A step that can NEVER be satisfied: no collection carries this
			// attestation type. Without it, verifySteps takes its
			// allStepsSatisfied early exit after depth 0 and never issues a
			// second search — which would make every frontier assertion below
			// vacuous, since the expanded digests are only visible on the NEXT
			// depth's search.
			"never-satisfied": {
				Name:          "never-satisfied",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: "https://example.com/never/v1"}},
			},
		},
	}
	_, _, err = p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:seed"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)

	// The canary is an ordinary edge; edges are not followed, so it never
	// reaches a search whether or not the collection passed its gate.
	_, canarySeen := src.seen[redTeamCanaryDigest]
	require.False(t, canarySeen, "a back-reference must never become a search seed")
	return src
}

// Every documented degenerate/low-entropy constant an attacker might use to
// re-hub the graph. Under the old walk only sha256("") under a tree key was
// dropped and the rest expanded the search. Edges are no longer followed, so
// none of them may enter the frontier.
func TestRedTeam_DegenerateConstantsInFrontier(t *testing.T) {
	cases := []struct {
		name   string
		digest string
	}{
		{"sha256 of empty input (non-tree key)", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"all-zero sha256", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"all-zero sha1 (branch create/delete sentinel)", "0000000000000000000000000000000000000000"},
		{`sha256("judge")`, "10e86c6514d40f2a3e861b31847340ee8c8ed181029a17b042f137121d28863e"},
		// The real sha256("main") — this is the `refnameshort:main` digest, a
		// measured hub carried as a subject by 1,269 production envelopes.
		{`sha256("main")`, "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := redTeamVerify(t, map[string]cryptoutil.DigestSet{
				"https://example.com/attestations/attacker/v1/ref:x": newDigestSet(tc.digest),
			}, true)
			_, entered := src.seen[tc.digest]
			assert.False(t, entered,
				"%s is a back-reference; edges are not followed, so it must never enter the search frontier", tc.name)
		})
	}
}

// THE ACTUAL BOUND. A gate-passing collection asserting N backrefs used to
// widen the frontier by N. Edges are no longer followed, so the frontier is
// exactly the seed set however many back-references a collection asserts.
func TestRedTeam_FrontierGrowthIsLinearNotCombinatorial(t *testing.T) {
	const n = 500
	refs := map[string]cryptoutil.DigestSet{}
	for i := 0; i < n; i++ {
		refs[fmt.Sprintf("https://example.com/attestations/attacker/v1/ref:%d", i)] =
			newDigestSet(fmt.Sprintf("%064x", i+1))
	}
	src := redTeamVerify(t, refs, true)

	assert.Equal(t, map[string]struct{}{"sha256:seed": {}}, src.seen,
		"the search frontier must be the seed set; any asserted back-reference in it means edges are followed")

	require.NotEmpty(t, src.perSearch)
	for i, n := range src.perSearch {
		assert.Equal(t, 1, n, "search %d must carry only the one seed digest", i)
	}
}

// The #5747 contract is what stops an UNAUTHORIZED signer from expanding at
// all. Pinned here because it, not the degenerate-digest guard, is the control
// that bounds an attacker who is not a policy functionary for the step.
func TestRedTeam_GateRejectedCollectionExpandsNothing(t *testing.T) {
	refs := map[string]cryptoutil.DigestSet{}
	for i := 0; i < 100; i++ {
		refs[fmt.Sprintf("https://example.com/attestations/attacker/v1/ref:%d", i)] =
			newDigestSet(fmt.Sprintf("%064x", i+1))
	}
	// gatePasses=false -> collection carries no required attestation -> rejected.
	src := redTeamVerify(t, refs, false)

	for i := 0; i < 100; i++ {
		_, entered := src.seen[fmt.Sprintf("%064x", i+1)]
		require.False(t, entered,
			"a gate-REJECTED collection must contribute no backrefs to the frontier (#5747)")
	}
}

// Depth amplification: with no edge following there is no chain to amplify.
// One pass over the seeds issues one search per step.
func TestRedTeam_DepthCapStopsChainAmplification(t *testing.T) {
	src := redTeamVerify(t, map[string]cryptoutil.DigestSet{
		"https://example.com/attestations/attacker/v1/ref:0": newDigestSet(fmt.Sprintf("%064x", 1)),
	}, true)
	// The fixture policy has 2 steps and verifySteps makes one pass, so it
	// issues exactly 2 searches. More than that means a further pass ran.
	assert.Equal(t, 2, len(src.perSearch),
		"one pass over the seeds issues one search per step; a further pass is an amplification vector")
}
