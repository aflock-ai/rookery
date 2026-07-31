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
// RED TEAM: envelope explosion against the back-reference expansion path.
//
// WHAT THE DEGENERATE-DIGEST GUARD DOES AND DOES NOT BOUND — read this before
// treating it as an anti-explosion control:
//
//   It removes ONE specific valueless value (sha256 of empty input) from the
//   expansion frontier. It is a de-hubbing fix for evidence that is already
//   signed and cannot be re-signed. It is NOT a bound on frontier growth.
//
//   A collection that PASSES its step gate may still assert arbitrarily many
//   back-references, and every one of them widens the next depth. The controls
//   that actually bound the walk are, in order:
//
//     1. #5747 — only collections that pass the STEP GATE contribute backrefs
//        (policy.go, verifySteps). An unauthorized signer expands nothing.
//     2. WithMaxSubjectFanout / filterHubOnlyPassed — candidates whose only
//        intersection with the closure is a high-fanout digest are rejected
//        before the gate. Production default VERIFY_SUBJECT_FANOUT_LIMIT=32.
//     3. searchDepth (default 3) — a hard cap on iterations.
//
//   These tests pin that division of labour so a future change cannot quietly
//   reclassify the guard as the bound.
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

// redTeamCanaryDigest is an unguarded, non-degenerate digest added to every
// red-team fixture so the depth loop always has something to expand on.
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

	// Precondition (gate-passing fixtures only): the CANARY backref must have
	// reached a search. That proves the depth loop iterated and the frontier
	// was re-searched, so "digest X never appeared" is a fact about X and not
	// an artifact of the loop stopping early.
	if gatePasses {
		_, canarySeen := src.seen[redTeamCanaryDigest]
		require.True(t, canarySeen,
			"fixture precondition: the canary backref must reach a search, otherwise the "+
				"depth loop never re-searched and every frontier assertion here is vacuous")
	}
	return src
}

// Every documented degenerate/low-entropy constant an attacker might use to
// re-hub the graph. Only sha256("") is currently guarded — the rest are listed
// so the test records exactly which values DO still expand the search, and a
// future widening of the guard has a ready-made table.
func TestRedTeam_DegenerateConstantsInFrontier(t *testing.T) {
	cases := []struct {
		name    string
		digest  string
		guarded bool
	}{
		// Guarded ONLY under the tree-root contract; this fixture emits it under
		// an attacker-chosen key, so it is expected to pass through. See
		// TestHubGuard_LaunderedEmptyDigestUnderNonTreeKeyIsNotDropped.
		{"sha256 of empty input (non-tree key)", sha256OfEmpty, false},
		{"all-zero sha256", "0000000000000000000000000000000000000000000000000000000000000000", false},
		{"all-zero sha1 (branch create/delete sentinel)", "0000000000000000000000000000000000000000", false},
		{`sha256("judge")`, "10e86c6514d40f2a3e861b31847340ee8c8ed181029a17b042f137121d28863e", false},
		// The real sha256("main") — this is the `refnameshort:main` digest, a
		// measured hub carried as a subject by 1,269 production envelopes.
		{`sha256("main")`, "0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := redTeamVerify(t, map[string]cryptoutil.DigestSet{
				"https://example.com/attestations/attacker/v1/ref:x": newDigestSet(tc.digest),
			}, true)
			_, entered := src.seen[tc.digest]
			if tc.guarded {
				assert.False(t, entered,
					"%s is guarded and must never enter the search frontier", tc.name)
			} else {
				assert.True(t, entered,
					"%s is NOT currently guarded; this test records that fact. If a future "+
						"change adds it to isEmptyTreeHubBackRef, flip guarded:true here.", tc.name)
			}
		})
	}
}

// THE ACTUAL BOUND. A gate-passing collection asserting N backrefs widens the
// frontier by N — the guard bounds nothing here, and pretending otherwise
// would be the dangerous reading. What DOES hold: growth is linear in the
// asserted backref count, never combinatorial, because knownDigests dedupes
// and expansion is deferred to the next depth.
func TestRedTeam_FrontierGrowthIsLinearNotCombinatorial(t *testing.T) {
	const n = 500
	refs := map[string]cryptoutil.DigestSet{}
	for i := 0; i < n; i++ {
		refs[fmt.Sprintf("https://example.com/attestations/attacker/v1/ref:%d", i)] =
			newDigestSet(fmt.Sprintf("%064x", i+1))
	}
	src := redTeamVerify(t, refs, true)

	// seed + n asserted backrefs, and NOT more: no depth may re-expand a digest
	// already known, so the ceiling is exactly 1+n however many depths run.
	// seed + n asserted backrefs + 1 canary.
	assert.LessOrEqual(t, len(src.seen), 2+n,
		"frontier must be bounded by seed+asserted backrefs+canary; anything larger means a "+
			"digest was re-expanded across depths and growth is combinatorial")

	require.NotEmpty(t, src.perSearch)
	assert.LessOrEqual(t, src.perSearch[len(src.perSearch)-1], 2+n,
		"the final search must not carry more digests than seed+asserted backrefs+canary")
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

// Depth amplification: a chain longer than searchDepth must stop at the cap,
// not run to exhaustion.
func TestRedTeam_DepthCapStopsChainAmplification(t *testing.T) {
	src := redTeamVerify(t, map[string]cryptoutil.DigestSet{
		"https://example.com/attestations/attacker/v1/ref:0": newDigestSet(fmt.Sprintf("%064x", 1)),
	}, true)
	// The fixture policy has 2 steps and searchDepth 3, so verifySteps may
	// issue at most 2*3 searches. More than that means the depth cap leaked.
	assert.LessOrEqual(t, len(src.perSearch), 6,
		"searches must not exceed steps*searchDepth; an unbounded loop here is an amplification vector")
}
