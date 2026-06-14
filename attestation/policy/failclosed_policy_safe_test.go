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
// Fail-closed acceptance tests for the policy verifier — change-set
// "policy-safe" (issues #5746 / #5747).
//
// These were the RED tests (originally gated behind the `redgate` build tag in
// redgate_findings_test.go); they assert the CORRECT, fail-closed behavior and
// now PASS against the fixed verifier. Two findings are covered here:
//
//   - B   (#5747) verifySteps backref harvest must iterate stepResult.Passed
//         (gate survivors), NOT the functionary-only survivors — a rejected
//         collection's BackRefs must not widen the reachable-subject set.
//   - F12 (#5746) Verify must not accumulate duplicate Passed collections across
//         depth iterations (cross-depth de-duplication).
// ============================================================================

package policy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// digestAwareTestSource returns different collections depending on which subject
// digests verifySteps searches with. This lets a test prove whether a digest
// leaked into the reachable-subject set across depth iterations (finding B).
// triggeredResults are returned (in addition to defaultResults) whenever
// triggerDigest appears in the search's subjectDigests.
//
// Named with a "Test" suffix so it does not collide with the redgate-only
// digestAwareSource in redgate_findings_test.go when both files are compiled
// under the `redgate` build tag.
type digestAwareTestSource struct {
	defaultResults   []source.CollectionVerificationResult
	triggerDigest    string
	triggeredResults []source.CollectionVerificationResult
}

func (s *digestAwareTestSource) Search(_ context.Context, _ string, subjectDigests []string, _ []string) ([]source.CollectionVerificationResult, error) {
	out := append([]source.CollectionVerificationResult{}, s.defaultResults...)
	for _, d := range subjectDigests {
		if d == s.triggerDigest {
			out = append(out, s.triggeredResults...)
			break
		}
	}
	return out, nil
}

func (s *digestAwareTestSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// F12 (#5746) — policy.go verifySteps cross-depth merge.
// Fail-closed contract: a single collection that the source returns on every
// depth iteration must appear in StepResult.Passed AT MOST ONCE. The cross-
// depth merge must not accumulate duplicate passed collections (which inflates
// trust signals and the step_results UI).
// ---------------------------------------------------------------------------
func TestRed_F12_NoDuplicatePassedAcrossDepthIterations(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	stepName := "build"
	// The step declares a real required attestation type and the collection
	// carries it, so the collection actually PASSES the step gate. This is
	// required since #5754 finding F9: a step with an EMPTY Attestations list is
	// a misconfigured no-op gate that now rejects every collection. Without a
	// passing collection there would be nothing in Passed to (fail to) dedup, so
	// the F12 invariant could not be exercised at all.
	cvr := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{
				Name: stepName,
				Attestations: []attestation.CollectionAttestation{
					{Type: noopStepAttType, Attestation: &dummyAttestor{name: "build-att", typeStr: noopStepAttType}},
				},
			},
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
	// Source returns the SAME collection regardless of subject digests, so a
	// merge bug across depths will append it once per depth iteration.
	ms := &mockVerifiedSource{results: []source.CollectionVerificationResult{cvr}}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			stepName: {
				Name:          stepName,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: noopStepAttType}},
			},
		},
	}

	_, results, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(3), // 3 iterations -> 3 appends if the merge bug is present
	)
	require.NoError(t, err)
	assert.Len(t, results[stepName].Passed, 1,
		"the same collection seen across 3 depth iterations must be deduped to a single Passed entry, not accumulated")
}

// ---------------------------------------------------------------------------
// B (#5747) — policy.go verifySteps backref harvest source.
// Fail-closed contract: backref expansion must iterate the step's
// policy-PASSED collections (stepResult.Passed), NOT the functionary-survivors
// (passedCollections). A collection that clears the functionary check but is
// REJECTED by the step gate must NOT have its signer-asserted BackRefs harvested
// into the reachable-subject set — otherwise a throwaway rejected collection can
// make an unrelated downstream collection reachable.
// ---------------------------------------------------------------------------
func TestRed_B_RejectedCollectionBackrefMustNotWidenSearch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	const seedDigest = "sha256:seed"
	const leakedDigest = "sha256:leaked-via-backref"
	reqAttType := "https://example.com/required/v1"

	// "seed" collection: clears the functionary check (valid verifier + matching
	// PublicKeyID) but is REJECTED by the gate because the required attestation
	// type is absent. It carries a RecordedBackRef pointing at leakedDigest.
	seedColl := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{
				Name:             "seed",
				RecordedBackRefs: map[string]cryptoutil.DigestSet{"ref": newDigestSet(leakedDigest)},
				// no Attestations -> required attestation is missing -> gate rejects
			},
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// "target" collection: only reachable if leakedDigest enters the search set.
	targetColl := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "target"},
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// The target collection is returned ONLY when leakedDigest is searched.
	src := &digestAwareTestSource{
		defaultResults:   []source.CollectionVerificationResult{seedColl},
		triggerDigest:    leakedDigest,
		triggeredResults: []source.CollectionVerificationResult{targetColl},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			"seed": {
				Name:          "seed",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: reqAttType}}, // missing in seedColl -> rejected
			},
			"target": {
				Name:          "target",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
			},
		},
	}

	_, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{seedDigest}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)

	// Fail-closed contract: the REJECTED seed collection's backref must not have
	// widened the search, so target must never find its collection.
	assert.Empty(t, results["target"].Passed,
		"a functionary-passed but gate-REJECTED collection must not contribute its BackRefs to the reachable-subject set")
}
