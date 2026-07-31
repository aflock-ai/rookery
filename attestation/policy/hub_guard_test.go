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
// Degenerate-digest (hub) guard for backref expansion.
//
// The RFC 6962 empty-tree root is sha256("") — the material and product
// attestors emit it as their tree root whenever a step consumed or produced
// nothing. Measured on a 16,939-envelope production corpus, that ONE value is
// emitted as a backref 3,973 times and carried as a subject by 3,314
// envelopes. Expanding on it joins every empty step into a single clique, and
// depth-3 verify fan-out balloons: 7,141 reachable envelopes from a build
// dispatch, versus 9 with the value guarded.
//
// The guard is enforced HERE, in the consumer, and not only in the attestors,
// because Collection.BackRefs() returns RecordedBackRefs when non-nil
// (collection.go) — 63% of the production corpus already carries these edges
// baked into signed payloads that cannot be re-signed.
//
// Contract: FALSE-REJECT-ONLY. The guard may only decline to WIDEN the search
// on a valueless edge. It must never remove a collection that some other, real
// digest makes reachable.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
)

const hubGuardAttType = "https://example.com/hub-guard-att/v1"

// hubGuardFixture builds a two-step policy where "target" is reachable ONLY if
// the seed collection's backref digest enters the search set. backRefs are the
// digests the (gate-PASSING) seed collection asserts; reachVia is the digest
// the source requires before it will hand back the target collection.
//
// Both steps declare a required attestation and both collections carry it: a
// step with NO declared attestations fail-closes and rejects every collection,
// which would make every assertion here vacuously "empty". The fixture asserts
// the seed step actually passed, so the test can never silently stop
// exercising the expansion path it exists to cover.
func hubGuardFixture(t *testing.T, backRefs map[string]cryptoutil.DigestSet, reachVia string) map[string]StepResult {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	withAtt := func(name string, refs map[string]cryptoutil.DigestSet) source.CollectionVerificationResult {
		return source.CollectionVerificationResult{
			Verifiers: []cryptoutil.Verifier{verifier},
			CollectionEnvelope: source.CollectionEnvelope{
				Collection: attestation.Collection{
					Name:             name,
					RecordedBackRefs: refs,
					Attestations: []attestation.CollectionAttestation{{
						Type:        hubGuardAttType,
						Attestation: &dummyAttestor{name: name + "-att", typeStr: hubGuardAttType},
					}},
				},
				Statement: intoto.Statement{PredicateType: attestation.CollectionType},
			},
		}
	}

	src := &digestAwareTestSource{
		defaultResults:   []source.CollectionVerificationResult{withAtt("seed", backRefs)},
		triggerDigest:    reachVia,
		triggeredResults: []source.CollectionVerificationResult{withAtt("target", nil)},
	}

	step := func(name string) Step {
		return Step{
			Name:          name,
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: hubGuardAttType}},
		}
	}
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps:   map[string]Step{"seed": step("seed"), "target": step("target")},
	}

	_, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:seed"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)

	// Guard against a vacuous pass: if the seed step did not itself pass, no
	// backrefs were ever harvested and the assertions below prove nothing.
	require.NotEmpty(t, results["seed"].Passed,
		"fixture precondition: the seed collection must PASS its gate, otherwise "+
			"its backrefs are never harvested and this test cannot reach its case")
	return results
}

// RED before the guard: the empty-tree root must not widen the search.
func TestHubGuard_EmptyTreeDigestDoesNotWidenSearch(t *testing.T) {
	results := hubGuardFixture(t,
		map[string]cryptoutil.DigestSet{
			"https://aflock.ai/attestations/product/v0.3/tree:products": newDigestSet(sha256OfEmpty),
		},
		sha256OfEmpty,
	)

	assert.Empty(t, results["target"].Passed,
		"the RFC 6962 empty-tree root (sha256 of empty input) carries no identity: "+
			"every step that produced nothing shares it, so it must not expand the search set")
}

// NEGATIVE CONTROL: a real tree root must still widen the search. Guards
// against an over-broad filter that eats legitimate artifact-flow edges.
func TestHubGuard_RealTreeDigestStillWidensSearch(t *testing.T) {
	const realRoot = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	results := hubGuardFixture(t,
		map[string]cryptoutil.DigestSet{
			"https://aflock.ai/attestations/product/v0.3/tree:products": newDigestSet(realRoot),
		},
		realRoot,
	)

	assert.Len(t, results["target"].Passed, 1,
		"a non-degenerate tree root is a real artifact-flow edge and must still expand the search set")
}

// FALSE-REJECT-ONLY: a collection reachable through BOTH the empty root and a
// real digest must still be reached, via the real digest. The guard drops the
// valueless EDGE, never the collection.
func TestHubGuard_IsFalseRejectOnly(t *testing.T) {
	const realRoot = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
	results := hubGuardFixture(t,
		map[string]cryptoutil.DigestSet{
			"https://aflock.ai/attestations/product/v0.3/tree:products":   newDigestSet(sha256OfEmpty),
			"https://aflock.ai/attestations/material/v0.3/tree:materials": newDigestSet(realRoot),
		},
		realRoot,
	)

	assert.Len(t, results["target"].Passed, 1,
		"dropping the degenerate edge must not remove a collection that a real digest makes reachable")
}

// A GENUINELY ZERO-BYTE ARTIFACT STILL VERIFIES.
//
// Raised in review on #7689: "sha256(\"\") legitimately identifies a zero-byte
// artifact, so this can suppress valid evidence relationships unrelated to
// empty merkle-tree roots and cause incorrect policy rejection."
//
// It does not. The guard has exactly ONE call site — the back-reference
// EXPANSION loop in verifySteps. It is not consulted when seeding
// (WithSubjectDigests) and not consulted when matching (the Sourcer subject
// index). So an operator verifying an artifact that really is empty seeds on
// the digest and matches collections by subject, and both paths run untouched.
// The only thing withheld is CHASING that digest outward to pull in unrelated
// evidence — which is exactly the behaviour that has no identifying value,
// because every empty artifact in existence shares the digest.
//
// Corpus evidence for the "unrelated to empty tree roots" half: across 16,939
// production envelopes, sha256("") appears as a back-reference 3,973 times and
// 100.0000% of those are material/product tree roots. Non-tree back-reference
// emissions of this value: ZERO.
func TestHubGuard_ZeroByteArtifactStillVerifiesWhenSeededOnIt(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	empty := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{
				Name: "empty-artifact",
				Attestations: []attestation.CollectionAttestation{{
					Type:        hubGuardAttType,
					Attestation: &dummyAttestor{name: "e", typeStr: hubGuardAttType},
				}},
			},
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
	// The source yields the collection ONLY when sha256("") is searched, so a
	// pass here can only come from the seed digest reaching the search.
	src := &digestAwareTestSource{
		triggerDigest:    sha256OfEmpty,
		triggeredResults: []source.CollectionVerificationResult{empty},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{"empty-artifact": {
			Name:          "empty-artifact",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: hubGuardAttType}},
		}},
	}

	passed, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{sha256OfEmpty}), // the operator's real, empty artifact
		WithSearchDepth(3),
	)
	require.NoError(t, err)

	assert.True(t, passed,
		"seeding on sha256(\"\") must still verify a genuinely zero-byte artifact: the guard "+
			"governs back-reference EXPANSION only, never seeding or subject matching")
	assert.Len(t, results["empty-artifact"].Passed, 1,
		"the collection whose subject is the empty digest must still be found and pass its gate")
}

// A ZERO-BYTE ARTIFACT REACHED ONLY THROUGH EXPANSION STILL VERIFIES.
//
// This is the case a value-blind guard got wrong, raised in review on #7689 and
// reproduced before the fix: a collection whose ONLY path is another
// collection's back-reference to a genuinely empty artifact was never searched,
// so it silently failed to verify. sha256("") is the legitimate content digest
// of a zero-byte file; only as a *tree root* is it a shared sentinel.
//
// Distinct from TestHubGuard_ZeroByteArtifactStillVerifiesWhenSeededOnIt, which
// covers the SEEDING path. Both are needed: the seeding test passes even under a
// value-blind guard, so it cannot catch this regression on its own.
func TestHubGuard_ZeroByteArtifactReachedViaExpansionStillVerifies(t *testing.T) {
	results := hubGuardFixture(t,
		map[string]cryptoutil.DigestSet{
			// A build step naming its genuinely empty output. NOT a tree root.
			"https://example.com/attestations/build/v1/output:empty.txt": newDigestSet(sha256OfEmpty),
		},
		sha256OfEmpty,
	)

	assert.Len(t, results["target"].Passed, 1,
		"sha256(\"\") is the real content digest of a zero-byte artifact outside the tree-root "+
			"contract; an edge naming one must still widen the search, or evidence reachable "+
			"only through it is falsely rejected")
}

// The empty-tree SENTINEL is still dropped — scoping is by back-reference
// contract, so the material/product tree roots this guard exists for are
// unaffected by the fix above.
func TestHubGuard_EmptyTreeSentinelStillDroppedUnderMaterialAndProduct(t *testing.T) {
	for _, name := range []string{
		"https://aflock.ai/attestations/material/v0.3/tree:materials",
		"https://aflock.ai/attestations/product/v0.3/tree:products",
		// Vendor/version prefix is not part of the contract — the suffix is.
		"https://witness.testifysec.com/attestations/product/v0.9/tree:products",
	} {
		t.Run(name, func(t *testing.T) {
			results := hubGuardFixture(t,
				map[string]cryptoutil.DigestSet{name: newDigestSet(sha256OfEmpty)},
				sha256OfEmpty,
			)
			assert.Empty(t, results["target"].Passed,
				"the empty-tree root is shared identically by every step that consumed or "+
					"produced nothing, so it must not widen the search")
		})
	}
}

// LAUNDERING IS DELIBERATELY NOT DEFENDED — this test asserts the CURRENT
// contract, which is the inverse of what an earlier revision of this file
// asserted. Do not "fix" it back without reading this.
//
// The earlier version pinned that relabelling sha256("") under a
// legitimate-looking key (e.g. "commithash:") was still dropped, on the theory
// that a value-blind guard was laundering-proof. That defense was worth less
// than it looked, and it cost a real false-reject (see the expansion test
// above), so it was given up deliberately.
//
// Why it is worth little: back-references are only harvested from collections
// that PASS the step gate (#5747). An adversary who can get a relabelled digest
// into the frontier is therefore ALREADY a policy-authorized functionary for
// that step — and such an adversary can simply emit a real high-fanout digest
// instead (a shared base-image layer, a runner image, a toolchain blob), which
// is strictly more effective than laundering a value that only ever collides
// with other empty artifacts. The bound on that adversary is
// WithMaxSubjectFanout (production default VERIFY_SUBJECT_FANOUT_LIMIT=32),
// not this guard.
func TestHubGuard_LaunderedEmptyDigestUnderNonTreeKeyIsNotDropped(t *testing.T) {
	results := hubGuardFixture(t,
		map[string]cryptoutil.DigestSet{
			"https://example.com/attestations/attacker/v1/commithash:deadbeef": newDigestSet(sha256OfEmpty),
		},
		sha256OfEmpty,
	)

	assert.Len(t, results["target"].Passed, 1,
		"outside the tree-root contract this guard does not filter by value; suppressing it "+
			"here would re-introduce the zero-byte-artifact false-reject for no security gain, "+
			"because the relabelling adversary is already gate-authorized and bounded by "+
			"WithMaxSubjectFanout")
}
