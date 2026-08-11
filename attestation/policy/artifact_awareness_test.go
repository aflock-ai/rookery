// Copyright 2026 The Rookery Contributors
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

// These tests pin the ARTIFACT-AWARENESS invariant of the depth loop's early
// break: allStepsSatisfied (policy.go) must consult verifyCollectionArtifacts,
// not merely StepResult.Analyze(), before declaring the policy settled.
//
// Why they exist: as of main@864122ee69 the invariant had ZERO coverage.
// Deleting the entire verifyCollectionArtifacts block from allStepsSatisfied
// left `go test ./policy/` fully green (2.717s baseline -> 2.846s mutated, zero
// reds). Both tests below redden under that deletion. This is the mandatory
// first mutation-ledger entry for Phase 2 of
// docs/design/minimum-witness-verification.md (§10.8).
//
// FIXTURE TRAP (design doc §10.7): passedCollectionKey hashes only
// (Statement, verified key IDs). Two candidates for the SAME step built the
// obvious way — identical zero-value statements — collapse to one entry in
// mergePassedCollections, which would silently vacuum out the depth-discovery
// case these tests exist to cover. artifactCollection therefore stamps a
// per-reference Statement.Subject, and the tests assert non-collapse
// explicitly. TestArtifactAwareness_IdenticalStatementFixturesCollapse pins
// the trap itself so the guard cannot rot into a no-op.

package policy

import (
	"context"
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

const (
	artProductType  = "https://aflock.ai/attestations/product/v0.3"
	artMaterialType = "https://aflock.ai/attestations/material/v0.3"
)

// artifactCollection builds a gate-passing source result for stepName carrying
// v0.3 inline product/material attestors and an optional back-reference.
//
// The collection deliberately carries NO Envelope.Payload: that keeps it on the
// uncompacted path (step.go: pass-time compaction only fires when a raw payload
// was retained), so the typed attestors survive into verifyCollectionArtifacts
// instead of being dropped and re-decoded from bytes these fixtures don't have.
//
// Statement.Subject is stamped with the collection's own reference so that no
// two fixtures share a statement — see the FIXTURE TRAP note at the top.
func artifactCollection(verifier cryptoutil.Verifier, ref, stepName string, attestors []attestation.Attestor, backRef string) source.CollectionVerificationResult {
	cas := make([]attestation.CollectionAttestation, 0, len(attestors))
	for _, at := range attestors {
		cas = append(cas, attestation.CollectionAttestation{Type: at.Type(), Attestation: at})
	}

	coll := attestation.Collection{Name: stepName, Attestations: cas}
	if backRef != "" {
		coll.RecordedBackRefs = map[string]cryptoutil.DigestSet{"ref": newDigestSet(backRef)}
	}

	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference:  ref,
			Collection: coll,
			Statement: intoto.Statement{
				PredicateType: attestation.CollectionType,
				Subject:       []intoto.Subject{{Name: ref, Digest: map[string]string{"sha256": ref}}},
			},
		},
	}
}

func productAttestor(products map[string]cryptoutil.DigestSet) attestation.Attestor {
	p := make(map[string]attestation.Product, len(products))
	for path, d := range products {
		p[path] = attestation.Product{Digest: d}
	}
	return &inlineFakeAttestor{typ: artProductType, products: p}
}

func materialAttestor(materials map[string]cryptoutil.DigestSet) attestation.Attestor {
	return &inlineFakeAttestor{typ: artMaterialType, materials: materials, inlinePresent: true}
}

// artifactChainPolicy is the minimal shape the invariant lives on: build
// consumes source's products via artifactsFrom, and NOTHING declares
// AttestationsFrom (so searchExpansionIsMonotone stays true and the depth
// loop's early break is actually reachable).
func artifactChainPolicy(keyID string) Policy {
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			"source": {
				Name:          "source",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: artProductType}},
			},
			"build": {
				Name:          "build",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: artMaterialType}},
				ArtifactsFrom: []string{"source"},
			},
		},
	}
}

// artifactChainFixtures returns the three collections the depth-discovery
// corpus is built from:
//
//	build       consumes libshared.so@good, back-references sha256:pipeline
//	sourceWrong publishes libshared.so@BAD  (reachable at depth 0)
//	sourceRight publishes libshared.so@good (reachable ONLY at depth 1)
func artifactChainFixtures(verifier cryptoutil.Verifier) (build, sourceWrong, sourceRight source.CollectionVerificationResult) {
	good := digest("aa")
	bad := digest("bb")

	build = artifactCollection(verifier, "build-v1", "build",
		[]attestation.Attestor{materialAttestor(map[string]cryptoutil.DigestSet{"libshared.so": good})},
		"sha256:pipeline")

	sourceWrong = artifactCollection(verifier, "source-v1", "source",
		[]attestation.Attestor{productAttestor(map[string]cryptoutil.DigestSet{"libshared.so": bad})}, "")

	sourceRight = artifactCollection(verifier, "source-v2", "source",
		[]attestation.Attestor{productAttestor(map[string]cryptoutil.DigestSet{"libshared.so": good})}, "")

	return build, sourceWrong, sourceRight
}

// ---------------------------------------------------------------------------
// Ledger entry 1 — the depth-discovered-upstream case, through the real Verify().
// ---------------------------------------------------------------------------

// The artifact-satisfying upstream is reachable ONLY through the downstream
// collection's back-reference, discovered at depth 1. A depth-0 decoy named for
// the same step passes the step gate (Analyze() == true) but publishes a
// MISMATCHING product digest.
//
// With artifact awareness (HEAD): allStepsSatisfied runs
// verifyCollectionArtifacts, sees build's chain unsatisfied by the decoy alone,
// returns false, the loop proceeds to depth 1, finds source-v2, and the verdict
// is PASS.
//
// Under the mutation (delete the verifyCollectionArtifacts block from
// allStepsSatisfied): both steps report Analyze() == true at the end of depth 0,
// the loop breaks early, source-v2 is never discovered, verifyArtifacts then
// fails build on the digest mismatch — verdict FAIL. THIS TEST REDDENS.
func TestArtifactAwareness_DepthDiscoveredUpstreamStillReached(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	build, sourceWrong, sourceRight := artifactChainFixtures(verifier)

	// Fixture-collapse guard (design doc §10.7), asserted on the PRISTINE
	// fixtures before the engine touches them: the two same-step candidates
	// must carry distinct merge identities, or mergePassedCollections would
	// drop source-v2 at depth 1 and this test would be measuring nothing.
	require.NotEqual(t,
		passedCollectionKeyOf(PassedCollection{Collection: sourceWrong}),
		passedCollectionKeyOf(PassedCollection{Collection: sourceRight}),
		"the two source fixtures must NOT share a merge key; identical statements collapse in mergePassedCollections and vacuum out this test")

	src := &reachableSource{byDigest: map[string][]source.CollectionVerificationResult{
		"sha256:binary":   {build, sourceWrong},
		"sha256:pipeline": {sourceRight},
	}}

	pass, results, err := artifactChainPolicy(keyID).Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:binary"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)

	// The load-bearing assertion, checked FIRST so its message is the one a
	// future reader sees: source-v2 lives only behind build's back-reference,
	// so its presence proves the depth loop kept searching past depth 0.
	// (Fixture collapse is already ruled out by the merge-key guard above, so
	// an absence here means the early break fired too soon — nothing else.)
	require.True(t, refPresent(results["source"].Passed, "source-v2"),
		"the depth-1 upstream was never discovered: the depth loop broke at depth 0 on Analyze() alone, without checking whether build's artifactsFrom edge was actually satisfied")

	// And the depth-0 decoy is still retained alongside it — the search widened,
	// it did not replace.
	require.Len(t, results["source"].Passed, 2,
		"both source candidates must survive the cross-depth merge (decoy from depth 0 + the real upstream from depth 1)")

	assert.True(t, pass,
		"the artifact-satisfying upstream is reachable at depth 1, so the depth loop must not break at depth 0 on Analyze() alone")
	assert.Len(t, results["build"].Passed, 1, "build's chain is satisfied by source-v2, so its passed collection must survive verifyArtifacts")
}

// ---------------------------------------------------------------------------
// Ledger entry 2 — the control.
// ---------------------------------------------------------------------------

// Both steps report Analyze() == true, but the ONLY upstream present publishes
// a mismatching digest. A naive freeze predicate (`every step has a passed
// collection`) would declare the policy settled here and stop the search; the
// artifact-aware predicate must return false.
//
// Under the deletion mutation this returns true and the test REDDENS.
func TestArtifactAwareness_AllStepsSatisfiedRejectsWrongUpstream(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	build, sourceWrong, sourceRight := artifactChainFixtures(verifier)
	p := artifactChainPolicy(keyID)

	withUpstream := func(upstream source.CollectionVerificationResult) map[string]StepResult {
		return map[string]StepResult{
			"source": {Step: "source", Passed: []PassedCollection{{Collection: upstream}}},
			"build":  {Step: "build", Passed: []PassedCollection{{Collection: build}}},
		}
	}

	wrong := withUpstream(sourceWrong)

	// The premise of the control: the naive predicate's inputs are BOTH true,
	// so a false answer below can only come from the artifact check.
	require.True(t, wrong["source"].Analyze(), "source must look satisfied to a naive predicate")
	require.True(t, wrong["build"].Analyze(), "build must look satisfied to a naive predicate")

	assert.False(t, p.allStepsSatisfied(context.Background(), &verifyOptions{}, wrong),
		"build's artifactsFrom edge is unsatisfied by the mismatching upstream, so the policy is NOT settled")

	// Positive companion — proves the false above is the artifact check firing
	// and not some unrelated defect in the fixtures.
	assert.True(t, p.allStepsSatisfied(context.Background(), &verifyOptions{}, withUpstream(sourceRight)),
		"with the matching upstream present the very same shape must be reported satisfied")
}

// ---------------------------------------------------------------------------
// The fixture trap itself (design doc §10.7), pinned executably.
// ---------------------------------------------------------------------------

// Two same-step candidates built the OBVIOUS way — no Statement, distinct
// attestor payloads — share a merge key and collapse. This is why
// artifactCollection stamps a per-reference subject. If passedCollectionKey
// ever widens to cover collection content, this test fails and the guards
// above can be simplified.
func TestArtifactAwareness_IdenticalStatementFixturesCollapse(t *testing.T) {
	a := inlineCollection("source", productAttestor(map[string]cryptoutil.DigestSet{"libshared.so": digest("aa")}))
	b := inlineCollection("source", productAttestor(map[string]cryptoutil.DigestSet{"libshared.so": digest("bb")}))

	require.Equal(t,
		passedCollectionKeyOf(PassedCollection{Collection: a}),
		passedCollectionKeyOf(PassedCollection{Collection: b}),
		"§10.7: passedCollectionKey hashes only (Statement, key IDs), so differing attestor content does NOT separate these")

	merged := mergePassedCollections(
		[]PassedCollection{{Collection: a}},
		[]PassedCollection{{Collection: b}},
	)
	require.Len(t, merged, 1, "§10.7: the obvious-way fixtures collapse to one entry — the trap this file's fixtures avoid")
}

func refPresent(pcs []PassedCollection, ref string) bool {
	for _, pc := range pcs {
		if pc.Collection.Reference == ref {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Codex round 4: the early-settlement predicate and the final verdict must
// evaluate the SAME view.
// ---------------------------------------------------------------------------

// prunableChainSource builds a three-step chain in which one of the middle
// step's collections is artifact-INVALID and the downstream step matches only
// that invalid collection:
//
//	r    products base.o@good                                  (depth 0)
//	s    artifactsFrom [r]
//	       s-c1 consumes base.o@good  -> products out1.bin@d1   (depth 0, VALID, carries the back-ref)
//	       s-c2 consumes base.o@BAD   -> products out2.bin@d2   (depth 0, INVALID)
//	       s-c3 consumes base.o@good  -> products out2.bin@d2   (depth 1, VALID — the replacement)
//	d    artifactsFrom [s], consumes out2.bin@d2                (depth 0)
//
// d can only be satisfied by out2.bin, which at depth 0 is published ONLY by
// the invalid s-c2. The collection-level pruning in verifyArtifacts removes
// s-c2, so d's evidence at depth 0 is illusory — but s-c3, reachable at depth 1
// through s-c1's back-reference, publishes the same product legitimately.
//
// withReplacement=false omits s-c3, so nothing deeper can rescue d.
func prunableChainSource(verifier cryptoutil.Verifier, withReplacement bool) *reachableSource {
	good := digest("aa")
	bad := digest("bb")
	d1 := digest("cc")
	d2 := digest("dd")

	seed := []source.CollectionVerificationResult{
		artifactCollection(verifier, "r-1", "r",
			[]attestation.Attestor{productAttestor(map[string]cryptoutil.DigestSet{"base.o": good})}, ""),
		artifactCollection(verifier, "s-c1", "s", []attestation.Attestor{
			materialAttestor(map[string]cryptoutil.DigestSet{"base.o": good}),
			productAttestor(map[string]cryptoutil.DigestSet{"out1.bin": d1}),
		}, "sha256:deeper"),
		artifactCollection(verifier, "s-c2", "s", []attestation.Attestor{
			materialAttestor(map[string]cryptoutil.DigestSet{"base.o": bad}),
			productAttestor(map[string]cryptoutil.DigestSet{"out2.bin": d2}),
		}, ""),
		artifactCollection(verifier, "d-1", "d",
			[]attestation.Attestor{materialAttestor(map[string]cryptoutil.DigestSet{"out2.bin": d2})}, ""),
	}

	deeper := []source.CollectionVerificationResult{}
	if withReplacement {
		deeper = append(deeper, artifactCollection(verifier, "s-c3", "s", []attestation.Attestor{
			materialAttestor(map[string]cryptoutil.DigestSet{"base.o": good}),
			productAttestor(map[string]cryptoutil.DigestSet{"out2.bin": d2}),
		}, ""))
	}

	return &reachableSource{byDigest: map[string][]source.CollectionVerificationResult{
		"sha256:seed":   seed,
		"sha256:deeper": deeper,
	}}
}

func prunableChainPolicy(keyID string) Policy {
	step := func(name, attType string, artifactsFrom ...string) Step {
		return Step{
			Name:          name,
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: attType}},
			ArtifactsFrom: artifactsFrom,
		}
	}
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps: map[string]Step{
			"r": step("r", artProductType),
			"s": step("s", artMaterialType, "r"),
			"d": step("d", artMaterialType, "s"),
		},
	}
}

// The early break must be decided on the PRUNED view — the same one the final
// verdict uses — or it settles on evidence the verdict is about to discard.
//
// At depth 0, d is "satisfied" only by s-c2, which verifyArtifacts then prunes
// for failing its own artifact check. A predicate reading the UNPRUNED results
// sees d satisfied, breaks the depth loop, and the verdict then rejects d —
// returning FAIL even though depth 1 holds s-c3, which satisfies d legitimately.
// That is a false FAIL manufactured by evaluating settlement on a different view
// than the verdict.
//
// RED against a predicate that reads unpruned results; MUTATION F restores that
// and this reddens.
func TestArtifactAwareness_PredicateUsesPrunedViewSoDeeperEvidenceIsStillFound(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	src := prunableChainSource(verifier, true)

	pass, results, err := prunableChainPolicy(keyID).Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:seed"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)

	// The headline: the depth loop must not have stopped at depth 0.
	require.True(t, pass,
		"FALSE FAIL: the early-settlement predicate settled on s-c2 (which the verdict then prunes) and stopped the search before depth 1's s-c3 — the replacement that legitimately satisfies d")

	// The mechanism: the replacement was discovered, the invalid sibling pruned.
	require.True(t, refPresent(results["s"].Passed, "s-c3"), "the depth-1 replacement must have been discovered")
	require.False(t, refPresent(results["s"].Passed, "s-c2"), "the artifact-invalid sibling must still be pruned")
	require.Len(t, results["s"].Passed, 2, "s keeps exactly s-c1 and s-c3; a count of 3 means pruning stopped, 1 means the fixtures collapsed (§10.7)")
	require.Len(t, results["d"].Passed, 1, "d is satisfied by the replacement")
}

// Mirror control: with no deeper replacement, the verdict is still FAIL and d
// still carries the artifact rejection. The predicate change must only stop the
// loop stopping early — it must not turn a genuine FAIL into a PASS, nor change
// the recorded reasons.
func TestArtifactAwareness_NoDeeperEvidenceStillFailsTheSameWay(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	src := prunableChainSource(verifier, false)

	pass, results, err := prunableChainPolicy(keyID).Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:seed"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)

	require.False(t, pass, "nothing legitimately satisfies d, so the verdict must remain FAIL")
	require.Empty(t, results["d"].Passed, "d must be rejected")
	require.NotEmpty(t, results["d"].Rejected, "d must carry the artifact rejection")
	require.False(t, refPresent(results["s"].Passed, "s-c2"), "the invalid sibling is still pruned")
	require.Len(t, results["s"].Passed, 1, "s survives on s-c1 alone")
}
