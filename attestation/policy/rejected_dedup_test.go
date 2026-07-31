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
// prod #7572 — every StepResult.Rejected entry retains the FULL parsed
// envelope (payload bytes + statement subject tree + collection attestor
// tree). The depth loop re-runs Search per step per depth against the whole
// grown digest set, and a source WITHOUT seen-envelope exclusion (judge-api's
// EntSource — the prod verify path) re-returns the same envelopes every depth.
// Passed collections are de-duplicated (#5746 F12); Rejected were appended
// raw, so one rejected prod-sized collection was retained once per depth —
// searchDepth (default 3, policy.go:436) copies of a multi-MB parse tree per
// rejection, times concurrent verification turns.
// ---------------------------------------------------------------------------

// dupReturningSource models EntSource: no seen-envelope exclusion, so the same
// collection is handed back on EVERY search whose digest set reaches it.
// Otherwise identical in shape to reachableSource (searchdepth_earlyexit_test.go).
type dupReturningSource struct {
	byDigest map[string][]source.CollectionVerificationResult
	// probes counts the diagnoseEmptyCollectionResult probe searches
	// (subjectDigests == nil while the depth loop always passes non-empty).
	probes int
}

func (s *dupReturningSource) Search(_ context.Context, stepName string, subjectDigests, _ []string) ([]source.CollectionVerificationResult, error) {
	if len(subjectDigests) == 0 {
		s.probes++
		return nil, nil
	}
	out := make([]source.CollectionVerificationResult, 0)
	seen := map[string]struct{}{}
	for _, d := range subjectDigests {
		for _, cvr := range s.byDigest[d] {
			if cvr.Collection.Name != stepName {
				continue
			}
			// Dedupe within ONE call (a real query returns a row once) but
			// deliberately NOT across calls — that is EntSource's behavior.
			if _, dup := seen[cvr.Reference]; dup {
				continue
			}
			seen[cvr.Reference] = struct{}{}
			out = append(out, cvr)
		}
	}
	return out, nil
}

func (s *dupReturningSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// distinctStatement returns a statement unique to ref. Real envelopes always
// carry distinct statements (the predicate is embedded), and the passed/
// rejected content keys hash the statement — identical empty statements would
// make DISTINCT fixtures collapse into one another and mask what these tests
// measure.
func distinctStatement(ref string) intoto.Statement {
	return intoto.Statement{
		PredicateType: attestation.CollectionType,
		Subject:       []intoto.Subject{{Name: ref, Digest: map[string]string{"sha256": fmt.Sprintf("%064x", len(ref))}}},
	}
}

// dupCollection is earlyExitCollection with a per-ref distinct statement.
func dupCollection(verifier cryptoutil.Verifier, ref, stepName, backRef string) source.CollectionVerificationResult {
	cvr := earlyExitCollection(verifier, ref, stepName, backRef)
	cvr.Statement = distinctStatement(ref)
	return cvr
}

// rejectedCollection builds a collection for stepName whose envelope signature
// did NOT verify (no Verifiers) — the shape VerifiedSource hands back for an
// untrusted signer. checkFunctionaries routes it to Rejected every time it is
// returned by a search.
func rejectedCollection(ref, stepName string) source.CollectionVerificationResult {
	return source.CollectionVerificationResult{
		// No Verifiers: signature verification failed upstream.
		Errors: []error{fmt.Errorf("failed to verify envelope: no matching signatures")},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference: ref,
			Collection: attestation.Collection{
				Name: stepName,
				Attestations: []attestation.CollectionAttestation{
					{Type: noopStepAttType, Attestation: &dummyAttestor{name: ref, typeStr: noopStepAttType}},
				},
			},
			Statement: distinctStatement(ref),
		},
	}
}

// dupPolicy: "build" is satisfiable from the seed; "audit" never matches any
// collection. The unsatisfied audit step keeps the depth loop running while
// build's back-reference chain keeps producing new digests, so every depth
// re-searches build against the full grown digest set.
func dupPolicy(keyID string) Policy {
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
			"build": step("build"),
			"audit": step("audit"),
		},
	}
}

// A collection rejected at depth 0 is re-returned by an exclusion-less source
// at depths 1 and 2 and must NOT be re-appended: each Rejected entry retains
// the full parsed envelope. Identity is content-based, so genuinely distinct
// rejections are all preserved.
func TestVerify_RejectedCollectionsDedupedAcrossDepths(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	src := &dupReturningSource{byDigest: map[string][]source.CollectionVerificationResult{
		"sha256:binary": {
			dupCollection(verifier, "build-current", "build", "sha256:pipeline"),
			rejectedCollection("build-badsig", "build"),
		},
		"sha256:pipeline": {
			dupCollection(verifier, "build-hop", "build", "sha256:commit"),
		},
	}}

	pass, results, err := dupPolicy(keyID).Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:binary"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)
	assert.False(t, pass, "audit step has no evidence; the verdict must be FAIL before and after the dedup change")

	// Verdict-bearing state is untouched: both build collections pass, exactly once.
	require.Len(t, results["build"].Passed, 2, "passed dedup (#5746 F12) must keep both distinct passing collections exactly once")

	// The rejected envelope is re-returned at every depth; it must be retained once.
	badsig := 0
	for _, rc := range results["build"].Rejected {
		if rc.Collection.Reference == "build-badsig" {
			badsig++
		}
	}
	assert.Equal(t, 1, badsig,
		"a rejected collection re-returned by an exclusion-less source at later depths must be retained once, not once per depth (each copy holds the full parsed envelope)")
}

// A step with no evidence at all must be diagnosed ONCE, not once per depth:
// each diagnosis appends a Rejected entry AND fires an UNFILTERED probe search
// (subjectDigests=nil) that on prod sources downloads every collection for the
// step name.
func TestVerify_MissingStepDiagnosedOncePerVerify(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)

	src := &dupReturningSource{byDigest: map[string][]source.CollectionVerificationResult{
		"sha256:binary":   {dupCollection(verifier, "build-current", "build", "sha256:pipeline")},
		"sha256:pipeline": {dupCollection(verifier, "build-hop", "build", "sha256:commit")},
	}}

	pass, results, err := dupPolicy(keyID).Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:binary"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)
	assert.False(t, pass, "audit step has no evidence; the verdict must be FAIL before and after")

	diag := 0
	for _, rc := range results["audit"].Rejected {
		var errNoColl ErrNoCollections
		if rc.Reason != nil && errors.As(rc.Reason, &errNoColl) {
			diag++
		}
	}
	assert.Equal(t, 1, diag,
		"a step with no evidence must carry ONE diagnostic rejection, not one per depth iteration")
	assert.Equal(t, 1, src.probes,
		"the unfiltered diagnostic probe must run once per verify for a missing step, not once per depth")
}

// BenchmarkVerify_DepthLoopWithDupSource measures one full Verify over the
// exclusion-less source shape: an unsatisfiable step keeps the depth loop
// running while the satisfiable step's envelopes (one passing chain, one
// rejected) are re-returned at every depth. Captures the policy-engine side of
// the per-depth rework (functionary checks, gate evaluation, merges, diag).
func BenchmarkVerify_DepthLoopWithDupSource(b *testing.B) {
	verifier, keyID := earlyExitVerifierB(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := &dupReturningSource{byDigest: map[string][]source.CollectionVerificationResult{
			"sha256:binary": {
				dupCollection(verifier, "build-current", "build", "sha256:pipeline"),
				rejectedCollection("build-badsig", "build"),
			},
			"sha256:pipeline": {
				dupCollection(verifier, "build-hop", "build", "sha256:commit"),
			},
		}}
		pass, _, err := dupPolicy(keyID).Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:binary"}),
			WithSearchDepth(3),
		)
		if err != nil || pass {
			b.Fatalf("expected clean FAIL verdict, got pass=%v err=%v", pass, err)
		}
	}
}

// earlyExitVerifierB is earlyExitVerifier for benchmarks.
func earlyExitVerifierB(b *testing.B) (cryptoutil.Verifier, string) {
	b.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(b, err)
	return verifier, keyID
}
