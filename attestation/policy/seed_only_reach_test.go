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
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verification follows only what the seed matches. A collection's
// relationship edges (its BackRefs: commithash, parenthash, pipeline URL,
// tree roots) are never turned into new search seeds, whatever search depth
// the caller asks for.
//
// The shape: the build collection is found from the seed and records a
// commithash edge; the only source-git collection hangs off that commit.
// Before the cutover the engine searched the commit at depth 1 and passed.
// After it, source-git has no evidence the seed names, so the verify FAILS,
// and the commit is never submitted to a search.

func seedOnlyBuildWithEdges(verifier cryptoutil.Verifier) source.CollectionVerificationResult {
	coll := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{Type: noopStepAttType, Attestation: &dummyAttestor{name: "build-current", typeStr: noopStepAttType}},
		},
		RecordedBackRefs: map[string]cryptoutil.DigestSet{
			"https://aflock.ai/attestations/git/v0.1/commithash": newDigestSet("sha256:commit"),
			"https://aflock.ai/attestations/git/v0.1/parenthash": newDigestSet("sha256:parent"),
		},
	}
	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference:  "build-current",
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
}

func seedOnlySource(verifier cryptoutil.Verifier) *reachableSource {
	return &reachableSource{byDigest: map[string][]source.CollectionVerificationResult{
		"sha256:binary": {seedOnlyBuildWithEdges(verifier)},
		"sha256:commit": {earlyExitCollection(verifier, "source-git-by-commit", "source-git", "")},
		"sha256:parent": {earlyExitCollection(verifier, "source-git-by-parent", "source-git", "")},
	}}
}

func TestVerify_RelationshipEdgesAreNotFollowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []VerifyOption
	}{
		{name: "default options"},
		{name: "WithSearchDepth(3) is accepted and changes nothing", opts: []VerifyOption{WithSearchDepth(3)}},
		{name: "WithSearchDepth(0) is accepted and changes nothing", opts: []VerifyOption{WithSearchDepth(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, keyID := earlyExitVerifier(t)
			src := seedOnlySource(verifier)

			opts := append([]VerifyOption{
				WithVerifiedSource(src),
				WithSubjectDigests([]string{"sha256:binary"}),
			}, tc.opts...)
			pass, results, err := releaseShapedPolicy(keyID).Verify(context.Background(), opts...)
			require.NoError(t, err)

			require.Len(t, results["build"].Passed, 1, "the seed names the build collection directly")
			assert.Empty(t, results["source-git"].Passed,
				"source-git is reachable only through build's commithash/parenthash edge; edges are no longer followed")
			assert.False(t, pass, "a step the seed does not reach must fail")

			for _, d := range []string{"sha256:commit", "sha256:parent"} {
				_, searched := src.searchedDigests[d]
				assert.False(t, searched, "edge digest %s must never become a search seed", d)
			}
		})
	}
}

// The same step passes when the caller seeds the commit: seeding is the way
// to reach source evidence now.
func TestVerify_SeededCommitStillReachesSourceStep(t *testing.T) {
	verifier, keyID := earlyExitVerifier(t)
	src := seedOnlySource(verifier)

	pass, results, err := releaseShapedPolicy(keyID).Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:binary", "sha256:commit"}),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	require.Len(t, results["source-git"].Passed, 1)
	assert.Equal(t, "source-git-by-commit", results["source-git"].Passed[0].Collection.Reference)
	_, searched := src.searchedDigests["sha256:parent"]
	assert.False(t, searched, "the parenthash edge must never become a search seed")
}
