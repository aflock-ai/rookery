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
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requiredChain(t *testing.T, required []string, upstream, downstream map[string]cryptoutil.DigestSet) bool {
	t.Helper()
	v, keyID := earlyExitVerifier(t)
	prods := make(map[string]attestation.Product, len(upstream))
	for p, d := range upstream {
		prods[p] = attestation.Product{Digest: d}
	}
	up := lazyCollection(v, "up-1", "up", "",
		&lazyAttestor{AttName: "up-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "up-1-prod", AttType: lazyChainAttType, products: prods, inline: true})
	down := lazyCollection(v, "down-1", "down", "",
		&lazyAttestor{AttName: "down-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "down-1-mat", AttType: lazyChainAttType, materials: downstream, inline: true})
	step := lazyStep("down", keyID)
	step.ArtifactsFrom = []string{"up"}
	step.RequiredArtifacts = required
	p := lazyPolicy(keyID, step, lazyStep("up", keyID))
	require.NoError(t, p.Validate())
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": {down, up}})),
		WithSubjectDigests([]string{"sha256:seed"}))
	require.NoError(t, err)
	return pass
}

func TestRequiredArtifacts(t *testing.T) {
	a := lazyDigest("aaaa")
	b := lazyDigest("bbbb")
	x := lazyDigest("cccc")
	up := map[string]cryptoutil.DigestSet{"out/app": a, "shared.so": b}

	cases := []struct {
		name     string
		required []string
		down     map[string]cryptoutil.DigestSet
		want     bool
	}{
		{"present with upstream digest", []string{"out/app"}, map[string]cryptoutil.DigestSet{"out/app": a}, true},
		{"glob matches the consumed artifact", []string{"out/*"}, map[string]cryptoutil.DigestSet{"out/app": a}, true},
		{"absent, only a shared path consumed", []string{"out/app"}, map[string]cryptoutil.DigestSet{"shared.so": b}, false},
		{
			// A material matching the pattern that upstream never produced is
			// not evidence of consuming the upstream artifact.
			"match is not an upstream artifact", []string{"**app"},
			map[string]cryptoutil.DigestSet{"shared.so": b, "scratch/app": x}, false,
		},
		{
			// An alternate spelling of the upstream path skips the raw-key
			// digest compare, so it must not satisfy the requirement either.
			"aliased spelling does not count", []string{"out/app"},
			map[string]cryptoutil.DigestSet{"shared.so": b, "./out/app": x}, false,
		},
		{"every pattern must be satisfied", []string{"out/app", "missing"}, map[string]cryptoutil.DigestSet{"out/app": a}, false},
		{"empty list keeps plain artifactsFrom", nil, map[string]cryptoutil.DigestSet{"shared.so": b}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, requiredChain(t, tc.required, up, tc.down))
		})
	}
}

func TestRequiredArtifacts_Validate(t *testing.T) {
	_, keyID := earlyExitVerifier(t)

	noEdge := lazyStep("down", keyID)
	noEdge.RequiredArtifacts = []string{"out/app"}
	err := lazyPolicy(keyID, noEdge).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requiredArtifacts needs artifactsFrom")

	for _, bad := range []string{"", "out/["} {
		s := lazyStep("down", keyID)
		s.ArtifactsFrom = []string{"up"}
		s.RequiredArtifacts = []string{bad}
		err := lazyPolicy(keyID, s, lazyStep("up", keyID)).Validate()
		require.Error(t, err, "pattern %q", bad)
		assert.Contains(t, err.Error(), "requiredArtifacts")
	}
}
