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
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #9946: the release sign step (deploy/dist/release-policy-signed-binary.json)
// chains artifactsFrom=[build], but artifactsFrom compares materials to upstream
// artifacts BY PATH. In the real v4.5.0 release evidence (release-fanout run
// 35883585020) build records its product as /tmp/build/cilock (trace mode,
// absolute) while sign extracts the binary into a mktemp directory and never
// records it as a material at all; the chain passed on 7 shared system files
// (libc, /etc/ld.so.cache, ...). A sign step over a DIFFERENT binary therefore
// verified.
//
// These cases run the real policy file's sign/build chain definitions
// (artifactsFrom, requiredArtifacts, allowedUntracked) through the real engine,
// with fixture evidence shaped like the real envelopes.

const (
	signTestBuildPath = "/tmp/build/cilock"
	signTestLib       = "/usr/lib/libc.so.6"
)

// releaseSignChainPolicy loads the real signed-binary release policy and keeps
// only what decides the build→sign chain; functionaries and attestation types
// are swapped for fixture ones so the evidence can be built in memory.
func releaseSignChainPolicy(t *testing.T, keyID string) Policy {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "dist", "release-policy-signed-binary.json"))
	require.NoError(t, err)
	var real Policy
	require.NoError(t, json.Unmarshal(body, &real))

	build := lazyStep("build", keyID)
	sign := lazyStep("sign", keyID)
	realSign := real.Steps["sign"]
	sign.ArtifactsFrom = realSign.ArtifactsFrom
	sign.AllowedUntracked = realSign.AllowedUntracked
	sign.RequiredArtifacts = realSign.RequiredArtifacts
	require.Equal(t, []string{"build"}, sign.ArtifactsFrom, "the real policy must chain sign to build")
	return lazyPolicy(keyID, build, sign)
}

func releaseSignChainSource(t *testing.T, v cryptoutil.Verifier, buildProducts, signMaterials map[string]cryptoutil.DigestSet) *lazySource {
	t.Helper()
	prods := make(map[string]attestation.Product, len(buildProducts))
	for p, d := range buildProducts {
		prods[p] = attestation.Product{Digest: d}
	}
	build := lazyCollection(v, "build-1", "build", "",
		&lazyAttestor{AttName: "build-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "build-1-mat", AttType: lazyChainAttType,
			materials: map[string]cryptoutil.DigestSet{signTestLib: lazyDigest("11b0")}, inline: true},
		&lazyAttestor{AttName: "build-1-prod", AttType: lazyChainAttType, products: prods, inline: true})
	sign := lazyCollection(v, "sign-1", "sign", "",
		&lazyAttestor{AttName: "sign-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "sign-1-mat", AttType: lazyChainAttType, materials: signMaterials, inline: true})
	return newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": {sign, build}})
}

func TestReleaseSignStepBindsTheBuiltBinary(t *testing.T) {
	built := lazyDigest("b111")
	other := lazyDigest("0the")
	lib := lazyDigest("11b0")

	cases := []struct {
		name          string
		buildProducts map[string]cryptoutil.DigestSet
		signMaterials map[string]cryptoutil.DigestSet
		wantPass      bool
		wantInReason  string
	}{
		{
			// The v4.5.0 shape: the signed binary is not a sign material at
			// all; only shared system files connect the steps. Passed before
			// #9946.
			name:          "sign does not record the binary",
			buildProducts: map[string]cryptoutil.DigestSet{signTestBuildPath: built},
			signMaterials: map[string]cryptoutil.DigestSet{signTestLib: lib},
			wantPass:      false, wantInReason: "requiredArtifacts",
		},
		{
			// A DIFFERENT binary signed from a scratch directory. Passed
			// before #9946 on the libc overlap alone.
			name:          "different binary at a scratch path",
			buildProducts: map[string]cryptoutil.DigestSet{signTestBuildPath: built},
			signMaterials: map[string]cryptoutil.DigestSet{signTestLib: lib, "/tmp/tmp.mnlZiVSOQT/cilock": other},
			wantPass:      false, wantInReason: "requiredArtifacts",
		},
		{
			// A DIFFERENT binary recorded under the build path.
			name:          "different binary at the build path",
			buildProducts: map[string]cryptoutil.DigestSet{signTestBuildPath: built},
			signMaterials: map[string]cryptoutil.DigestSet{signTestLib: lib, signTestBuildPath: other},
			wantPass:      false, wantInReason: "mismatched digests",
		},
		{
			name:          "the built binary, linux/darwin name",
			buildProducts: map[string]cryptoutil.DigestSet{signTestBuildPath: built},
			signMaterials: map[string]cryptoutil.DigestSet{signTestLib: lib, signTestBuildPath: built},
			wantPass:      true,
		},
		{
			name:          "the built binary, windows name",
			buildProducts: map[string]cryptoutil.DigestSet{signTestBuildPath + ".exe": built},
			signMaterials: map[string]cryptoutil.DigestSet{signTestBuildPath + ".exe": built},
			wantPass:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier, keyID := earlyExitVerifier(t)
			p := releaseSignChainPolicy(t, keyID)
			src := releaseSignChainSource(t, verifier, tc.buildProducts, tc.signMaterials)
			pass, results, err := p.Verify(context.Background(),
				WithVerifiedSource(src), WithSubjectDigests([]string{"sha256:seed"}))
			require.NoError(t, err)

			var reasons string
			for _, r := range results["sign"].Rejected {
				if r.Reason != nil {
					reasons += r.Reason.Error() + "\n"
				}
			}
			assert.Equal(t, tc.wantPass, pass, "sign rejections: %s", reasons)
			if tc.wantInReason != "" {
				assert.Contains(t, reasons, tc.wantInReason)
			}
		})
	}
}
