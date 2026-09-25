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

package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// testdata/sigstore/bundle-provenance.json and trusted-root-public-good.json
// are sigstore-go v1.3.0's examples (Apache-2.0): sigstore-js 1.3.0's npm
// provenance, a v0.1 bundle signed on public-good infrastructure. They are
// not sigstore-conformance assets; those are the holdout (#9916).
const (
	exampleBundle   = "testdata/sigstore/bundle-provenance.json"
	exampleRoot     = "testdata/sigstore/trusted-root-public-good.json"
	exampleSAN      = "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"
	exampleIssuer   = "https://token.actions.githubusercontent.com"
	exampleArtifact = "sha512:76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751"
)

func execVerifyBundle(t *testing.T, args ...string) error {
	t.Helper()
	root := New()
	root.SetArgs(append([]string{"verify-bundle"}, args...))
	return root.Execute()
}

func TestVerifyBundleAcceptsPublicGoodProvenance(t *testing.T) {
	require.NoError(t, execVerifyBundle(t,
		"--bundle", exampleBundle, "--trusted-root", exampleRoot,
		"--certificate-identity", exampleSAN, "--certificate-oidc-issuer", exampleIssuer,
		exampleArtifact))
}

func TestVerifyBundleRefuses(t *testing.T) {
	base := func(identity, issuer, artifact string) []string {
		args := []string{"--bundle", exampleBundle, "--trusted-root", exampleRoot}
		if identity != "-" {
			args = append(args, "--certificate-identity", identity)
		}
		if issuer != "-" {
			args = append(args, "--certificate-oidc-issuer", issuer)
		}
		return append(args, artifact)
	}
	unconstrained := "required and must be non-empty"
	for name, c := range map[string]struct {
		args []string
		why  string // the refusal must be for this reason, not another
	}{
		"wrong san":       {base("https://github.com/sigstore/sigstore-js/.github/workflows/other.yml@refs/heads/main", exampleIssuer, exampleArtifact), "expected SAN value"},
		"wrong issuer":    {base(exampleSAN, "https://gitlab.com", exampleArtifact), "expected issuer value"},
		"no san":          {base("-", exampleIssuer, exampleArtifact), unconstrained},
		"empty san":       {base("", exampleIssuer, exampleArtifact), unconstrained},
		"no issuer":       {base(exampleSAN, "-", exampleArtifact), unconstrained},
		"wrong digest":    {base(exampleSAN, exampleIssuer, "sha512:"+strings.Repeat("00", 64)), "does not match any digest"},
		"malformed input": {base(exampleSAN, exampleIssuer, "sha512:zz"), "hex-encoded bytes of sha512"},
		"key and identity": {[]string{"--bundle", exampleBundle, "--trusted-root", exampleRoot, "--key", exampleRoot,
			"--certificate-identity", exampleSAN, "--certificate-oidc-issuer", exampleIssuer, exampleArtifact}, "not both"},
	} {
		t.Run(name, func(t *testing.T) {
			err := execVerifyBundle(t, c.args...)
			require.ErrorContains(t, err, c.why)
		})
	}
}
