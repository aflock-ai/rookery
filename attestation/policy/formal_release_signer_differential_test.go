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

// formal:differential
//
// Binds the Lean release-signer model (formal/release-install, #10944) to the
// committed appliance release policy and the real certificate-constraint
// check. The test reads deploy/dist/appliance-release.policy.json and
// requires its appliance-build functionary's extension constraint to equal
// the one the model proves things about. A policy edit therefore fails here
// until the model is updated. Each generated case's Fulcio extensions are
// rendered into a real leaf extension list and run through checkExtensions;
// the verdict must equal the model's.
//
// The vectors and the policy live in the Judge monorepo, so this test skips
// when rookery is built on its own, unless JADE_FORMAL_DIFFERENTIAL=1.

import (
	"crypto/x509/pkix"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/require"
)

const (
	releaseSignerVectors = "../../../../formal/release-install/vectors/signer.json"
	applianceReleasePol  = "../../../../deploy/dist/appliance-release.policy.json"
)

type releaseSignerExt struct {
	Issuer      string `json:"issuer"`
	Repo        string `json:"repo"`
	Ref         string `json:"ref"`
	BuildConfig string `json:"build_config"`
	Runner      string `json:"runner"`
	Admit       bool   `json:"admit"`
}

func (e releaseSignerExt) fulcio() certificate.Extensions {
	return certificate.Extensions{
		Issuer:              e.Issuer,
		SourceRepositoryURI: e.Repo,
		SourceRepositoryRef: e.Ref,
		BuildConfigURI:      e.BuildConfig,
		RunnerEnvironment:   e.Runner,
	}
}

// render builds the leaf's extension list. Fulcio's Render refuses an empty
// issuer, so a case whose issuer is absent is rendered with a stand-in and
// both issuer extensions are dropped: the leaf then does not carry one.
func (e releaseSignerExt) render() ([]pkix.Extension, error) {
	f := e.fulcio()
	if f.Issuer != "" {
		return f.Render()
	}
	f.Issuer = "https://stand-in.example"
	exts, err := f.Render()
	if err != nil {
		return nil, err
	}
	out := exts[:0]
	for _, x := range exts {
		if !x.Id.Equal(certificate.OIDIssuer) && !x.Id.Equal(certificate.OIDIssuerV2) {
			out = append(out, x)
		}
	}
	return out, nil
}

func readOrSkip(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but %s is unreadable: %v", path, err)
		}
		t.Skipf("formal:differential: %s not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", path, err)
	}
	return raw
}

func TestFormalDifferentialReleaseSigner(t *testing.T) {
	var v struct {
		Constraint releaseSignerExt     `json:"constraint"`
		Groups     [][]releaseSignerExt `json:"groups"`
	}
	require.NoError(t, json.Unmarshal(readOrSkip(t, releaseSignerVectors), &v))

	// Only the steps: the committed file is a template whose roots are
	// placeholders, rendered with the real PEMs at release time.
	var pol struct {
		Steps map[string]struct {
			Functionaries []Functionary `json:"functionaries"`
		} `json:"steps"`
	}
	require.NoError(t, json.Unmarshal(readOrSkip(t, applianceReleasePol), &pol))
	step, ok := pol.Steps["appliance-build"]
	require.True(t, ok, "the release policy has no appliance-build step")
	require.Len(t, step.Functionaries, 1, "the model covers exactly one functionary")
	cc := step.Functionaries[0].CertConstraint
	require.Equal(t, v.Constraint.fulcio(), cc.Extensions,
		"the committed policy's extension constraint is not the one formal/release-install proves things about; update the model")

	var n, admitted int
	for _, g := range v.Groups {
		for _, c := range g {
			n++
			leaf, err := c.render()
			require.NoError(t, err)
			got := cc.checkExtensions(leaf) == nil
			require.Equal(t, c.Admit, got, "case %+v", c)
			if got {
				admitted++
			}
		}
	}
	// Release/Vectors.lean cases_length: a truncated file must not pass.
	require.Equal(t, 271, n)
	require.Positive(t, admitted)
	t.Logf("formal:differential: cases=%d admitted=%d", n, admitted)
}
