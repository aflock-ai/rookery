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
// Binds the verifier half of the Lean CI OIDC model (formal/ci-oidc,
// CiOidc/Verifier.lean) to CertConstraint.checkExtensions. Each vector
// is one (constraint, extension value, verdict) triple; "" is an extension the
// leaf does not carry. The model proves an absent extension fails every pin
// except exactly `*` (V1); `**` refuses it too.
//
// The vectors live in the Judge monorepo (formal/ci-oidc/vectors/verifier.json),
// so this test skips when rookery is built on its own, unless
// JADE_FORMAL_DIFFERENTIAL=1, which makes their absence a failure.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/require"
)

const ciOIDCVerifierVectors = "../../../../formal/ci-oidc/vectors/verifier.json"

func TestFormalDifferentialCIOIDCVerifier(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(ciOIDCVerifierVectors))
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var v struct {
		Checks []struct {
			Constraint string `json:"constraint"`
			Value      string `json:"value"`
			Accept     bool   `json:"accept"`
		} `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Checks)

	var accepted, refused int
	for _, c := range v.Checks {
		leaf, err := certificate.Extensions{Issuer: "https://issuer.example", SourceRepositoryURI: c.Value}.Render()
		require.NoError(t, err)
		got := CertConstraint{Extensions: certificate.Extensions{SourceRepositoryURI: c.Constraint}}.checkExtensions(leaf) == nil
		require.Equal(t, c.Accept, got, "constraint %q against value %q", c.Constraint, c.Value)
		if got {
			accepted++
		} else {
			refused++
		}
	}
	t.Logf("formal:differential: checks=%d accepted=%d refused=%d", len(v.Checks), accepted, refused)
	require.Positive(t, accepted)
	require.Positive(t, refused)
}
