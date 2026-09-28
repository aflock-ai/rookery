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
// Binds the tenant-scoped agent functionary model (formal/policy-publish,
// PolicyPublish/AgentUri.lean) to checkCertConstraint on the URI SANs. Each
// vector is one (pattern, leaf URIs, admitted) triple the model computes with
// `uriAdmits`. The model proves an agent leaf of another tenant never
// satisfies `spiffe://<td>/tenant/<t>/agent/*` when the trust domain and
// tenant id carry no glob metacharacter and no '/', and refutes the pattern
// without that precondition ('*', '?' and '/' in a segment admit another
// tenant). These rows hold Go to the same answers.
//
// The vectors live in the Judge monorepo (formal/policy-publish/vectors), so
// this test skips when rookery is built on its own, unless
// JADE_FORMAL_DIFFERENTIAL=1, which makes their absence a failure.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const agentURIVectors = "../../../../formal/policy-publish/vectors/agent-uri.json"

func TestFormalDifferentialAgentURI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(agentURIVectors))
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var v struct {
		Checks []struct {
			Pattern string   `json:"pattern"`
			URIs    []string `json:"uris"`
			Admit   bool     `json:"admit"`
		} `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Checks)

	var admitted, refused int
	for _, c := range v.Checks {
		got := checkCertConstraint("uri", []string{c.Pattern}, c.URIs) == nil
		require.Equal(t, c.Admit, got, "pattern %q against URIs %q", c.Pattern, c.URIs)
		if got {
			admitted++
		} else {
			refused++
		}
	}
	t.Logf("formal:differential: checks=%d admitted=%d refused=%d", len(v.Checks), admitted, refused)
	require.Positive(t, admitted)
	require.Positive(t, refused)
}
