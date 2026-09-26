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

package slsa

import "testing"

// A named CI builder.id is a claim that the build platform can reach the
// level a verifier grants that builder. The formal support matrix
// (formal/slsa-tracks) shows Build L2 needs a Fulcio issuer mapping for the
// platform's workload token. Jenkins has no mapping and CodeBuild has no
// workload OIDC token, so neither ever reaches it, and a GitHub or GitLab
// token from an instance without a mapping (GHES, self-managed GitLab) does
// not either (#9839).
func TestBuilderIDClaimsOnlyWhatTheIssuerMappingSupports(t *testing.T) {
	cases := []struct {
		name     string
		attestor string
		claims   map[string]interface{}
		want     string
	}{
		{"github.com actions", "github", map[string]interface{}{"iss": "https://token.actions.githubusercontent.com"}, GHABuilderId},
		{"github enterprise server", "github", map[string]interface{}{"iss": "https://ghes.acme.example/_services/token"}, DefaultBuilderId},
		{"github enterprise slug issuer", "github", map[string]interface{}{"iss": "https://token.actions.githubusercontent.com/acme"}, DefaultBuilderId},
		{"github without a verified token", "github", nil, DefaultBuilderId},
		{"github issuer not a string", "github", map[string]interface{}{"iss": 7}, DefaultBuilderId},
		{"gitlab.com", "gitlab", map[string]interface{}{"iss": "https://gitlab.com"}, GLCBuilderId},
		{"self-managed gitlab", "gitlab", map[string]interface{}{"iss": "https://gitlab.acme.example"}, DefaultBuilderId},
		{"gitlab.com lookalike", "gitlab", map[string]interface{}{"iss": "https://gitlab.com.evil.example"}, DefaultBuilderId},
		{"gitlab without a verified token", "gitlab", nil, DefaultBuilderId},
		{"jenkins", "jenkins", nil, DefaultBuilderId},
		{"jenkins with a token", "jenkins", map[string]interface{}{"iss": "https://gitlab.com"}, DefaultBuilderId},
		{"aws codebuild", "aws-codebuild", nil, DefaultBuilderId},
		{"unknown attestor", "circleci", map[string]interface{}{"iss": "https://oidc.circleci.com/org/x"}, DefaultBuilderId},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := builderIDFor(tc.attestor, tc.claims); got != tc.want {
				t.Fatalf("builderIDFor(%q, %v) = %q, want %q", tc.attestor, tc.claims, got, tc.want)
			}
		})
	}
}
