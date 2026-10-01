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

import (
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
)

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
		{"github.com actions", "github", map[string]interface{}{"iss": "https://token.actions.githubusercontent.com"}, InlineGHABuilderId},
		{"github enterprise server", "github", map[string]interface{}{"iss": "https://ghes.acme.example/_services/token"}, DefaultBuilderId},
		{"github enterprise slug issuer", "github", map[string]interface{}{"iss": "https://token.actions.githubusercontent.com/acme"}, DefaultBuilderId},
		{"github without a verified token", "github", nil, DefaultBuilderId},
		{"github issuer not a string", "github", map[string]interface{}{"iss": 7}, DefaultBuilderId},
		{"gitlab.com", "gitlab", map[string]interface{}{"iss": "https://gitlab.com"}, InlineGLCBuilderId},
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
			var tok *jwt.Attestor
			if tc.claims != nil {
				tok = &jwt.Attestor{Claims: tc.claims, VerifiedBy: jwt.VerificationInfo{JWKSUrl: canonicalJWKS[tc.attestor]}}
			}
			if got := builderIDFor(tc.attestor, tok); got != tc.want {
				t.Fatalf("builderIDFor(%q, %v) = %q, want %q", tc.attestor, tc.claims, got, tc.want)
			}
		})
	}
}

// canonicalJWKS is the key set each platform publishes; a token verified
// against it is the only kind whose iss claim names the builder.
var canonicalJWKS = map[string]string{
	"github": "https://token.actions.githubusercontent.com/.well-known/jwks",
	"gitlab": "https://gitlab.com/oauth/discovery/keys",
}

// An earlier step of the CI job can point the github or gitlab attestor at a
// key set it controls (WITNESS_GITHUB_JWKS_URL, WITNESS_GITLAB_JWKS_URL) and
// mint a token carrying the platform's iss. Such a token names no builder.
func TestBuilderIDRefusesAnIssuerVerifiedAgainstABuildChosenKeySet(t *testing.T) {
	for attestorName, iss := range map[string]string{
		"github": "https://token.actions.githubusercontent.com",
		"gitlab": "https://gitlab.com",
	} {
		for _, jwks := range []string{"https://attacker.example/jwks", "", canonicalJWKS[attestorName] + "/"} {
			tok := &jwt.Attestor{
				Claims:     map[string]interface{}{"iss": iss},
				VerifiedBy: jwt.VerificationInfo{JWKSUrl: jwks},
			}
			if got := builderIDFor(attestorName, tok); got != DefaultBuilderId {
				t.Fatalf("%s with key set %q: builderIDFor = %q, want %q", attestorName, jwks, got, DefaultBuilderId)
			}
		}
	}
}
