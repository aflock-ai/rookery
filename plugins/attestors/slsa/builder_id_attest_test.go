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

	"github.com/aflock-ai/rookery/attestation"
	awscodebuild "github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild"
	"github.com/aflock-ai/rookery/plugins/attestors/github"
	"github.com/aflock-ai/rookery/plugins/attestors/gitlab"
	"github.com/aflock-ai/rookery/plugins/attestors/jenkins"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
)

// Stubs that complete with fixed data instead of reading a real CI
// environment. Each keeps the real attestor's type, so the slsa attestor's
// type assertions see exactly what a real run produces.
type stubGitHub struct{ *github.Attestor }

func (*stubGitHub) Attest(*attestation.AttestationContext) error { return nil }

type stubGitLab struct{ *gitlab.Attestor }

func (*stubGitLab) Attest(*attestation.AttestationContext) error { return nil }

type stubJenkins struct{ *jenkins.Attestor }

func (*stubJenkins) Attest(*attestation.AttestationContext) error { return nil }

type stubCodeBuild struct{ *awscodebuild.Attestor }

func (*stubCodeBuild) Attest(*attestation.AttestationContext) error { return nil }

func withIssuer(iss, jwks string) *jwt.Attestor {
	if iss == "" {
		return nil
	}
	return &jwt.Attestor{
		Claims:     map[string]interface{}{"iss": iss, "sha": "0123456789abcdef0123456789abcdef01234567"},
		VerifiedBy: jwt.VerificationInfo{JWKSUrl: jwks},
	}
}

// attestWith runs the real slsa attestor after ci and returns the builder id
// and invocation id it emitted.
func attestWith(t *testing.T, ci attestation.Attestor) (builderID, invocationID string) {
	t.Helper()
	p := New()
	ctx, err := attestation.NewContext("build", []attestation.Attestor{ci, p})
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors: %v", err)
	}
	for _, c := range ctx.CompletedAttestors() {
		if c.Error != nil {
			t.Fatalf("attestor %s failed: %v", c.Attestor.Name(), c.Error)
		}
	}
	return p.PbProvenance.RunDetails.Builder.ID, p.PbProvenance.RunDetails.Metadata.InvocationID
}

// TestAttestEmitsANamedBuilderOnlyForAMappedIssuer drives Provenance.Attest
// end to end, so it fails if Attest ever goes back to stamping a builder id
// from the attestor's name alone (#9839).
func TestAttestEmitsANamedBuilderOnlyForAMappedIssuer(t *testing.T) {
	gh := func(iss string) attestation.Attestor {
		a := github.New()
		a.PipelineUrl = "https://github.com/acme/widget/actions/runs/1"
		a.JWT = withIssuer(iss, canonicalJWKS["github"])
		return &stubGitHub{a}
	}
	gl := func(iss string) attestation.Attestor {
		a := gitlab.New()
		a.PipelineUrl = "https://gitlab.example/acme/widget/-/pipelines/1"
		a.JWT = withIssuer(iss, canonicalJWKS["gitlab"])
		return &stubGitLab{a}
	}
	jk := jenkins.New()
	jk.PipelineUrl = "https://jenkins.example/job/widget/1"
	cb := awscodebuild.New()
	cb.BuildInfo.BuildARN = "arn:aws:codebuild:us-east-1:111111111111:build/widget:1"

	cases := []struct {
		name       string
		ci         attestation.Attestor
		wantID     string
		wantInvoke string
	}{
		{"github.com actions", gh("https://token.actions.githubusercontent.com"), GHABuilderId, "https://github.com/acme/widget/actions/runs/1"},
		{"github without a token", gh(""), DefaultBuilderId, "https://github.com/acme/widget/actions/runs/1"},
		{"github enterprise server", gh("https://ghes.acme.example/_services/token"), DefaultBuilderId, "https://github.com/acme/widget/actions/runs/1"},
		{"gitlab.com", gl("https://gitlab.com"), GLCBuilderId, "https://gitlab.example/acme/widget/-/pipelines/1"},
		{"gitlab without a token", gl(""), DefaultBuilderId, "https://gitlab.example/acme/widget/-/pipelines/1"},
		{"self-managed gitlab", gl("https://gitlab.acme.example"), DefaultBuilderId, "https://gitlab.example/acme/widget/-/pipelines/1"},
		{"jenkins", &stubJenkins{jk}, DefaultBuilderId, "https://jenkins.example/job/widget/1"},
		{"aws codebuild", &stubCodeBuild{cb}, DefaultBuilderId, "arn:aws:codebuild:us-east-1:111111111111:build/widget:1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, invoke := attestWith(t, tc.ci)
			if id != tc.wantID {
				t.Errorf("builder.id = %q, want %q", id, tc.wantID)
			}
			if invoke != tc.wantInvoke {
				t.Errorf("invocationId = %q, want %q: run data must still be recorded", invoke, tc.wantInvoke)
			}
		})
	}
}
