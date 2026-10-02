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
	"testing"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/require"
)

// The extension sets below are what a Fulcio CA (public Sigstore, or the
// TestifySec platform since an earlier change) stamps for a GitLab.com, Buildkite and
// CircleCI job. These tests pin how a policy's certConstraint.extensions
// reads them, including the fields those vendors leave empty, because the
// customer docs tell people which constraints are meaningful per CI.

func checkCIExtensions(t *testing.T, constraint, cert certificate.Extensions) error {
	t.Helper()
	exts, err := cert.Render()
	require.NoError(t, err)
	return CertConstraint{Extensions: constraint}.checkExtensions(exts)
}

var gitlabComLeafExtensions = certificate.Extensions{
	Issuer:              "https://gitlab.com",
	BuildSignerURI:      "https://gitlab.com/acme/widget//.gitlab-ci.yml@refs/heads/main",
	RunnerEnvironment:   "gitlab-hosted",
	SourceRepositoryURI: "https://gitlab.com/acme/widget",
	SourceRepositoryRef: "refs/heads/main",
	RunInvocationURI:    "https://gitlab.com/acme/widget/-/jobs/777",
}

func TestCIExtensionConstraintsGitLabCom(t *testing.T) {
	pin := certificate.Extensions{
		Issuer:              "https://gitlab.com",
		BuildSignerURI:      "https://gitlab.com/acme/widget//.gitlab-ci.yml@refs/heads/main",
		SourceRepositoryURI: "https://gitlab.com/acme/widget",
		RunnerEnvironment:   "gitlab-hosted",
	}
	require.NoError(t, checkCIExtensions(t, pin, gitlabComLeafExtensions))

	selfHosted := gitlabComLeafExtensions
	selfHosted.RunnerEnvironment = "self-hosted"
	require.Error(t, checkCIExtensions(t, pin, selfHosted), "runner-environment pin must refuse a self-hosted runner")

	// The same signer URI under another issuer is a different identity.
	otherIssuer := gitlabComLeafExtensions
	otherIssuer.Issuer = "https://gitlab.acme.example"
	require.Error(t, checkCIExtensions(t, pin, otherIssuer))
}

func TestCIExtensionConstraintsBuildkiteHasNoRepositoryURI(t *testing.T) {
	leaf := certificate.Extensions{
		Issuer:                 "https://agent.buildkite.com",
		RunnerEnvironment:      "buildkite-hosted",
		SourceRepositoryDigest: "0123456789abcdef0123456789abcdef01234567",
		RunInvocationURI:       "https://buildkite.com/acme/widget/builds/42#job",
	}
	require.NoError(t, checkCIExtensions(t, certificate.Extensions{
		Issuer:            "https://agent.buildkite.com",
		RunnerEnvironment: "buildkite-hosted",
		RunInvocationURI:  "https://buildkite.com/acme/widget/*",
	}, leaf))

	// A Buildkite cert carries no Source Repository URI, so a policy that pins
	// one fails closed rather than passing on an absent field.
	require.Error(t, checkCIExtensions(t, certificate.Extensions{
		Issuer:              "https://agent.buildkite.com",
		SourceRepositoryURI: "https://github.com/acme/widget",
	}, leaf))
}

func TestCIExtensionConstraintsCircleCIRunnerIsUnknowable(t *testing.T) {
	leaf := certificate.Extensions{
		Issuer:              "https://oidc.circleci.com/org/0190f4a8-aaaa-bbbb-cccc-ddddeeeeffff",
		BuildSignerURI:      "https://circleci.com/api/v2/projects/p/pipeline-definitions/d",
		RunnerEnvironment:   `""`,
		SourceRepositoryURI: "github.com/acme/widget",
	}
	require.NoError(t, checkCIExtensions(t, certificate.Extensions{
		Issuer:         "https://oidc.circleci.com/org/0190f4a8-aaaa-bbbb-cccc-ddddeeeeffff",
		BuildSignerURI: "https://circleci.com/api/v2/projects/p/pipeline-definitions/d",
	}, leaf))

	// Another org's issuer must not satisfy an org pin.
	other := leaf
	other.Issuer = "https://oidc.circleci.com/org/0190f4a8-0000-0000-0000-000000000000"
	require.Error(t, checkCIExtensions(t, certificate.Extensions{
		Issuer: "https://oidc.circleci.com/org/0190f4a8-aaaa-bbbb-cccc-ddddeeeeffff",
	}, other))

	// No runner-environment value distinguishes cloud from self-hosted.
	for _, want := range []string{"cloud", "circleci-hosted", "*hosted*"} {
		require.Error(t, checkCIExtensions(t, certificate.Extensions{RunnerEnvironment: want}, leaf), want)
	}
}
