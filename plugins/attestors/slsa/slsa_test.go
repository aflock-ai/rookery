// jade:ring local
// Copyright 2026 The Aflock Authors
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
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/github"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// The SLSA v1.0 spec (https://slsa.dev/spec/v1.0/provenance) defines the
// predicateType as exactly this string. Tools that match it exactly
// (slsa-verifier, gh attestation verify, cosign --type slsaprovenance1) ignore
// anything else, so the literal is pinned here rather than compared with the
// package constant.
const specPredicateType = "https://slsa.dev/provenance/v1"

func TestEmittedPredicateTypeIsTheSpecString(t *testing.T) {
	require.Equal(t, specPredicateType, Type)
	require.Equal(t, specPredicateType, New().Type())

	p := runProvenance(t, nil)
	stmt, err := intoto.NewStatement(p.Type(), mustJSON(t, p), p.Subjects())
	require.NoError(t, err)
	require.Equal(t, specPredicateType, stmt.PredicateType)
}

// The pre-#9827 "v1.0" string is not accepted (Cole, 2026-09-29): it has no
// factory and no alias, so nothing resolves it to the slsa attestor.
func TestLegacyV10PredicateTypeIsGone(t *testing.T) {
	const legacy = "https://slsa.dev/provenance/v1.0"
	_, ok := attestation.FactoryByType(legacy)
	require.False(t, ok, "%s must not decode through the slsa attestor", legacy)
	require.Equal(t, legacy, attestation.ResolveLegacyType(legacy))
	require.Empty(t, attestation.LegacyAlternate(specPredicateType))
	factory, ok := attestation.FactoryByType(specPredicateType)
	require.True(t, ok)
	require.Equal(t, Name, factory().Name())
}

func TestInlineBuilderIDs(t *testing.T) {
	require.Equal(t, "https://aflock.ai/cilock/inline/github-actions@v1", InlineGHABuilderId)

	t.Run("no build platform attestor names the default builder, which claims nothing", func(t *testing.T) {
		p := runProvenance(t, nil)
		require.Equal(t, DefaultBuilderId, p.PbProvenance.RunDetails.Builder.ID)
	})

	t.Run("github inline job names the inline mode", func(t *testing.T) {
		p := runProvenance(t, fakeGitHub(canonicalGitHubJWKS, map[string]any{
			"job_workflow_ref": "tenant/app/.github/workflows/ci.yml@refs/heads/main",
			"workflow_ref":     "tenant/app/.github/workflows/ci.yml@refs/heads/main",
		}))
		require.Equal(t, InlineGHABuilderId, p.PbProvenance.RunDetails.Builder.ID)
	})

	t.Run("github job without a verified JWT names the default builder (#10444)", func(t *testing.T) {
		p := runProvenance(t, &fakeGitHubAttestor{data: &github.Attestor{}})
		require.Equal(t, DefaultBuilderId, p.PbProvenance.RunDetails.Builder.ID)
	})
}

func TestIsolatedProvenanceWorkflowBuilderID(t *testing.T) {
	const ref = "aflock-ai/cilock-action/.github/workflows/provenance.yml@refs/tags/v1.2.3"

	t.Run("the trusted reusable workflow, stamped by GitHub, becomes builder.id", func(t *testing.T) {
		p := runProvenance(t, fakeGitHub(canonicalGitHubJWKS, map[string]any{
			"job_workflow_ref": ref,
			"workflow_ref":     "tenant/app/.github/workflows/release.yml@refs/heads/main",
		}))
		require.Equal(t, "https://github.com/"+ref, p.PbProvenance.RunDetails.Builder.ID)
	})

	t.Run("a tenant's own reusable workflow is still inline", func(t *testing.T) {
		p := runProvenance(t, fakeGitHub(canonicalGitHubJWKS, map[string]any{
			"job_workflow_ref": "tenant/app/.github/workflows/provenance.yml@refs/heads/main",
		}))
		require.Equal(t, InlineGHABuilderId, p.PbProvenance.RunDetails.Builder.ID)
	})

	t.Run("a look-alike path is still inline", func(t *testing.T) {
		p := runProvenance(t, fakeGitHub(canonicalGitHubJWKS, map[string]any{
			"job_workflow_ref": "aflock-ai/cilock-action/.github/workflows/provenance.yml.evil@refs/heads/main",
		}))
		require.Equal(t, InlineGHABuilderId, p.PbProvenance.RunDetails.Builder.ID)
	})

	t.Run("a ref-less claim is still inline", func(t *testing.T) {
		p := runProvenance(t, fakeGitHub(canonicalGitHubJWKS, map[string]any{
			"job_workflow_ref": "aflock-ai/cilock-action/.github/workflows/provenance.yml",
		}))
		require.Equal(t, InlineGHABuilderId, p.PbProvenance.RunDetails.Builder.ID)
	})

	// WITNESS_GITHUB_JWKS_URL is an env var a build step can set. A token
	// verified against any key set other than GitHub's own proves nothing
	// about job_workflow_ref, so it must not promote builder.id.
	t.Run("a claim verified against a non-GitHub JWKS names the default builder (#10444)", func(t *testing.T) {
		p := runProvenance(t, fakeGitHub("https://attacker.example/jwks", map[string]any{
			"job_workflow_ref": ref,
		}))
		require.Equal(t, DefaultBuilderId, p.PbProvenance.RunDetails.Builder.ID)
	})
}

const canonicalGitHubJWKS = "https://token.actions.githubusercontent.com/.well-known/jwks"

// runProvenance runs the slsa attestor after a fake command run (so the
// provenance carries externalParameters, as every cilock run does) and an
// optional fake build-platform attestor.
func runProvenance(t *testing.T, platform attestation.Attestor) *Provenance {
	t.Helper()
	p := New()
	attestors := []attestation.Attestor{&fakeCommandRun{}}
	if platform != nil {
		attestors = append(attestors, platform)
	}
	attestors = append(attestors, p)
	ctx, err := attestation.NewContext("build", attestors, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	for _, c := range ctx.CompletedAttestors() {
		require.NoError(t, c.Error, c.Attestor.Name())
	}
	return p
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func fakeGitHub(jwksURL string, claims map[string]any) *fakeGitHubAttestor {
	claims["sha"] = "0123456789abcdef0123456789abcdef01234567"
	// builderIDFor names a builder only for GitHub's own issuer (#10444).
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = "https://token.actions.githubusercontent.com"
	}
	return &fakeGitHubAttestor{data: &github.Attestor{
		PipelineUrl: "https://github.com/tenant/app/actions/runs/1",
		JWT:         &jwt.Attestor{Claims: claims, VerifiedBy: jwt.VerificationInfo{JWKSUrl: jwksURL}},
	}}
}

type fakeGitHubAttestor struct{ data *github.Attestor }

func (f *fakeGitHubAttestor) Name() string                                   { return github.Name }
func (f *fakeGitHubAttestor) Type() string                                   { return github.Type }
func (f *fakeGitHubAttestor) RunType() attestation.RunType                   { return github.RunType }
func (f *fakeGitHubAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fakeGitHubAttestor) Schema() *jsonschema.Schema                     { return nil }
func (f *fakeGitHubAttestor) Data() *github.Attestor                         { return f.data }
func (f *fakeGitHubAttestor) Subjects() map[string]cryptoutil.DigestSet      { return nil }
func (f *fakeGitHubAttestor) BackRefs() map[string]cryptoutil.DigestSet      { return nil }

type fakeCommandRun struct{}

func (f *fakeCommandRun) Name() string                                   { return commandrun.Name }
func (f *fakeCommandRun) Type() string                                   { return commandrun.Type }
func (f *fakeCommandRun) RunType() attestation.RunType                   { return commandrun.RunType }
func (f *fakeCommandRun) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fakeCommandRun) Schema() *jsonschema.Schema                     { return nil }
func (f *fakeCommandRun) Data() *commandrun.CommandRun {
	return &commandrun.CommandRun{Cmd: []string{"go", "build", "./..."}}
}
