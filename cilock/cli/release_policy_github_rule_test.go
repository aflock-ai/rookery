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

// The committed rookery release policy (deploy/cilock/release.policy.json,
// signed by .github/workflows/release.yml at publish time) binds a release to
// aflock-ai/rookery and to a tag with a rego module on the github predicate.
// Its first form read input.repository and input.reftype. The github attestor
// emits neither: the workflow's OIDC claims sit under jwt.claims
// (plugins/attestors/github/github.go:96, plugins/attestors/jwt/jwt.go:65), so
// both rules were undefined on every real predicate and the gate passed every
// build. These tests evaluate the committed module, through the verifier's own
// entry point, against the github predicate of a real rookery release and
// against what a signer who controls the predicate could hand the verifier.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/plugins/attestors/github"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// releaseGithubPredicateFixture is the github attestation from the published
// v1.0.0-rc1 rookery release (asset linux-amd64.attestation.json, sha256
// cd5d7abc28620fef97e4449360363846a591ec633ad4eb33bb76bab9b0023af6, run
// 26756800912), extracted from the collection. It is the only rookery
// release.yml run whose attestations are still downloadable. The claims that
// name the person who pushed the tag (actor, actor_id) are synthetic, because
// this tree is published; every other byte is as extracted. The module reads
// neither claim, and nothing here checks the predicate's signature.
var releaseGithubPredicateFixture = filepath.Join("testdata", "release-policy", "github-v1.0.0-rc1-linux-amd64.json")

func releaseGithubRule(t *testing.T) []policy.RegoPolicy {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "deploy", "cilock", "release.policy.json"))
	require.NoError(t, err)
	var p policy.Policy
	require.NoError(t, json.Unmarshal(body, &p))
	step, ok := p.Steps["release-build"]
	require.True(t, ok, "the release policy must keep its release-build step")
	var mods []policy.RegoPolicy
	for _, att := range step.Attestations {
		if attestation.ResolveLegacyType(att.Type) == github.Type {
			mods = append(mods, att.RegoPolicies...)
		}
	}
	require.NotEmpty(t, mods, "release-build must carry a rego module on the github predicate")
	return mods
}

// rawPredicate hands the verifier a predicate as exact JSON, for shapes the
// real attestor type cannot carry (a non-object jwt, extra top-level keys).
type rawPredicate string

func (r rawPredicate) MarshalJSON() ([]byte, error)                 { return []byte(r), nil }
func (rawPredicate) Name() string                                   { return github.Name }
func (rawPredicate) Type() string                                   { return github.Type }
func (rawPredicate) RunType() attestation.RunType                   { return github.RunType }
func (rawPredicate) Attest(_ *attestation.AttestationContext) error { return nil }
func (rawPredicate) Schema() *jsonschema.Schema                     { return nil }

// releaseGithubDenials evaluates the committed module under the CLI's
// enforced hardening and returns the denial reasons, nil for a pass. Any
// outcome other than a pass or a policy denial fails the test.
func releaseGithubDenials(t *testing.T, a attestation.Attestor) []string {
	t.Helper()
	resetHardeningAfter(t)
	policy.SetHardening(policy.EnforcedHardening())
	err := policy.EvaluateRegoPolicy(a, releaseGithubRule(t))
	if err == nil {
		return nil
	}
	var denied policy.ErrPolicyDenied
	require.True(t, errors.As(err, &denied), "want a pass or a policy denial, got %v", err)
	require.NotEmpty(t, denied.Reasons)
	return denied.Reasons
}

// realReleasePredicate decodes the fixture into the registered github
// attestor type, as the verifier does, so the module sees the JSON the real
// type re-marshals rather than the bytes on disk.
func realReleasePredicate(t *testing.T, edit func(claims map[string]interface{})) *github.Attestor {
	t.Helper()
	body, err := os.ReadFile(releaseGithubPredicateFixture)
	require.NoError(t, err)
	a := github.New()
	require.NoError(t, json.Unmarshal(body, a))
	require.NotNil(t, a.JWT, "the fixture must carry the workflow's OIDC claims")
	if edit != nil {
		edit(a.JWT.Claims)
	}
	return a
}

func TestReleasePolicyGithubRuleAdmitsTheRealTaggedRelease(t *testing.T) {
	a := realReleasePredicate(t, nil)
	require.Equal(t, "aflock-ai/rookery", a.JWT.Claims["repository"])
	require.Equal(t, "tag", a.JWT.Claims["ref_type"])
	require.Empty(t, releaseGithubDenials(t, a))
}

func TestReleasePolicyGithubRuleDeniesAForeignRepository(t *testing.T) {
	for _, repo := range []string{"attacker/rookery", "aflock-ai/rookery-fork", "Aflock-AI/rookery", "aflock-ai/rookery ", ""} {
		t.Run(repo, func(t *testing.T) {
			reasons := releaseGithubDenials(t, realReleasePredicate(t, func(c map[string]interface{}) { c["repository"] = repo }))
			require.Len(t, reasons, 1, "only the repository rule should fire, got %q", reasons)
			require.Contains(t, reasons[0], "aflock-ai/rookery")
		})
	}
}

// ref_type "tags" and "tagged" passed the first form's startswith check.
func TestReleasePolicyGithubRuleDeniesAnythingButATag(t *testing.T) {
	for _, refType := range []string{"branch", "tags", "tagged", "TAG", ""} {
		t.Run(refType, func(t *testing.T) {
			reasons := releaseGithubDenials(t, realReleasePredicate(t, func(c map[string]interface{}) {
				c["ref_type"] = refType
				c["ref"] = "refs/heads/main"
			}))
			require.Len(t, reasons, 1, "only the tag rule should fire, got %q", reasons)
			require.Contains(t, reasons[0], "tag")
		})
	}
}

func TestReleasePolicyGithubRuleDeniesAbsentOrMistypedClaims(t *testing.T) {
	cases := map[string]attestation.Attestor{
		"no jwt (real type, omitempty)": github.New(),
		"no claims":                     realReleasePredicate(t, func(c map[string]interface{}) { clear(c) }),
		"claims missing both keys": realReleasePredicate(t, func(c map[string]interface{}) {
			delete(c, "repository")
			delete(c, "ref_type")
		}),
		"non-string claims": realReleasePredicate(t, func(c map[string]interface{}) {
			c["repository"] = []string{"aflock-ai/rookery"}
			c["ref_type"] = map[string]string{"tag": "tag"}
		}),
		"empty object":      rawPredicate(`{}`),
		"jwt null":          rawPredicate(`{"jwt":null}`),
		"jwt not object":    rawPredicate(`{"jwt":"aflock-ai/rookery"}`),
		"claims null":       rawPredicate(`{"jwt":{"claims":null}}`),
		"claims not object": rawPredicate(`{"jwt":{"claims":["aflock-ai/rookery","tag"]}}`),
		// The fields the first form read, set to passing values, must not
		// stand in for the claims.
		"top-level decoys only": rawPredicate(`{"repository":"aflock-ai/rookery","reftype":"tag","ref_type":"tag","jwt":{"claims":{}}}`),
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			reasons := releaseGithubDenials(t, a)
			require.Len(t, reasons, 2, "absent or mistyped claims must trip both rules, got %q", reasons)
			joined := strings.Join(reasons, "\n")
			require.Contains(t, joined, "jwt.claims.repository")
			require.Contains(t, joined, "jwt.claims.ref_type")
		})
	}
}

// The rule must be read through object.get with a failing default, never a
// bare input reference: a bare reference is undefined when the field is
// absent, and an undefined deny body admits.
func TestReleasePolicyGithubRuleReadsNoBareInputPath(t *testing.T) {
	for _, m := range releaseGithubRule(t) {
		src := string(m.Module)
		require.NotContains(t, src, "input.", "module %s reads a bare input path", m.Name)
		require.Contains(t, src, "object.get(input,", "module %s must read input through object.get", m.Name)
	}
}

// The committed file keeps the module base64-encoded; guard the encoding so
// a hand edit cannot leave a module the verifier decodes differently.
func TestReleasePolicyGithubRuleIsCanonicalBase64(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "deploy", "cilock", "release.policy.json"))
	require.NoError(t, err)
	for _, m := range releaseGithubRule(t) {
		require.Contains(t, string(body), base64.StdEncoding.EncodeToString(m.Module))
	}
}
