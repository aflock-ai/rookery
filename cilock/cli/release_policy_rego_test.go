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

// The committed release policy's github rule must bind the release to
// aflock-ai/rookery and to a tag. Its first form read input.repository and
// input.reftype, which the github predicate does not carry (they sit under
// jwt.claims), so both rules were undefined on every real predicate and never
// denied anything. These tests evaluate the committed module against real
// github attestor values through the verifier's own entry point.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/plugins/attestors/github"
	"github.com/aflock-ai/rookery/plugins/attestors/jwt"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

const releasePolicyGithubType = "https://witness.dev/attestations/github/v0.1"

func releasePolicyGithubModules(t *testing.T) []policy.RegoPolicy {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "deploy", "cilock", "release.policy.json"))
	require.NoError(t, err)
	var doc struct {
		Steps map[string]struct {
			Attestations []struct {
				Type         string `json:"type"`
				RegoPolicies []struct {
					Name   string `json:"name"`
					Module string `json:"module"`
				} `json:"regopolicies"`
			} `json:"attestations"`
		} `json:"steps"`
	}
	require.NoError(t, json.Unmarshal(body, &doc))
	var out []policy.RegoPolicy
	for _, att := range doc.Steps["release-build"].Attestations {
		if att.Type != releasePolicyGithubType {
			continue
		}
		for _, rp := range att.RegoPolicies {
			module, err := base64.StdEncoding.DecodeString(rp.Module)
			require.NoError(t, err)
			out = append(out, policy.RegoPolicy{Name: rp.Name, Module: module})
		}
	}
	require.NotEmpty(t, out, "release-build must carry a github rego module")
	return out
}

// githubPredicate is the github attestor's wire shape with JWT claims set.
// A real jwt.Attestor carries a verifying JWK that cannot be marshalled
// without a key, so the fixture marshals github.New() and inserts the claims
// under the JSON names the real structs declare.
type githubPredicate struct {
	*github.Attestor
	claims map[string]interface{}
}

func jsonName(t reflect.Type, field string) string {
	f, ok := t.FieldByName(field)
	if !ok {
		panic("no field " + field)
	}
	return strings.Split(f.Tag.Get("json"), ",")[0]
}

func (g githubPredicate) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(g.Attestor)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	if g.claims != nil {
		m[jsonName(reflect.TypeOf(github.Attestor{}), "JWT")] = map[string]interface{}{
			jsonName(reflect.TypeOf(jwt.Attestor{}), "Claims"): g.claims,
		}
	}
	return json.Marshal(m)
}

func (g githubPredicate) Schema() *jsonschema.Schema                     { return nil }
func (g githubPredicate) Attest(_ *attestation.AttestationContext) error { return nil }

func githubAttestorWithClaims(claims map[string]interface{}) githubPredicate {
	return githubPredicate{Attestor: github.New(), claims: claims}
}

func releaseDenyReasons(t *testing.T, a attestation.Attestor) []string {
	t.Helper()
	err := policy.EvaluateRegoPolicy(a, releasePolicyGithubModules(t))
	if err == nil {
		return nil
	}
	var denied policy.ErrPolicyDenied
	require.True(t, errors.As(err, &denied), "want a policy denial, got %v", err)
	return denied.Reasons
}

func TestReleasePolicyGithubRuleDeniesForeignBranch(t *testing.T) {
	reasons := releaseDenyReasons(t, githubAttestorWithClaims(map[string]interface{}{
		"repository": "attacker/rookery-fork",
		"ref_type":   "branch",
		"ref":        "refs/heads/main",
	}))
	require.Len(t, reasons, 2, "a foreign repository on a branch must trip both rules, got %q", reasons)
}

func TestReleasePolicyGithubRuleDeniesMissingJWT(t *testing.T) {
	reasons := releaseDenyReasons(t, githubAttestorWithClaims(nil))
	require.Len(t, reasons, 2, "a github predicate with no jwt claims must fail closed, got %q", reasons)
}

func TestReleasePolicyGithubRuleDeniesNonStringClaims(t *testing.T) {
	reasons := releaseDenyReasons(t, githubAttestorWithClaims(map[string]interface{}{
		"repository": 42,
		"ref_type":   []string{"tag"},
	}))
	require.Len(t, reasons, 2, "non-string claims must not satisfy the rules, got %q", reasons)
}

func TestReleasePolicyGithubRuleAdmitsTaggedRelease(t *testing.T) {
	reasons := releaseDenyReasons(t, githubAttestorWithClaims(map[string]interface{}{
		"repository": "aflock-ai/rookery",
		"ref_type":   "tag",
		"ref":        "refs/tags/v4.5.0",
	}))
	require.Empty(t, reasons)
}

// The fail-open negation lint is an authoring aid. `cilock policy validate`
// reports each finding as a warning and passes under every --policy-hardening
// mode, and verification under the CLI's default hardening evaluates the
// module instead of refusing it.
const failOpenNegationPolicy = `{
  "expires": "2030-01-01T00:00:00Z",
  "steps": {"build": {"name": "build",
    "functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
    "attestations": [{"type": "https://witness.dev/attestations/github/v0.1",
      "regopolicies": [{"name": "tagged", "module": "%s"}]}]}},
  "publickeys": {"key-1": {"keyid": "key-1", "key": ""}}
}`

func writeFailOpenPolicy(t *testing.T, module string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	body := strings.Replace(failOpenNegationPolicy, "%s", base64.StdEncoding.EncodeToString([]byte(module)), 1)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

const inlineNegationModule = `package tagged

deny[msg] {
	not startswith(input.reftype, "tag")
	msg := "releases must be tagged"
}
`

// Each module validates under default hardening and under warn. wantWarning
// is the text the warning must carry, or "" for a module with no finding.
var failOpenValidateCases = []struct {
	name, module, wantWarning string
}{
	{"inline negation", inlineNegationModule, "never fires when input.reftype is missing"},
	// Review round 2: fail-closed, since a missing ref leaves ok at its
	// default and `ok == false` holds.
	{"boolean comparison over a false default", "package p\ndefault ok = false\nok { not startswith(input.ref, \"refs/heads/evil\") }\ndeny[\"bad ref\"] { ok == false }\n", ""},
	// Review round 4: omitting a leaves f("a") false and admits.
	{"distinct calls to one function", "package p\nf(k) { not startswith(input[k], \"bad\") } else = false { true }\ndeny[\"bad\"] { f(\"a\"); not f(\"b\") }\n", "never fires when input[_] is missing"},
	// Review round 4: fail-closed, since a missing ref empties the
	// comprehension and count(...) == 0 holds.
	{"helper counted as empty", "package p\nok { not startswith(input.ref, \"evil\") }\ndeny[\"bad ref\"] { count([1 | ok]) == 0 }\n", ""},
	// Review round 5, finding 1: fail-closed (a missing ref empties the
	// partial set). The lint does not model a partial set read whole, so it
	// says it cannot decide.
	{"partial set counted as empty", "package p\nallowed[true] { not startswith(input.ref, \"evil\") }\ndeny[\"bad ref\"] { count(allowed) == 0 }\n", "cannot decide"},
	// Review round 5, finding 2: fail-open (a missing ref empties the
	// comprehension, so ok holds and `not ok` does not).
	{"comprehension counted as empty under not", "package p\nok { count([1 | not startswith(input.ref, \"trusted\")]) == 0 }\ndeny[\"bad ref\"] { not ok }\n", "never fires when input.ref is missing"},
}

func TestPolicyValidateReportsFailOpenAsWarnings(t *testing.T) {
	for _, tc := range failOpenValidateCases {
		for _, mode := range []string{"enforce", "warn"} {
			t.Run(tc.name+" "+mode, func(t *testing.T) {
				resetHardeningAfter(t)
				args := []string{"policy", "validate", "--policy", writeFailOpenPolicy(t, tc.module), "--format", "json"}
				if mode == "warn" {
					args = append(args, "--policy-hardening=warn")
				}
				stdout, _, err := executeCmdOutput(args...)
				require.NoError(t, err, "a lint finding never fails validation; output:\n%s", stdout)
				var res struct {
					Valid    bool     `json:"valid"`
					Warnings []string `json:"warnings"`
				}
				require.NoError(t, json.Unmarshal([]byte(stdout), &res))
				require.True(t, res.Valid)
				if tc.wantWarning == "" {
					require.NotContains(t, stdout, "never fires")
					return
				}
				require.Contains(t, strings.Join(res.Warnings, "\n"), tc.wantWarning)
			})
		}
	}
}

// Verification under the CLI's default hardening evaluates a module with a
// fail-open negation instead of refusing it: the finding is logged, and the
// verdict is the engine's.
func TestVerifyUnderDefaultHardeningEvaluatesFailOpenNegation(t *testing.T) {
	resetHardeningAfter(t)
	policy.SetHardening(enforcedHardening())
	mods := []policy.RegoPolicy{{Name: "tagged", Module: []byte(inlineNegationModule)}}
	require.NoError(t, policy.EvaluateRegoPolicy(mapAttestor{"reftype": "tag"}, mods), "a lint finding must not refuse verification")
	err := policy.EvaluateRegoPolicy(mapAttestor{"reftype": "branch"}, mods)
	var denied policy.ErrPolicyDenied
	require.True(t, errors.As(err, &denied), "the module still denies what it reads as denying, got %v", err)
}

// mapAttestor is a predicate given as a JSON object.
type mapAttestor map[string]interface{}

func (mapAttestor) Name() string                                   { return "map" }
func (mapAttestor) Type() string                                   { return "https://example.com/map/v1" }
func (mapAttestor) RunType() attestation.RunType                   { return "test" }
func (mapAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (mapAttestor) Schema() *jsonschema.Schema                     { return nil }

func TestReleasePolicyValidatesCleanUnderEnforce(t *testing.T) {
	resetHardeningAfter(t)
	path := filepath.Join("..", "..", "deploy", "cilock", "release.policy.json")
	stdout, _, err := executeCmdOutput("policy", "validate", "--policy", path, "--format", "json")
	require.NoError(t, err, "the committed release policy must validate under enforce; output:\n%s", stdout)
	require.NotContains(t, stdout, "empty predicate", "the release policy's rego must deny an empty predicate")
	require.NotContains(t, stdout, "never fires", "the release policy must carry no fail-open negation")
}
