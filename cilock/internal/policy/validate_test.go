// Copyright 2025 The Aflock Authors
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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	rpolicy "github.com/aflock-ai/rookery/attestation/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateRawPolicy_EmptyJSON tests that an empty JSON object is rejected.
func TestValidateRawPolicy_EmptyJSON(t *testing.T) {
	result := ValidateRawPolicy(context.Background(), []byte("{}"))
	assert.False(t, result.Valid, "empty policy should be invalid")
	assert.NotEmpty(t, result.Errors, "empty policy should have errors")
}

// TestValidateRawPolicy_InvalidJSON tests that invalid JSON is rejected.
func TestValidateRawPolicy_InvalidJSON(t *testing.T) {
	result := ValidateRawPolicy(context.Background(), []byte("not json at all"))
	assert.False(t, result.Valid, "invalid JSON should be rejected")
}

// TestValidateRawPolicy_ValidMinimalPolicy tests a minimal valid policy.
func TestValidateRawPolicy_ValidMinimalPolicy(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://aflock.ai/attestations/command-run/v0.1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1", Key: ""},
		},
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	result := ValidateRawPolicy(context.Background(), data)
	assert.True(t, result.Valid, "valid minimal policy should pass: errors=%v", result.Errors)
}

// TestValidateRawPolicy_StepNameMismatch tests that a step whose key doesn't
// match its Name field is flagged.
func TestValidateRawPolicy_StepNameMismatch(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "different-name",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://aflock.ai/attestations/command-run/v0.1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	result := ValidateRawPolicy(context.Background(), data)
	assert.False(t, result.Valid, "step name mismatch should be invalid")
}

// TestValidateRawPolicy_MissingFunctionaries tests that a step with no
// functionaries is rejected.
func TestValidateRawPolicy_MissingFunctionaries(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name:          "build",
				Functionaries: []functionary{},
				Attestations: []attestation{
					{Type: "https://aflock.ai/attestations/command-run/v0.1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	result := ValidateRawPolicy(context.Background(), data)
	assert.False(t, result.Valid, "step with no functionaries should be invalid")
}

// TestValidateRawPolicy_ExpiredPolicy tests that an expired policy generates
// a warning but is still structurally valid.
func TestValidateRawPolicy_ExpiredPolicy(t *testing.T) {
	policy := policyDocument{
		Expires: "2020-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://aflock.ai/attestations/command-run/v0.1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	result := ValidateRawPolicy(context.Background(), data)
	// Expired policy is structurally valid but should have a warning
	assert.True(t, result.Valid, "expired policy should be structurally valid")
	found := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			found = true
		}
	}
	assert.True(t, found, "expired policy should have at least one warning")
}

// TestValidateRawPolicy_UndefinedKeyReference tests that a functionary
// referencing an undefined public key is flagged.
func TestValidateRawPolicy_UndefinedKeyReference(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "nonexistent-key"},
				},
				Attestations: []attestation{
					{Type: "https://aflock.ai/attestations/command-run/v0.1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	result := ValidateRawPolicy(context.Background(), data)
	assert.False(t, result.Valid, "undefined key reference should be invalid")
}

// ===========================================================================
// BUG: policyStep struct is missing AttestationsFrom field
// ===========================================================================

// TestValidateRawPolicy_AttestationsFromDeserialization tests that a policy
// with attestationsFrom is correctly deserialized and validated. This exposes
// a BUG: the policyStep struct in validate.go does not include AttestationsFrom,
// so attestationsFrom entries in policy JSON are silently dropped during
// deserialization.
func TestValidateRawPolicy_AttestationsFromDeserialization(t *testing.T) {
	// Build a raw JSON policy with attestationsFrom
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}]
			},
			"deploy": {
				"name": "deploy",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}],
				"attestationsFrom": ["build"]
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	assert.True(t, result.Valid, "valid policy with attestationsFrom should pass: errors=%v", result.Errors)

	// Now verify that the policyStep struct actually captures attestationsFrom.
	// BUG: The policyStep struct is missing AttestationsFrom, so the following
	// deserialization will silently lose the field.
	var doc policyDocument
	err := json.Unmarshal([]byte(rawJSON), &doc)
	require.NoError(t, err)

	deployStep, ok := doc.Steps["deploy"]
	require.True(t, ok, "deploy step should exist in deserialized policy")

	// This assertion exposes the BUG: AttestationsFrom is not in policyStep,
	// so this field is always empty after JSON deserialization.
	// The validate code cannot warn about invalid cross-step references
	// because it never sees the attestationsFrom data.
	if len(deployStep.ArtifactsFrom) == 0 {
		// This is expected to be empty in the test JSON, just sanity check
		t.Log("ArtifactsFrom is empty as expected (not testing artifactsFrom)")
	}

	// The real test: does the validator know about attestationsFrom at all?
	// We intentionally reference a NON-EXISTENT step to see if validation catches it.
	rawJSONBadRef := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}]
			},
			"deploy": {
				"name": "deploy",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}],
				"attestationsFrom": ["nonexistent-step"]
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	resultBadRef := ValidateRawPolicy(context.Background(), []byte(rawJSONBadRef))
	// BUG: The validator should flag this as an error because "nonexistent-step"
	// doesn't exist in the policy, but since AttestationsFrom is not in the
	// policyStep struct, it passes silently.
	if resultBadRef.Valid {
		t.Error("BUG: policy with attestationsFrom referencing nonexistent step " +
			"should be flagged as invalid, but validator silently accepts it " +
			"because policyStep struct is missing the AttestationsFrom field")
	}
}

// TestValidateRawPolicy_CircularAttestationsFrom tests that the validator
// detects circular dependencies in attestationsFrom. This is related to the
// policyStep missing AttestationsFrom field.
func TestValidateRawPolicy_CircularAttestationsFrom(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"a": {
				"name": "a",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}],
				"attestationsFrom": ["b"]
			},
			"b": {
				"name": "b",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}],
				"attestationsFrom": ["a"]
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	// BUG: Circular dependency should be detected, but since policyStep
	// doesn't capture attestationsFrom, the validator cannot detect cycles.
	if result.Valid {
		t.Error("BUG: policy with circular attestationsFrom should be flagged " +
			"as invalid, but validator silently accepts it because policyStep " +
			"struct is missing the AttestationsFrom field")
	}
}

func combinedCyclePolicy(aFrom, bFrom string) []byte {
	return []byte(`{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"a": {
				"name": "a",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}],
				` + aFrom + `
			},
			"b": {
				"name": "b",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}],
				` + bFrom + `
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`)
}

// #9813: each relation is acyclic, but a artifactsFrom b plus b
// attestationsFrom a is a cycle in their union, which the engine refuses. The
// static validator must refuse it too and name every hop.
func TestValidateRawPolicy_CombinedAttestationsFromArtifactsFromCycle(t *testing.T) {
	result := ValidateRawPolicy(context.Background(),
		combinedCyclePolicy(`"artifactsFrom": ["b"]`, `"attestationsFrom": ["a"]`))
	assert.False(t, result.Valid, "a cycle through artifactsFrom and attestationsFrom must be refused")
	assert.Contains(t, result.Errors,
		"Circular dependency across attestationsFrom and artifactsFrom detected: a -[artifactsFrom]-> b -[attestationsFrom]-> a")

	// The same edges pointing one way are not a cycle.
	ok := ValidateRawPolicy(context.Background(),
		combinedCyclePolicy(`"artifactsFrom": ["b"]`, `"attestationsFrom": []`))
	assert.True(t, ok.Valid, "an acyclic union must validate: %v", ok.Errors)
	for _, e := range ok.Errors {
		assert.NotContains(t, e, "Circular", "an acyclic union must not be reported as a cycle")
	}

	// A cycle within one relation keeps its existing message and is not
	// reported a second time by the union check.
	pair := ValidateRawPolicy(context.Background(),
		combinedCyclePolicy(`"artifactsFrom": ["b"]`, `"artifactsFrom": ["a"]`))
	assert.False(t, pair.Valid)
	circular := 0
	for _, e := range pair.Errors {
		if strings.Contains(e, "Circular") {
			circular++
			assert.Contains(t, e, "Circular artifactsFrom dependency detected")
		}
	}
	assert.Equal(t, 1, circular)
}

// ===========================================================================
// Additional edge case tests for validate
// ===========================================================================

// TestValidateRawPolicy_NoSteps tests that a policy with no steps is rejected.
func TestValidateRawPolicy_NoSteps(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	assert.False(t, result.Valid, "policy with no steps should be invalid")
}

// TestValidateRawPolicy_NoKeysOrRoots tests that a policy with no public keys
// and no root certificates is rejected.
func TestValidateRawPolicy_NoKeysOrRoots(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "test"}]
			}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	assert.False(t, result.Valid, "policy with no keys or roots should be invalid")
}

// TestValidateRawPolicy_InvalidFunctionaryType tests that an invalid
// functionary type is rejected.
func TestValidateRawPolicy_InvalidFunctionaryType(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{"type": "invalid-type"}],
				"attestations": [{"type": "test"}]
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	assert.False(t, result.Valid, "invalid functionary type should be rejected")
}

// TestValidateRawPolicy_TestResultsFlatInputWarns covers #9312: the
// test-results attestor marshals as {"predicate": {...}}, so a rego module
// bound to that predicate type which reads input.summary.* (the flat form
// every other attestor uses) evaluates against an undefined path and never
// denies. The lint flags it at authoring time; it is a warning, not an
// error, because a module can legitimately read nothing from input.
func TestValidateRawPolicy_TestResultsFlatInputWarns(t *testing.T) {
	mk := func(module string) []byte {
		policy := policyDocument{
			Expires: "2030-01-01T00:00:00Z",
			Steps: map[string]policyStep{
				"test": {
					Name:          "test",
					Functionaries: []functionary{{Type: "publickey", PublicKeyID: "key-1"}},
					Attestations: []attestation{{
						Type: "https://aflock.ai/attestations/test-results/v0.1",
						RegoPolicies: []regoPolicy{{
							Name:   "tests-passed",
							Module: base64.StdEncoding.EncodeToString([]byte(module)),
						}},
					}},
				},
			},
			PublicKeys: map[string]publicKeyEntry{"key-1": {KeyID: "key-1", Key: ""}},
		}
		data, err := json.Marshal(policy)
		require.NoError(t, err)
		return data
	}

	flat := "package testresults\n\ndeny[msg] {\n\tinput.summary.failed > 0\n\tmsg := \"failed\"\n}\n"
	res := ValidateRawPolicy(context.Background(), mk(flat))
	assert.True(t, res.Valid, "a flat read is a warning, not an error: %v", res.Errors)
	require.NotEmpty(t, res.Warnings)
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "tests-passed") && strings.Contains(w, "input.summary") && strings.Contains(w, "input.predicate.summary") {
			found = true
		}
	}
	assert.True(t, found, "warning must name the policy, the flat path read, and the wrapped path to use; got %v", res.Warnings)

	wrapped := "package testresults\n\ndeny[msg] {\n\tinput.predicate.summary.failed > 0\n\tmsg := \"failed\"\n}\n"
	res = ValidateRawPolicy(context.Background(), mk(wrapped))
	assert.True(t, res.Valid)
	for _, w := range res.Warnings {
		assert.NotContains(t, w, "input.predicate.summary", "the correct shape must not warn: %v", res.Warnings)
	}

	// The lint is keyed on the predicate type: the same flat module bound
	// to command-run (whose fields ARE top-level) must not warn.
	other := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name:          "build",
				Functionaries: []functionary{{Type: "publickey", PublicKeyID: "key-1"}},
				Attestations: []attestation{{
					Type:         "https://aflock.ai/attestations/command-run/v0.1",
					RegoPolicies: []regoPolicy{{Name: "flat-elsewhere", Module: base64.StdEncoding.EncodeToString([]byte(flat))}},
				}},
			},
		},
		PublicKeys: map[string]publicKeyEntry{"key-1": {KeyID: "key-1", Key: ""}},
	}
	data, err := json.Marshal(other)
	require.NoError(t, err)
	res = ValidateRawPolicy(context.Background(), data)
	for _, w := range res.Warnings {
		assert.NotContains(t, w, "flat-elsewhere", "lint must be scoped to the test-results predicate type: %v", res.Warnings)
	}
}

// A comment or a string literal that merely NAMES the flat path is not a read
// of it. The lint used to match the module's raw bytes, so a policy that warns
// its own reader away from `input.summary` was told it read it (#9312 review).
func TestWrappedPredicateLintReadsReferencesNotText(t *testing.T) {
	const wrapped = "https://aflock.ai/attestations/test-results/v0.1"
	cases := []struct {
		name   string
		module string
		warn   bool
	}{
		{
			name: "a real flat read warns",
			module: `package p
deny[msg] { input.summary.failed > 0; msg := "x" }`,
			warn: true,
		},
		{
			name: "a bracket read warns",
			module: `package p
deny[msg] { input["summary"].failed > 0; msg := "x" }`,
			warn: true,
		},
		{
			name: "a comment naming the flat path does not warn",
			module: `package p
# Do not write input.summary.failed here: it is undefined at verify time.
deny[msg] { input.predicate.summary.failed > 0; msg := "x" }`,
			warn: false,
		},
		{
			name: "a string literal naming the flat path does not warn",
			module: `package p
deny[msg] { input.predicate.summary.failed > 0; msg := "read input.predicate.summary, never input.summary" }`,
			warn: false,
		},
		{
			name: "the wrapped read alone does not warn",
			module: `package p
deny[msg] { input.predicate.summary.failed > 0; msg := "x" }`,
			warn: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := &ValidationResult{}
			lintWrappedPredicateReads("s", 0, wrapped, "pol", []byte(c.module), result)
			warned := len(result.Warnings) > 0
			if warned != c.warn {
				t.Fatalf("warned=%v want %v; warnings=%v", warned, c.warn, result.Warnings)
			}
		})
	}
}

func regoPolicyDoc(t *testing.T, modules ...string) []byte {
	t.Helper()
	rps := make([]regoPolicy, 0, len(modules))
	for i, m := range modules {
		rps = append(rps, regoPolicy{Name: fmt.Sprintf("rule-%d", i), Module: base64.StdEncoding.EncodeToString([]byte(m))})
	}
	doc := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"release": {
				Name:          "release",
				Functionaries: []functionary{{Type: "publickey", PublicKeyID: "key-1"}},
				Attestations:  []attestation{{Type: "https://witness.dev/attestations/github/v0.1", RegoPolicies: rps}},
			},
		},
		PublicKeys: map[string]publicKeyEntry{"key-1": {KeyID: "key-1", Key: ""}},
	}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	return data
}

// underEachHardening validates doc with no hardening option on and with every
// one on (the cilock CLI's default), and returns both results. The fail-open
// lint reads none of the options, so every assertion must hold for both.
func underEachHardening(t *testing.T, doc []byte) []*ValidationResult {
	t.Helper()
	prev := rpolicy.Hardening()
	t.Cleanup(func() { rpolicy.SetHardening(prev) })
	var every rpolicy.HardeningOptions
	v := reflect.ValueOf(&every).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Bool {
			v.Field(i).SetBool(true)
		}
	}
	modes := []rpolicy.HardeningOptions{{}, every}
	out := make([]*ValidationResult, 0, len(modes))
	for _, h := range modes {
		rpolicy.SetHardening(h)
		out = append(out, ValidateRawPolicy(context.Background(), doc))
	}
	return out
}

func joinedLines(ss []string) string { return strings.Join(ss, "\n") }

const inlineNegation = "package tagged\n\ndeny[msg] {\n\tnot startswith(input.reftype, \"tag\")\n\tmsg := \"untagged\"\n}\n"

// An inline negation over input never fires on a predicate without the field:
// the compiler reads input.reftype outside the `not`. validate reports it as
// a warning naming the path, and never fails the policy for it.
func TestValidateRawPolicy_InlineNegationWarns(t *testing.T) {
	for _, res := range underEachHardening(t, regoPolicyDoc(t, inlineNegation)) {
		assert.True(t, res.Valid, "a lint finding is a warning, never a validation error: %v", res.Errors)
		assert.Contains(t, joinedLines(res.Warnings), "input.reftype")
		assert.Contains(t, joinedLines(res.Warnings), "rule-0")
		assert.NotContains(t, joinedLines(res.Warnings), "rejected")
	}
}

func TestValidateRawPolicy_GuardedNegationPasses(t *testing.T) {
	guarded := "package tagged\n\ntagged { startswith(input.reftype, \"tag\") }\n\ndeny[msg] {\n\tnot tagged\n\tmsg := \"untagged\"\n}\n"
	for _, res := range underEachHardening(t, regoPolicyDoc(t, guarded)) {
		assert.True(t, res.Valid, "the helper-rule form fires on a missing field and must pass: %v", res.Errors)
		assert.NotContains(t, joinedLines(res.Warnings), "empty predicate")
		assert.NotContains(t, joinedLines(res.Warnings), "never fires")
	}
}

// The probe catches what the negation lint cannot: a comparison over a
// missing field (`input.repository != "x"`) is undefined, not true. It is a
// warning, because some modules legitimately gate only on present data.
func TestValidateRawPolicy_EmptyPredicateProbeWarns(t *testing.T) {
	vacuous := "package repo\n\ndeny[msg] {\n\tinput.repository != \"aflock-ai/rookery\"\n\tmsg := \"foreign\"\n}\n"
	for _, res := range underEachHardening(t, regoPolicyDoc(t, vacuous)) {
		assert.True(t, res.Valid, "the probe is a warning: %v", res.Errors)
		assert.Contains(t, joinedLines(res.Warnings), "empty predicate")
		assert.Contains(t, joinedLines(res.Warnings), "release")
	}
}

// The reviewer's reproduction: the negation sits in a helper that deny
// consumes as `not ok`. On a missing field ok is undefined, so `not ok` is
// true and deny fires. That is fail-closed, so there is nothing to report.
func TestValidateRawPolicy_NegationInNegatedHelperPasses(t *testing.T) {
	helper := "package branch\n\nok { not startswith(input.ref, \"refs/heads/evil\") }\n\ndeny[msg] {\n\tnot ok\n\tmsg := \"x\"\n}\n"
	for _, res := range underEachHardening(t, regoPolicyDoc(t, helper)) {
		assert.True(t, res.Valid, "a negation in a negated helper fails closed: %v", res.Errors)
		assert.NotContains(t, joinedLines(res.Warnings), "input.ref")
		assert.NotContains(t, joinedLines(res.Warnings), "empty predicate")
	}
}

// Review round 2: a rule compared by value to its default is fail-closed.
// A missing ref leaves ok at false, so `ok == false` holds and deny fires.
const booleanComparisonOverDefault = "package p\ndefault ok = false\nok { not startswith(input.ref, \"refs/heads/evil\") }\ndeny[\"bad ref\"] { ok == false }\n"

func TestValidateRawPolicy_BooleanComparisonOverDefaultPasses(t *testing.T) {
	for _, res := range underEachHardening(t, regoPolicyDoc(t, booleanComparisonOverDefault)) {
		assert.True(t, res.Valid, "ok == false over a false default fails closed: %v", res.Errors)
		assert.NotContains(t, joinedLines(res.Warnings), "input.ref")
	}
}

// The same comparison over a true default is fail-open: a missing ref leaves
// ok at true, and deny never fires. validate warns and still passes.
func TestValidateRawPolicy_BooleanComparisonOverTrueDefaultWarns(t *testing.T) {
	mod := "package p\ndefault ok = true\nok = false { not startswith(input.ref, \"refs/heads/evil\") }\ndeny[\"bad ref\"] { ok == false }\n"
	for _, res := range underEachHardening(t, regoPolicyDoc(t, mod)) {
		assert.True(t, res.Valid, "a lint finding is a warning, never a validation error: %v", res.Errors)
		assert.Contains(t, joinedLines(res.Warnings), "input.ref")
		assert.NotContains(t, joinedLines(res.Warnings), "cannot decide")
	}
}

// A comparison the lint does not model is a warning that says the lint could
// not decide.
func TestValidateRawPolicy_UndecidedPolarityWarns(t *testing.T) {
	mod := "package p\ndefault ok = false\nok { not startswith(input.ref, \"refs/heads/evil\") }\nwant = false { true }\ndeny[\"bad ref\"] { ok == want }\n"
	for _, res := range underEachHardening(t, regoPolicyDoc(t, mod)) {
		assert.True(t, res.Valid, "an undecided finding must not fail validation: %v", res.Errors)
		assert.Contains(t, joinedLines(res.Warnings), "input.ref")
		assert.Contains(t, joinedLines(res.Warnings), "cannot decide")
	}
}

// The evaluator loads an attestation's modules together, so validate lints
// them together: a module calling a sibling module's function compiles, and
// its fail-open negation is reported rather than skipped as a compile error.
func TestValidateRawPolicy_LintsTheAttestationModuleSet(t *testing.T) {
	caller := "package caller\n\ndeny[msg] {\n\tnot data.helpers.tagged(input.ref)\n\tmsg := \"untagged\"\n}\n"
	helpers := "package helpers\n\ntagged(r) { startswith(r, \"refs/tags/\") }\n\ndeny[msg] {\n\tinput.never == true\n\tmsg := \"never\"\n}\n"
	for _, res := range underEachHardening(t, regoPolicyDoc(t, caller, helpers)) {
		assert.True(t, res.Valid, "a lint finding is a warning, never a validation error: %v", res.Errors)
		assert.Contains(t, joinedLines(res.Warnings), "input.ref")
		assert.Contains(t, joinedLines(res.Warnings), "rule-0")
		assert.NotContains(t, joinedLines(res.Warnings), "does not compile")
	}
}
