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
	"encoding/json"
	"testing"

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
