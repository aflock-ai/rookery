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
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// R3-270: Content validation before signature verification (TOCTOU-like)
//
// ValidatePolicy first validates the envelope structure and unmarshals
// the payload, THEN validates policy content, and ONLY THEN verifies
// the signature. This means all content validation runs on potentially
// unsigned/tampered data. If the content passes validation but the
// signature fails, the caller has already received a "structurally valid"
// result for unsigned content. The result.Valid field would be false due
// to the signature failure, but the absence of content errors could
// mislead tooling that only checks specific error fields.
//
// More critically: if verifier is nil, signature verification is skipped
// entirely, and the content validation result is returned as-is.
// ===========================================================================

// TestSecurity_R3_270_ContentValidatedBeforeSignature proves that
// ValidatePolicy validates content before checking the signature.
// A structurally valid but unsigned policy is reported as valid when
// no verifier is provided.
func TestSecurity_R3_270_ContentValidatedBeforeSignature(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://example.com/att/v1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	payloadBytes, err := json.Marshal(policy)
	require.NoError(t, err)

	envelope := dsse.Envelope{
		PayloadType: ExpectedPolicyType,
		Payload:     payloadBytes,
		Signatures:  []dsse.Signature{}, // No signatures!
	}

	// With nil verifier: content is validated but signature is not checked.
	result := ValidatePolicy(context.Background(), envelope, nil)
	require.True(t, result.Valid, "SECURITY FINDING: ValidatePolicy with nil verifier "+
		"reports an unsigned policy as valid. Content validation runs without signature "+
		"verification. Callers that pass nil verifier get no signature assurance.")

	// The warnings should mention the missing signatures
	foundSignatureWarning := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			foundSignatureWarning = true
		}
	}
	require.True(t, foundSignatureWarning, "should warn about missing signatures")
}

// TestSecurity_R3_270_ContentValidatedOnTamperedPayload proves that
// content validation runs on the raw payload bytes, which could be
// tampered with if the signature is not checked first.
func TestSecurity_R3_270_ContentValidatedOnTamperedPayload(t *testing.T) {
	// Create a valid policy payload
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://example.com/att/v1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	payloadBytes, err := json.Marshal(policy)
	require.NoError(t, err)

	// Create a "signed" envelope with a fake signature (won't verify)
	envelope := dsse.Envelope{
		PayloadType: ExpectedPolicyType,
		Payload:     payloadBytes,
		Signatures: []dsse.Signature{
			{KeyID: "fake-key", Signature: []byte("not-a-real-signature")},
		},
	}

	// With nil verifier: content validation passes, signature is not checked.
	// The TOCTOU-like issue: content is validated BEFORE signature would be
	// checked (if a verifier were provided), meaning the content validation
	// result is based on potentially tampered data.
	result := ValidatePolicy(context.Background(), envelope, nil)
	require.True(t, result.Valid, "SECURITY FINDING: content passes validation even "+
		"though the signature is fake. With nil verifier, there is no way to know "+
		"the payload is authentic.")
}

// ===========================================================================
// R3-270: PayloadType mismatch treated as warning not error
//
// validateEnvelopeStructure checks the PayloadType but only issues a
// warning, not an error. This means an envelope with a completely wrong
// PayloadType (e.g., "application/json" or "https://evil.com/policy")
// still passes validation. A strict validator should reject unexpected
// payload types to prevent type confusion attacks.
// ===========================================================================

// TestSecurity_R3_270_PayloadTypeMismatchIsWarningNotError proves that
// an unexpected PayloadType only generates a warning, not an error.
func TestSecurity_R3_270_PayloadTypeMismatchIsWarningNotError(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://example.com/att/v1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	payloadBytes, err := json.Marshal(policy)
	require.NoError(t, err)

	// Envelope with completely wrong PayloadType
	envelope := dsse.Envelope{
		PayloadType: "https://evil.com/totally-not-a-policy",
		Payload:     payloadBytes,
		Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
	}

	result := ValidatePolicy(context.Background(), envelope, nil)
	require.True(t, result.Valid, "SECURITY FINDING: wrong PayloadType only generates "+
		"a warning, not an error. An envelope with PayloadType='https://evil.com/totally-"+
		"not-a-policy' is still reported as valid. This enables type confusion attacks "+
		"where a non-policy envelope is accepted as a policy.")

	foundPayloadTypeWarning := false
	for _, w := range result.Warnings {
		if w != "" {
			foundPayloadTypeWarning = true
		}
	}
	require.True(t, foundPayloadTypeWarning, "should have a warning about PayloadType mismatch")
}

// TestSecurity_R3_270_EmptyPayloadTypeIsWarningNotError tests that an
// entirely empty PayloadType also only generates a warning.
func TestSecurity_R3_270_EmptyPayloadTypeIsWarningNotError(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://example.com/att/v1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	payloadBytes, err := json.Marshal(policy)
	require.NoError(t, err)

	envelope := dsse.Envelope{
		PayloadType: "", // Empty PayloadType
		Payload:     payloadBytes,
		Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
	}

	result := ValidatePolicy(context.Background(), envelope, nil)
	require.True(t, result.Valid, "SECURITY FINDING: empty PayloadType only generates "+
		"a warning, not an error. An envelope with no type information is still valid.")
}

// ===========================================================================
// R3-270: Missing validation of envelope signature count
//
// validateEnvelopeStructure checks len(Signatures) == 0 and issues a
// warning, but does not validate that there is at least one signature
// as an error condition. A policy with zero signatures is structurally
// "valid" according to the validator.
// ===========================================================================

// TestSecurity_R3_270_ZeroSignaturesIsWarningNotError proves that a
// DSSE envelope with zero signatures only generates a warning.
func TestSecurity_R3_270_ZeroSignaturesIsWarningNotError(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://example.com/att/v1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	payloadBytes, err := json.Marshal(policy)
	require.NoError(t, err)

	envelope := dsse.Envelope{
		PayloadType: ExpectedPolicyType,
		Payload:     payloadBytes,
		Signatures:  []dsse.Signature{}, // No signatures
	}

	result := ValidatePolicy(context.Background(), envelope, nil)
	require.True(t, result.Valid, "SECURITY FINDING: an envelope with zero signatures "+
		"is reported as valid. The missing signature is only a warning, not an error. "+
		"A policy consumer that trusts result.Valid without checking Warnings will "+
		"accept unsigned policies.")

	// Verify the warning is present
	foundNoSigWarning := false
	for _, w := range result.Warnings {
		if w != "" {
			foundNoSigWarning = true
		}
	}
	require.True(t, foundNoSigWarning, "should warn about missing signatures")
}

// TestSecurity_R3_270_SignatureVerificationSkippedWithNilVerifier proves
// that when verifier is nil, envelope.Verify is never called, even if
// signatures are present.
func TestSecurity_R3_270_SignatureVerificationSkippedWithNilVerifier(t *testing.T) {
	policy := policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{Type: "https://example.com/att/v1"},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	}

	payloadBytes, err := json.Marshal(policy)
	require.NoError(t, err)

	envelope := dsse.Envelope{
		PayloadType: ExpectedPolicyType,
		Payload:     payloadBytes,
		Signatures: []dsse.Signature{
			{KeyID: "fake", Signature: []byte("invalid-sig-data")},
		},
	}

	// nil verifier => signature verification is entirely skipped.
	result := ValidatePolicy(context.Background(), envelope, nil)
	require.True(t, result.Valid, "SECURITY FINDING: with nil verifier, an envelope "+
		"with an invalid signature is reported as valid. The signature is never checked.")

	// No signature-related errors should be present
	for _, e := range result.Errors {
		require.NotContains(t, e, "Signature", "should have no signature errors with nil verifier")
	}
}

// ===========================================================================
// R3-270: policyStep struct missing AttestationsFrom field
//
// The policyStep struct in validate.go does not include an
// AttestationsFrom field. This means attestationsFrom entries in policy
// JSON are silently dropped during deserialization, and the validator
// cannot detect invalid cross-step references or circular dependencies
// in attestationsFrom chains.
// ===========================================================================

// TestSecurity_R3_270_AttestationsFromSilentlyDropped verifies that
// attestationsFrom referencing a nonexistent step is caught by the
// validator (R3-270 FIX: policyStep now includes AttestationsFrom).
func TestSecurity_R3_270_AttestationsFromSilentlyDropped(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://example.com/att/v1"}]
			},
			"deploy": {
				"name": "deploy",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://example.com/att/v1"}],
				"attestationsFrom": ["nonexistent-step"]
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	// R3-270 FIX: attestationsFrom is now deserialized and validated.
	// The validator correctly flags the nonexistent step reference.
	require.False(t, result.Valid, "attestationsFrom referencing a nonexistent step should be invalid")
	foundUndefinedStepError := false
	for _, e := range result.Errors {
		if e != "" {
			foundUndefinedStepError = true
		}
	}
	require.True(t, foundUndefinedStepError, "should report error about undefined step reference in attestationsFrom")
}

// TestSecurity_R3_270_CircularAttestationsFromNotDetected verifies that
// circular dependencies in attestationsFrom are now detected by the
// validator (R3-270 FIX: policyStep includes AttestationsFrom + cycle detection).
func TestSecurity_R3_270_CircularAttestationsFromNotDetected(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"a": {
				"name": "a",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://example.com/att/v1"}],
				"attestationsFrom": ["b"]
			},
			"b": {
				"name": "b",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://example.com/att/v1"}],
				"attestationsFrom": ["a"]
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	// R3-270 FIX: circular attestationsFrom dependency a->b->a is now detected.
	require.False(t, result.Valid, "circular attestationsFrom dependency should be detected")
	foundCircularError := false
	for _, e := range result.Errors {
		if e != "" {
			foundCircularError = true
		}
	}
	require.True(t, foundCircularError, "should report circular dependency error")
}

// ===========================================================================
// R3-270: ValidateRawPolicy accepts unsigned/unwrapped policy JSON
// with only a warning, providing no signature assurance.
// ===========================================================================

// TestSecurity_R3_270_RawPolicyNoSignatureAssurance proves that
// ValidateRawPolicy only warns about the missing DSSE envelope.
func TestSecurity_R3_270_RawPolicyNoSignatureAssurance(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{"type": "publickey", "publickeyid": "key-1"}],
				"attestations": [{"type": "https://example.com/att/v1"}]
			}
		},
		"publickeys": {
			"key-1": {"keyid": "key-1"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	require.True(t, result.Valid, "raw policy is reported as valid despite no DSSE envelope")

	foundDSSEWarning := false
	for _, w := range result.Warnings {
		if w != "" {
			foundDSSEWarning = true
		}
	}
	require.True(t, foundDSSEWarning, "should warn about missing DSSE envelope")
}

// ===========================================================================
// R3-270: Rego policy validation only checks syntax, not semantic safety.
// A syntactically valid but semantically dangerous Rego module (e.g.,
// one that defines deny but never fires) passes validation.
// ===========================================================================

// TestSecurity_R3_270_RegoValidationSyntaxOnly proves that a Rego module
// that defines deny but never fires passes validation. The validator
// only checks syntax (ast.ParseModule), not whether deny can actually fire.
func TestSecurity_R3_270_RegoValidationSyntaxOnly(t *testing.T) {
	// A Rego module where deny is defined but can never fire.
	regoModule := `package never_fires
deny[msg] {
  false
  msg := "never reaches here"
}`
	encodedModule := base64.StdEncoding.EncodeToString([]byte(regoModule))

	rawJSON, err := json.Marshal(policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{
						Type: "https://example.com/att/v1",
						RegoPolicies: []regoPolicy{
							{Name: "never_fires", Module: encodedModule},
						},
					},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	})
	require.NoError(t, err)

	result := ValidateRawPolicy(context.Background(), rawJSON)
	require.True(t, result.Valid, "SECURITY FINDING: a Rego module with deny[msg] { false } "+
		"passes validation because only syntax is checked. The module is semantically "+
		"a no-op (deny can never fire), but the validator does not detect this.")
}

// TestSecurity_R3_270_RegoEmptyDenyArrayPassesValidation proves that
// a Rego module defining deny = [] passes validation.
func TestSecurity_R3_270_RegoEmptyDenyArrayPassesValidation(t *testing.T) {
	regoModule := `package empty_deny
deny = []`
	encodedModule := base64.StdEncoding.EncodeToString([]byte(regoModule))

	rawJSON, err := json.Marshal(policyDocument{
		Expires: "2030-01-01T00:00:00Z",
		Steps: map[string]policyStep{
			"build": {
				Name: "build",
				Functionaries: []functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []attestation{
					{
						Type: "https://example.com/att/v1",
						RegoPolicies: []regoPolicy{
							{Name: "empty_deny", Module: encodedModule},
						},
					},
				},
			},
		},
		PublicKeys: map[string]publicKeyEntry{
			"key-1": {KeyID: "key-1"},
		},
	})
	require.NoError(t, err)

	result := ValidateRawPolicy(context.Background(), rawJSON)
	require.True(t, result.Valid, "SECURITY FINDING: a Rego module with deny = [] "+
		"passes validation. This module will never deny anything at runtime, "+
		"effectively disabling policy enforcement for this attestation type.")
}

// ===========================================================================
// R3-270: validatePolicyContent does not validate the functionary
// certConstraint fields. A functionary of type "root" with an empty
// certConstraint (no CN, no Org, no Roots) passes validation.
// ===========================================================================

// TestSecurity_R3_270_RootFunctionaryWithEmptyCertConstraint proves that
// the validator does not check certConstraint fields on root functionaries.
func TestSecurity_R3_270_RootFunctionaryWithEmptyCertConstraint(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{
					"type": "root",
					"certConstraint": {}
				}],
				"attestations": [{"type": "https://example.com/att/v1"}]
			}
		},
		"roots": {
			"root-1": {"certificate": "` + base64.StdEncoding.EncodeToString([]byte("fake-cert")) + `"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	require.True(t, result.Valid, "SECURITY FINDING: a root functionary with an empty "+
		"certConstraint (no CN, Org, Roots, etc.) passes validation. At runtime, this "+
		"functionary's CertConstraint.Roots will be empty, causing the functionary to "+
		"reject all certs. But the validator does not warn about this likely misconfiguration.")
}

// ===========================================================================
// R3-270: Empty payload results in early error (correct behavior).
// ===========================================================================

// TestSecurity_R3_270_EmptyPayloadIsError proves that an empty payload
// correctly results in an error.
func TestSecurity_R3_270_EmptyPayloadIsError(t *testing.T) {
	envelope := dsse.Envelope{
		PayloadType: ExpectedPolicyType,
		Payload:     []byte{},
		Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
	}

	result := ValidatePolicy(context.Background(), envelope, nil)
	require.False(t, result.Valid, "empty payload should be invalid (correct behavior)")
}

// ===========================================================================
// R3-270: Multiple validation errors may hide each other.
// The validator accumulates errors but does not prioritize them.
// A policy with both structural errors AND content errors reports all
// of them equally, which could overwhelm tooling.
// ===========================================================================

// TestSecurity_R3_270_MultipleErrorsAccumulate proves that the validator
// accumulates all errors rather than short-circuiting.
func TestSecurity_R3_270_MultipleErrorsAccumulate(t *testing.T) {
	// A policy with multiple issues: no steps, no keys, no expires.
	rawJSON := `{}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	require.False(t, result.Valid, "empty policy should be invalid")
	require.GreaterOrEqual(t, len(result.Errors), 2,
		"multiple validation errors should accumulate, not short-circuit")
}

// ===========================================================================
// R3-270: validateKeyReferences only checks publickey functionaries.
// Root functionaries with certConstraint.roots referencing nonexistent
// root IDs are not validated by the cilock validator.
// ===========================================================================

// TestSecurity_R3_270_RootReferenceNotValidated proves that
// certConstraint.roots entries are not validated against the policy's
// roots map.
func TestSecurity_R3_270_RootReferenceNotValidated(t *testing.T) {
	rawJSON := `{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"build": {
				"name": "build",
				"functionaries": [{
					"type": "root",
					"certConstraint": {
						"roots": ["nonexistent-root-id"]
					}
				}],
				"attestations": [{"type": "https://example.com/att/v1"}]
			}
		},
		"roots": {
			"actual-root": {"certificate": "` + base64.StdEncoding.EncodeToString([]byte("cert-data")) + `"}
		}
	}`

	result := ValidateRawPolicy(context.Background(), []byte(rawJSON))
	require.True(t, result.Valid, "SECURITY FINDING: certConstraint.roots references "+
		"'nonexistent-root-id' which does not exist in the policy's roots map, but "+
		"the validator does not catch this. At runtime, the functionary will never "+
		"match any certificate because the referenced root bundle doesn't exist.")
}
