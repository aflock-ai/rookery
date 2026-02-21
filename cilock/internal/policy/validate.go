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
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/open-policy-agent/opa/ast"
)

const (
	ExpectedPolicyType = "https://witness.testifysec.com/policy/v0.1"
)

type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type policyDocument struct {
	Expires              string                        `json:"expires"`
	Steps                map[string]policyStep         `json:"steps"`
	PublicKeys           map[string]publicKeyEntry     `json:"publickeys,omitempty"`
	Roots                map[string]rootEntry          `json:"roots,omitempty"`
	TimestampAuthorities map[string]timestampAuthority `json:"timestampauthorities,omitempty"`
}

type policyStep struct {
	Name          string        `json:"name"`
	Functionaries []functionary `json:"functionaries"`
	Attestations  []attestation `json:"attestations"`
	ArtifactsFrom []string      `json:"artifactsfrom,omitempty"`
}

type functionary struct {
	Type           string          `json:"type"`
	PublicKeyID    string          `json:"publickeyid,omitempty"`
	CertConstraint *certConstraint `json:"certConstraint,omitempty"`
}

type certConstraint struct {
	CommonName    string   `json:"commonname,omitempty"`
	DNSNames      []string `json:"dnsnames,omitempty"`
	Emails        []string `json:"emails,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	URIs          []string `json:"uris,omitempty"`
	Roots         []string `json:"roots,omitempty"`
}

type attestation struct {
	Type         string       `json:"type"`
	RegoPolicies []regoPolicy `json:"regopolicies,omitempty"`
}

type regoPolicy struct {
	Name   string `json:"name"`
	Module string `json:"module"`
}

type publicKeyEntry struct {
	KeyID string `json:"keyid"`
	Key   string `json:"key"`
}

type rootEntry struct {
	Certificate string `json:"certificate"`
}

type timestampAuthority struct {
	Certificate string `json:"certificate"`
}

func ValidatePolicy(ctx context.Context, envelope dsse.Envelope, verifier cryptoutil.Verifier) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	validateEnvelopeStructure(&envelope, result)

	var policy policyDocument
	if err := json.Unmarshal(envelope.Payload, &policy); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to unmarshal policy payload: %v", err))
		result.Valid = false
		return result
	}

	validatePolicyContent(&policy, result)

	if verifier != nil {
		validateSignature(ctx, &envelope, verifier, result)
	}

	return result
}

func ValidateRawPolicy(ctx context.Context, policyJSON []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	result.Warnings = append(result.Warnings, "Policy is not wrapped in a DSSE envelope - signatures cannot be verified")

	var policy policyDocument
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to unmarshal policy JSON: %v", err))
		result.Valid = false
		return result
	}

	validatePolicyContent(&policy, result)

	return result
}

func validatePolicyContent(policy *policyDocument, result *ValidationResult) {
	validatePolicySchema(policy, result)
	validateExpiration(policy, result)
	validateSteps(policy, result)
	validatePublicKeys(policy, result)
	validateRoots(policy, result)
	validateRegoPolicies(policy, result)
	validateKeyReferences(policy, result)
}

func validateEnvelopeStructure(envelope *dsse.Envelope, result *ValidationResult) {
	if envelope.PayloadType != ExpectedPolicyType {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Unexpected PayloadType: expected %s, got %s", ExpectedPolicyType, envelope.PayloadType))
	}

	if len(envelope.Payload) == 0 {
		result.Errors = append(result.Errors, "DSSE envelope payload is empty")
		result.Valid = false
	}

	if len(envelope.Signatures) == 0 {
		result.Warnings = append(result.Warnings, "Policy is not signed - no signatures found in DSSE envelope")
	}
}

func validatePolicySchema(policy *policyDocument, result *ValidationResult) {
	if policy.Expires == "" {
		result.Errors = append(result.Errors, "Policy missing required field: expires")
		result.Valid = false
	}

	if len(policy.Steps) == 0 {
		result.Errors = append(result.Errors, "Policy must define at least one step")
		result.Valid = false
	}

	if len(policy.PublicKeys) == 0 && len(policy.Roots) == 0 {
		result.Errors = append(result.Errors, "Policy must define at least one public key or root certificate")
		result.Valid = false
	}
}

func validateExpiration(policy *policyDocument, result *ValidationResult) {
	if policy.Expires == "" {
		return
	}

	expiresTime, err := time.Parse(time.RFC3339, policy.Expires)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid expires timestamp format: %v (expected RFC3339)", err))
		result.Valid = false
		return
	}

	if time.Now().After(expiresTime) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Policy has expired (expires: %s)", policy.Expires))
	}
}

func validateSteps(policy *policyDocument, result *ValidationResult) {
	for stepName, step := range policy.Steps {
		if step.Name != stepName {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': name field '%s' does not match key", stepName, step.Name))
			result.Valid = false
		}

		if len(step.Functionaries) == 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': must define at least one functionary", stepName))
			result.Valid = false
		}

		if len(step.Attestations) == 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': must define at least one attestation", stepName))
			result.Valid = false
		}

		for i, functionary := range step.Functionaries {
			if functionary.Type != "publickey" && functionary.Type != "root" {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: invalid type '%s' (must be 'publickey' or 'root')", stepName, i, functionary.Type))
				result.Valid = false
			}

			if functionary.Type == "publickey" && functionary.PublicKeyID == "" {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: publickey type must have publickeyid", stepName, i))
				result.Valid = false
			}
		}

		for i, attestation := range step.Attestations {
			if attestation.Type == "" {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d: missing type field", stepName, i))
				result.Valid = false
			}
		}
	}
}

func validatePublicKeys(policy *policyDocument, result *ValidationResult) {
	for keyID, keyEntry := range policy.PublicKeys {
		if keyEntry.KeyID != keyID {
			result.Errors = append(result.Errors, fmt.Sprintf("Public key '%s': keyid field '%s' does not match map key", keyID, keyEntry.KeyID))
			result.Valid = false
		}

		if keyEntry.Key != "" {
			if _, err := base64.StdEncoding.DecodeString(keyEntry.Key); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Public key '%s': key is not valid base64: %v", keyID, err))
				result.Valid = false
			}
		}
	}
}

func validateRoots(policy *policyDocument, result *ValidationResult) {
	for rootID, rootEntry := range policy.Roots {
		if rootEntry.Certificate == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("Root '%s': missing certificate data", rootID))
			result.Valid = false
			continue
		}

		if _, err := base64.StdEncoding.DecodeString(rootEntry.Certificate); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Root '%s': certificate is not valid base64: %v", rootID, err))
			result.Valid = false
		}
	}
}

func validateRegoPolicies(policy *policyDocument, result *ValidationResult) {
	for stepName, step := range policy.Steps {
		for attIdx, att := range step.Attestations {
			for regoIdx, regoPol := range att.RegoPolicies {
				if regoPol.Name == "" {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy %d: missing name", stepName, attIdx, regoIdx))
					result.Valid = false
				}

				if regoPol.Module == "" {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy %d: missing module", stepName, attIdx, regoIdx))
					result.Valid = false
					continue
				}

				moduleBytes, err := base64.StdEncoding.DecodeString(regoPol.Module)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy '%s': module is not valid base64: %v", stepName, attIdx, regoPol.Name, err))
					result.Valid = false
					continue
				}

				if err := validateRegoSyntax(string(moduleBytes), regoPol.Name); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy '%s': invalid Rego syntax: %v", stepName, attIdx, regoPol.Name, err))
					result.Valid = false
				}
			}
		}
	}
}

func validateKeyReferences(policy *policyDocument, result *ValidationResult) {
	availableKeys := make(map[string]bool)
	for keyID := range policy.PublicKeys {
		availableKeys[keyID] = true
	}

	for stepName, step := range policy.Steps {
		for i, functionary := range step.Functionaries {
			if functionary.Type == "publickey" && functionary.PublicKeyID != "" {
				if !availableKeys[functionary.PublicKeyID] {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: references undefined public key '%s'", stepName, i, functionary.PublicKeyID))
					result.Valid = false
				}
			}
		}
	}
}

func validateSignature(ctx context.Context, envelope *dsse.Envelope, verifier cryptoutil.Verifier, result *ValidationResult) {
	if len(envelope.Signatures) == 0 {
		result.Errors = append(result.Errors, "Signature verification requested but envelope has no signatures")
		result.Valid = false
		return
	}

	_, err := envelope.Verify(dsse.VerifyWithVerifiers(verifier))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Signature verification failed: %v", err))
		result.Valid = false
	}
}

func validateRegoSyntax(module string, name string) error {
	_, err := ast.ParseModule(name, module)
	return err
}
