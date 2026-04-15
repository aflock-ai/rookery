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

// Package vsa provides a typed attestor for SLSA Verification Summary
// Attestations (VSAs). VSAs are emitted by cilock's --vsa-outfile flag (see
// PR #31) and can now be consumed as first-class external attestations
// inside downstream policies — closes issue #38.
package vsa

import (
	"encoding/json"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	// Name is the attestor name under which the typed VSA factory registers.
	Name = "vsa"

	// PredicateType is the SLSA Verification Summary v1 predicate URI. Matches
	// the constant in attestation/slsa/verificationsummary.go so that
	// downstream consumers see a single canonical value.
	PredicateType = "https://slsa.dev/verification_summary/v1"

	// RunType reflects that this factory is used during verification of
	// pre-signed bare-predicate DSSEs (external attestations), not during
	// an aflock build.
	RunType = attestation.VerifyRunType
)

// Verification results per the SLSA VSA v1 spec.
const (
	PassedVerificationResult VerificationResult = "PASSED"
	FailedVerificationResult VerificationResult = "FAILED"
)

// VerificationResult is the enumerated outcome field of a VSA.
type VerificationResult string

// Verifier identifies the party that ran verification.
type Verifier struct {
	ID string `json:"id"`
}

// ResourceDescriptor is a minimal RD shape matching the SLSA v1 spec, used
// both for the policy reference and for input attestations.
type ResourceDescriptor struct {
	URI    string               `json:"uri,omitempty"`
	Digest cryptoutil.DigestSet `json:"digest,omitempty"`
}

// VerificationSummary is the SLSA VSA v1 predicate shape. It mirrors the
// struct in attestation/slsa/verificationsummary.go so that policies can
// read the same field names regardless of which package produced the
// value.
type VerificationSummary struct {
	Verifier           Verifier             `json:"verifier"`
	TimeVerified       time.Time            `json:"timeVerified"`
	Policy             ResourceDescriptor   `json:"policy"`
	InputAttestations  []ResourceDescriptor `json:"inputAttestations"`
	VerificationResult VerificationResult   `json:"verificationResult"`
}

// Compile-time interface assertion.
var _ attestation.Attestor = (*Attestor)(nil)

func init() {
	attestation.RegisterAttestation(
		Name,
		PredicateType,
		RunType,
		func() attestation.Attestor { return New() },
	)
}

// Attestor is the typed-attestor wrapper around VerificationSummary.
type Attestor struct {
	Predicate VerificationSummary `json:",inline"`
}

// New returns an empty VSA attestor ready to unmarshal into.
func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string                                   { return Name }
func (a *Attestor) Type() string                                   { return PredicateType }
func (a *Attestor) RunType() attestation.RunType                   { return RunType }
func (a *Attestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *Attestor) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(&VerificationSummary{}) }

// UnmarshalJSON decodes the bare VSA predicate into the embedded
// VerificationSummary. Called by the external-attestation source path when
// FactoryByType matches PredicateType.
func (a *Attestor) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &a.Predicate)
}

// MarshalJSON emits the VerificationSummary directly so Rego input sees
// input.verifier.id, input.verificationResult, etc. — matching the SLSA
// spec's field names.
func (a *Attestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(&a.Predicate)
}
