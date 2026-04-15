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

package slsa

import (
	"encoding/json"

	"github.com/aflock-ai/rookery/attestation"
	prov "github.com/aflock-ai/rookery/attestation/intoto/provenance"
	"github.com/invopop/jsonschema"
)

const (
	// SLSAProvenanceV1Name is the attestor name under which the typed SLSA
	// Provenance v1 factory registers. Distinct from the existing "slsa"
	// attestor (which emits collection-embedded provenance during a build)
	// so callers can disambiguate via the attestation factory registry.
	SLSAProvenanceV1Name = "slsa-provenance-v1"

	// SLSAProvenanceV1PredicateType is the canonical SLSA v1.0 predicate
	// URI as published at https://slsa.dev/spec/v1.0/provenance.
	SLSAProvenanceV1PredicateType = "https://slsa.dev/provenance/v1"

	// SLSAProvenanceV1RunType reflects that this factory is used during
	// verification of pre-built bare-predicate DSSEs (external attestations),
	// not during an aflock build.
	SLSAProvenanceV1RunType = attestation.VerifyRunType
)

// Compile-time interface assertions.
var _ attestation.Attestor = (*ProvenanceV1)(nil)

func init() {
	attestation.RegisterAttestation(
		SLSAProvenanceV1Name,
		SLSAProvenanceV1PredicateType,
		SLSAProvenanceV1RunType,
		func() attestation.Attestor { return NewProvenanceV1() },
	)
}

// ProvenanceV1 is the typed-attestor wrapper around the SLSA v1.0 Provenance
// predicate used by the policy engine's external-attestation flow. The
// embedded prov.Provenance struct already matches the SLSA v1 spec
// (BuildDefinition + RunDetails with Byproducts, ResolvedDependencies, and
// Builder sub-fields) so rego policies can access the structured fields as
// input.buildDefinition.*, input.runDetails.* — exactly the shape SLSA v1
// consumers expect.
//
// This is a VerifyRunType attestor — it is not invoked during an aflock
// build. Its purpose is to provide UnmarshalJSON/MarshalJSON for the
// factory lookup that attestation.FactoryByType performs when
// SearchByPredicateType matches an external envelope.
type ProvenanceV1 struct {
	Predicate prov.Provenance `json:",inline"`
}

// NewProvenanceV1 returns an empty ProvenanceV1 ready to unmarshal into.
func NewProvenanceV1() *ProvenanceV1 {
	return &ProvenanceV1{}
}

func (p *ProvenanceV1) Name() string                                   { return SLSAProvenanceV1Name }
func (p *ProvenanceV1) Type() string                                   { return SLSAProvenanceV1PredicateType }
func (p *ProvenanceV1) RunType() attestation.RunType                   { return SLSAProvenanceV1RunType }
func (p *ProvenanceV1) Attest(_ *attestation.AttestationContext) error { return nil }
func (p *ProvenanceV1) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(&prov.Provenance{}) }

// UnmarshalJSON decodes the bare predicate JSON into the inlined Provenance
// struct. Used by the source layer when a factory match is made on
// SearchByPredicateType.
func (p *ProvenanceV1) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &p.Predicate)
}

// MarshalJSON emits the inlined Provenance so Rego sees the same structure
// the SLSA v1 spec defines (no "Predicate" wrapping envelope).
func (p *ProvenanceV1) MarshalJSON() ([]byte, error) {
	return json.Marshal(&p.Predicate)
}
