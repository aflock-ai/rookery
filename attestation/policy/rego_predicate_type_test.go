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

package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// A module that requires the spec SLSA v1 predicate type. The type the
// evidence was signed under reaches rego as data.rookery.predicateType;
// input stays the bare predicate, unchanged.
var regoRequireSLSAv1 = []byte(`package pt
deny[msg] {
	data.rookery.predicateType != "https://slsa.dev/provenance/v1"
	msg := sprintf("predicateType %v is not https://slsa.dev/provenance/v1", [data.rookery.predicateType])
}
deny[msg] {
	input.predicateType
	msg := "input shape changed: predicateType leaked into the predicate"
}`)

func TestRegoSeesTheSignedPredicateType(t *testing.T) {
	predicate := json.RawMessage(`{"runDetails":{"builder":{"id":"b"}}}`)
	policies := []RegoPolicy{{Name: "pt.rego", Module: regoRequireSLSAv1}}

	// The attestor's own Type() is the decoded factory's; the signed type is
	// what the evidence was signed under, and is what Rego must see.
	legacy := attestation.NewRawAttestation(slsaProvenanceV1Type, predicate)
	require.Error(t, EvaluateRegoPolicyForPredicateType(legacy, legacySLSAProvenanceV10Type, policies))
	require.NoError(t, EvaluateRegoPolicyForPredicateType(legacy, slsaProvenanceV1Type, policies))
	// The plain entry point uses the attestor's Type().
	require.NoError(t, EvaluateRegoPolicy(legacy, policies))
}

// Externals are judged by the envelope's own predicateType: a candidate the
// search returns for the spec type but signed under the pre-#9827 spelling is
// refused, by name.
func TestExternalRegoSeesEnvelopePredicateType(t *testing.T) {
	verifier, keyID := newECDSAVerifier(t)
	envelope := mkExternalEnvelope(t, legacySLSAProvenanceV10Type, passingSLSAPredicate, verifier)
	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"noop": validNoopStep(keyID)},
		ExternalAttestations: map[string]ExternalAttestation{"slsa": {
			Name: "slsa", PredicateType: slsaProvenanceV1Type, Required: true,
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			RegoPolicies:  []RegoPolicy{{Name: "pt.rego", Module: regoRequireSLSAv1}},
		}},
	}
	ms := &stepAwareVerifiedSource{
		byStep:      map[string][]source.CollectionVerificationResult{"noop": {validNoopCollection(verifier)}},
		byPredicate: map[string][]source.StatementEnvelope{slsaProvenanceV1Type: {envelope}},
	}
	pass, _, ext, _ := p.VerifyWithExternals(context.Background(), WithVerifiedSource(ms), WithSubjectDigests([]string{"sha256:artifact"}))
	require.False(t, pass)
	require.Len(t, ext["slsa"].Rejected, 1)
	require.Contains(t, ext["slsa"].Rejected[0].Reason.Error(), "https://slsa.dev/provenance/v1.0")
}

// Collections are evaluated against each entry's recorded type.
func TestCollectionRegoSeesRecordedPredicateType(t *testing.T) {
	step := Step{Name: "build", Attestations: []Attestation{{
		Type:         slsaProvenanceV1Type,
		RegoPolicies: []RegoPolicy{{Name: "pt.rego", Module: regoRequireSLSAv1}},
	}}}
	coll := func(recorded string) source.CollectionVerificationResult {
		return source.CollectionVerificationResult{CollectionEnvelope: source.CollectionEnvelope{Collection: attestation.Collection{
			Name: "build",
			Attestations: []attestation.CollectionAttestation{{
				Type:        recorded,
				Attestation: attestation.NewRawAttestation(recorded, json.RawMessage(`{}`)),
			}},
		}}}
	}
	res := step.validateAttestations([]source.CollectionVerificationResult{coll(legacySLSAProvenanceV10Type)}, "", nil)
	require.Len(t, res.Rejected, 1)
	require.Contains(t, res.Rejected[0].Reason.Error(), "https://slsa.dev/provenance/v1.0")
	res = step.validateAttestations([]source.CollectionVerificationResult{coll(slsaProvenanceV1Type)}, "", nil)
	require.Len(t, res.Passed, 1, "%v", res.Rejected)
}
