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
	"testing"

	intotoprov "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestEmittedProvenanceConformsToSLSAv1 validates emitted provenance against
// the in-toto attestation project's reference Go types for SLSA Provenance v1
// (github.com/in-toto/attestation/go/predicates/provenance/v1). protojson
// rejects any field the spec does not define and any value of the wrong JSON
// type; Validate() then enforces the spec's REQUIRED fields (buildType,
// externalParameters, builder.id) and resource-descriptor digest encoding.
//
// slsa-verifier is not a dependency anywhere in this monorepo, so the
// slsa-verifier half of #9827's conformance ask is not covered here.
func TestEmittedProvenanceConformsToSLSAv1(t *testing.T) {
	cases := map[string]*Provenance{
		"inline default": runProvenance(t, nil),
		"inline github": runProvenance(t, fakeGitHub(canonicalGitHubJWKS, map[string]any{
			"job_workflow_ref": "tenant/app/.github/workflows/ci.yml@refs/heads/main",
		})),
		"isolated provenance workflow": runProvenance(t, fakeGitHub(canonicalGitHubJWKS, map[string]any{
			"job_workflow_ref": "aflock-ai/cilock-action/.github/workflows/provenance.yml@refs/tags/v1",
		})),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			var ref intotoprov.Provenance
			require.NoError(t, protojson.Unmarshal(mustJSON(t, p), &ref), "emitted predicate has a field or type outside SLSA v1")
			require.NoError(t, ref.Validate())
			require.Equal(t, p.PbProvenance.RunDetails.Builder.ID, ref.GetRunDetails().GetBuilder().GetId())
		})
	}
}

// The reference validator must actually be able to fail, or the test above
// proves nothing.
func TestConformanceValidatorRejectsNonConformingProvenance(t *testing.T) {
	for name, doc := range map[string]string{
		"missing builder.id":         `{"buildDefinition":{"buildType":"x","externalParameters":{"a":1}},"runDetails":{"builder":{}}}`,
		"missing externalParameters": `{"buildDefinition":{"buildType":"x"},"runDetails":{"builder":{"id":"b"}}}`,
		"unknown field":              `{"buildDefinition":{"buildType":"x","externalParameters":{"a":1}},"runDetails":{"builder":{"id":"b"}},"invocation":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var ref intotoprov.Provenance
			err := protojson.Unmarshal([]byte(doc), &ref)
			if err == nil {
				err = ref.Validate()
			}
			require.Error(t, err)
		})
	}
}
