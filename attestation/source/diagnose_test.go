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

package source

import (
	"context"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/assert"
)

const (
	typeProductV03 = "https://aflock.ai/attestations/product/v0.3"
	typeGitV01     = "https://aflock.ai/attestations/git/v0.1"
	typeCmdRunV01  = "https://aflock.ai/attestations/command-run/v0.1"
)

// TestMemorySource_DiagnoseStep is white-box: it seeds the index directly (the
// index population path is covered by TestLoadEnvelope / TestSearch) so each
// candidate-selection failure mode can be asserted in isolation.
func TestMemorySource_DiagnoseStep(t *testing.T) {
	const step = "release-build"
	required := []string{typeProductV03, typeGitV01}

	t.Run("nothing loaded under the step name", func(t *testing.T) {
		s := NewMemorySource()
		d := s.DiagnoseStep(step, required)
		assert.False(t, d.NameLoaded, "no collection under this name")
		assert.False(t, d.TypesSatisfied)
		assert.Nil(t, d.ObservedSubjects)
	})

	t.Run("loaded but missing a required type", func(t *testing.T) {
		s := NewMemorySource()
		s.referencesByCollectionName[step] = []string{"ref0"}
		s.attestationsByReference["ref0"] = map[string]struct{}{typeGitV01: {}, typeCmdRunV01: {}}
		s.envelopesByReference["ref0"] = CollectionEnvelope{}
		d := s.DiagnoseStep(step, required)
		assert.True(t, d.NameLoaded)
		assert.False(t, d.TypesSatisfied)
		assert.Equal(t, []string{typeProductV03}, d.MissingTypes, "product/v0.3 is the absent required type")
		assert.Contains(t, d.ObservedTypes, typeCmdRunV01, "observed types name what the collection carries")
		assert.Contains(t, d.ObservedTypes, typeGitV01)
	})

	t.Run("types satisfied — subject mismatch case surfaces subjects", func(t *testing.T) {
		s := NewMemorySource()
		s.referencesByCollectionName[step] = []string{"ref0"}
		s.attestationsByReference["ref0"] = map[string]struct{}{typeProductV03: {}, typeGitV01: {}}
		s.envelopesByReference["ref0"] = CollectionEnvelope{
			Statement: intoto.Statement{
				Subject: []intoto.Subject{
					{Name: "product/v0.3/tree:products", Digest: map[string]string{"sha256": "4c847902"}},
				},
			},
		}
		d := s.DiagnoseStep(step, required)
		assert.True(t, d.NameLoaded)
		assert.True(t, d.TypesSatisfied)
		assert.Empty(t, d.MissingTypes)
		assert.Contains(t, strings.Join(d.ObservedSubjects, ","), "tree:products")
		assert.Contains(t, strings.Join(d.ObservedSubjects, ","), "sha256:4c847902")
	})

	t.Run("required types split across collections — none carries all", func(t *testing.T) {
		s := NewMemorySource()
		s.referencesByCollectionName[step] = []string{"ref0", "ref1"}
		s.attestationsByReference["ref0"] = map[string]struct{}{typeProductV03: {}}
		s.attestationsByReference["ref1"] = map[string]struct{}{typeGitV01: {}}
		s.envelopesByReference["ref0"] = CollectionEnvelope{}
		s.envelopesByReference["ref1"] = CollectionEnvelope{}
		d := s.DiagnoseStep(step, required)
		assert.True(t, d.NameLoaded)
		assert.False(t, d.TypesSatisfied, "no single collection carries BOTH required types")
		assert.Empty(t, d.MissingTypes, "both types present somewhere → union is complete, so MissingTypes is empty")
	})
}

// TestMultiSource_DiagnoseStep_Aggregates verifies the OR-aggregation across
// children, and that a non-diagnosing child (no StepDiagnoser) is skipped.
func TestMultiSource_DiagnoseStep_Aggregates(t *testing.T) {
	const step = "release-build"
	required := []string{typeProductV03, typeGitV01}

	mem := NewMemorySource()
	mem.referencesByCollectionName[step] = []string{"ref0"}
	mem.attestationsByReference["ref0"] = map[string]struct{}{typeProductV03: {}, typeGitV01: {}}
	mem.envelopesByReference["ref0"] = CollectionEnvelope{
		Statement: intoto.Statement{Subject: []intoto.Subject{{Name: "tree:products", Digest: map[string]string{"sha256": "abc"}}}},
	}

	ms := NewMultiSource(mem, &nonDiagnosingSource{})
	d := ms.DiagnoseStep(step, required)
	assert.True(t, d.NameLoaded, "aggregated from the MemorySource child")
	assert.True(t, d.TypesSatisfied)
	assert.Contains(t, strings.Join(d.ObservedSubjects, ","), "tree:products")
}

// nonDiagnosingSource is a Sourcer that does NOT implement StepDiagnoser, so it
// must be skipped by MultiSource.DiagnoseStep without panicking.
type nonDiagnosingSource struct{}

func (nonDiagnosingSource) Search(_ context.Context, _ string, _, _ []string) ([]CollectionEnvelope, error) {
	return nil, nil
}

func (nonDiagnosingSource) SearchByPredicateType(_ context.Context, _, _ []string) ([]StatementEnvelope, error) {
	return nil, nil
}
