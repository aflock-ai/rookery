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
//
// ============================================================================
// Fail-closed acceptance tests for step.go (issues #5746 and #5747).
//
// These were the RED tests (formerly build-tagged `redgate`) for findings F9,
// F10, F17, and G. They assert the CORRECT, fail-closed behavior and pass now
// that step.go fails closed. Helpers (dummyAttestor, marshalableAttestor) live
// in untagged *_test.go files in this package.
// ============================================================================

package policy

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// F9 (#5746, HIGH) — step.go validateAttestations
// Fail-closed contract: a step with an EMPTY Attestations list is a
// misconfigured no-op gate; it must NOT pass an arbitrary collection. A gate
// with no requirements must reject (or produce no Passed), not accept anything.
// ---------------------------------------------------------------------------
func TestRed_F9_EmptyAttestationsMustNotPassAnyCollection(t *testing.T) {
	s := Step{
		Name:         "build",
		Attestations: []Attestation{}, // no required attestations
	}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "build"},
		},
	}
	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Empty(t, result.Passed,
		"a step with no required attestations must not auto-pass a collection (no-op gate is a misconfiguration, fail closed)")
}

// ---------------------------------------------------------------------------
// F10 (#5746, MEDIUM) — step.go validateAttestations (empty coll name)
// Fail-closed contract: an empty collection Name must NOT match every step. An
// attacker who produces a name-less collection must not bypass the step-name
// filter. A collection with Name=="" for a step named "build" must not pass.
// ---------------------------------------------------------------------------
func TestRed_F10_EmptyCollectionNameMustNotMatchAnyStep(t *testing.T) {
	attType := "https://example.com/att/v1"
	s := Step{
		Name:         "build",
		Attestations: []Attestation{{Type: attType}},
	}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{
				Name: "", // empty name should not match the "build" step
				Attestations: []attestation.CollectionAttestation{
					{Type: attType, Attestation: &dummyAttestor{name: "t", typeStr: attType}},
				},
			},
		},
	}
	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Empty(t, result.Passed,
		"a collection with an empty name must not match the 'build' step (no step-name-filter bypass)")
}

// ---------------------------------------------------------------------------
// F17 (#5746, MEDIUM) — step.go buildStepContext (last-writer-wins)
// Fail-closed contract: when two PASSED collections present the same
// attestation type, buildStepContext must NOT let a later collection silently
// overwrite the earlier one (which lets an attacker's second signed collection
// shadow the legitimate one in the Rego cross-step context). The first
// (legitimate) collection's data must be preserved (not "second-scan").
// ---------------------------------------------------------------------------
func TestRed_F17_BuildStepContextMustNotLastWriterWin(t *testing.T) {
	attType := "https://example.com/scan/v1"
	mkColl := func(name string) source.CollectionVerificationResult {
		return source.CollectionVerificationResult{
			CollectionEnvelope: source.CollectionEnvelope{
				Collection: attestation.Collection{
					Name: "scan",
					Attestations: []attestation.CollectionAttestation{{
						Type:        attType,
						Attestation: &marshalableAttestor{AttName: name, AttType: attType},
					}},
				},
			},
		}
	}
	results := map[string]StepResult{
		"scan": {
			Step: "scan",
			Passed: []PassedCollection{
				{Collection: mkColl("first-scan")},
				{Collection: mkColl("second-scan")},
			},
		},
	}
	ctx := buildStepContext([]string{"scan"}, results)
	require.NotNil(t, ctx)
	scanCtx, ok := ctx["scan"].(map[string]interface{})
	require.True(t, ok)
	attData, ok := scanCtx[attType].(map[string]interface{})
	require.True(t, ok)
	assert.NotEqual(t, "second-scan", attData["name"],
		"a second signed collection of the same type must not overwrite the first in cross-step Rego context (last-writer-wins is a shadowing vector)")
}

// ---------------------------------------------------------------------------
// G (#5747, MEDIUM) — step.go validateAttestations (duplicate type)
// Fail-closed contract: when a collection presents two attestors of the SAME
// type — one that FAILS a Rego policy and one that PASSES — the failing one must
// NOT be shadowed by last-writer-wins. The collection must be REJECTED (every
// attestor of the type is evaluated), not pass because the passing attestor was
// the final writer into the found[] map.
// ---------------------------------------------------------------------------
func TestRed_G_DuplicateTypeFailingAttestorMustNotBeShadowed(t *testing.T) {
	attType := "https://example.com/scan/v1"
	// A rego policy that DENIES when the attestor's name == "bad".
	denyModule := []byte(`package redgate_dup_type

deny[msg] {
	input.name == "bad"
	msg := "bad attestor present"
}
`)
	s := Step{
		Name: "scan",
		Attestations: []Attestation{{
			Type:         attType,
			RegoPolicies: []RegoPolicy{{Name: "deny-bad", Module: denyModule}},
		}},
	}
	// Collection has the FAILING ("bad") attestor first and a PASSING ("good")
	// attestor second; last-writer-wins keeps only "good" -> wrongly passes.
	coll := attestation.Collection{
		Name: "scan",
		Attestations: []attestation.CollectionAttestation{
			{Type: attType, Attestation: &marshalableAttestor{AttName: "bad", AttType: attType}},
			{Type: attType, Attestation: &marshalableAttestor{AttName: "good", AttType: attType}},
		},
	}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Empty(t, result.Passed,
		"a duplicate-type collection containing a policy-FAILING attestor must be rejected; the passing attestor must not shadow it (no last-writer-wins)")
}
