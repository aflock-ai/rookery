//go:build audit

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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

// ===========================================================================
// Test helpers for R3 audit round
// ===========================================================================

// auditAttestor is a JSON-marshalable Attestor for security audit tests.
type auditAttestor struct {
	AttName string                 `json:"name"`
	AttType string                 `json:"type"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

func (a *auditAttestor) Name() string                                   { return a.AttName }
func (a *auditAttestor) Type() string                                   { return a.AttType }
func (a *auditAttestor) RunType() attestation.RunType                   { return "test" }
func (a *auditAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *auditAttestor) Schema() *jsonschema.Schema                     { return nil }

// auditWrappedAttestor wraps any value for custom JSON marshaling.
type auditWrappedAttestor struct {
	inner    interface{}
	typeName string
}

func (w *auditWrappedAttestor) Name() string                                   { return "audit-wrapped" }
func (w *auditWrappedAttestor) Type() string                                   { return w.typeName }
func (w *auditWrappedAttestor) RunType() attestation.RunType                   { return "test" }
func (w *auditWrappedAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (w *auditWrappedAttestor) Schema() *jsonschema.Schema                     { return nil }
func (w *auditWrappedAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.inner)
}

// auditMockSource returns pre-configured results per step name.
type auditMockSource struct {
	byStep map[string][]source.CollectionVerificationResult
}

func (s *auditMockSource) Search(_ context.Context, stepName string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	return s.byStep[stepName], nil
}

func auditMakeVerifierAndKeyID(t *testing.T) (cryptoutil.Verifier, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	return verifier, keyID
}

func auditMakeCVR(stepName string, verifier cryptoutil.Verifier, attestations ...attestation.CollectionAttestation) source.CollectionVerificationResult {
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

// ===========================================================================
// R3-200: validateAttestations evaluates Rego/AI policies even when the
//         collection has Errors.
//
// When a collection arrives with Errors (e.g., from envelope verification
// failure), lines 265-270 set passed=false and record the error. However,
// the code then falls through to the for loop over s.Attestations
// (line 282) and calls EvaluateRegoPolicy/EvaluateAIPolicy on attestations
// found in the collection. The Rego policy is evaluated against attestation
// data from a collection that FAILED verification.
//
// Severity: MEDIUM
// Impact: Rego policies are evaluated on potentially tampered attestation
//         data from collections that failed verification. While the
//         collection will still be rejected (passed=false is sticky), the
//         Rego evaluation is unnecessary and could trigger side effects
//         (e.g., slow Rego evaluation consuming up to 30s on bad data,
//         or error messages leaking data from unverified collections).
// ===========================================================================

func TestSecurity_R3_200_RegoEvalOnCollectionWithErrors(t *testing.T) {
	attType := "https://example.com/test/v1"

	// A Rego policy that always denies -- we'll check if it was evaluated
	// by looking at the rejection reasons.
	regoModule := []byte(`
package r3_200

deny[msg] {
  msg := "rego was evaluated"
}
`)
	step := Step{
		Name: "build",
		Attestations: []Attestation{{
			Type:         attType,
			RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "r3_200.rego"}},
		}},
	}

	// Collection with Errors AND a matching attestation.
	coll := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{
				Type:        attType,
				Attestation: &auditAttestor{AttName: "test", AttType: attType},
			},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
		Errors:             []error{fmt.Errorf("envelope signature verification failed")},
	}

	result := step.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)

	// The collection should be rejected (because of the error).
	require.Len(t, result.Rejected, 1, "collection with errors should be rejected")
	assert.Empty(t, result.Passed)

	// Now check whether the Rego policy was evaluated by looking at
	// the rejection reason. If Rego was evaluated, the reason will contain
	// "rego was evaluated" in addition to the envelope error.
	reason := result.Rejected[0].Reason.Error()
	if assert.Contains(t, reason, "envelope signature verification failed") {
		// Expected: the envelope error is in the reason.
	}

	// BUG: The Rego policy was ALSO evaluated on the bad collection.
	if assert.Contains(t, reason, "rego was evaluated",
		"SECURITY FINDING R3-200: Rego policy was evaluated on a collection "+
			"that had verification Errors. The code should skip Rego/AI evaluation "+
			"when the collection has Errors, not just set passed=false and continue. "+
			"This wastes compute on unverified data and could cause denial-of-service "+
			"(30s Rego timeout per attestation type).") {
		t.Log("SECURITY FINDING CONFIRMED: Rego policies are evaluated against " +
			"attestation data from collections that failed envelope verification.")
	}
}

// ===========================================================================
// R3-201: Cross-step context wrapping changes Rego input structure,
//         silently breaking backward-compatible Rego policies.
//
// When stepContext is non-nil, EvaluateRegoPolicy wraps the input as:
//   { "attestation": attestorData, "steps": stepContext }
//
// But when stepContext is nil, input IS the attestorData directly.
//
// A Rego policy written for the direct input format (input.name) will
// fail silently when stepContext is provided because input.name is now
// undefined (the name is at input.attestation.name). "Fail silently"
// means the deny rule's body doesn't match (because input.name is
// undefined), so the deny set is empty, and the policy PASSES.
//
// Severity: HIGH
// Impact: Adding AttestationsFrom to a step changes the Rego input
//         structure. Existing Rego policies that use input.fieldName
//         will silently pass when they should deny, because the field
//         is now at input.attestation.fieldName.
// ===========================================================================

func TestSecurity_R3_201_CrossStepContextBreaksExistingRegoPolicy(t *testing.T) {
	attType := "https://example.com/scan/v1"

	// A backward-compatible Rego policy that checks input.name directly.
	// This works when there is no step context (input = attestorData).
	regoModule := []byte(`
package r3_201

deny[msg] {
  input.name == "vulnerable-build"
  msg := "vulnerable build detected"
}
`)

	attestor := &auditAttestor{
		AttName: "vulnerable-build",
		AttType: attType,
	}

	// Without step context: input = attestorData directly.
	// The Rego policy should DENY because input.name == "vulnerable-build".
	err := EvaluateRegoPolicy(attestor, []RegoPolicy{{Module: regoModule, Name: "r3_201.rego"}})
	require.Error(t, err, "without step context, policy should deny vulnerable-build")
	assert.Contains(t, err.Error(), "vulnerable build detected")

	// With step context (non-nil, even empty): input is wrapped.
	// input.name is now UNDEFINED (name is at input.attestation.name).
	// The deny rule body fails because input.name is not "vulnerable-build".
	emptyStepCtx := map[string]interface{}{}
	err = EvaluateRegoPolicy(attestor, []RegoPolicy{{Module: regoModule, Name: "r3_201.rego"}}, emptyStepCtx)

	if err == nil {
		// BUG CONFIRMED: The policy silently passed because the input
		// structure changed and the deny rule body didn't match.
		t.Error("SECURITY BUG R3-201: When stepContext is non-nil (even empty), " +
			"the Rego input is wrapped as {attestation: ..., steps: ...}. " +
			"A Rego policy checking input.name no longer matches because the " +
			"field moved to input.attestation.name. The deny rule fails silently, " +
			"and the policy PASSES a vulnerable build. This is a silent policy " +
			"bypass triggered by adding AttestationsFrom to a step.")
	} else {
		assert.Contains(t, err.Error(), "vulnerable build detected",
			"policy should still deny, proving the input structure was preserved")
		t.Log("FIXED: Rego input structure is consistent regardless of stepContext.")
	}
}

// ===========================================================================
// R3-202: validateAttestations returns an empty StepResult (no Passed,
//         no Rejected) when ALL collections are skipped by the name filter.
//
// In Verify(), the step result merge logic (lines 475-483) checks:
//   if resultsByStep[stepName].Step == "" { ... }
//
// If validateAttestations returns a result where Step is set but Passed
// and Rejected are both empty (all collections skipped), the merge logic
// stores this result. Then in verifyArtifacts, the step has no Passed
// collections, so it gets a "no passed collections present" rejection.
//
// The problem: the step SILENTLY has no results. There is no indication
// that collections were skipped due to name mismatch. The error message
// says "no passed collections" which is misleading -- the real issue is
// that the search returned collections with wrong names.
//
// More critically: if validateAttestations returns an empty result
// (no Passed, no Rejected) because all collections were skipped, and
// then StepResult.Analyze() is called, it returns false (no Passed).
// This is correct failure behavior, BUT the empty Rejected list means
// StepResult.HasErrors() returns false. A caller checking HasErrors()
// without checking HasPassed() would think the step is in an ambiguous
// state rather than a clear failure.
//
// Severity: MEDIUM
// Impact: Misleading error diagnostics. A step that fails because all
//         collections were name-filtered produces an empty StepResult
//         with HasErrors()=false and HasPassed()=false.
// ===========================================================================

func TestSecurity_R3_202_AllCollectionsFilteredProducesAmbiguousResult(t *testing.T) {
	step := Step{
		Name:         "build",
		Attestations: []Attestation{},
	}

	// Collection with a different name that will be skipped by the filter.
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "deploy"},
		},
	}

	result := step.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)

	// The result has the step name set but no Passed or Rejected.
	assert.Equal(t, "build", result.Step)
	assert.Empty(t, result.Passed, "all collections were name-filtered, so none passed")
	assert.Empty(t, result.Rejected, "all collections were name-filtered, so none rejected")

	// This creates an ambiguous state: the step is neither passed nor has errors.
	assert.False(t, result.HasPassed())
	assert.False(t, result.HasErrors(),
		"SECURITY FINDING R3-202: HasErrors() returns false even though the step "+
			"has no passed collections. A caller checking HasErrors() alone would "+
			"think the step is in an ambiguous state. The correct check is "+
			"Analyze() which returns false, but HasErrors() is misleading.")

	// Analyze correctly returns false (no passed collections).
	assert.False(t, result.Analyze(), "Analyze should return false for empty result")
}

// ===========================================================================
// R3-203: buildStepContext overwrites attestation types from multiple
//         PassedCollections for the same dependency step.
//
// When a dependency step has multiple PassedCollections (from depth
// iterations or multiple search results), buildStepContext iterates
// ALL of them (line 204) and writes stepData[att.Type] = data for each.
// If two PassedCollections have the same attestation type, the LAST one
// wins -- and which is "last" depends on slice order, which is
// non-deterministic from the caller's perspective.
//
// This is distinct from R3-150 which showed the issue end-to-end.
// This test proves the issue at the buildStepContext level directly
// with controlled ordering.
//
// Severity: HIGH
// Impact: Cross-step context is non-deterministic when a dependency
//         has multiple passed collections with the same attestation type.
//         A Rego policy evaluating cross-step data could see different
//         results on different runs.
// ===========================================================================

func TestSecurity_R3_203_BuildStepContextLastWriterWins(t *testing.T) {
	attType := "https://example.com/scan/v1"

	// Two passed collections for the "scan" step with the same attestation type
	// but different data.
	firstAtt := &auditAttestor{AttName: "first-scan", AttType: attType, Data: map[string]interface{}{"score": 95}}
	secondAtt := &auditAttestor{AttName: "second-scan", AttType: attType, Data: map[string]interface{}{"score": 20}}

	results := map[string]StepResult{
		"scan": {
			Step: "scan",
			Passed: []PassedCollection{
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "scan",
								Attestations: []attestation.CollectionAttestation{
									{Type: attType, Attestation: firstAtt},
								},
							},
						},
					},
				},
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "scan",
								Attestations: []attestation.CollectionAttestation{
									{Type: attType, Attestation: secondAtt},
								},
							},
						},
					},
				},
			},
		},
	}

	ctx := buildStepContext([]string{"scan"}, results)
	require.NotNil(t, ctx)

	scanCtx, ok := ctx["scan"]
	require.True(t, ok)
	scanMap, ok := scanCtx.(map[string]interface{})
	require.True(t, ok)
	attData, ok := scanMap[attType]
	require.True(t, ok)

	// The data should be from the second collection (last writer wins).
	attMap, ok := attData.(map[string]interface{})
	require.True(t, ok)
	name, _ := attMap["name"].(string)

	assert.Equal(t, "second-scan", name,
		"SECURITY FINDING R3-203: buildStepContext uses last-writer-wins when "+
			"multiple PassedCollections have the same attestation type. The first "+
			"collection's data ('first-scan') was overwritten by the second "+
			"('second-scan'). A Rego policy checking cross-step data will see "+
			"whichever collection happens to be last in the Passed slice.")
}

// ===========================================================================
// R3-204: AI policy evaluation double-counts FAIL status.
//
// In validateAttestations (step.go lines 307-336), when EvaluateAIPolicy
// returns a response with Status="FAIL", it returns BOTH a non-nil error
// AND the response. The error causes `passed = false` and records the
// error reason (line 309-310). Then, the code enters the aiResponses
// check block (line 313), but ONLY checks FAIL status when `err == nil`
// (line 316). Since err is non-nil for FAIL, the FAIL status check is
// skipped for the FIRST failed AI policy.
//
// However, if EvaluateAIPolicy returns multiple responses (from iterating
// policies), it returns on the FIRST error (ai.go line 60-61), meaning
// policies AFTER the first failure are NEVER evaluated. The responses
// slice contains responses up to and including the first failure.
//
// The net effect: the first AI policy failure is recorded once via err
// (correct), subsequent AI policies are never evaluated (bug: short-circuit).
//
// Severity: HIGH
// Impact: When multiple AI policies are configured for a single
//         attestation type, only the FIRST one that fails causes
//         rejection. Subsequent AI policies are never evaluated, so
//         their failures are never detected.
// ===========================================================================

func TestSecurity_R3_204_AIPolicyShortCircuitsOnFirstFailure(t *testing.T) {
	// We can't easily test AI policy evaluation without an HTTP server,
	// but we CAN prove the short-circuit behavior of EvaluateAIPolicy
	// by examining its control flow. The function returns early on the
	// first error, which means subsequent policies are never evaluated.
	//
	// This test documents the behavior by testing EvaluateAIPolicy with
	// policies that would require an HTTP server, so we verify the
	// structure/contract rather than executing.

	// Verify that EvaluateAIPolicy returns nil for empty policies.
	responses, err := EvaluateAIPolicy(
		&auditAttestor{AttName: "test", AttType: "test"},
		nil, // no policies
		"",
	)
	assert.NoError(t, err)
	assert.Nil(t, responses)

	// Verify that EvaluateAIPolicy with an invalid server URL fails fast.
	responses, err = EvaluateAIPolicy(
		&auditAttestor{AttName: "test", AttType: "test"},
		[]AiPolicy{
			{Name: "policy1", Prompt: "check something"},
			{Name: "policy2", Prompt: "check something else"},
		},
		"invalid://bad-url",
	)
	require.Error(t, err, "invalid URL should cause immediate failure")

	// The key finding: only ONE response was generated before the error.
	// The second policy was never evaluated.
	assert.Len(t, responses, 1,
		"SECURITY FINDING R3-204: EvaluateAIPolicy short-circuits on the first "+
			"error. With 2 AI policies configured, only 1 response was generated "+
			"before the error. The second AI policy was never evaluated. An attacker "+
			"who knows the first AI policy will fail (e.g., due to server issues) can "+
			"rely on the second policy never being checked.")
}

// ===========================================================================
// R3-205: Rego policy with multiple packages -- the len(rs)==0 check
//         is bypassed if ANY package defines a deny rule.
//
// When multiple Rego modules with DIFFERENT packages are used, the query
// contains multiple deny paths: "data.pkg1.deny\ndata.pkg2.deny\n"
// OPA evaluates the combined query. If pkg1 defines deny (even as an
// empty set) but pkg2 does NOT define deny, OPA returns results for
// pkg1's deny but not for pkg2's deny. The result set is non-empty
// (rs has at least one element from pkg1), so the len(rs)==0 check
// does NOT fire. pkg2's missing deny rule is silently ignored.
//
// Severity: HIGH
// Impact: In a multi-module Rego policy configuration, one module with
//         a valid deny rule masks the fact that another module is missing
//         its deny rule entirely. An attacker can supply a trivially-
//         passing module (no deny rule) alongside a legitimate module,
//         and the missing-deny check is bypassed.
// ===========================================================================

func TestSecurity_R3_205_MissingDenyInOneModuleMaskedByAnother(t *testing.T) {
	// Module 1: has a proper deny rule that always passes.
	goodModule := RegoPolicy{
		Name: "good.rego",
		Module: []byte(`package good

deny[msg] {
  false
  msg := "never fires"
}
`),
	}

	// Module 2: has NO deny rule at all. It just defines a helper.
	// An attacker could supply this to bypass policy enforcement.
	badModule := RegoPolicy{
		Name: "bad.rego",
		Module: []byte(`package bad

some_other_rule = true
`),
	}

	attestor := &auditAttestor{AttName: "test", AttType: "test"}

	// With only the bad module, the len(rs)==0 check should catch it.
	err := EvaluateRegoPolicy(attestor, []RegoPolicy{badModule})
	require.Error(t, err, "single module missing deny should be caught")
	assert.Contains(t, err.Error(), "missing a 'deny' rule",
		"the missing deny rule should be detected")

	// With BOTH modules, the good module's deny result makes rs non-empty,
	// masking the bad module's missing deny rule.
	err = EvaluateRegoPolicy(attestor, []RegoPolicy{goodModule, badModule})
	if err == nil {
		t.Error("SECURITY BUG R3-205: When two Rego modules have different packages, " +
			"a module with a valid deny rule masks the fact that the other module " +
			"is missing a deny rule entirely. The len(rs)==0 check only fires when " +
			"ALL packages return no results. An attacker can supply a trivially-passing " +
			"module (package with deny[msg]{false}) alongside a module with no deny " +
			"rule, and the missing-deny check is bypassed. The query evaluates both " +
			"deny paths, but only the good module returns a result, making rs non-empty.")
	} else {
		t.Logf("FIXED: missing deny rule detected even with multiple modules: %v", err)
	}
}

// ===========================================================================
// R3-206: Verify() search depth accumulates duplicate step results.
//
// When searchDepth > 1, Verify() loops over all steps for each depth
// iteration. The merge logic at lines 475-483 appends Passed and Rejected
// from each iteration. If the source returns the same collection across
// multiple depth iterations (because the subject digests didn't change
// or because back-references re-discover the same digests), the same
// collection appears in the Passed list multiple times.
//
// More importantly: the functionary check is re-run on the same
// collections in each depth iteration, potentially producing DIFFERENT
// results if the checkFunctionaries function has side effects (it
// mutates the input slice's ValidFunctionaries, as proven by R3-158).
//
// Severity: MEDIUM
// Impact: Duplicate passed collections inflate the step result. If any
//         downstream logic counts passed collections, it gets an
//         inflated count. The verifyArtifacts phase only needs ONE
//         passed collection to succeed, so duplicates don't break
//         correctness there, but they waste memory and processing.
// ===========================================================================

func TestSecurity_R3_206_SearchDepthAccumulatesDuplicates(t *testing.T) {
	verifier, keyID := auditMakeVerifierAndKeyID(t)

	stepName := "build"
	cvr := auditMakeCVR(stepName, verifier)

	// Source always returns the same collection.
	src := &auditMockSource{
		byStep: map[string][]source.CollectionVerificationResult{
			stepName: {cvr},
		},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			stepName: {
				Name:          stepName,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
			},
		},
	}

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(5),
	)
	require.NoError(t, err)
	require.True(t, pass)

	passedCount := len(results[stepName].Passed)
	assert.Greater(t, passedCount, 1,
		"SECURITY FINDING R3-206: With searchDepth=5, the same collection is "+
			"added to Passed multiple times (got %d). Each depth iteration "+
			"re-processes the same collection because the source returns identical "+
			"results. This inflates the Passed count and wastes resources.",
		passedCount)
}

// ===========================================================================
// R3-207: validateAttestations with an empty Attestations list passes
//         any collection that matches by name, regardless of content.
//
// When step.Attestations is empty, the for loop at line 282 has nothing
// to iterate. The `passed` variable stays true (from initialization at
// line 262), and the collection is added to result.Passed. No Rego or
// AI policies are evaluated because there are no expected attestation
// types to evaluate against.
//
// This means a step with Functionaries but no Attestations requirements
// is fully "verified" by ANY signed collection from an authorized
// functionary, regardless of what attestation data the collection contains.
//
// Severity: HIGH
// Impact: A step with empty Attestations accepts any collection content.
//         An authorized signer can produce a completely empty or irrelevant
//         collection and satisfy the step. This is a policy bypass for
//         any step that forgets to specify required attestation types.
// ===========================================================================

func TestSecurity_R3_207_EmptyAttestationsPassesAnyContent(t *testing.T) {
	step := Step{
		Name:         "security-scan",
		Attestations: []Attestation{}, // No attestations required!
	}

	// A collection with completely irrelevant content.
	coll := attestation.Collection{
		Name: "security-scan",
		Attestations: []attestation.CollectionAttestation{
			{
				Type:        "https://example.com/totally-random/v1",
				Attestation: &auditAttestor{AttName: "not-a-scan", AttType: "random"},
			},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	result := step.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)

	assert.Len(t, result.Passed, 1,
		"SECURITY BUG R3-207: A step with empty Attestations list auto-passes "+
			"ANY collection that matches by name. The 'security-scan' step accepted "+
			"a collection containing 'totally-random/v1' attestation. No Rego or AI "+
			"policies were evaluated. Steps should require at least one expected "+
			"attestation type, or Validate() should warn about empty Attestations lists.")
	assert.Empty(t, result.Rejected)
}

// ===========================================================================
// R3-208: Rego cross-step context does NOT include the current step's
//         OWN attestation data for multi-attestation steps.
//
// In validateAttestations, each expected attestation type gets its own
// call to EvaluateRegoPolicy (line 302). The attestor passed is the one
// found for that specific attestation type. But if a step has multiple
// attestation types, attestation A's Rego policy cannot access attestation
// B's data from the same collection, because only attestation A's data
// is passed as input.
//
// This means cross-attestation Rego policies within the same step are
// impossible. A policy that needs to check relationships between multiple
// attestation types in the same collection cannot do so.
//
// Severity: MEDIUM
// Impact: Policy authors cannot write Rego policies that check
//         relationships between attestation types in the same step.
//         Each Rego policy only sees its own attestation type's data.
// ===========================================================================

func TestSecurity_R3_208_RegoCannotAccessOtherAttestationsInSameStep(t *testing.T) {
	scanType := "https://example.com/scan/v1"
	buildType := "https://example.com/build/v1"

	// Rego policy on the scan attestation that tries to access the build
	// attestation data from the same collection.
	regoModule := []byte(`
package r3_208

deny[msg] {
  # Try to access build data -- it's not in the input because only
  # the scan attestor is passed as input.
  not input.build_version
  msg := "cannot access build data from scan policy"
}
`)

	step := Step{
		Name: "combined",
		Attestations: []Attestation{
			{Type: buildType},
			{
				Type:         scanType,
				RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "r3_208.rego"}},
			},
		},
	}

	coll := attestation.Collection{
		Name: "combined",
		Attestations: []attestation.CollectionAttestation{
			{
				Type: buildType,
				Attestation: &auditAttestor{
					AttName: "build",
					AttType: buildType,
					Data:    map[string]interface{}{"build_version": "1.2.3"},
				},
			},
			{
				Type: scanType,
				Attestation: &auditAttestor{
					AttName: "scan",
					AttType: scanType,
					Data:    map[string]interface{}{"vulnerabilities": 0},
				},
			},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	result := step.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)

	// The Rego policy should deny because it cannot access build_version.
	assert.NotEmpty(t, result.Rejected,
		"SECURITY FINDING R3-208: Rego policies on one attestation type cannot "+
			"access data from another attestation type in the same collection. "+
			"The scan policy tried to check build_version but it's not in the input. "+
			"Cross-attestation policies within the same step are impossible. "+
			"The input only contains the single attestor's JSON, not the full collection.")
	assert.Empty(t, result.Passed)
}

// ===========================================================================
// R3-209: Verify() does NOT validate that step.Name matches its map key.
//
// Policy.Validate() checks AttestationsFrom references and cycles, but
// does NOT check that step.Name matches the map key. This creates a
// split-brain where:
//   - Search uses the map key
//   - validateAttestations name filter uses step.Name
//   - StepResult is stored under the map key
//   - verifyArtifacts iterates p.Steps and uses step.Name for lookup
//
// When Name != map key, verifyArtifacts looks up results by step.Name
// but they're stored under the map key, causing a "not found" error.
//
// Severity: HIGH
// Impact: A misconfigured policy where any step's Name differs from its
//         map key silently breaks verification. Validate() does not catch
//         this, leaving it to manifest as confusing runtime errors.
// ===========================================================================

func TestSecurity_R3_209_ValidateDoesNotCheckStepNameMatchesKey(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"map-key": {
				Name: "different-name", // Doesn't match map key!
			},
		},
	}

	err := p.Validate()
	if err == nil {
		t.Error("SECURITY BUG R3-209: Policy.Validate() does not check that " +
			"step.Name matches its map key. A step stored under key 'map-key' " +
			"with Name='different-name' passes validation. This creates a split-brain " +
			"between the search (uses map key), name filter (uses step.Name), and " +
			"artifact verification (uses step.Name for lookup but results are stored " +
			"under map key). Validate() should reject policies where step.Name != map key.")
	} else {
		t.Logf("FIXED: Validate catches name vs key mismatch: %v", err)
	}
}

// ===========================================================================
// R3-210: Verify() allows a policy with zero Steps to pass Validate()
//         but catches it later with "policy has no steps to verify" at
//         line 507. However, the check at line 507 only fires AFTER all
//         the expensive verification work (trust bundles, topological sort,
//         search, functionary checks, attestation validation, artifact
//         verification). The empty-steps check should be in Validate()
//         or at least before the expensive work in Verify().
//
// Additionally: Validate() returns nil for an empty Steps map, which
// means a policy with no steps is considered structurally valid. This
// is semantically wrong -- a policy with no steps cannot verify anything.
//
// Severity: LOW
// Impact: Wasted computation when verifying an empty policy. Not a
//         security bypass because the verification does fail, but it's
//         an efficiency issue and a Validate() completeness gap.
// ===========================================================================

func TestSecurity_R3_210_EmptyStepsPolicyPassesValidate(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{},
	}

	err := p.Validate()
	assert.NoError(t, err,
		"SECURITY FINDING R3-210: Validate() returns nil for a policy with zero "+
			"steps. An empty policy is structurally 'valid' even though it can never "+
			"verify anything. The check for empty steps only happens in Verify() at "+
			"line 507, after expensive operations like trust bundle parsing and "+
			"topological sorting. Validate() should reject empty policies.")
}

// ===========================================================================
// R3-211: Rego result iteration returns ErrRegoInvalidData on FIRST
//         type mismatch, preventing collection of deny reasons from
//         subsequent expressions.
//
// In EvaluateRegoPolicy, lines 149-165 iterate over rs (result set)
// and rs[i].Expressions. If ANY expression has a non-[]interface{} value
// or any deny reason is not a string, the function returns immediately
// with ErrRegoInvalidData. This means:
//
// 1. If module A's deny returns an unexpected type, module B's deny
//    reasons are never collected, even if they're valid.
// 2. This is a policy bypass: an attacker can supply a module whose
//    deny evaluates to a non-set type, causing ErrRegoInvalidData to
//    short-circuit before legitimate deny reasons are collected.
//
// Wait -- ErrRegoInvalidData IS an error, so the function does return
// an error. The policy evaluation fails with a type error. This is NOT
// a bypass. But it IS a loss of information: the actual deny reasons
// from other modules are lost, replaced by a type error message.
//
// Severity: MEDIUM
// Impact: Type errors from one Rego module mask legitimate deny reasons
//         from other modules. Error diagnostics are degraded.
// ===========================================================================

func TestSecurity_R3_211_RegoTypeErrorMasksOtherDenyReasons(t *testing.T) {
	// Module 1: proper deny rule that denies.
	goodModule := RegoPolicy{
		Name: "good.rego",
		Module: []byte(`package good

deny[msg] {
  msg := "legitimate denial reason"
}
`),
	}

	// Module 2: same package, deny rule that returns an integer (not a string).
	badModule := RegoPolicy{
		Name: "bad.rego",
		Module: []byte(`package good

deny[val] {
  val := 42
}
`),
	}

	attestor := &auditAttestor{AttName: "test", AttType: "test"}

	// With both modules, the deny set contains both "legitimate denial reason"
	// and 42. When iterating, the function will encounter the integer and
	// return ErrRegoInvalidData.
	err := EvaluateRegoPolicy(attestor, []RegoPolicy{goodModule, badModule})
	require.Error(t, err, "should fail due to type mismatch or deny reasons")

	errStr := err.Error()

	// Check if the legitimate deny reason is in the error.
	hasLegitReason := assert.Contains(t, errStr, "legitimate denial reason") ||
		assert.Contains(t, errStr, "ErrRegoInvalidData") ||
		assert.Contains(t, errStr, "invalid data")

	_ = hasLegitReason

	// The real concern: is the error a type error or a policy denial?
	// If it's a type error, the legitimate deny reason was masked.
	if !assert.Contains(t, errStr, "legitimate denial reason") {
		t.Log("SECURITY FINDING R3-211: A Rego module with a non-string deny " +
			"element (integer 42) caused the error processing to return a type " +
			"error instead of the legitimate deny reasons. The actual denial " +
			"('legitimate denial reason') is masked by the type error. An attacker " +
			"who can add a module to the same package can degrade error diagnostics " +
			"and prevent operators from seeing the real denial reasons.")
	}
}

// ===========================================================================
// R3-212: Rego cross-step context key collision -- the "attestation" key
//         in the wrapped input collides if a dependency step is named
//         "attestation".
//
// When stepContext is non-nil, the input is:
//   { "attestation": attestorData, "steps": stepContext }
//
// A Rego policy accessing input.attestation would get the current
// attestor's data. But if a dependency step is named "attestation",
// the stepContext would have a key "attestation" in the steps map:
//   input.steps.attestation -- this is fine.
//
// The REAL issue: the key "attestation" in the top-level map shadows
// any possibility of having a step named "attestation" at the top level.
// But steps are nested under "steps", so this is NOT a collision.
//
// HOWEVER: what if the attestor's own JSON output has a field named
// "steps"? When wrapped, the attestor data is at input.attestation,
// so input.attestation.steps would be the attestor's field. And
// input.steps would be the cross-step context. No collision.
//
// The ACTUAL issue I want to test: what happens when stepContext
// contains a key called "attestation"? The wrapped input would be:
//   {
//     "attestation": attestorData,
//     "steps": { "attestation": someData }
//   }
// input.steps.attestation would work fine. No issue here.
//
// Let me pivot to a real bug: multiple variadic stepContext args.
// ===========================================================================

// ===========================================================================
// R3-212: EvaluateRegoPolicy accepts variadic stepContext args but
//         only uses the first one, silently ignoring extras.
//
// The function signature is:
//   func EvaluateRegoPolicy(attestor, policies, stepContext ...map[string]interface{}) error
//
// If called with multiple maps, only stepContext[0] is used (line 80).
// Additional maps are silently ignored. While this is unlikely to happen
// through validateAttestations (which passes one map), a direct caller
// could mistakenly pass multiple maps expecting them to be merged.
//
// Severity: LOW
// Impact: Silent data loss if multiple step context maps are passed.
//         The API is misleading -- variadic suggests multiple values
//         are useful, but only the first is used.
// ===========================================================================

func TestSecurity_R3_212_RegoVariadicStepContextIgnoresExtras(t *testing.T) {
	regoModule := []byte(`
package r3_212

deny[msg] {
  not input.steps.extra
  msg := "extra context not found"
}
`)

	attestor := &auditAttestor{AttName: "test", AttType: "test"}

	// Pass two step context maps. The second one has "extra" data.
	ctx1 := map[string]interface{}{
		"build": map[string]interface{}{"data": "first"},
	}
	ctx2 := map[string]interface{}{
		"extra": map[string]interface{}{"data": "second"},
	}

	// Only ctx1 should be used. ctx2 with "extra" is silently ignored.
	err := EvaluateRegoPolicy(attestor, []RegoPolicy{{Module: regoModule, Name: "r3_212.rego"}}, ctx1, ctx2)

	if err != nil {
		assert.Contains(t, err.Error(), "extra context not found",
			"CONFIRMED R3-212: Only the first variadic stepContext arg is used. "+
				"The second map containing 'extra' was silently ignored. The Rego "+
				"policy denied because input.steps.extra is undefined.")
	} else {
		t.Log("Both context maps were merged (unexpected - this would be fixed behavior)")
	}
}

// ===========================================================================
// R3-213: checkCertConstraint treats duplicate constraint values as a
//         single requirement via map deduplication, weakening the
//         constraint set in a way that may surprise policy authors.
//
// When constraints = ["A", "A"], the map unmet = {A:{}}, which has
// one entry. A cert with values = ["A"] satisfies this because deleting
// "A" from unmet leaves it empty. But the policy author may have intended
// two separate "A" entries (a multiset constraint).
//
// More importantly, this interacts with duplicate cert values:
// If both constraints and cert have ["A", "A"], the map has one entry,
// but the cert has two values. The first "A" deletes the map entry,
// the second "A" triggers "unexpected value".
//
// Severity: MEDIUM
// Impact: Asymmetric handling of duplicates in constraints vs cert values.
//         Policy authors get inconsistent behavior depending on which
//         side has duplicates.
// ===========================================================================

func TestSecurity_R3_213_ConstraintDuplicateAsymmetry(t *testing.T) {
	// Case 1: Duplicate constraints, single cert value => PASSES
	// because map dedup reduces constraints to one entry.
	err := checkCertConstraint("org", []string{"A", "A"}, []string{"A"})
	assert.NoError(t, err,
		"SECURITY FINDING R3-213a: Duplicate constraints ['A','A'] are silently "+
			"reduced to one entry via map. Cert with single 'A' satisfies it.")

	// Case 2: Single constraint, duplicate cert values => FAILS
	// because the second cert "A" is "unexpected" after the first consumed it.
	err = checkCertConstraint("org", []string{"A"}, []string{"A", "A"})
	assert.Error(t, err,
		"CONFIRMED R3-213b: Single constraint 'A' rejects cert with duplicate "+
			"'A' values. The second 'A' is unexpected after the first consumed "+
			"the constraint entry.")

	// Case 3: Duplicate constraints AND duplicate cert values => FAILS
	// because map dedup reduces constraints to one entry, but cert has two.
	err = checkCertConstraint("org", []string{"A", "A"}, []string{"A", "A"})
	assert.Error(t, err,
		"SECURITY FINDING R3-213c: Duplicate constraints ['A','A'] reduced to "+
			"one map entry, but cert has two 'A' values. The second cert 'A' is "+
			"'unexpected'. Asymmetric dedup behavior means constraints=['A','A'] "+
			"cert=['A','A'] FAILS, while constraints=['A','A'] cert=['A'] PASSES.")
}

// ===========================================================================
// R3-214: Verify() merges results across depth iterations by appending
//         Passed and Rejected lists. But the initial check at line 475
//         only populates the result if resultsByStep[stepName].Step == "".
//         On subsequent iterations, it falls through to the else branch
//         (line 478) which appends. This means the Step name is set only
//         on the FIRST iteration. If the first iteration produces a
//         result with Step=s.Name (via validateAttestations, which sets
//         Step from s.Name), all subsequent iterations append to it.
//         This is correct.
//
//         BUT: the initial check compares resultsByStep[stepName].Step
//         against "", using the MAP KEY (stepName) for the lookup but
//         checking the Step FIELD (from StepResult). If a step has
//         Name != map key, the first iteration stores a StepResult with
//         Step=s.Name (wrong), and subsequent lookups by map key find
//         a result with a non-empty Step field, so they append.
//         The artifact verification phase then fails because it uses
//         step.Name for lookup.
//
// This test verifies the merge behavior is correct for normal cases
// and documents the failure mode for mismatched names.
// ===========================================================================

func TestSecurity_R3_214_ResultMergeUsesMapKeyNotStepName(t *testing.T) {
	verifier, keyID := auditMakeVerifierAndKeyID(t)

	stepName := "build"
	attType := "https://example.com/att/v1"

	cvr := auditMakeCVR(stepName, verifier, attestation.CollectionAttestation{
		Type:        attType,
		Attestation: &auditAttestor{AttName: "att", AttType: attType},
	})

	src := &auditMockSource{
		byStep: map[string][]source.CollectionVerificationResult{
			stepName: {cvr},
		},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			stepName: {
				Name:          stepName,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: attType}},
			},
		},
	}

	// With depth 2, the merge logic should produce results under "build".
	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(2),
	)
	require.NoError(t, err)
	require.True(t, pass)

	// Verify results are stored under the map key "build".
	stepResult, ok := results[stepName]
	require.True(t, ok, "results should be stored under the map key")
	assert.Equal(t, stepName, stepResult.Step,
		"StepResult.Step should match the step name")

	// With depth 2, we expect duplicates (as proven by R3-206).
	// The key assertion: results are keyed by map key, not by step.Name.
	assert.True(t, stepResult.HasPassed())
}

// Ensure all types compile properly.
var _ = fmt.Sprintf
var _ = metav1.Time{}
var _ = context.Background
