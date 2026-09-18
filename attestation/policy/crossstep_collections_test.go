// jade:ring local

package policy

// input.steps.<step>.collections: every passed collection of a dependency step, in a
// deterministic order, instead of the single first-writer-wins object per attestation type.
//
// Background (2026-09-18): buildStepContext keeps the first collection that presents a given
// attestation type (F17, #5746: last-writer-wins was a shadowing vector). "First" was the
// order collections were discovered in, so a verdict that read input.steps.<step>.<type>
// could depend on which file or Archivista row arrived first when several collections had
// passed. These tests pin three things:
//
//  1. input.steps.<step>.collections is a list of {reference, name, attestations{type: data}}
//     containing EVERY passed collection, ordered by reference (then by position for ties).
//  2. The legacy input.steps.<step>.<type> object is still present and now deterministic:
//     it is the attestor from the lowest-reference collection, whatever the discovery order.
//  3. A rego module that reaches for the legacy shape gets a deprecation WARN naming the
//     replacement; a module that uses .collections does not.

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func passedScan(reference, attName, attType string) PassedCollection {
	return PassedCollection{
		Collection: source.CollectionVerificationResult{
			CollectionEnvelope: source.CollectionEnvelope{
				Reference: reference,
				Collection: attestation.Collection{
					Name: "scan",
					Attestations: []attestation.CollectionAttestation{
						{Type: attType, Attestation: &marshalableAttestor{AttName: attName, AttType: attType}},
					},
				},
			},
		},
	}
}

func TestBuildStepContext_CollectionsListHasEveryPassedCollection(t *testing.T) {
	attType := "https://example.com/scan/v1"
	results := map[string]StepResult{
		"scan": {Step: "scan", Passed: []PassedCollection{
			passedScan("gitoid:b", "b-scan", attType),
			passedScan("gitoid:a", "a-scan", attType),
			passedScan("gitoid:c", "c-scan", attType),
		}},
	}
	ctx := buildStepContext([]string{"scan"}, results)
	require.NotNil(t, ctx)
	stepData, ok := ctx["scan"].(map[string]interface{})
	require.True(t, ok)

	colls, ok := stepData["collections"].([]interface{})
	require.True(t, ok, "input.steps.scan.collections must be a list")
	require.Len(t, colls, 3, "every passed collection is listed, none dropped")

	refs := make([]string, 0, len(colls))
	names := make([]string, 0, len(colls))
	for _, c := range colls {
		cm := c.(map[string]interface{})
		refs = append(refs, cm["reference"].(string))
		assert.Equal(t, "scan", cm["name"])
		atts := cm["attestations"].(map[string]interface{})
		names = append(names, atts[attType].(map[string]interface{})["name"].(string))
	}
	assert.Equal(t, []string{"gitoid:a", "gitoid:b", "gitoid:c"}, refs, "ordered by reference, not discovery order")
	assert.Equal(t, []string{"a-scan", "b-scan", "c-scan"}, names)
}

func TestBuildStepContext_LegacyTypeKeyIsDeterministic(t *testing.T) {
	attType := "https://example.com/scan/v1"
	discoveryOrders := [][]PassedCollection{
		{passedScan("gitoid:b", "b-scan", attType), passedScan("gitoid:a", "a-scan", attType)},
		{passedScan("gitoid:a", "a-scan", attType), passedScan("gitoid:b", "b-scan", attType)},
	}
	for i, order := range discoveryOrders {
		ctx := buildStepContext([]string{"scan"}, map[string]StepResult{"scan": {Step: "scan", Passed: order}})
		stepData := ctx["scan"].(map[string]interface{})
		legacy := stepData[attType].(map[string]interface{})
		assert.Equal(t, "a-scan", legacy["name"], "order %d: legacy key must not depend on discovery order", i)
	}
}

func TestBuildStepContext_TiesFallBackToDiscoveryOrder(t *testing.T) {
	// Collections with no reference (local files hand-built in tests, some sources) keep the
	// F17 behaviour exactly: first discovered wins the legacy key, and the list keeps order.
	attType := "https://example.com/scan/v1"
	ctx := buildStepContext([]string{"scan"}, map[string]StepResult{"scan": {Step: "scan", Passed: []PassedCollection{
		passedScan("", "first-scan", attType), passedScan("", "second-scan", attType),
	}}})
	stepData := ctx["scan"].(map[string]interface{})
	assert.Equal(t, "first-scan", stepData[attType].(map[string]interface{})["name"])
	colls := stepData["collections"].([]interface{})
	assert.Equal(t, "first-scan", colls[0].(map[string]interface{})["attestations"].(map[string]interface{})[attType].(map[string]interface{})["name"])
	assert.Equal(t, "second-scan", colls[1].(map[string]interface{})["attestations"].(map[string]interface{})[attType].(map[string]interface{})["name"])
}

func TestBuildStepContext_DepWithoutAttestorsStaysAbsent(t *testing.T) {
	// Pinned in the audit-tagged suite as TestCrossStep_DepStepHasNoAttestations; repeated here so
	// the default test run catches it too. A passed collection with no attestors must not make
	// input.steps.<step> exist, or every `not input.steps.<step>` rule silently stops firing.
	ctx := buildStepContext([]string{"build"}, map[string]StepResult{"build": {Step: "build", Passed: []PassedCollection{{
		Collection: source.CollectionVerificationResult{CollectionEnvelope: source.CollectionEnvelope{
			Reference: "gitoid:x", Collection: attestation.Collection{Name: "build"}}},
	}}}})
	assert.Nil(t, ctx)
}

func TestLegacyStepsShape_DeprecationWarning(t *testing.T) {
	capture := installWarnCapture(t)
	legacy := `package p
deny[msg] {
    input.steps.build["https://example.com/build-att/v1"].name == "x"
    msg := "legacy"
}`
	warnLegacyStepsShape("legacy-module", legacy)
	assert.True(t, capture.sawContaining("input.steps.<step>.<type> is deprecated"), "legacy shape must warn")
	assert.True(t, capture.sawContaining("legacy-module"), "warning names the module")
	assert.True(t, capture.sawContaining(".collections"), "warning names the replacement")

	capture2 := installWarnCapture(t)
	modern := `package p
deny[msg] {
    c := input.steps.build.collections[_]
    c.attestations["https://example.com/build-att/v1"].name == "x"
    msg := "modern"
}
deny[msg] {
    not input.steps.build
    msg := "missing"
}`
	warnLegacyStepsShape("modern-module", modern)
	assert.False(t, capture2.sawContaining("deprecated"), "existence checks and .collections access must not warn")
}
