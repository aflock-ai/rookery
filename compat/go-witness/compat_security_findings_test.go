//go:build audit

// compat_security_findings_test.go documents known behavioral differences
// between the go-witness compat shim and the original go-witness library.
//
// These tests intentionally fail to document findings. They are gated behind
// the "audit" build tag and are NOT run in CI.
//
// Run with: go test -tags audit ./...
package witness_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	compatAttestation "github.com/in-toto/go-witness/attestation"
	compatPolicy "github.com/in-toto/go-witness/policy"
	compatSource "github.com/in-toto/go-witness/source"
	witness "github.com/in-toto/go-witness"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/file"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
)

// R3-160: PolicyPredicate uses aflock.ai URI instead of testifysec.com
func TestSecurity_R3_160_PolicyPredicateConstantChanged(t *testing.T) {
	goWitnessPolicyPredicate := "https://witness.testifysec.com/policy/v0.1"
	if compatPolicy.PolicyPredicate == goWitnessPolicyPredicate {
		t.Skip("PolicyPredicate matches go-witness -- bug is fixed")
	}
	t.Logf("FINDING R3-160: compatPolicy.PolicyPredicate = %q (expected %q)", compatPolicy.PolicyPredicate, goWitnessPolicyPredicate)
	t.Error("SECURITY: PolicyPredicate silently changed from go-witness value.")
}

// R3-161: CollectionType uses aflock.ai URI instead of testifysec.com
func TestSecurity_R3_161_CollectionTypeConstantChanged(t *testing.T) {
	goWitnessCollectionType := "https://witness.testifysec.com/attestation-collection/v0.1"
	if compatAttestation.CollectionType == goWitnessCollectionType {
		t.Skip("CollectionType matches go-witness -- bug is fixed")
	}
	t.Logf("FINDING R3-161: compatAttestation.CollectionType = %q (expected %q)", compatAttestation.CollectionType, goWitnessCollectionType)
	t.Error("SECURITY: CollectionType silently changed from go-witness value.")
}

// R3-162: StepResult.Passed uses []PassedCollection instead of []CollectionVerificationResult
func TestSecurity_R3_162_StepResultPassedFieldTypeChanged(t *testing.T) {
	stepResultType := reflect.TypeOf(compatPolicy.StepResult{})
	passedField, ok := stepResultType.FieldByName("Passed")
	if !ok {
		t.Fatal("StepResult does not have a Passed field")
	}
	goWitnessExpectedType := reflect.TypeOf([]source.CollectionVerificationResult{})
	if passedField.Type == goWitnessExpectedType {
		t.Skip("StepResult.Passed matches go-witness type -- bug is fixed")
	}
	t.Logf("FINDING R3-162: StepResult.Passed type: expected %v, got %v", goWitnessExpectedType, passedField.Type)
	t.Error("SECURITY: StepResult.Passed field type silently changed.")
}

// R3-163: RecordArtifacts has 9 params instead of 7
func TestSecurity_R3_163_RecordArtifactsSignatureChanged(t *testing.T) {
	fnType := reflect.ValueOf(file.RecordArtifacts).Type()
	if fnType.NumIn() == 7 {
		t.Skip("RecordArtifacts parameter count matches go-witness")
	}
	t.Logf("FINDING R3-163: RecordArtifacts has %d params (expected 7)", fnType.NumIn())
	t.Error("COMPAT BREAK: RecordArtifacts signature changed.")
}

// R3-164: Unknown attestation types succeed with RawAttestation instead of error
func TestSecurity_R3_164_CollectionAttestationUnmarshalFallbackToRaw(t *testing.T) {
	collAttJSON := `{"type":"https://example.com/unknown-attestor/v99.0","attestation":{"key":"value"},"starttime":"2024-01-01T00:00:00Z","endtime":"2024-01-01T00:01:00Z"}`
	var collAtt compatAttestation.CollectionAttestation
	err := json.Unmarshal([]byte(collAttJSON), &collAtt)
	if err != nil {
		t.Skip("UnmarshalJSON returned error for unknown type -- matches go-witness behavior")
	}
	t.Error("SECURITY: Unknown attestation types silently succeed with RawAttestation.")
}

// R3-165: MemorySource dual-URI indexing
func TestSecurity_R3_165_MemorySourceDualURIIndexing(t *testing.T) {
	ms := compatSource.NewMemorySource()
	collection := attestation.Collection{
		Name:         "test-step",
		Attestations: []attestation.CollectionAttestation{{Type: "https://aflock.ai/attestations/git/v0.1"}},
	}
	collJSON, _ := json.Marshal(collection)
	stmt := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v0.1", "predicateType": attestation.CollectionType,
		"subject": []map[string]interface{}{{"name": "artifact", "digest": map[string]string{"sha256": "abc123"}}},
		"predicate": json.RawMessage(collJSON),
	}
	stmtJSON, _ := json.Marshal(stmt)
	env := dsse.Envelope{Payload: stmtJSON, PayloadType: "application/vnd.in-toto+json"}
	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}
	results, _ := ms.Search(context.Background(), "test-step", []string{"abc123"}, []string{"https://witness.testifysec.com/attestation/git/v0.1"})
	_ = results
	t.Error("BEHAVIORAL: Rookery MemorySource indexes under both new and legacy URIs.")
}

// R3-166: ArchivistaSource partial failure behavior changed
func TestSecurity_R3_166_ArchivistaSourcePartialFailureBehavior(t *testing.T) {
	archivistaType := reflect.TypeOf(compatSource.ArchivistaSource{})
	_, hasMutex := archivistaType.FieldByName("mu")
	t.Logf("FINDING R3-166: ArchivistaSource has mutex: %v", hasMutex)
	t.Error("BEHAVIORAL: ArchivistaSource partial failure behavior changed.")
}

// R3-167: RejectedCollection has additional AiResponses field
func TestSecurity_R3_167_RejectedCollectionAdditionalField(t *testing.T) {
	rejType := reflect.TypeOf(compatPolicy.RejectedCollection{})
	if _, ok := rejType.FieldByName("AiResponses"); !ok {
		t.Skip("RejectedCollection does not have AiResponses field")
	}
	t.Error("BEHAVIORAL: RejectedCollection has additional AiResponses field.")
}

// R3-168: Attestation struct has additional AiPolicies field
func TestSecurity_R3_168_AttestationStructHasAiPolicies(t *testing.T) {
	if _, ok := reflect.TypeOf(compatPolicy.Attestation{}).FieldByName("AiPolicies"); !ok {
		t.Skip("Attestation does not have AiPolicies field")
	}
	original := `{"type":"https://witness.testifysec.com/attestation/git/v0.1","regopolicies":[]}`
	var att compatPolicy.Attestation
	json.Unmarshal([]byte(original), &att)
	data, _ := json.Marshal(att)
	var outputMap map[string]json.RawMessage
	json.Unmarshal(data, &outputMap)
	if _, hasKey := outputMap["aipolicies"]; hasKey {
		t.Error("BEHAVIORAL: JSON round-trip adds 'aipolicies' field.")
	}
}

// R3-169: Run() produces collections with new aflock.ai URI
func TestSecurity_R3_169_RunProducesNewURICollectionType(t *testing.T) {
	result, err := witness.Run("compat-run-test", witness.RunWithInsecure(true))
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if compatAttestation.CollectionType == "https://witness.testifysec.com/attestation-collection/v0.1" {
		t.Skip("CollectionType matches go-witness")
	}
	_ = result
	t.Error("SECURITY: witness.Run() through compat layer uses new CollectionType URI.")
}

// R3-170: Compat exports rookery-only APIs
func TestSecurity_R3_170_CompatExportsRookeryOnlyAPIs(t *testing.T) {
	// Verify rookery-only types exist
	_ = compatPolicy.AiPolicy{}
	_ = compatPolicy.AiResponse{}
	_ = compatPolicy.PassedCollection{}
	_ = string(compatPolicy.LegacyPolicyPredicate)
	_ = string(compatAttestation.LegacyCollectionType)
	t.Error("BEHAVIORAL: Compat layer exports rookery-only APIs.")
}

// R3-171: Policy.Validate() exists in compat but not go-witness
func TestSecurity_R3_171_PolicyValidateNotInGoWitness(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"build": {Name: "build"},
			"test":  {Name: "test", AttestationsFrom: []string{"build"}},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	t.Error("BEHAVIORAL: Policy.Validate() does not exist in go-witness.")
}

// R3-172: Step struct has additional AttestationsFrom field
func TestSecurity_R3_172_StepStructHasAttestationsFrom(t *testing.T) {
	if _, ok := reflect.TypeOf(compatPolicy.Step{}).FieldByName("AttestationsFrom"); !ok {
		t.Skip("Step does not have AttestationsFrom field")
	}
	step := compatPolicy.Step{Name: "deploy", AttestationsFrom: []string{"build"}}
	data, _ := json.Marshal(step)
	var m map[string]json.RawMessage
	json.Unmarshal(data, &m)
	if _, ok := m["attestationsFrom"]; ok {
		t.Error("BEHAVIORAL: Step has AttestationsFrom field not in go-witness.")
	}
}

// Ensure unused imports are satisfied
var _ = policy.PassedCollection{}
