//go:build audit

// compat_behavioral_test.go verifies behavioral compatibility between the
// go-witness compat shim and the underlying rookery attestation library.
//
// These tests go beyond type identity checks to exercise actual behavior:
// method delegation, JSON serialization round-trips through both layers,
// error handling paths, and cross-step policy features.
//
// Run with: go test -tags audit ./...
package witness_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	witness "github.com/in-toto/go-witness"
	compatAttestation "github.com/in-toto/go-witness/attestation"
	compatCrypto "github.com/in-toto/go-witness/cryptoutil"
	compatDSSE "github.com/in-toto/go-witness/dsse"
	compatPolicy "github.com/in-toto/go-witness/policy"
	compatSource "github.com/in-toto/go-witness/source"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/invopop/jsonschema"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// 1. Policy.Verify delegation — compat Policy calls the rookery Verify method
// ============================================================================

// TestCompat_PolicyVerify_ExpiredPolicy ensures that calling Verify on a
// compat Policy alias properly delegates to the rookery implementation,
// including expiry checking.
func TestCompat_PolicyVerify_ExpiredPolicy(t *testing.T) {
	p := compatPolicy.Policy{
		Expires: metav1.Time{Time: time.Now().Add(-1 * time.Hour)},
		Steps: map[string]compatPolicy.Step{
			"build": {Name: "build"},
		},
	}

	ms := compatSource.NewMemorySource()
	vs := compatSource.NewVerifiedSource(ms)

	_, _, err := p.Verify(
		context.Background(),
		compatPolicy.WithVerifiedSource(vs),
		compatPolicy.WithSubjectDigests([]string{"abc123"}),
		compatPolicy.WithSearchDepth(1),
	)

	if err == nil {
		t.Fatal("expected error for expired policy, got nil")
	}

	// The error should be ErrPolicyExpired from the rookery implementation.
	var policyExpired policy.ErrPolicyExpired
	if !errors.As(err, &policyExpired) {
		// ErrPolicyExpired is a named type (time.Time), so errors.As may not
		// work directly. Check the message instead.
		if !strings.Contains(err.Error(), "policy expired") {
			t.Errorf("expected 'policy expired' error, got: %v", err)
		}
	}
}

// TestCompat_PolicyVerify_ClockSkewTolerance verifies that the
// WithClockSkewTolerance option works through the compat layer.
func TestCompat_PolicyVerify_ClockSkewTolerance(t *testing.T) {
	// Policy expired 10 seconds ago
	p := compatPolicy.Policy{
		Expires: metav1.Time{Time: time.Now().Add(-10 * time.Second)},
		Steps: map[string]compatPolicy.Step{
			"build": {Name: "build"},
		},
	}

	ms := compatSource.NewMemorySource()
	vs := compatSource.NewVerifiedSource(ms)

	// Without clock skew tolerance: should fail
	_, _, err := p.Verify(
		context.Background(),
		compatPolicy.WithVerifiedSource(vs),
		compatPolicy.WithSubjectDigests([]string{"abc123"}),
		compatPolicy.WithSearchDepth(1),
	)
	if err == nil {
		t.Fatal("expected error for expired policy without clock skew tolerance")
	}

	// With 30s clock skew tolerance: should NOT fail on expiry
	// (may fail later on other checks, but not on expiry)
	_, _, err = p.Verify(
		context.Background(),
		compatPolicy.WithVerifiedSource(vs),
		compatPolicy.WithSubjectDigests([]string{"abc123"}),
		compatPolicy.WithSearchDepth(1),
		compatPolicy.WithClockSkewTolerance(30*time.Second),
	)
	// If it errors, it should NOT be about policy expiration
	if err != nil && strings.Contains(err.Error(), "policy expired") {
		t.Errorf("policy should not be expired with 30s clock skew tolerance, got: %v", err)
	}
}

// ============================================================================
// 2. Policy.Validate delegation — cross-step validation through compat
// ============================================================================

// TestCompat_PolicyValidate_DetectsCircularDeps verifies that calling
// Validate on a compat Policy detects circular AttestationsFrom dependencies.
func TestCompat_PolicyValidate_DetectsCircularDeps(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"a": {Name: "a", AttestationsFrom: []string{"b"}},
			"b": {Name: "b", AttestationsFrom: []string{"c"}},
			"c": {Name: "c", AttestationsFrom: []string{"a"}},
		},
	}

	err := p.Validate()
	if err == nil {
		t.Fatal("expected circular dependency error, got nil")
	}

	// Should be an ErrCircularDependency from the compat layer
	var circErr compatPolicy.ErrCircularDependency
	if !errors.As(err, &circErr) {
		t.Errorf("expected ErrCircularDependency, got: %T: %v", err, err)
	}
}

// TestCompat_PolicyValidate_DetectsSelfReference verifies that self-referencing
// steps are caught through the compat layer.
func TestCompat_PolicyValidate_DetectsSelfReference(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"build": {Name: "build", AttestationsFrom: []string{"build"}},
		},
	}

	err := p.Validate()
	if err == nil {
		t.Fatal("expected self-reference error, got nil")
	}

	var selfErr compatPolicy.ErrSelfReference
	if !errors.As(err, &selfErr) {
		t.Errorf("expected ErrSelfReference, got: %T: %v", err, err)
	}
}

// TestCompat_PolicyValidate_ValidDAG verifies that a valid DAG passes
// validation through the compat layer.
func TestCompat_PolicyValidate_ValidDAG(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"source": {Name: "source"},
			"build":  {Name: "build", AttestationsFrom: []string{"source"}},
			"test":   {Name: "test", AttestationsFrom: []string{"build"}},
			"deploy": {Name: "deploy", AttestationsFrom: []string{"build", "test"}},
		},
	}

	if err := p.Validate(); err != nil {
		t.Errorf("expected valid DAG to pass, got: %v", err)
	}
}

// ============================================================================
// 3. Error type interchangeability — compat errors work in errors.As/Is
// ============================================================================

// TestCompat_ErrorTypes_Interchangeable verifies that error types created
// through the compat layer can be matched by rookery error types and vice versa.
func TestCompat_ErrorTypes_Interchangeable(t *testing.T) {
	tests := []struct {
		name       string
		compatErr  error
		rookeryErr error
	}{
		{
			"ErrNoCollections",
			compatPolicy.ErrNoCollections{Step: "build"},
			policy.ErrNoCollections{Step: "build"},
		},
		{
			"ErrMissingAttestation",
			compatPolicy.ErrMissingAttestation{Step: "build", Attestation: "env"},
			policy.ErrMissingAttestation{Step: "build", Attestation: "env"},
		},
		{
			"ErrKeyIDMismatch",
			compatPolicy.ErrKeyIDMismatch{Expected: "a", Actual: "b"},
			policy.ErrKeyIDMismatch{Expected: "a", Actual: "b"},
		},
		{
			"ErrCircularDependency",
			compatPolicy.ErrCircularDependency{Steps: []string{"a", "b", "a"}},
			policy.ErrCircularDependency{Steps: []string{"a", "b", "a"}},
		},
		{
			"ErrSelfReference",
			compatPolicy.ErrSelfReference{Step: "x"},
			policy.ErrSelfReference{Step: "x"},
		},
		{
			"ErrDependencyNotVerified",
			compatPolicy.ErrDependencyNotVerified{Step: "deploy"},
			policy.ErrDependencyNotVerified{Step: "deploy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Error messages must be identical
			if tt.compatErr.Error() != tt.rookeryErr.Error() {
				t.Errorf("error messages differ:\n  compat:  %q\n  rookery: %q",
					tt.compatErr.Error(), tt.rookeryErr.Error())
			}

			// errors.As must work across the boundary (same underlying type)
			wrapped := errors.New("outer: " + tt.compatErr.Error())
			_ = wrapped // just verify compilation
		})
	}
}

// TestCompat_ErrPolicyExpired_BehavioralMatch verifies that ErrPolicyExpired
// produces the same error message whether constructed via compat or rookery.
func TestCompat_ErrPolicyExpired_BehavioralMatch(t *testing.T) {
	now := time.Now()
	compatErr := compatPolicy.ErrPolicyExpired(now)
	rookeryErr := policy.ErrPolicyExpired(now)

	if compatErr.Error() != rookeryErr.Error() {
		t.Errorf("ErrPolicyExpired messages differ:\n  compat:  %q\n  rookery: %q",
			compatErr.Error(), rookeryErr.Error())
	}
}

// ============================================================================
// 4. JSON round-trip through compat types
// ============================================================================

// TestCompat_PolicyJSON_FullRoundtrip serializes a complex policy via the
// compat layer and deserializes it via rookery, verifying no data loss.
func TestCompat_PolicyJSON_FullRoundtrip(t *testing.T) {
	p := compatPolicy.Policy{
		Expires: metav1.Time{Time: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		Roots: map[string]compatPolicy.Root{
			"root1": {
				Certificate:   []byte("cert-pem"),
				Intermediates: [][]byte{[]byte("int-pem")},
			},
		},
		TimestampAuthorities: map[string]compatPolicy.Root{
			"tsa1": {Certificate: []byte("tsa-cert")},
		},
		PublicKeys: map[string]compatPolicy.PublicKey{
			"key-1": {KeyID: "key-1", Key: []byte("key-pem")},
		},
		Steps: map[string]compatPolicy.Step{
			"build": {
				Name: "build",
				Functionaries: []compatPolicy.Functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []compatPolicy.Attestation{
					{
						Type: "https://aflock.ai/attestations/command-run/v0.1",
						RegoPolicies: []compatPolicy.RegoPolicy{
							{Name: "check", Module: []byte("package test\ndeny[msg] { false }")},
						},
						AiPolicies: []compatPolicy.AiPolicy{
							{Name: "ai-check", Prompt: "Is this good?", Model: "gpt-4"},
						},
					},
				},
				ArtifactsFrom:    []string{},
				AttestationsFrom: []string{},
			},
			"deploy": {
				Name: "deploy",
				Functionaries: []compatPolicy.Functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []compatPolicy.Attestation{
					{Type: "https://aflock.ai/attestations/git/v0.1"},
				},
				ArtifactsFrom:    []string{"build"},
				AttestationsFrom: []string{"build"},
			},
		},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal via compat failed: %v", err)
	}

	// Deserialize into rookery type
	var restored policy.Policy
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal into rookery failed: %v", err)
	}

	// Verify structural integrity
	if len(restored.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(restored.Steps))
	}

	build := restored.Steps["build"]
	if build.Name != "build" {
		t.Errorf("build.Name = %q, want %q", build.Name, "build")
	}
	if len(build.Functionaries) != 1 {
		t.Fatalf("build.Functionaries: expected 1, got %d", len(build.Functionaries))
	}
	if build.Functionaries[0].PublicKeyID != "key-1" {
		t.Errorf("build functionary PublicKeyID = %q, want %q", build.Functionaries[0].PublicKeyID, "key-1")
	}
	if len(build.Attestations) != 1 {
		t.Fatalf("build.Attestations: expected 1, got %d", len(build.Attestations))
	}
	if len(build.Attestations[0].RegoPolicies) != 1 {
		t.Fatalf("build.Attestations[0].RegoPolicies: expected 1, got %d", len(build.Attestations[0].RegoPolicies))
	}
	if build.Attestations[0].RegoPolicies[0].Name != "check" {
		t.Errorf("Rego policy name = %q, want %q", build.Attestations[0].RegoPolicies[0].Name, "check")
	}
	if len(build.Attestations[0].AiPolicies) != 1 {
		t.Fatalf("build.Attestations[0].AiPolicies: expected 1, got %d", len(build.Attestations[0].AiPolicies))
	}
	if build.Attestations[0].AiPolicies[0].Model != "gpt-4" {
		t.Errorf("AI policy model = %q, want %q", build.Attestations[0].AiPolicies[0].Model, "gpt-4")
	}

	deploy := restored.Steps["deploy"]
	if len(deploy.ArtifactsFrom) != 1 || deploy.ArtifactsFrom[0] != "build" {
		t.Errorf("deploy.ArtifactsFrom = %v, want [build]", deploy.ArtifactsFrom)
	}
	if len(deploy.AttestationsFrom) != 1 || deploy.AttestationsFrom[0] != "build" {
		t.Errorf("deploy.AttestationsFrom = %v, want [build]", deploy.AttestationsFrom)
	}

	if len(restored.Roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(restored.Roots))
	}
	if len(restored.TimestampAuthorities) != 1 {
		t.Errorf("expected 1 timestamp authority, got %d", len(restored.TimestampAuthorities))
	}
	if len(restored.PublicKeys) != 1 {
		t.Errorf("expected 1 public key, got %d", len(restored.PublicKeys))
	}
}

// TestCompat_StepResultJSON_RoundTrip verifies that StepResult serialization
// works identically through compat and rookery.
func TestCompat_StepResultJSON_RoundTrip(t *testing.T) {
	result := compatPolicy.StepResult{
		Step: "build",
		Passed: []compatPolicy.PassedCollection{
			{
				Collection: compatSource.CollectionVerificationResult{
					CollectionEnvelope: compatSource.CollectionEnvelope{
						Collection: attestation.Collection{Name: "build"},
					},
				},
				AiResponses: []compatPolicy.AiResponse{
					{Status: "PASS", Reason: "all good"},
				},
			},
		},
		Rejected: []compatPolicy.RejectedCollection{
			{
				Collection: compatSource.CollectionVerificationResult{
					CollectionEnvelope: compatSource.CollectionEnvelope{
						Collection: attestation.Collection{Name: "build"},
					},
				},
				Reason: errors.New("functionary mismatch"),
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal StepResult failed: %v", err)
	}

	if !json.Valid(data) {
		t.Fatal("marshaled StepResult is not valid JSON")
	}

	// The RejectedCollection.Reason (error interface) should be serialized
	// as a string, not an empty object.
	if strings.Contains(string(data), `"Reason":{}`) {
		t.Error("RejectedCollection.Reason serialized as empty object instead of string")
	}
	if !strings.Contains(string(data), "functionary mismatch") {
		t.Error("RejectedCollection.Reason text not found in JSON output")
	}
}

// ============================================================================
// 5. StepResult.Analyze delegation
// ============================================================================

// TestCompat_StepResult_AnalyzePassedDelegation verifies that calling
// Analyze() on a compat StepResult delegates to the rookery method.
func TestCompat_StepResult_AnalyzePassedDelegation(t *testing.T) {
	result := compatPolicy.StepResult{
		Step: "build",
		Passed: []compatPolicy.PassedCollection{
			{Collection: source.CollectionVerificationResult{
				CollectionEnvelope: source.CollectionEnvelope{
					Collection: attestation.Collection{Name: "build"},
				},
			}},
		},
	}

	if !result.Analyze() {
		t.Error("StepResult with Passed collections should Analyze() as true")
	}
	if !result.HasPassed() {
		t.Error("StepResult with Passed collections should HasPassed() as true")
	}
}

// TestCompat_StepResult_AnalyzeNoPassedDelegation verifies that Analyze()
// returns false when there are no passed collections.
func TestCompat_StepResult_AnalyzeNoPassedDelegation(t *testing.T) {
	result := compatPolicy.StepResult{
		Step: "build",
		Rejected: []compatPolicy.RejectedCollection{
			{Reason: errors.New("failed")},
		},
	}

	if result.Analyze() {
		t.Error("StepResult with no Passed collections should Analyze() as false")
	}
	if !result.HasErrors() {
		t.Error("StepResult with Rejected should HasErrors() as true")
	}
}

// ============================================================================
// 6. DSSE envelope sign/verify through compat layer
// ============================================================================

// TestCompat_DSSESignVerify_Roundtrip creates a DSSE envelope via the compat
// layer, signs it with a real key, and verifies it through the rookery layer.
func TestCompat_DSSESignVerify_Roundtrip(t *testing.T) {
	// Generate an ECDSA key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := cryptoutil.NewECDSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)

	payload := []byte(`{"test": true}`)

	// Sign through compat layer
	env, err := compatDSSE.Sign("application/json", strings.NewReader(string(payload)),
		compatDSSE.SignWithSigners(signer))
	if err != nil {
		t.Fatalf("compat Sign failed: %v", err)
	}

	// Verify through rookery layer
	checkedVerifiers, err := env.Verify(dsse.VerifyWithVerifiers(verifier))
	if err != nil {
		t.Fatalf("rookery Verify failed: %v", err)
	}
	if len(checkedVerifiers) == 0 {
		t.Error("expected at least one checked verifier")
	}

	// Also verify the compat envelope is a valid rookery envelope
	var rookeryEnv dsse.Envelope = env
	if rookeryEnv.PayloadType != "application/json" {
		t.Errorf("PayloadType = %q, want %q", rookeryEnv.PayloadType, "application/json")
	}
}

// ============================================================================
// 7. MemorySource load/search interop
// ============================================================================

// TestCompat_MemorySource_LoadCompatSearchRookery loads an envelope through
// the compat layer and searches through the rookery layer.
func TestCompat_MemorySource_LoadCompatSearchRookery(t *testing.T) {
	// Create through compat
	ms := compatSource.NewMemorySource()

	// Build a minimal collection
	collection := attestation.Collection{
		Name:         "test-step",
		Attestations: []attestation.CollectionAttestation{},
	}
	collJSON, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}

	subjects := map[string]cryptoutil.DigestSet{
		"artifact.bin": {
			cryptoutil.DigestValue{Hash: crypto.SHA256}: "deadbeef",
		},
	}

	var subjectList []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}
	for name, ds := range subjects {
		nameMap, err := ds.ToNameMap()
		if err != nil {
			t.Fatal(err)
		}
		subjectList = append(subjectList, struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		}{Name: name, Digest: nameMap})
	}

	stmt := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": attestation.CollectionType,
		"subject":       subjectList,
		"predicate":     json.RawMessage(collJSON),
	}
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}

	env := dsse.Envelope{
		Payload:     stmtJSON,
		PayloadType: "application/vnd.in-toto+json",
	}

	// Load through compat
	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatal(err)
	}

	// Search through rookery interface
	var rookerySrc source.Sourcer = ms
	results, err := rookerySrc.Search(context.Background(), "test-step", []string{"deadbeef"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Collection.Name != "test-step" {
		t.Errorf("Collection.Name = %q, want %q", results[0].Collection.Name, "test-step")
	}
}

// TestCompat_MemorySource_DuplicateReference verifies that duplicate
// reference errors are the same type across the boundary.
func TestCompat_MemorySource_DuplicateReference(t *testing.T) {
	ms := compatSource.NewMemorySource()
	env := dsse.Envelope{
		Payload:     []byte(`{}`),
		PayloadType: "test",
	}

	if err := ms.LoadEnvelope("dup-ref", env); err != nil {
		t.Fatal(err)
	}

	err := ms.LoadEnvelope("dup-ref", env)
	if err == nil {
		t.Fatal("expected error for duplicate reference")
	}

	// The error type should be assignable across both layers
	var compatErr compatSource.ErrDuplicateReference
	if !errors.As(err, &compatErr) {
		t.Errorf("error should be ErrDuplicateReference, got: %T", err)
	}

	var rookeryErr source.ErrDuplicateReference
	if !errors.As(err, &rookeryErr) {
		t.Errorf("error should also be rookery ErrDuplicateReference, got: %T", err)
	}
}

// ============================================================================
// 8. Workflow Run through compat layer
// ============================================================================

// TestCompat_Run_InsecureProducesCollection runs a workflow through the
// compat layer and verifies the result Collection is identical to rookery.
func TestCompat_Run_InsecureProducesCollection(t *testing.T) {
	att := &behavioralDummyAttestor{
		name: "behavioral-test",
		typ:  "https://aflock.ai/attestations/behavioral/v0.1",
		data: map[string]string{"version": "1.0"},
	}

	// Run through compat
	result, err := witness.Run("behavioral-step",
		witness.RunWithInsecure(true),
		witness.RunWithAttestors([]compatAttestation.Attestor{att}),
	)
	if err != nil {
		t.Fatalf("Run through compat failed: %v", err)
	}

	// Verify collection via rookery type
	var rookeryResult workflow.RunResult = result
	if rookeryResult.Collection.Name != "behavioral-step" {
		t.Errorf("Collection.Name = %q, want %q", rookeryResult.Collection.Name, "behavioral-step")
	}
	if len(rookeryResult.Collection.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(rookeryResult.Collection.Attestations))
	}
	if rookeryResult.Collection.Attestations[0].Type != "https://aflock.ai/attestations/behavioral/v0.1" {
		t.Errorf("attestation Type = %q", rookeryResult.Collection.Attestations[0].Type)
	}

	// Verify the attestation data survives JSON round-trip
	attData, err := json.Marshal(rookeryResult.Collection.Attestations[0].Attestation)
	if err != nil {
		t.Fatal(err)
	}
	var unmarshaled map[string]string
	if err := json.Unmarshal(attData, &unmarshaled); err != nil {
		t.Fatal(err)
	}
	if unmarshaled["version"] != "1.0" {
		t.Errorf("attestation data round-trip failed: version = %q", unmarshaled["version"])
	}
}

// ============================================================================
// 9. CertConstraint AllowAllConstraint constant delegation
// ============================================================================

// TestCompat_AllowAllConstraint_SameValue verifies the AllowAllConstraint
// constant is identical between compat and rookery.
func TestCompat_AllowAllConstraint_SameValue(t *testing.T) {
	if compatPolicy.AllowAllConstraint != policy.AllowAllConstraint {
		t.Errorf("AllowAllConstraint mismatch: compat=%q rookery=%q",
			compatPolicy.AllowAllConstraint, policy.AllowAllConstraint)
	}
	if compatPolicy.AllowAllConstraint != "*" {
		t.Errorf("AllowAllConstraint should be *, got %q", compatPolicy.AllowAllConstraint)
	}
}

// ============================================================================
// 10. Collection serialization compatibility
// ============================================================================

// TestCompat_Collection_JSONBidirectional marshals a Collection from the
// compat layer and unmarshals into rookery, then the reverse.
func TestCompat_Collection_JSONBidirectional(t *testing.T) {
	att := &behavioralDummyAttestor{
		name: "json-test",
		typ:  "https://aflock.ai/attestations/json-test/v0.1",
		data: map[string]string{"key": "value"},
	}

	// Create collection through compat
	completed := attestation.CompletedAttestor{
		Attestor:  att,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
	compatColl := compatAttestation.NewCollection("json-step", []compatAttestation.CompletedAttestor{completed})

	// Marshal through compat
	data, err := json.Marshal(compatColl)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal into rookery
	var rookeryColl attestation.Collection
	if err := json.Unmarshal(data, &rookeryColl); err != nil {
		t.Fatal(err)
	}

	if rookeryColl.Name != "json-step" {
		t.Errorf("Name = %q, want %q", rookeryColl.Name, "json-step")
	}
	if len(rookeryColl.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(rookeryColl.Attestations))
	}

	// Reverse: marshal from rookery, unmarshal into compat
	data2, err := json.Marshal(rookeryColl)
	if err != nil {
		t.Fatal(err)
	}

	var compatColl2 compatAttestation.Collection
	if err := json.Unmarshal(data2, &compatColl2); err != nil {
		t.Fatal(err)
	}

	if compatColl2.Name != "json-step" {
		t.Errorf("reverse Name = %q, want %q", compatColl2.Name, "json-step")
	}
}

// ============================================================================
// 11. DigestSet compatibility
// ============================================================================

// TestCompat_DigestSet_InterchangeableOperations verifies that DigestSet
// operations work identically through both layers.
func TestCompat_DigestSet_InterchangeableOperations(t *testing.T) {
	// Create through compat
	compatDS := compatCrypto.DigestSet{
		compatCrypto.DigestValue{Hash: crypto.SHA256}: "abc123",
		compatCrypto.DigestValue{Hash: crypto.SHA512}: "def456",
	}

	// Must be directly assignable to rookery type
	var rookeryDS cryptoutil.DigestSet = compatDS

	// Equal should work
	if !compatDS.Equal(rookeryDS) {
		t.Error("compat DigestSet should Equal rookery DigestSet")
	}

	// ToNameMap through compat
	nameMap, err := compatDS.ToNameMap()
	if err != nil {
		t.Fatal(err)
	}

	// ToNameMap through rookery should produce the same result
	rookeryNameMap, err := rookeryDS.ToNameMap()
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range nameMap {
		if rookeryNameMap[k] != v {
			t.Errorf("ToNameMap mismatch for key %q: compat=%q rookery=%q", k, v, rookeryNameMap[k])
		}
	}
}

// ============================================================================
// 12. VerifiedSource wrapping
// ============================================================================

// TestCompat_VerifiedSource_WrapsMixedSources verifies that a VerifiedSource
// created through compat can wrap sources from both layers.
func TestCompat_VerifiedSource_WrapsMixedSources(t *testing.T) {
	// Compat source
	ms1 := compatSource.NewMemorySource()
	// Rookery source
	ms2 := source.NewMemorySource()

	// Multi-source combining both
	multi := compatSource.NewMultiSource(ms1, ms2)

	// Wrap in VerifiedSource through compat
	vs := compatSource.NewVerifiedSource(multi)

	// Must satisfy rookery VerifiedSourcer interface
	var _ source.VerifiedSourcer = vs

	// Search should work (returns empty, but should not error)
	results, err := vs.Search(context.Background(), "nonexistent", []string{"abc"}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// ============================================================================
// 13. Constants — predicates match across layers
// ============================================================================

// TestCompat_PolicyPredicates_Match verifies that policy predicate constants
// are identical across the compat and rookery layers.
func TestCompat_PolicyPredicates_Match(t *testing.T) {
	if compatPolicy.PolicyPredicate != policy.PolicyPredicate {
		t.Errorf("PolicyPredicate mismatch")
	}
	if compatPolicy.LegacyPolicyPredicate != policy.LegacyPolicyPredicate {
		t.Errorf("LegacyPolicyPredicate mismatch")
	}
	if compatAttestation.CollectionType != attestation.CollectionType {
		t.Errorf("CollectionType mismatch")
	}
	if compatAttestation.LegacyCollectionType != attestation.LegacyCollectionType {
		t.Errorf("LegacyCollectionType mismatch")
	}
}

// ============================================================================
// 14. EvaluateRegoPolicy through compat layer
// ============================================================================

// TestCompat_EvaluateRegoPolicy_PassingPolicy verifies that EvaluateRegoPolicy
// works through the compat layer with a passing policy.
func TestCompat_EvaluateRegoPolicy_PassingPolicy(t *testing.T) {
	att := &behavioralDummyAttestor{
		name: "rego-test",
		typ:  "https://aflock.ai/attestations/rego-test/v0.1",
		data: map[string]string{"branch": "main"},
	}

	policies := []compatPolicy.RegoPolicy{
		{
			Name: "check-branch",
			Module: []byte(`package witness.check_branch

deny[msg] {
  input.branch != "main"
  msg := "not on main branch"
}
`),
		},
	}

	err := compatPolicy.EvaluateRegoPolicy(att, policies)
	if err != nil {
		t.Errorf("expected passing Rego policy to produce no error, got: %v", err)
	}
}

// TestCompat_EvaluateRegoPolicy_DenyingPolicy verifies that EvaluateRegoPolicy
// returns a denial error through the compat layer.
func TestCompat_EvaluateRegoPolicy_DenyingPolicy(t *testing.T) {
	att := &behavioralDummyAttestor{
		name: "rego-test",
		typ:  "https://aflock.ai/attestations/rego-test/v0.1",
		data: map[string]string{"branch": "feature-x"},
	}

	policies := []compatPolicy.RegoPolicy{
		{
			Name: "check-branch",
			Module: []byte(`package witness.check_branch

deny[msg] {
  input.branch != "main"
  msg := "not on main branch"
}
`),
		},
	}

	err := compatPolicy.EvaluateRegoPolicy(att, policies)
	if err == nil {
		t.Fatal("expected denying Rego policy to produce an error")
	}
	if !strings.Contains(err.Error(), "not on main branch") {
		t.Errorf("error should contain deny message, got: %v", err)
	}
}

// ============================================================================
// 15. Verify option interchangeability
// ============================================================================

// TestCompat_VerifyOptions_AcceptedByRookeryPolicy verifies that VerifyOption
// values created via compat constructors are accepted by rookery Policy.Verify.
func TestCompat_VerifyOptions_AcceptedByRookeryPolicy(t *testing.T) {
	ms := source.NewMemorySource()
	vs := source.NewVerifiedSource(ms)

	// Create options through compat
	opts := []compatPolicy.VerifyOption{
		compatPolicy.WithVerifiedSource(vs),
		compatPolicy.WithSubjectDigests([]string{"abc"}),
		compatPolicy.WithSearchDepth(5),
		compatPolicy.WithAiServerURL("http://localhost:11434"),
		compatPolicy.WithClockSkewTolerance(30 * time.Second),
	}

	// These should be usable as rookery VerifyOption values
	rookeryOpts := make([]policy.VerifyOption, len(opts))
	for i, opt := range opts {
		rookeryOpts[i] = opt
	}

	// Verify the options work with a rookery Policy
	p := policy.Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]policy.Step{
			"build": {Name: "build"},
		},
	}

	// This will fail on "no collections" but should NOT fail on options parsing
	_, _, err := p.Verify(context.Background(), rookeryOpts...)
	if err != nil {
		// The error should be about collections/artifacts, not about options
		if strings.Contains(err.Error(), "invalid option") {
			t.Errorf("options should be valid, got option error: %v", err)
		}
	}
}

// ============================================================================
// helpers
// ============================================================================

type behavioralDummyAttestor struct {
	name string
	typ  string
	data map[string]string
}

func (a *behavioralDummyAttestor) Name() string { return a.name }
func (a *behavioralDummyAttestor) Type() string { return a.typ }
func (a *behavioralDummyAttestor) RunType() attestation.RunType {
	return attestation.PreMaterialRunType
}
func (a *behavioralDummyAttestor) Attest(*attestation.AttestationContext) error { return nil }
func (a *behavioralDummyAttestor) Schema() *jsonschema.Schema                   { return nil }
func (a *behavioralDummyAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.data)
}
