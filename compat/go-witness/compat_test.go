//nolint:staticcheck // explicit type annotations verify cross-package type compatibility
package witness_test

import (
	"context"
	"crypto"
	"encoding/json"
	"testing"
	"time"

	witness "github.com/in-toto/go-witness"
	compatAttestation "github.com/in-toto/go-witness/attestation"
	compatDSSE "github.com/in-toto/go-witness/dsse"
	compatPolicy "github.com/in-toto/go-witness/policy"
	compatRegistry "github.com/in-toto/go-witness/registry"
	compatSource "github.com/in-toto/go-witness/source"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/invopop/jsonschema"
)

// ============================================================================
// Compatibility verification tests
//
// These tests verify that the go-witness compat shim correctly maps types,
// constants, interfaces, and behaviors to the underlying rookery library.
// ============================================================================

func TestCompatSourceMemorySource(t *testing.T) {
	compatMS := compatSource.NewMemorySource()
	rookeryMS := source.NewMemorySource()

	if compatMS == nil {
		t.Fatal("compat NewMemorySource returned nil")
	}
	if rookeryMS == nil {
		t.Fatal("rookery NewMemorySource returned nil")
	}

	var _ *source.MemorySource = compatSource.NewMemorySource()
	var _ *compatSource.MemorySource = source.NewMemorySource()
}

func TestCompatSourceMultiSource(t *testing.T) {
	ms1 := compatSource.NewMemorySource()
	ms2 := source.NewMemorySource()

	multi := compatSource.NewMultiSource(ms1, ms2)
	if multi == nil {
		t.Fatal("compat NewMultiSource returned nil")
	}

	var _ *source.MultiSource = compatSource.NewMultiSource(ms1)
	var _ *compatSource.MultiSource = source.NewMultiSource(ms2)
}

func TestCompatSourceVerifiedSource(t *testing.T) {
	ms := compatSource.NewMemorySource()
	vs := compatSource.NewVerifiedSource(ms)
	if vs == nil {
		t.Fatal("compat NewVerifiedSource returned nil")
	}

	var _ *source.VerifiedSource = compatSource.NewVerifiedSource(ms)
	var _ *compatSource.VerifiedSource = source.NewVerifiedSource(ms)
}

func TestCompatSourceCollectionEnvelope(t *testing.T) {
	env := compatSource.CollectionEnvelope{
		Reference: "test-ref",
		Envelope:  dsse.Envelope{PayloadType: "application/vnd.in-toto+json"},
	}

	var rookeryEnv source.CollectionEnvelope = env
	if rookeryEnv.Reference != "test-ref" {
		t.Errorf("Reference = %q, want %q", rookeryEnv.Reference, "test-ref")
	}
	if rookeryEnv.Envelope.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("PayloadType = %q, want %q", rookeryEnv.Envelope.PayloadType, "application/vnd.in-toto+json")
	}
}

func TestCompatSourceInterfaces(t *testing.T) {
	ms := compatSource.NewMemorySource()
	var _ compatSource.Sourcer = ms
	var _ source.Sourcer = ms

	vs := compatSource.NewVerifiedSource(ms)
	var _ compatSource.VerifiedSourcer = vs
	var _ source.VerifiedSourcer = vs
}

func TestCompatSourceErrDuplicateReference(t *testing.T) {
	var compatErr compatSource.ErrDuplicateReference = "test-dup"
	var rookeryErr source.ErrDuplicateReference = compatErr

	if rookeryErr.Error() != compatErr.Error() {
		t.Errorf("error messages differ: compat=%q rookery=%q", compatErr.Error(), rookeryErr.Error())
	}
}

func TestCompatSourceSearchViaCombinedTypes(t *testing.T) {
	ms := compatSource.NewMemorySource()

	collection := attestation.Collection{
		Name:         "test-step",
		Attestations: []attestation.CollectionAttestation{},
	}
	collJSON, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}

	subjects := map[string]cryptoutil.DigestSet{
		"test-subject": {
			cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
		},
	}

	subjectList := make([]struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}, 0, len(subjects))
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
		Signatures:  []dsse.Signature{},
	}

	if err := ms.LoadEnvelope("ref1", env); err != nil {
		t.Fatalf("LoadEnvelope failed: %v", err)
	}

	var s compatSource.Sourcer = ms
	results, err := s.Search(context.Background(), "test-step", []string{"abc123"}, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Collection.Name != "test-step" {
		t.Errorf("Collection.Name = %q, want %q", results[0].Collection.Name, "test-step")
	}
}

func TestCompatRegistryTypeAliases(t *testing.T) {
	var _ compatRegistry.Configurer = nil
	_ = compatRegistry.Configurer(nil)
}

func TestCompatRegistryRegistrationViaCompat(t *testing.T) {
	testType := "https://aflock.ai/attestations/compat-reg-test/v0.1"

	compatAttestation.RegisterAttestation(
		"compat-reg-test",
		testType,
		compatAttestation.PreMaterialRunType,
		func() compatAttestation.Attestor {
			return &dummyAttestor{name: "compat-reg-test", typ: testType}
		},
	)

	factory, ok := attestation.FactoryByType(testType)
	if !ok {
		t.Fatal("attestor registered through compat not found via rookery FactoryByType")
	}
	att := factory()
	if att.Name() != "compat-reg-test" {
		t.Errorf("Name() = %q, want %q", att.Name(), "compat-reg-test")
	}

	compatFactory, ok := compatAttestation.FactoryByType(testType)
	if !ok {
		t.Fatal("attestor registered through compat not found via compat FactoryByType")
	}
	att2 := compatFactory()
	if att2.Type() != testType {
		t.Errorf("Type() = %q, want %q", att2.Type(), testType)
	}
}

func TestCompatDSSEEnvelope(t *testing.T) {
	compatEnv := compatDSSE.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     []byte(`{"test": true}`),
		Signatures: []compatDSSE.Signature{
			{
				KeyID:     "key-1",
				Signature: []byte("sig-bytes"),
			},
		},
	}

	var rookeryEnv dsse.Envelope = compatEnv
	if rookeryEnv.PayloadType != compatEnv.PayloadType {
		t.Errorf("PayloadType mismatch")
	}
	if len(rookeryEnv.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(rookeryEnv.Signatures))
	}
	if rookeryEnv.Signatures[0].KeyID != "key-1" {
		t.Errorf("KeyID = %q, want %q", rookeryEnv.Signatures[0].KeyID, "key-1")
	}

	data, err := json.Marshal(compatEnv)
	if err != nil {
		t.Fatal(err)
	}
	var deserialized dsse.Envelope
	if err := json.Unmarshal(data, &deserialized); err != nil {
		t.Fatal(err)
	}
	if deserialized.PayloadType != compatEnv.PayloadType {
		t.Errorf("roundtrip PayloadType mismatch")
	}
}

func TestCompatDSSEErrorTypes(t *testing.T) {
	var _ error = compatDSSE.ErrNoSignatures{}
	var _ error = compatDSSE.ErrInvalidThreshold(0)

	noSigs := compatDSSE.ErrNoSignatures{}
	var rookeryNoSigs dsse.ErrNoSignatures = noSigs
	if noSigs.Error() != rookeryNoSigs.Error() {
		t.Errorf("ErrNoSignatures messages differ")
	}

	invalidThresh := compatDSSE.ErrInvalidThreshold(5)
	var rookeryThresh dsse.ErrInvalidThreshold = invalidThresh
	if invalidThresh.Error() != rookeryThresh.Error() {
		t.Errorf("ErrInvalidThreshold messages differ")
	}
}

func TestCompatDSSEConstants(t *testing.T) {
	if compatDSSE.PemTypeCertificate != dsse.PemTypeCertificate {
		t.Errorf("PemTypeCertificate: compat=%q rookery=%q", compatDSSE.PemTypeCertificate, dsse.PemTypeCertificate)
	}
	if compatDSSE.TimestampRFC3161 != dsse.TimestampRFC3161 {
		t.Errorf("TimestampRFC3161: compat=%q rookery=%q", compatDSSE.TimestampRFC3161, dsse.TimestampRFC3161)
	}
}

func TestCompatDSSESignatureTimestamp(t *testing.T) {
	ts := compatDSSE.SignatureTimestamp{
		Type: compatDSSE.TimestampRFC3161,
		Data: []byte("timestamp-data"),
	}
	var rookeryTs dsse.SignatureTimestamp = ts
	if string(rookeryTs.Type) != string(dsse.TimestampRFC3161) {
		t.Errorf("Type mismatch")
	}
}

func TestCompatAttestationTypes(t *testing.T) {
	coll := compatAttestation.Collection{
		Name:         "test-step",
		Attestations: []compatAttestation.CollectionAttestation{},
	}
	var rookeryColl attestation.Collection = coll
	if rookeryColl.Name != "test-step" {
		t.Errorf("Name = %q, want %q", rookeryColl.Name, "test-step")
	}

	errAtt := compatAttestation.ErrAttestor{
		Name:    "test",
		RunType: compatAttestation.ExecuteRunType,
		Reason:  "test error",
	}
	var rookeryErr attestation.ErrAttestor = errAtt
	if rookeryErr.Error() == "" {
		t.Error("ErrAttestor.Error() returned empty string")
	}

	var notFound compatAttestation.ErrAttestationNotFound = "missing"
	var rookeryNotFound attestation.ErrAttestationNotFound = notFound
	if rookeryNotFound.Error() == "" {
		t.Error("ErrAttestationNotFound.Error() returned empty string")
	}

	var attNotFound compatAttestation.ErrAttestorNotFound = "missing-att"
	var rookeryAttNotFound attestation.ErrAttestorNotFound = attNotFound
	if rookeryAttNotFound.Error() == "" {
		t.Error("ErrAttestorNotFound.Error() returned empty string")
	}
}

func TestCompatAttestationRunTypeConstants(t *testing.T) {
	tests := []struct {
		name    string
		compat  compatAttestation.RunType
		rookery attestation.RunType
	}{
		{"PreMaterial", compatAttestation.PreMaterialRunType, attestation.PreMaterialRunType},
		{"Material", compatAttestation.MaterialRunType, attestation.MaterialRunType},
		{"Execute", compatAttestation.ExecuteRunType, attestation.ExecuteRunType},
		{"Product", compatAttestation.ProductRunType, attestation.ProductRunType},
		{"PostProduct", compatAttestation.PostProductRunType, attestation.PostProductRunType},
		{"Verify", compatAttestation.VerifyRunType, attestation.VerifyRunType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.compat != tt.rookery {
				t.Errorf("compat=%q rookery=%q", tt.compat, tt.rookery)
			}
		})
	}
}

func TestCompatAttestationCollectionTypeConstants(t *testing.T) {
	if compatAttestation.CollectionType != attestation.CollectionType {
		t.Errorf("CollectionType: compat=%q rookery=%q", compatAttestation.CollectionType, attestation.CollectionType)
	}
	if compatAttestation.LegacyCollectionType != attestation.LegacyCollectionType {
		t.Errorf("LegacyCollectionType: compat=%q rookery=%q", compatAttestation.LegacyCollectionType, attestation.LegacyCollectionType)
	}
}

func TestCompatAttestationContextOptions(t *testing.T) {
	opt := compatAttestation.WithWorkingDir("/tmp/test")
	var rookeryOpt attestation.AttestationContextOption = opt

	ctx, err := compatAttestation.NewContext("test-step", nil, rookeryOpt)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.WorkingDir() != "/tmp/test" {
		t.Errorf("WorkingDir = %q, want %q", ctx.WorkingDir(), "/tmp/test")
	}
}

func TestCompatAttestationNewCollection(t *testing.T) {
	coll := compatAttestation.NewCollection("build", nil)
	if coll.Name != "build" {
		t.Errorf("Name = %q, want %q", coll.Name, "build")
	}
	if len(coll.Attestations) != 0 {
		t.Errorf("expected 0 attestations, got %d", len(coll.Attestations))
	}
}

func TestCompatPolicyTypes(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"build": {
				Name: "build",
				Functionaries: []compatPolicy.Functionary{
					{Type: "publickey", PublicKeyID: "key-1"},
				},
				Attestations: []compatPolicy.Attestation{
					{Type: "https://aflock.ai/attestations/command-run/v0.1"},
				},
			},
		},
		PublicKeys: map[string]compatPolicy.PublicKey{
			"key-1": {KeyID: "key-1", Key: []byte("pem-data")},
		},
	}

	var rookeryPolicy policy.Policy = p
	if len(rookeryPolicy.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(rookeryPolicy.Steps))
	}
	step := rookeryPolicy.Steps["build"]
	if step.Name != "build" {
		t.Errorf("step Name = %q, want %q", step.Name, "build")
	}
}

func TestCompatPolicyConstants(t *testing.T) {
	if compatPolicy.PolicyPredicate != policy.PolicyPredicate {
		t.Errorf("PolicyPredicate: compat=%q rookery=%q", compatPolicy.PolicyPredicate, policy.PolicyPredicate)
	}
	if compatPolicy.LegacyPolicyPredicate != policy.LegacyPolicyPredicate {
		t.Errorf("LegacyPolicyPredicate: compat=%q rookery=%q", compatPolicy.LegacyPolicyPredicate, policy.LegacyPolicyPredicate)
	}
	if compatPolicy.AllowAllConstraint != policy.AllowAllConstraint {
		t.Errorf("AllowAllConstraint: compat=%q rookery=%q", compatPolicy.AllowAllConstraint, policy.AllowAllConstraint)
	}
}

func TestCompatPolicyErrorTypes(t *testing.T) {
	errMissing := compatPolicy.ErrMissingAttestation{Step: "build", Attestation: "env"}
	var rookeryErr policy.ErrMissingAttestation = errMissing
	if rookeryErr.Error() == "" {
		t.Error("ErrMissingAttestation.Error() empty")
	}

	errKeyMismatch := compatPolicy.ErrKeyIDMismatch{Expected: "a", Actual: "b"}
	var rookeryKeyErr policy.ErrKeyIDMismatch = errKeyMismatch
	if rookeryKeyErr.Error() == "" {
		t.Error("ErrKeyIDMismatch.Error() empty")
	}

	errNoColl := compatPolicy.ErrNoCollections{Step: "build"}
	var rookeryNoColl policy.ErrNoCollections = errNoColl
	if rookeryNoColl.Error() == "" {
		t.Error("ErrNoCollections.Error() empty")
	}
}

func TestCompatPolicyJSONRoundtrip(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"test": {
				Name: "test",
				Attestations: []compatPolicy.Attestation{
					{
						Type: "https://aflock.ai/attestations/git/v0.1",
						RegoPolicies: []compatPolicy.RegoPolicy{
							{Name: "check-branch", Module: []byte("package witness")},
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	var restored policy.Policy
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}

	if len(restored.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(restored.Steps))
	}
	if restored.Steps["test"].Attestations[0].Type != "https://aflock.ai/attestations/git/v0.1" {
		t.Error("attestation type mismatch after roundtrip")
	}
}

func TestCompatWitnessRunResult(t *testing.T) {
	rr := witness.RunResult{
		Collection:   attestation.Collection{Name: "build"},
		AttestorName: "commandrun",
	}
	var rookeryRR workflow.RunResult = rr
	if rookeryRR.Collection.Name != "build" {
		t.Errorf("Collection.Name = %q, want %q", rookeryRR.Collection.Name, "build")
	}
}

func TestCompatWitnessRunOptions(t *testing.T) {
	opt := witness.RunWithInsecure(true)
	var _ workflow.RunOption = opt

	opt2 := witness.RunWithIgnoreErrors(true)
	var _ workflow.RunOption = opt2
}

func TestCompatWitnessVerifyOptions(t *testing.T) {
	ms := compatSource.NewMemorySource()
	opt := witness.VerifyWithCollectionSource(ms)
	var _ workflow.VerifyOption = opt
}

func TestCompatWitnessRunInsecure(t *testing.T) {
	result, err := witness.Run("compat-test-step", witness.RunWithInsecure(true))
	if err != nil {
		t.Fatalf("Run through compat failed: %v", err)
	}
	if result.Collection.Name != "compat-test-step" {
		t.Errorf("Collection.Name = %q, want %q", result.Collection.Name, "compat-test-step")
	}

	var rookeryResult workflow.RunResult = result
	if rookeryResult.Collection.Name != "compat-test-step" {
		t.Errorf("rookery Collection.Name = %q, want %q", rookeryResult.Collection.Name, "compat-test-step")
	}
}

func TestCompatAttestorWithRookeryContext(t *testing.T) {
	att := &dummyAttestor{
		name: "cross-layer",
		typ:  "https://aflock.ai/attestations/cross-layer/v0.1",
	}

	ctx, err := attestation.NewContext("cross-layer-step", []attestation.Attestor{att},
		attestation.WithWorkingDir("/tmp"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	completed := ctx.CompletedAttestors()
	if len(completed) != 1 {
		t.Fatalf("expected 1 completed attestor, got %d", len(completed))
	}
	if completed[0].Attestor.Name() != "cross-layer" {
		t.Errorf("attestor Name = %q, want %q", completed[0].Attestor.Name(), "cross-layer")
	}

	coll := compatAttestation.NewCollection("cross-layer-step", completed)
	if coll.Name != "cross-layer-step" {
		t.Errorf("Collection.Name = %q, want %q", coll.Name, "cross-layer-step")
	}
	if len(coll.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(coll.Attestations))
	}
}

func TestCompatProductType(t *testing.T) {
	p := compatAttestation.Product{
		MimeType: "application/json",
		Digest: cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
		},
	}
	var rookeryProduct attestation.Product = p
	if rookeryProduct.MimeType != "application/json" {
		t.Error("MimeType mismatch")
	}
}

func TestCompatCompletedAttestor(t *testing.T) {
	ca := compatAttestation.CompletedAttestor{
		Attestor:  &dummyAttestor{name: "test", typ: "test/v1"},
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}
	var rookeryCA attestation.CompletedAttestor = ca
	if rookeryCA.Attestor.Name() != "test" {
		t.Error("Name mismatch")
	}
}

func TestCompatPolicyCrossStepErrorTypes(t *testing.T) {
	circErr := policy.ErrCircularDependency{Steps: []string{"a", "b", "a"}}
	if circErr.Error() == "" {
		t.Error("ErrCircularDependency.Error() returned empty string")
	}

	selfErr := policy.ErrSelfReference{Step: "build"}
	if selfErr.Error() == "" {
		t.Error("ErrSelfReference.Error() returned empty string")
	}

	depErr := policy.ErrDependencyNotVerified{Step: "deploy"}
	if depErr.Error() == "" {
		t.Error("ErrDependencyNotVerified.Error() returned empty string")
	}
}

func TestCompatPolicyWithClockSkewTolerance(t *testing.T) {
	opt := policy.WithClockSkewTolerance(30 * time.Second)
	var _ policy.VerifyOption = opt
}

func TestCompatPolicyCrossStepAttestationsFrom(t *testing.T) {
	step := compatPolicy.Step{
		Name: "deploy",
		Functionaries: []compatPolicy.Functionary{
			{Type: "publickey", PublicKeyID: "key-1"},
		},
		Attestations: []compatPolicy.Attestation{
			{Type: "https://aflock.ai/attestations/command-run/v0.1"},
		},
		AttestationsFrom: []string{"build", "test"},
	}

	data, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}

	var restored policy.Step
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}

	if len(restored.AttestationsFrom) != 2 {
		t.Fatalf("AttestationsFrom: expected 2, got %d", len(restored.AttestationsFrom))
	}
	if restored.AttestationsFrom[0] != "build" {
		t.Errorf("AttestationsFrom[0] = %q, want %q", restored.AttestationsFrom[0], "build")
	}
	if restored.AttestationsFrom[1] != "test" {
		t.Errorf("AttestationsFrom[1] = %q, want %q", restored.AttestationsFrom[1], "test")
	}
}

func TestCompatPolicyValidateCircularDeps(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"a": {Name: "a", AttestationsFrom: []string{"b"}},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
		},
	}

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate should return error for circular AttestationsFrom dependency")
	}
}

func TestCompatPolicyValidateSelfRef(t *testing.T) {
	p := compatPolicy.Policy{
		Steps: map[string]compatPolicy.Step{
			"build": {Name: "build", AttestationsFrom: []string{"build"}},
		},
	}

	err := p.Validate()
	if err == nil {
		t.Fatal("Validate should return error for self-referencing step")
	}
}

// ============================================================================
// helpers
// ============================================================================

type dummyAttestor struct {
	name string
	typ  string
}

func (a *dummyAttestor) Name() string                                 { return a.name }
func (a *dummyAttestor) Type() string                                 { return a.typ }
func (a *dummyAttestor) RunType() attestation.RunType                 { return attestation.PreMaterialRunType }
func (a *dummyAttestor) Attest(*attestation.AttestationContext) error { return nil }
func (a *dummyAttestor) Schema() *jsonschema.Schema                   { return nil }
