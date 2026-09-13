//go:build audit

// The shim aliases current Rookery APIs; it is not a frozen upstream release.
// Exercise the public mapping and its boundaries rather than failing merely
// because Rookery has additional fields or a current predicate URI.
package witness_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	witness "github.com/in-toto/go-witness"
	compatAttestation "github.com/in-toto/go-witness/attestation"
	compatFile "github.com/in-toto/go-witness/file"
	compatPolicy "github.com/in-toto/go-witness/policy"
	compatSource "github.com/in-toto/go-witness/source"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/file"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

func TestSecurity_R3_160_PolicyPredicateConstantChanged(t *testing.T) {
	require.Equal(t, policy.PolicyPredicate, compatPolicy.PolicyPredicate)
	require.Equal(t, policy.LegacyPolicyPredicate, compatPolicy.LegacyPolicyPredicate)
	require.NotEqual(t, compatPolicy.PolicyPredicate, compatPolicy.LegacyPolicyPredicate)
}

func TestSecurity_R3_161_CollectionTypeConstantChanged(t *testing.T) {
	require.Equal(t, attestation.CollectionType, compatAttestation.CollectionType)
	require.Equal(t, attestation.LegacyCollectionType, compatAttestation.LegacyCollectionType)
	require.NotEqual(t, compatAttestation.CollectionType, compatAttestation.LegacyCollectionType)
}

func TestSecurity_R3_162_StepResultPassedFieldTypeChanged(t *testing.T) {
	field, ok := reflect.TypeOf(compatPolicy.StepResult{}).FieldByName("Passed")
	require.True(t, ok)
	require.Equal(t, reflect.TypeOf([]policy.PassedCollection{}), field.Type)
	var native policy.StepResult = compatPolicy.StepResult{Step: "build"}
	require.Equal(t, "build", native.Step)
}

func TestSecurity_R3_163_RecordArtifactsSignatureChanged(t *testing.T) {
	require.Equal(t, reflect.TypeOf(file.RecordArtifacts), reflect.TypeOf(compatFile.RecordArtifacts))
	require.Equal(t, reflect.ValueOf(file.RecordArtifacts).Pointer(), reflect.ValueOf(compatFile.RecordArtifacts).Pointer())
}

func TestSecurity_R3_164_CollectionAttestationUnmarshalFallbackToRaw(t *testing.T) {
	const raw = `{"type":"https://example.com/unknown-attestor/v99.0","attestation":{"key":"value"},"starttime":"2024-01-01T00:00:00Z","endtime":"2024-01-01T00:01:00Z"}`
	var observed compatAttestation.CollectionAttestation
	require.NoError(t, json.Unmarshal([]byte(raw), &observed))
	require.IsType(t, &compatAttestation.RawAttestation{}, observed.Attestation)
	encoded, err := json.Marshal(observed)
	require.NoError(t, err)
	require.JSONEq(t, raw, string(encoded), "unknown evidence must retain its exact JSON values")
	_, registered := compatAttestation.FactoryByType(observed.Type)
	require.False(t, registered, "reading opaque evidence must not register an executable attestor")
}

func TestSecurity_R3_165_MemorySourceDualURIIndexing(t *testing.T) {
	const current = "https://aflock.ai/attestations/git/v0.1"
	legacy := compatAttestation.LegacyAlternate(current)
	require.NotEmpty(t, legacy)
	digest := strings.Repeat("a", 64)
	predicate := attestation.Collection{Name: "test-step", Attestations: []attestation.CollectionAttestation{{Type: current}}}
	stmt := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v0.1", "predicateType": attestation.CollectionType,
		"subject":   []map[string]interface{}{{"name": "artifact", "digest": map[string]string{"sha256": digest}}},
		"predicate": predicate,
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	ms := compatSource.NewMemorySource()
	require.NoError(t, ms.LoadEnvelope("ref1", dsse.Envelope{Payload: payload, PayloadType: "application/vnd.in-toto+json"}))
	for _, typ := range []string{current, legacy} {
		found, err := ms.Search(context.Background(), "test-step", []string{digest}, []string{typ})
		require.NoError(t, err)
		require.Len(t, found, 1)
	}
	for _, query := range []struct{ digest, typ string }{{strings.Repeat("b", 64), current}, {digest, "https://example.com/unrelated"}} {
		found, err := ms.Search(context.Background(), "test-step", []string{query.digest}, []string{query.typ})
		require.NoError(t, err)
		require.Empty(t, found, "URI aliases must not widen artifact or predicate matching")
	}
}

func TestSecurity_R3_166_ArchivistaSourcePartialFailureBehavior(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"dsses":{"edges":[]}}}`))
	}))
	defer server.Close()
	src := compatSource.NewArchivistaSource(archivista.New(server.URL))
	require.Equal(t, reflect.TypeOf(&source.ArchivistaSource{}), reflect.TypeOf(src))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	found, err := src.Search(ctx, "build", []string{strings.Repeat("a", 64)}, nil)
	require.Error(t, err)
	require.Empty(t, found)
	require.Zero(t, calls.Load(), "a canceled query must not reach the server")
	found, err = src.Search(context.Background(), "build", []string{strings.Repeat("a", 64)}, nil)
	require.NoError(t, err)
	require.Empty(t, found)
	require.EqualValues(t, 1, calls.Load(), "a failed search must not poison a later query")
}

func TestSecurity_R3_167_RejectedCollectionAdditionalField(t *testing.T) {
	require.Equal(t, reflect.TypeOf(policy.RejectedCollection{}), reflect.TypeOf(compatPolicy.RejectedCollection{}))
	field, ok := reflect.TypeOf(compatPolicy.RejectedCollection{}).FieldByName("AiResponses")
	require.True(t, ok)
	native, ok := reflect.TypeOf(policy.RejectedCollection{}).FieldByName("AiResponses")
	require.True(t, ok)
	require.Equal(t, native.Type, field.Type)
}

func TestSecurity_R3_168_AttestationStructHasAiPolicies(t *testing.T) {
	const raw = `{"type":"https://example.com/evidence","regopolicies":[]}`
	var alias compatPolicy.Attestation
	var native policy.Attestation
	require.NoError(t, json.Unmarshal([]byte(raw), &alias))
	require.NoError(t, json.Unmarshal([]byte(raw), &native))
	a, err := json.Marshal(alias)
	require.NoError(t, err)
	b, err := json.Marshal(native)
	require.NoError(t, err)
	require.Equal(t, string(b), string(a), "the shim must serialize exactly like its aliased implementation")
	require.Equal(t, "https://example.com/evidence", alias.Type)
}

func TestSecurity_R3_169_RunProducesNewURICollectionType(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	result, err := witness.Run("compat-run-test", witness.RunWithSigners(cryptoutil.NewED25519Signer(priv)))
	require.NoError(t, err)
	_, err = result.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(cryptoutil.NewED25519Verifier(pub)))
	require.NoError(t, err)
	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	require.NoError(t, json.Unmarshal(result.SignedEnvelope.Payload, &statement))
	require.Equal(t, compatAttestation.CollectionType, statement.PredicateType)
	require.Equal(t, "compat-run-test", result.Collection.Name)
}

func TestSecurity_R3_170_CompatExportsRookeryOnlyAPIs(t *testing.T) {
	require.Equal(t, reflect.TypeOf(policy.AiPolicy{}), reflect.TypeOf(compatPolicy.AiPolicy{}))
	require.Equal(t, reflect.TypeOf(policy.AiResponse{}), reflect.TypeOf(compatPolicy.AiResponse{}))
	require.Equal(t, reflect.TypeOf(policy.PassedCollection{}), reflect.TypeOf(compatPolicy.PassedCollection{}))
}

func TestSecurity_R3_171_PolicyValidateNotInGoWitness(t *testing.T) {
	p := compatPolicy.Policy{Steps: map[string]compatPolicy.Step{
		"build": {Name: "build"}, "test": {Name: "test", AttestationsFrom: []string{"build"}},
	}}
	require.NoError(t, p.Validate())
	step := p.Steps["test"]
	step.AttestationsFrom = []string{"missing"}
	p.Steps["test"] = step
	require.Error(t, p.Validate(), "the aliased validator must reject an unknown dependency")
}

func TestSecurity_R3_172_StepStructHasAttestationsFrom(t *testing.T) {
	step := compatPolicy.Step{Name: "deploy", AttestationsFrom: []string{"build"}}
	data, err := json.Marshal(step)
	require.NoError(t, err)
	var native policy.Step
	require.NoError(t, json.Unmarshal(data, &native))
	require.Equal(t, "deploy", native.Name)
	require.Equal(t, []string{"build"}, native.AttestationsFrom)
}
