package attestation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Register test attestors under both old and new URIs
	RegisterAttestation("compat-test", "https://aflock.ai/attestations/compat-test/v0.1", PreMaterialRunType, func() Attestor {
		return &compatTestAttestor{}
	})
}

type compatTestAttestor struct {
	Value string `json:"value"`
}

func (a *compatTestAttestor) Name() string                     { return "compat-test" }
func (a *compatTestAttestor) Type() string                     { return "https://aflock.ai/attestations/compat-test/v0.1" }
func (a *compatTestAttestor) RunType() RunType                 { return PreMaterialRunType }
func (a *compatTestAttestor) Attest(*AttestationContext) error { return nil }
func (a *compatTestAttestor) Schema() *jsonschema.Schema       { return jsonschema.Reflect(a) }

// TestLegacyAliasRegistration verifies that RegisterLegacyAlias makes old URIs
// resolve to the same factory as new URIs.
func TestLegacyAliasRegistration(t *testing.T) {
	currentType := "https://aflock.ai/attestations/compat-test/v0.1"
	legacyType := "https://witness.dev/attestations/compat-test/v0.1"

	// Before alias registration, legacy type should not be found
	_, found := FactoryByType(legacyType)
	assert.False(t, found, "legacy type should not be registered before alias")

	// Register alias
	RegisterLegacyAlias(legacyType, currentType)

	// After alias, legacy type should resolve
	factory, found := FactoryByType(legacyType)
	require.True(t, found, "legacy type should be found after alias registration")

	// Both should produce the same attestor type
	currentFactory, _ := FactoryByType(currentType)
	assert.Equal(t, currentFactory().Name(), factory().Name())
}

// TestCollectionTypeConstants verifies both collection type constants are defined correctly.
func TestCollectionTypeConstants(t *testing.T) {
	assert.Equal(t, "https://aflock.ai/attestation-collection/v0.1", CollectionType)
	assert.Equal(t, "https://witness.testifysec.com/attestation-collection/v0.1", LegacyCollectionType)
}

// TestCollectionAttestationUnmarshalWithLegacyType verifies that CollectionAttestation
// can unmarshal attestations using legacy predicate type URIs.
func TestCollectionAttestationUnmarshalWithLegacyType(t *testing.T) {
	legacyType := "https://witness.dev/attestations/compat-test/v0.1"
	currentType := "https://aflock.ai/attestations/compat-test/v0.1"

	// Ensure legacy alias is registered
	RegisterLegacyAlias(legacyType, currentType)

	// JSON using the legacy URI
	collJSON := `{
		"type": "https://witness.dev/attestations/compat-test/v0.1",
		"attestation": {"value": "hello-legacy"},
		"starttime": "2024-01-01T00:00:00Z",
		"endtime": "2024-01-01T00:01:00Z"
	}`

	var ca CollectionAttestation
	err := json.Unmarshal([]byte(collJSON), &ca)
	require.NoError(t, err)

	assert.Equal(t, legacyType, ca.Type)
	assert.Equal(t, "compat-test", ca.Attestation.Name())

	// Verify the attestor data was deserialized
	ct, ok := ca.Attestation.(*compatTestAttestor)
	require.True(t, ok)
	assert.Equal(t, "hello-legacy", ct.Value)
}

// TestCollectionAttestationUnmarshalWithCurrentType verifies that CollectionAttestation
// can unmarshal attestations using the current aflock.ai predicate type URI.
func TestCollectionAttestationUnmarshalWithCurrentType(t *testing.T) {
	collJSON := `{
		"type": "https://aflock.ai/attestations/compat-test/v0.1",
		"attestation": {"value": "hello-current"},
		"starttime": "2024-01-01T00:00:00Z",
		"endtime": "2024-01-01T00:01:00Z"
	}`

	var ca CollectionAttestation
	err := json.Unmarshal([]byte(collJSON), &ca)
	require.NoError(t, err)

	assert.Equal(t, "https://aflock.ai/attestations/compat-test/v0.1", ca.Type)
	ct, ok := ca.Attestation.(*compatTestAttestor)
	require.True(t, ok)
	assert.Equal(t, "hello-current", ct.Value)
}

// TestCollectionJSONRoundtrip verifies that a Collection can be marshaled and unmarshaled
// without data loss.
func TestCollectionJSONRoundtrip(t *testing.T) {
	original := Collection{
		Name: "test-step",
		Attestations: []CollectionAttestation{
			{
				Type:        "https://aflock.ai/attestations/compat-test/v0.1",
				Attestation: &compatTestAttestor{Value: "roundtrip-data"},
				StartTime:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				EndTime:     time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var restored Collection
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, original.Name, restored.Name)
	require.Len(t, restored.Attestations, 1)
	assert.Equal(t, original.Attestations[0].Type, restored.Attestations[0].Type)

	ct, ok := restored.Attestations[0].Attestation.(*compatTestAttestor)
	require.True(t, ok)
	assert.Equal(t, "roundtrip-data", ct.Value)
}

// TestLegacyCollectionJSONRoundtrip verifies that a Collection with legacy URIs
// can be deserialized (simulating old attestations stored in Archivista).
func TestLegacyCollectionJSONRoundtrip(t *testing.T) {
	legacyType := "https://witness.dev/attestations/compat-test/v0.1"
	currentType := "https://aflock.ai/attestations/compat-test/v0.1"
	RegisterLegacyAlias(legacyType, currentType)

	// Simulate a JSON document stored with old URIs
	legacyJSON := `{
		"name": "build",
		"attestations": [
			{
				"type": "https://witness.dev/attestations/compat-test/v0.1",
				"attestation": {"value": "stored-in-archivista"},
				"starttime": "2023-06-15T10:30:00Z",
				"endtime": "2023-06-15T10:31:00Z"
			}
		]
	}`

	var collection Collection
	err := json.Unmarshal([]byte(legacyJSON), &collection)
	require.NoError(t, err)

	assert.Equal(t, "build", collection.Name)
	require.Len(t, collection.Attestations, 1)
	assert.Equal(t, legacyType, collection.Attestations[0].Type)

	ct, ok := collection.Attestations[0].Attestation.(*compatTestAttestor)
	require.True(t, ok)
	assert.Equal(t, "stored-in-archivista", ct.Value)
}

// TestRegisterLegacyAliasNonExistent verifies that registering an alias for a
// non-existent type is a no-op (doesn't panic).
func TestRegisterLegacyAliasNonExistent(t *testing.T) {
	RegisterLegacyAlias("https://witness.dev/attestations/nonexistent/v0.1", "https://aflock.ai/attestations/nonexistent/v0.1")
	_, found := FactoryByType("https://witness.dev/attestations/nonexistent/v0.1")
	assert.False(t, found)
}

// TestRawAttestationFallback verifies that unknown attestor types produce a
// RawAttestation instead of an error.
func TestRawAttestationFallback(t *testing.T) {
	unknownType := "https://example.com/attestations/unknown/v0.1"
	collJSON := `{
		"type": "https://example.com/attestations/unknown/v0.1",
		"attestation": {"foo": "bar", "count": 42},
		"starttime": "2024-01-01T00:00:00Z",
		"endtime": "2024-01-01T00:01:00Z"
	}`

	var ca CollectionAttestation
	err := json.Unmarshal([]byte(collJSON), &ca)
	require.NoError(t, err, "unknown types should not fail unmarshal")

	assert.Equal(t, unknownType, ca.Type)
	assert.Equal(t, unknownType, ca.Attestation.Name())
	assert.Equal(t, unknownType, ca.Attestation.Type())

	raw, ok := ca.Attestation.(*RawAttestation)
	require.True(t, ok, "should be *RawAttestation")

	// RawAttestation cannot attest
	assert.Error(t, raw.Attest(nil))
	assert.Nil(t, raw.Schema())
	assert.Equal(t, RunType(""), raw.RunType())
}

// TestRawAttestationMarshalJSON verifies that marshaling a RawAttestation
// produces the original JSON verbatim — this is what Rego/AI policy evaluation needs.
func TestRawAttestationMarshalJSON(t *testing.T) {
	inputJSON := `{"foo":"bar","nested":{"a":1}}`

	collJSON := `{
		"type": "https://example.com/attestations/rawtest/v0.1",
		"attestation": ` + inputJSON + `,
		"starttime": "2024-01-01T00:00:00Z",
		"endtime": "2024-01-01T00:01:00Z"
	}`

	var ca CollectionAttestation
	require.NoError(t, json.Unmarshal([]byte(collJSON), &ca))

	marshaled, err := json.Marshal(ca.Attestation)
	require.NoError(t, err)
	assert.JSONEq(t, inputJSON, string(marshaled))
}

// TestRawAttestationCollectionRoundtrip verifies that a Collection with mixed
// known and unknown attestor types roundtrips through JSON correctly.
func TestRawAttestationCollectionRoundtrip(t *testing.T) {
	collJSON := `{
		"name": "mixed-step",
		"attestations": [
			{
				"type": "https://aflock.ai/attestations/compat-test/v0.1",
				"attestation": {"value": "typed"},
				"starttime": "2024-01-01T00:00:00Z",
				"endtime": "2024-01-01T00:01:00Z"
			},
			{
				"type": "https://example.com/attestations/unknown/v0.1",
				"attestation": {"data": "raw-preserved"},
				"starttime": "2024-01-01T00:00:00Z",
				"endtime": "2024-01-01T00:01:00Z"
			}
		]
	}`

	var collection Collection
	err := json.Unmarshal([]byte(collJSON), &collection)
	require.NoError(t, err)
	require.Len(t, collection.Attestations, 2)

	// First: typed attestor
	_, isTyped := collection.Attestations[0].Attestation.(*compatTestAttestor)
	assert.True(t, isTyped, "known type should be typed attestor")

	// Second: raw fallback
	_, isRaw := collection.Attestations[1].Attestation.(*RawAttestation)
	assert.True(t, isRaw, "unknown type should be RawAttestation")

	// Marshal the whole collection and verify it's valid JSON
	data, err := json.Marshal(collection)
	require.NoError(t, err)
	assert.True(t, json.Valid(data))
}

// TestRawAttestationSkippedByInterfaces verifies that Collection.Subjects(),
// Materials(), etc. gracefully skip RawAttestation entries.
func TestRawAttestationSkippedByInterfaces(t *testing.T) {
	collJSON := `{
		"name": "raw-only",
		"attestations": [
			{
				"type": "https://example.com/attestations/unknown/v0.1",
				"attestation": {"data": "opaque"},
				"starttime": "2024-01-01T00:00:00Z",
				"endtime": "2024-01-01T00:01:00Z"
			}
		]
	}`

	var collection Collection
	require.NoError(t, json.Unmarshal([]byte(collJSON), &collection))

	// These should all return empty maps — not panic
	assert.Empty(t, collection.Subjects())
	assert.Empty(t, collection.Materials())
	assert.Empty(t, collection.Artifacts())
	assert.Empty(t, collection.BackRefs())
}

// TestResolveLegacyType verifies the pure-lookup function.
func TestResolveLegacyType(t *testing.T) {
	// Known legacy URI resolves
	resolved := ResolveLegacyType("https://witness.dev/attestations/git/v0.1")
	assert.Equal(t, "https://aflock.ai/attestations/git/v0.1", resolved)

	// Unknown URI passes through unchanged
	unknown := "https://example.com/unknown/v1"
	assert.Equal(t, unknown, ResolveLegacyType(unknown))

	// Current URI passes through unchanged
	current := "https://aflock.ai/attestations/git/v0.1"
	assert.Equal(t, current, ResolveLegacyType(current))
}

// TestFactoryByTypeLegacyFallback verifies that FactoryByType checks
// legacyAliases when the direct lookup fails.
func TestFactoryByTypeLegacyFallback(t *testing.T) {
	// The legacyAliases map has "https://witness.dev/attestations/environment/v0.1"
	// -> "https://aflock.ai/attestations/environment/v0.1". But without the
	// environment plugin imported, neither URI has a factory registered.
	// This should return false, not panic.
	_, found := FactoryByType("https://witness.dev/attestations/environment/v0.1")
	// No assertion on true/false here — depends on whether environment plugin is imported.
	// The key test is that it doesn't panic.
	_ = found
}
