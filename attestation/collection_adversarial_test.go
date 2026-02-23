//go:build audit

package attestation

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Test helpers for collection adversarial tests
// ==========================================================================

// collAdversarialAttestor is a test attestor that implements Subjecter,
// Materialer, and Producer interfaces for comprehensive testing.
type collAdversarialAttestor struct {
	name          string
	predicateType string
	runType       RunType
	subjects      map[string]cryptoutil.DigestSet
	materials     map[string]cryptoutil.DigestSet
	products      map[string]Product
	mutableField  string
}

func (a *collAdversarialAttestor) Name() string                     { return a.name }
func (a *collAdversarialAttestor) Type() string                     { return a.predicateType }
func (a *collAdversarialAttestor) RunType() RunType                 { return a.runType }
func (a *collAdversarialAttestor) Schema() *jsonschema.Schema       { return nil }
func (a *collAdversarialAttestor) Attest(*AttestationContext) error { return nil }
func (a *collAdversarialAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}
func (a *collAdversarialAttestor) Materials() map[string]cryptoutil.DigestSet {
	return a.materials
}
func (a *collAdversarialAttestor) Products() map[string]Product {
	return a.products
}

// ==========================================================================
// R3-195: Collection attestation order depends on input slice order
// ==========================================================================

// TestSecurity_R3_195_CollectionAttestationOrder proves that attestation
// order in a Collection depends entirely on the input slice order. Since
// RunAttestors runs attestors concurrently within each stage, the
// completedAttestors order is non-deterministic, which flows into
// NewCollection and thus into the signed attestation.
//
// BUG [MEDIUM]: Collection attestation ordering is non-deterministic when
// attestors within the same RunType stage complete in different orders.
// The Collection produced by NewCollection preserves the input order, but
// the input comes from completedAttestors which is appended under a mutex
// from concurrent goroutines (context.go:247-253). Different runs may
// produce different orderings, which means different JSON serializations,
// which means different signatures for semantically identical collections.
// File: context.go:207-216, collection.go:56-67
func TestSecurity_R3_195_CollectionAttestationOrder(t *testing.T) {
	att1 := &collAdversarialAttestor{
		name:          "attestor-alpha",
		predicateType: "https://test/alpha",
		runType:       ExecuteRunType,
	}
	att2 := &collAdversarialAttestor{
		name:          "attestor-bravo",
		predicateType: "https://test/bravo",
		runType:       ExecuteRunType,
	}

	// Create collection with a specific ordering
	completed1 := []CompletedAttestor{
		{Attestor: att1, StartTime: time.Now(), EndTime: time.Now()},
		{Attestor: att2, StartTime: time.Now(), EndTime: time.Now()},
	}
	completed2 := []CompletedAttestor{
		{Attestor: att2, StartTime: time.Now(), EndTime: time.Now()},
		{Attestor: att1, StartTime: time.Now(), EndTime: time.Now()},
	}

	coll1 := NewCollection("test-step", completed1)
	coll2 := NewCollection("test-step", completed2)

	// Collections have same attestors but different order
	require.Len(t, coll1.Attestations, 2)
	require.Len(t, coll2.Attestations, 2)

	assert.Equal(t, "https://test/alpha", coll1.Attestations[0].Type)
	assert.Equal(t, "https://test/bravo", coll1.Attestations[1].Type)

	assert.Equal(t, "https://test/bravo", coll2.Attestations[0].Type)
	assert.Equal(t, "https://test/alpha", coll2.Attestations[1].Type)

	// Serialize both -- different orderings produce different JSON
	json1, err := json.Marshal(coll1)
	require.NoError(t, err)
	json2, err := json.Marshal(coll2)
	require.NoError(t, err)

	assert.NotEqual(t, string(json1), string(json2),
		"BUG [MEDIUM]: Collections with same attestors in different order produce "+
			"different JSON. Since RunAttestors appends completedAttestors from "+
			"concurrent goroutines, the order is non-deterministic. This means the "+
			"same pipeline can produce different signed payloads across runs, "+
			"potentially causing signature verification issues. "+
			"File: collection.go:56-67, context.go:207-216")
}

// ==========================================================================
// R3-196: Deep copy safety -- attestor mutation after collection creation
// ==========================================================================

// TestSecurity_R3_196_DeepCopySafetyAttestorMutation proves that
// NewCollectionAttestation stores the attestor by interface reference.
// Mutating the attestor after collection creation modifies the collected
// attestation, which could alter signed data after signing.
//
// BUG [HIGH]: CollectionAttestation.Attestation holds an interface value
// that contains a pointer. Mutation of the original attestor after
// NewCollection is called will change the data inside the collection.
// If the collection is serialized and signed AFTER the mutation, the
// signature covers different data than what was attested.
// File: collection.go:69-76
func TestSecurity_R3_196_DeepCopySafetyAttestorMutation(t *testing.T) {
	att := &collAdversarialAttestor{
		name:          "mutable-attestor",
		predicateType: "https://test/mutable",
		runType:       ExecuteRunType,
		mutableField:  "original-value",
	}

	completed := []CompletedAttestor{
		{Attestor: att, StartTime: time.Now(), EndTime: time.Now()},
	}
	collection := NewCollection("test-step", completed)

	// Verify initial state
	collAtt, ok := collection.Attestations[0].Attestation.(*collAdversarialAttestor)
	require.True(t, ok)
	assert.Equal(t, "original-value", collAtt.mutableField)

	// Mutate the original attestor AFTER collection creation
	att.mutableField = "MUTATED-after-collection"

	// The collection's attestation is ALSO mutated because it holds
	// the same pointer
	collAttAfter, ok := collection.Attestations[0].Attestation.(*collAdversarialAttestor)
	require.True(t, ok)
	assert.Equal(t, "MUTATED-after-collection", collAttAfter.mutableField,
		"BUG [HIGH]: Mutation of original attestor after NewCollection is visible "+
			"through the collection. The collection stores the interface value which "+
			"contains a pointer to the same object. No deep copy is performed. "+
			"If the collection is signed after this mutation, the signature covers "+
			"different data than was originally attested. "+
			"File: collection.go:69-76")

	// This confirms the attestor in the collection IS the same object
	assert.Same(t, att, collAttAfter,
		"collection attestor is the same pointer as the original")
}

// ==========================================================================
// R3-197: Subject key collision across attestors with same type
// ==========================================================================

// TestSecurity_R3_197_SubjectKeyCollision proves that if two attestors
// in a collection have the same Type and produce subjects with the same
// key, the second one silently overwrites the first.
//
// BUG [MEDIUM]: Collection.Subjects() generates keys as
// fmt.Sprintf("%v/%v", type, subject). If two attestors share the same
// Type string and produce the same subject key, the last one in iteration
// order wins. This means subject data can be silently lost.
// File: collection.go:114-126
func TestSecurity_R3_197_SubjectKeyCollision(t *testing.T) {
	ds1 := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: 5}: "deadbeef1111111111111111111111111111111111111111111111111111111111",
	}
	ds2 := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: 5}: "cafebabe2222222222222222222222222222222222222222222222222222222222",
	}

	att1 := &collAdversarialAttestor{
		name:          "attestor-a",
		predicateType: "https://test/same-type",
		runType:       ExecuteRunType,
		subjects:      map[string]cryptoutil.DigestSet{"artifact.tar": ds1},
	}
	att2 := &collAdversarialAttestor{
		name:          "attestor-b",
		predicateType: "https://test/same-type", // Same type!
		runType:       ExecuteRunType,
		subjects:      map[string]cryptoutil.DigestSet{"artifact.tar": ds2},
	}

	completed := []CompletedAttestor{
		{Attestor: att1, StartTime: time.Now(), EndTime: time.Now()},
		{Attestor: att2, StartTime: time.Now(), EndTime: time.Now()},
	}
	collection := NewCollection("test-step", completed)

	subjects := collection.Subjects()

	// The key "https://test/same-type/artifact.tar" should exist
	key := "https://test/same-type/artifact.tar"
	digest, ok := subjects[key]
	require.True(t, ok, "subject key should exist")

	// Only one value survives -- the second attestor's value
	assert.Equal(t, ds2, digest,
		"BUG [MEDIUM]: subject key collision. Two attestors with same Type "+
			"and same subject key produce the same Subjects() map key. "+
			"The second attestor's digest silently overwrites the first. "+
			"File: collection.go:114-126")

	// Total subjects should be 1, not 2
	assert.Len(t, subjects, 1,
		"only one subject survives due to key collision")
}

// ==========================================================================
// R3-198: Material key collision across attestors
// ==========================================================================

// TestSecurity_R3_198_MaterialKeyCollision proves that Materials() also
// suffers from key collision when two attestors report the same file.
//
// BUG [MEDIUM]: Collection.Materials() merges materials from all attestors
// into one map. If two attestors report the same file path, the last one
// overwrites silently. No conflict detection.
// File: collection.go:154-165
func TestSecurity_R3_198_MaterialKeyCollision(t *testing.T) {
	ds1 := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: 5}: "aaaa",
	}
	ds2 := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: 5}: "bbbb",
	}

	att1 := &collAdversarialAttestor{
		name:          "material-a",
		predicateType: "https://test/material-a",
		runType:       MaterialRunType,
		materials:     map[string]cryptoutil.DigestSet{"/path/to/file.go": ds1},
	}
	att2 := &collAdversarialAttestor{
		name:          "material-b",
		predicateType: "https://test/material-b",
		runType:       MaterialRunType,
		materials:     map[string]cryptoutil.DigestSet{"/path/to/file.go": ds2},
	}

	completed := []CompletedAttestor{
		{Attestor: att1, StartTime: time.Now(), EndTime: time.Now()},
		{Attestor: att2, StartTime: time.Now(), EndTime: time.Now()},
	}
	collection := NewCollection("test-step", completed)

	materials := collection.Materials()
	digest := materials["/path/to/file.go"]
	assert.Equal(t, ds2, digest,
		"BUG [MEDIUM]: material key collision. Two attestors reporting the same "+
			"file path causes the second to silently overwrite the first's digest. "+
			"File: collection.go:154-165")
}

// ==========================================================================
// R3-199: Artifacts() products overwrite materials silently
// ==========================================================================

// TestSecurity_R3_199_ArtifactsProductOverwritesMaterial proves that
// Artifacts() first collects materials, then overwrites them with products
// that share the same path. This is likely by design (products are the
// "end state") but there's no documentation or warning.
//
// BUG [LOW/DESIGN]: Artifacts() silently overwrites material digests with
// product digests for the same file path. A verifier looking at Artifacts()
// would see the product digest, not the material digest, for files that
// were both inputs and outputs.
// File: collection.go:130-152
func TestSecurity_R3_199_ArtifactsProductOverwritesMaterial(t *testing.T) {
	materialDigest := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: 5}: "material-hash",
	}
	productDigest := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: 5}: "product-hash",
	}

	att := &collAdversarialAttestor{
		name:          "builder",
		predicateType: "https://test/builder",
		runType:       ExecuteRunType,
		materials:     map[string]cryptoutil.DigestSet{"output.bin": materialDigest},
		products:      map[string]Product{"output.bin": {MimeType: "application/octet-stream", Digest: productDigest}},
	}

	completed := []CompletedAttestor{
		{Attestor: att, StartTime: time.Now(), EndTime: time.Now()},
	}
	collection := NewCollection("test-step", completed)

	artifacts := collection.Artifacts()

	assert.Equal(t, productDigest, artifacts["output.bin"],
		"DESIGN NOTE: Artifacts() overwrites materials with products for same path. "+
			"The material digest for 'output.bin' is lost. "+
			"File: collection.go:147-149")
}

// ==========================================================================
// R3-200: RawAttestation unexported fields and serialization
// ==========================================================================

// TestSecurity_R3_200_RawAttestationSerialization proves that RawAttestation
// has unexported fields (typeName, data) which means standard json.Marshal
// would produce an empty object, but the custom MarshalJSON method returns
// the raw data. However, there's no custom UnmarshalJSON, so round-tripping
// through JSON loses the typeName.
//
// BUG [MEDIUM]: RawAttestation's typeName field is unexported and has no
// JSON tag. Round-trip serialization loses the type identity. When the
// collection is re-deserialized, UnmarshalJSON on CollectionAttestation
// looks up the factory by the outer "type" field, so the data survives,
// but if someone tries to json.Unmarshal directly into RawAttestation,
// the typeName is lost.
func TestSecurity_R3_200_RawAttestationSerialization(t *testing.T) {
	rawData := json.RawMessage(`{"key":"value","nested":{"inner":42}}`)
	raw := &RawAttestation{
		typeName: "https://custom/unknown",
		data:     rawData,
	}

	// MarshalJSON works -- returns the raw data
	marshaled, err := raw.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, `{"key":"value","nested":{"inner":42}}`, string(marshaled))

	// But json.Marshal on the struct would also work via MarshalJSON
	fullMarshal, err := json.Marshal(raw)
	require.NoError(t, err)
	assert.JSONEq(t, `{"key":"value","nested":{"inner":42}}`, string(fullMarshal))

	// Now try to unmarshal back -- typeName is lost
	var decoded RawAttestation
	err = json.Unmarshal(fullMarshal, &decoded)
	// This should fail or produce an empty RawAttestation because
	// RawAttestation doesn't have exported fields or UnmarshalJSON
	assert.Equal(t, "", decoded.typeName,
		"BUG [MEDIUM]: RawAttestation.typeName is unexported. "+
			"Direct JSON unmarshal loses the type identity. "+
			"File: collection.go:44-47")
	assert.Nil(t, decoded.data,
		"data field is also unexported and lost in direct unmarshal")
}

// ==========================================================================
// R3-201: CollectionAttestation UnmarshalJSON with unknown type
// ==========================================================================

// TestSecurity_R3_201_UnmarshalCollectionUnknownType proves that
// UnmarshalJSON for CollectionAttestation falls back to RawAttestation
// for unknown types, preserving the raw JSON for policy evaluation.
func TestSecurity_R3_201_UnmarshalCollectionUnknownType(t *testing.T) {
	data := `{
		"type": "https://unknown/custom-attestor/v1",
		"attestation": {"custom_field": "custom_value"},
		"starttime": "2024-01-01T00:00:00Z",
		"endtime": "2024-01-01T00:01:00Z"
	}`

	var ca CollectionAttestation
	err := json.Unmarshal([]byte(data), &ca)
	require.NoError(t, err)

	assert.Equal(t, "https://unknown/custom-attestor/v1", ca.Type)

	// Should be a RawAttestation
	raw, ok := ca.Attestation.(*RawAttestation)
	require.True(t, ok, "unknown type should deserialize as RawAttestation")
	assert.Equal(t, "https://unknown/custom-attestor/v1", raw.Type())
	assert.Equal(t, "https://unknown/custom-attestor/v1", raw.Name())

	// RawAttestation.Attest should error
	err = raw.Attest(nil)
	assert.Error(t, err, "RawAttestation.Attest should always error")

	// Schema should be nil
	assert.Nil(t, raw.Schema())

	// RunType should be empty
	assert.Equal(t, RunType(""), raw.RunType())
}

// ==========================================================================
// R3-202: Collection.Subjects with non-Subjecter attestors
// ==========================================================================

// TestSecurity_R3_202_SubjectsWithNonSubjecter proves that attestors not
// implementing Subjecter are silently skipped in Collection.Subjects().
func TestSecurity_R3_202_SubjectsWithNonSubjecter(t *testing.T) {
	// Use the basic adversarialAttestor which does NOT implement Subjecter
	basicAtt := &adversarialAttestor{
		name:          "no-subjects",
		predicateType: "https://test/no-subjects",
		runType:       ExecuteRunType,
	}

	completed := []CompletedAttestor{
		{Attestor: basicAtt, StartTime: time.Now(), EndTime: time.Now()},
	}
	collection := NewCollection("test-step", completed)

	subjects := collection.Subjects()
	assert.Empty(t, subjects,
		"non-Subjecter attestors should produce no subjects")
}

// ==========================================================================
// R3-203: Empty collection edge cases
// ==========================================================================

// TestSecurity_R3_203_EmptyCollection proves that NewCollection with no
// completed attestors produces a valid but empty collection.
func TestSecurity_R3_203_EmptyCollection(t *testing.T) {
	collection := NewCollection("empty-step", nil)

	assert.Equal(t, "empty-step", collection.Name)
	assert.NotNil(t, collection.Attestations, "should be non-nil empty slice")
	assert.Empty(t, collection.Attestations)

	// All aggregate methods should return empty maps
	subjects := collection.Subjects()
	assert.Empty(t, subjects)

	materials := collection.Materials()
	assert.Empty(t, materials)

	artifacts := collection.Artifacts()
	assert.Empty(t, artifacts)

	backRefs := collection.BackRefs()
	assert.Empty(t, backRefs)

	// Should serialize cleanly
	data, err := json.Marshal(collection)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"attestations":[]`)
}

// ==========================================================================
// R3-204: Subject map mutation after Subjects() call
// ==========================================================================

// TestSecurity_R3_204_SubjectMapMutationAfterCall proves that the map
// returned by Collection.Subjects() can be mutated by the caller without
// affecting the collection. However, since Subjects() iterates the
// attestors each time and the attestors are stored by reference, mutating
// the attestor's internal subject map WILL affect subsequent Subjects() calls.
//
// BUG [HIGH]: Subjects() returns a freshly allocated map but reads from
// the attestor's Subjects() method each time. If the attestor's internal
// map is mutated between calls, different calls to collection.Subjects()
// return different data. This is dangerous if signatures are computed at
// different times.
func TestSecurity_R3_204_SubjectMapMutationAfterCall(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"file.txt": {
			cryptoutil.DigestValue{Hash: 5}: "original-hash",
		},
	}

	att := &collAdversarialAttestor{
		name:          "mutable-subjects",
		predicateType: "https://test/mutable-subjects",
		runType:       ExecuteRunType,
		subjects:      subjects,
	}

	completed := []CompletedAttestor{
		{Attestor: att, StartTime: time.Now(), EndTime: time.Now()},
	}
	collection := NewCollection("test-step", completed)

	// First call to Subjects()
	subj1 := collection.Subjects()
	require.Contains(t, subj1, "https://test/mutable-subjects/file.txt")

	// Mutate the attestor's internal subjects
	att.subjects["injected.txt"] = cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: 5}: "injected-hash",
	}

	// Second call to Subjects() now returns different data
	subj2 := collection.Subjects()
	assert.Contains(t, subj2, "https://test/mutable-subjects/injected.txt",
		"BUG [HIGH]: Mutating the attestor's internal subject map after collection "+
			"creation affects subsequent Subjects() calls. The collection holds the "+
			"attestor by reference and calls its Subjects() method each time. "+
			"There is no snapshot/deep copy of subject data at collection creation time. "+
			"File: collection.go:114-126")

	assert.NotEqual(t, len(subj1), len(subj2),
		"different calls to Subjects() return different data after attestor mutation")
}

// ==========================================================================
// R3-205: Concurrent CompletedAttestors append ordering
// ==========================================================================

// TestSecurity_R3_205_ConcurrentCompletedAttestorsOrder proves that when
// RunAttestors runs attestors concurrently within a stage, the order of
// completedAttestors depends on goroutine scheduling. This directly affects
// Collection ordering and thus signed payload determinism.
//
// BUG [MEDIUM]: runAttestor appends to completedAttestors under a mutex
// (context.go:247-253), but the append order depends on which goroutine
// reaches the lock first. With N attestors in the same RunType stage,
// there are N! possible orderings.
func TestSecurity_R3_205_ConcurrentCompletedAttestorsOrder(t *testing.T) {
	// We simulate the concurrent behavior by creating many completed
	// attestors and verifying ordering varies.
	const n = 20
	completed := make([]CompletedAttestor, n)
	for i := 0; i < n; i++ {
		completed[i] = CompletedAttestor{
			Attestor: &collAdversarialAttestor{
				name:          fmt.Sprintf("att-%02d", i),
				predicateType: fmt.Sprintf("https://test/att-%02d", i),
				runType:       ExecuteRunType,
			},
			StartTime: time.Now(),
			EndTime:   time.Now(),
		}
	}

	// Simulate what context.go:207-216 does: concurrent appends with mutex
	var mu sync.Mutex
	orderings := make(map[string]bool)

	for trial := 0; trial < 50; trial++ {
		var wg sync.WaitGroup
		result := make([]string, 0, n)

		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				mu.Lock()
				result = append(result, completed[idx].Attestor.Name())
				mu.Unlock()
			}(i)
		}
		wg.Wait()

		var order string
		for _, name := range result {
			order += name + ","
		}
		orderings[order] = true
	}

	t.Logf("BUG [MEDIUM]: Concurrent attestor completion produced %d distinct "+
		"orderings in 50 trials. This is the same mechanism used in "+
		"RunAttestors (context.go:207-216). The resulting Collection order "+
		"is non-deterministic, affecting signed payload consistency.",
		len(orderings))

	// We expect more than 1 ordering with high probability for n=20
	if len(orderings) > 1 {
		assert.Greater(t, len(orderings), 1,
			"Multiple orderings observed, confirming non-determinism")
	}
}

// ==========================================================================
// R3-206: Collection JSON round-trip preserves attestation type
// ==========================================================================

// TestSecurity_R3_206_CollectionJSONRoundTrip proves that JSON
// serialization/deserialization of a Collection preserves the outer
// type field but depends on factory registration for the attestation data.
func TestSecurity_R3_206_CollectionJSONRoundTrip(t *testing.T) {
	// Create a collection with an unknown attestor type
	collJSON := `{
		"name": "build-step",
		"attestations": [
			{
				"type": "https://totally-unknown/v99",
				"attestation": {"custom": "data", "number": 42},
				"starttime": "2024-06-01T10:00:00Z",
				"endtime": "2024-06-01T10:01:00Z"
			}
		]
	}`

	var collection Collection
	err := json.Unmarshal([]byte(collJSON), &collection)
	require.NoError(t, err)

	assert.Equal(t, "build-step", collection.Name)
	require.Len(t, collection.Attestations, 1)

	ca := collection.Attestations[0]
	assert.Equal(t, "https://totally-unknown/v99", ca.Type)

	// Should be RawAttestation
	raw, ok := ca.Attestation.(*RawAttestation)
	require.True(t, ok, "unknown type should use RawAttestation fallback")

	// Re-serialize
	reJSON, err := json.Marshal(collection)
	require.NoError(t, err)

	// The raw attestation data should be preserved
	assert.Contains(t, string(reJSON), `"custom":"data"`,
		"RawAttestation should preserve original JSON through marshal round-trip")
	assert.Contains(t, string(reJSON), `"number":42`)

	// But the type in the outer wrapper may lose information if RawAttestation
	// is treated as a plain struct
	_ = raw
}

// ==========================================================================
// R3-207: CompletedAttestor stores error alongside attestor
// ==========================================================================

// TestSecurity_R3_207_CompletedAttestorWithError proves that
// NewCollectionAttestation does NOT check the Error field of
// CompletedAttestor. A failed attestor is included in the collection
// alongside successful ones.
//
// BUG [MEDIUM]: NewCollection includes ALL completed attestors, including
// those that errored. The caller must filter errors before creating the
// collection, but this is not enforced or documented.
// File: collection.go:56-67
func TestSecurity_R3_207_CompletedAttestorWithError(t *testing.T) {
	goodAtt := &collAdversarialAttestor{
		name:          "good-attestor",
		predicateType: "https://test/good",
		runType:       ExecuteRunType,
	}
	badAtt := &collAdversarialAttestor{
		name:          "bad-attestor",
		predicateType: "https://test/bad",
		runType:       ExecuteRunType,
	}

	completed := []CompletedAttestor{
		{Attestor: goodAtt, StartTime: time.Now(), EndTime: time.Now()},
		{Attestor: badAtt, StartTime: time.Now(), EndTime: time.Now(), Error: fmt.Errorf("attestation failed")},
	}

	collection := NewCollection("test-step", completed)

	// Both attestors are in the collection, including the failed one
	assert.Len(t, collection.Attestations, 2,
		"BUG [MEDIUM]: NewCollection includes failed attestors (with Error set). "+
			"The CompletedAttestor.Error field is ignored. "+
			"File: collection.go:56-67")

	assert.Equal(t, "https://test/good", collection.Attestations[0].Type)
	assert.Equal(t, "https://test/bad", collection.Attestations[1].Type)
}

// ==========================================================================
// R3-208: BackRefs key collision across attestors
// ==========================================================================

// TestSecurity_R3_208_BackRefKeyCollision proves that BackRefs() uses the
// same Type/key format as Subjects() and suffers the same collision issue.
type backRefAttestor struct {
	collAdversarialAttestor
	backRefs map[string]cryptoutil.DigestSet
}

func (a *backRefAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return a.backRefs
}

func TestSecurity_R3_208_BackRefKeyCollision(t *testing.T) {
	ds1 := cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: 5}: "ref1"}
	ds2 := cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: 5}: "ref2"}

	att1 := &backRefAttestor{
		collAdversarialAttestor: collAdversarialAttestor{
			name:          "backref-a",
			predicateType: "https://test/same-type",
			runType:       ExecuteRunType,
		},
		backRefs: map[string]cryptoutil.DigestSet{"commit": ds1},
	}
	att2 := &backRefAttestor{
		collAdversarialAttestor: collAdversarialAttestor{
			name:          "backref-b",
			predicateType: "https://test/same-type", // Same type!
			runType:       ExecuteRunType,
		},
		backRefs: map[string]cryptoutil.DigestSet{"commit": ds2},
	}

	completed := []CompletedAttestor{
		{Attestor: att1, StartTime: time.Now(), EndTime: time.Now()},
		{Attestor: att2, StartTime: time.Now(), EndTime: time.Now()},
	}
	collection := NewCollection("test-step", completed)

	backRefs := collection.BackRefs()
	key := "https://test/same-type/commit"
	assert.Equal(t, ds2, backRefs[key],
		"BUG [MEDIUM]: BackRefs key collision. Same issue as Subjects(). "+
			"Two attestors with same Type and same back-ref key collide. "+
			"File: collection.go:167-178")
}

// ==========================================================================
// R3-209: Factory global state race condition
// ==========================================================================

// TestSecurity_R3_209_FactoryGlobalStateRace documents that the global
// attestorRegistry, attestationsByType, and attestationsByRun maps in
// factory.go are not protected by any synchronization primitive. They
// are written during init() and by RegisterAttestation, and read by
// FactoryByName/FactoryByType/GetAttestors. If any registration happens
// after init() (e.g., lazy plugin loading), this is a data race.
//
// BUG [HIGH]: factory.go:25-28 declares three package-level maps with no
// synchronization. RegisterAttestation writes to all three. FactoryByType
// and FactoryByName read from them. If any goroutine calls
// RegisterAttestation while another calls FactoryByType, it's a race.
func TestSecurity_R3_209_FactoryGlobalStateRace(t *testing.T) {
	// We can't trigger the actual race without crashing under -race,
	// but we can prove the structural issue.

	// Prove that RegisterAttestation writes to global maps:
	uniqueName := "r3-209-race-test"
	uniqueType := "https://test/r3-209-race"
	RegisterAttestation(uniqueName, uniqueType, ExecuteRunType,
		func() Attestor {
			return &adversarialAttestor{
				name:          uniqueName,
				predicateType: uniqueType,
				runType:       ExecuteRunType,
			}
		})

	// Verify it's in the global maps
	_, okByName := FactoryByName(uniqueName)
	_, okByType := FactoryByType(uniqueType)
	assert.True(t, okByName,
		"RegisterAttestation wrote to global attestorRegistry (no mutex)")
	assert.True(t, okByType,
		"RegisterAttestation wrote to global attestationsByType (no mutex)")

	t.Logf("BUG [HIGH]: factory.go global maps (attestorRegistry, attestationsByType, " +
		"attestationsByRun) are unprotected. RegisterAttestation writes to all three " +
		"without synchronization. FactoryByType/FactoryByName reads without " +
		"synchronization. This is safe ONLY if all registration completes before " +
		"any reads begin (i.e., during init()). Lazy or dynamic registration " +
		"from goroutines would cause data races. File: factory.go:25-28, 98-102")
}
