// Copyright 2026 The Aflock Authors
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

package product

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacy_RoundTrip(t *testing.T) {
	// Historical predicate body: a map of path → Product.
	predicate := map[string]attestation.Product{
		"dist/binary": {
			Digest:   cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "deadbeef"},
			MimeType: "application/octet-stream",
		},
		"LICENSE": {
			Digest:   cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "cafebabe"},
			MimeType: "text/plain",
		},
	}
	payload, err := json.Marshal(predicate)
	require.NoError(t, err)

	dec := newLegacyDecoder(LegacyV01Type)
	require.NoError(t, dec.UnmarshalJSON(payload))

	// Subjects emit per-file entries with the file:<path> name convention.
	subs := dec.Subjects()
	require.Len(t, subs, 2)
	assert.Contains(t, subs, "file:dist/binary")
	assert.Contains(t, subs, "file:LICENSE")
	assert.Equal(t, "deadbeef", subs["file:dist/binary"][cryptoutil.DigestValue{Hash: crypto.SHA256}])

	// BackRefs is empty by design — explosion prevention.
	require.Empty(t, dec.BackRefs(),
		"legacy product decoder must not contribute per-file BackRefs (explosion risk)")

	// Re-marshal produces the same byte set.
	out, err := dec.MarshalJSON()
	require.NoError(t, err)

	var back map[string]attestation.Product
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, predicate, back)
}

// TestLegacy_V01AndV02SharePredicateShape proves the design assertion:
// v0.1 and v0.2 predicates share the same byte shape (a flat per-file
// map). Both URIs MUST decode identically through the same LegacyDecoder.
func TestLegacy_V01AndV02SharePredicateShape(t *testing.T) {
	predicate := map[string]attestation.Product{
		"a.go": {Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "aa"}},
	}
	payload, err := json.Marshal(predicate)
	require.NoError(t, err)

	v01 := newLegacyDecoder(LegacyV01Type)
	require.NoError(t, v01.UnmarshalJSON(payload))

	v02 := newLegacyDecoder(LegacyV02Type)
	require.NoError(t, v02.UnmarshalJSON(payload))

	assert.Equal(t, v01.Subjects(), v02.Subjects(),
		"v0.1 and v0.2 must yield identical Subjects from the same predicate body")
	assert.Equal(t, LegacyV01Type, v01.Type())
	assert.Equal(t, LegacyV02Type, v02.Type())
	assert.Equal(t, "product-v0.1", v01.Name())
	assert.Equal(t, "product-v0.2", v02.Name())
}

// TestLegacy_V01CapturedFixture decodes a real captured-from-Archivista
// v0.1 product predicate body. The fixture is the byte-exact predicate
// payload an old `cilock run` emitted before the v0.3 cutover, so this
// test catches any drift between what production wrote and what the
// decoder accepts (e.g., a future DigestSet.MarshalJSON change that
// silently broke pre-cutover envelopes).
func TestLegacy_V01CapturedFixture(t *testing.T) {
	fixturePath := filepath.Join("testdata", "legacy_v01_product_predicate.json")
	body, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "v0.1 fixture must exist at %s", fixturePath)

	dec := newLegacyDecoder(LegacyV01Type)
	require.NoError(t, dec.UnmarshalJSON(body),
		"captured v0.1 predicate must decode cleanly — drift in DigestSet.MarshalJSON would surface here")

	prods := dec.Products()
	require.NotEmpty(t, prods, "fixture must contain at least one product")

	subs := dec.Subjects()
	require.NotEmpty(t, subs, "Subjects must populate from a decoded fixture")
	for path, ds := range subs {
		require.NotEmpty(t, ds, "subject %q must carry a non-empty digest set", path)
	}

	// Round-trip through MarshalJSON and confirm the predicate is
	// byte-stable under the modern serializer (modulo map ordering).
	out, err := dec.MarshalJSON()
	require.NoError(t, err)
	var back map[string]attestation.Product
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, prods, back,
		"re-marshalled v0.1 fixture must round-trip to the same in-memory shape")

	// The same fixture must decode through the v0.2 factory too — the
	// predicate body is identical between v0.1 and v0.2.
	v02 := newLegacyDecoder(LegacyV02Type)
	require.NoError(t, v02.UnmarshalJSON(body),
		"v0.2 decoder must accept a v0.1-shape fixture (the two share predicate body)")
	assert.Equal(t, prods, v02.Products())
}

func TestLegacy_AttestRefuses(t *testing.T) {
	dec := newLegacyDecoder(LegacyV01Type)
	err := dec.Attest(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errLegacyDecodeOnly,
		"legacy decoder must refuse producer-mode invocation")
}

func TestLegacy_FactoriesRegistered(t *testing.T) {
	// Both v0.1 and v0.2 types must be findable through the registry, and
	// each must return a *LegacyDecoder typed with its own predicate URI.
	v01Factory, ok := attestation.FactoryByType(LegacyV01Type)
	require.True(t, ok, "v0.1 product factory must be registered")
	v01, isLegacy := v01Factory().(*LegacyDecoder)
	require.True(t, isLegacy, "v0.1 factory must return *LegacyDecoder, not the v0.3 producer")
	require.Equal(t, LegacyV01Type, v01.Type())

	v02Factory, ok := attestation.FactoryByType(LegacyV02Type)
	require.True(t, ok, "v0.2 product factory must be registered")
	v02, isLegacy := v02Factory().(*LegacyDecoder)
	require.True(t, isLegacy, "v0.2 factory must return *LegacyDecoder")
	require.Equal(t, LegacyV02Type, v02.Type())

	// v0.3 factory must NOT be a LegacyDecoder.
	v03Factory, ok := attestation.FactoryByType(Type)
	require.True(t, ok)
	v03 := v03Factory()
	_, isLegacy = v03.(*LegacyDecoder)
	require.False(t, isLegacy, "v0.3 factory must return the producer Attestor, not LegacyDecoder")
}

func TestLegacy_SubjectsSkipsNilDigest(t *testing.T) {
	// Defense-in-depth: a malformed historical predicate with a nil Digest
	// must not panic and must not produce a nil-digest subject (which the
	// policy engine would not handle).
	dec := newLegacyDecoder(LegacyV01Type)
	dec.products = map[string]attestation.Product{
		"bad/file":  {}, // Digest is nil
		"good/file": {Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "ff"}},
	}
	subs := dec.Subjects()
	require.Len(t, subs, 1)
	assert.NotContains(t, subs, "file:bad/file")
	assert.Contains(t, subs, "file:good/file")
}
