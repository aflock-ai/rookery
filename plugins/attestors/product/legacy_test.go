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

	dec := newLegacyDecoder()
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

	dec := newLegacyDecoder()
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
}

func TestLegacy_AttestRefuses(t *testing.T) {
	dec := newLegacyDecoder()
	err := dec.Attest(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errLegacyDecodeOnly,
		"legacy decoder must refuse producer-mode invocation")
}

func TestLegacy_V01FactoryRegistered(t *testing.T) {
	// The v0.1 type must be findable through the attestation registry
	// so the policy verify path can instantiate it by predicate URI.
	v01Factory, ok := attestation.FactoryByType(LegacyV01Type)
	require.True(t, ok, "v0.1 product factory must be registered")

	v01 := v01Factory()
	_, isLegacy := v01.(*LegacyDecoder)
	require.True(t, isLegacy, "v0.1 factory must return *LegacyDecoder, not the v0.3 producer")

	// v0.3 factory must NOT be a LegacyDecoder.
	v03Factory, ok := attestation.FactoryByType(Type)
	require.True(t, ok)
	v03 := v03Factory()
	_, isLegacy = v03.(*LegacyDecoder)
	require.False(t, isLegacy, "v0.3 factory must return the producer Attestor, not LegacyDecoder")
}

// TestV02_UnsupportedFactoryReturnsErrorStub ensures the v0.2 predicate
// URI is registered but resolves to a stub that errors on every method,
// so operators encountering a v0.2 envelope get a clear "unsupported"
// diagnostic instead of a registry miss.
func TestV02_UnsupportedFactoryReturnsErrorStub(t *testing.T) {
	v02Factory, ok := attestation.FactoryByType(UnsupportedV02Type)
	require.True(t, ok, "v0.2 product factory must be registered as an error stub")

	stub := v02Factory()
	v02, isStub := stub.(*V02Unsupported)
	require.True(t, isStub, "v0.2 factory must return *V02Unsupported, not a decoder")

	require.Equal(t, UnsupportedV02Type, v02.Type())
	require.Equal(t, "product-v0.2", v02.Name())

	// Attest must surface the unsupported-version error.
	err := v02.Attest(nil)
	require.ErrorIs(t, err, ErrV02Unsupported)

	// UnmarshalJSON must refuse with the same error so any verify path
	// that tries to decode a v0.2 envelope sees an actionable message.
	err = v02.UnmarshalJSON([]byte(`{}`))
	require.ErrorIs(t, err, ErrV02Unsupported)

	// MarshalJSON also surfaces the error.
	_, err = v02.MarshalJSON()
	require.ErrorIs(t, err, ErrV02Unsupported)

	// Subjects / BackRefs return empty maps so a misuse can't crash a
	// downstream BFS that iterates them.
	require.Empty(t, v02.Subjects())
	require.Empty(t, v02.BackRefs())
}

func TestLegacy_SubjectsSkipsNilDigest(t *testing.T) {
	// Defense-in-depth: a malformed historical predicate with a nil Digest
	// must not panic and must not produce a nil-digest subject (which the
	// policy engine would not handle).
	dec := newLegacyDecoder()
	dec.products = map[string]attestation.Product{
		"bad/file":  {}, // Digest is nil
		"good/file": {Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "ff"}},
	}
	subs := dec.Subjects()
	require.Len(t, subs, 1)
	assert.NotContains(t, subs, "file:bad/file")
	assert.Contains(t, subs, "file:good/file")
}
