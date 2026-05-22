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

	// Both decoders produce the same per-file Subjects output. They differ
	// in Type() — that's what the registry uses to dispatch.
	assert.Equal(t, v01.Subjects(), v02.Subjects())
	assert.Equal(t, LegacyV01Type, v01.Type())
	assert.Equal(t, LegacyV02Type, v02.Type())
	assert.Equal(t, "product-v0.1", v01.Name())
	assert.Equal(t, "product-v0.2", v02.Name())
}

func TestLegacy_AttestRefuses(t *testing.T) {
	dec := newLegacyDecoder(LegacyV01Type)
	err := dec.Attest(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errLegacyDecodeOnly,
		"legacy decoder must refuse producer-mode invocation")
}

func TestLegacy_FactoriesRegistered(t *testing.T) {
	// Both legacy types must be findable through the attestation registry
	// so the policy verify path can instantiate them by predicate URI.
	v01Factory, ok := attestation.FactoryByType(LegacyV01Type)
	require.True(t, ok, "v0.1 product factory must be registered")

	v02Factory, ok := attestation.FactoryByType(LegacyV02Type)
	require.True(t, ok, "v0.2 product factory must be registered")

	v01 := v01Factory()
	_, isLegacy := v01.(*LegacyDecoder)
	require.True(t, isLegacy, "v0.1 factory must return *LegacyDecoder, not the v0.3 producer")

	v02 := v02Factory()
	_, isLegacy = v02.(*LegacyDecoder)
	require.True(t, isLegacy, "v0.2 factory must return *LegacyDecoder, not the v0.3 producer")

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
