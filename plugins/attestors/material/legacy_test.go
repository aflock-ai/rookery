// Copyright 2026 TestifySec, Inc.
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

package material

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

func TestLegacyMaterial_RoundTrip(t *testing.T) {
	predicate := map[string]cryptoutil.DigestSet{
		"go.mod": {cryptoutil.DigestValue{Hash: crypto.SHA256}: "aabb"},
		"go.sum": {cryptoutil.DigestValue{Hash: crypto.SHA256}: "ccdd"},
	}
	payload, err := json.Marshal(predicate)
	require.NoError(t, err)

	dec := newLegacyDecoder()
	require.NoError(t, dec.UnmarshalJSON(payload))

	subs := dec.Subjects()
	require.Len(t, subs, 2)
	assert.Contains(t, subs, "file:go.mod")
	assert.Contains(t, subs, "file:go.sum")
	assert.Equal(t, "aabb", subs["file:go.mod"][cryptoutil.DigestValue{Hash: crypto.SHA256}])

	require.Empty(t, dec.BackRefs(),
		"legacy material decoder must not contribute per-file BackRefs")

	out, err := dec.MarshalJSON()
	require.NoError(t, err)
	var back map[string]cryptoutil.DigestSet
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, predicate, back)
}

func TestLegacyMaterial_AttestRefuses(t *testing.T) {
	dec := newLegacyDecoder()
	err := dec.Attest(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errLegacyDecodeOnly)
}

func TestLegacyMaterial_FactoryRegistered(t *testing.T) {
	factory, ok := attestation.FactoryByType(LegacyV01Type)
	require.True(t, ok, "v0.1 material factory must be registered")

	v01 := factory()
	_, isLegacy := v01.(*LegacyDecoder)
	require.True(t, isLegacy, "v0.1 factory must return *LegacyDecoder, not the v0.3 producer")

	v03Factory, ok := attestation.FactoryByType(Type)
	require.True(t, ok)
	v03 := v03Factory()
	_, isLegacy = v03.(*LegacyDecoder)
	require.False(t, isLegacy, "v0.3 factory must return the v0.3 Attestor, not LegacyDecoder")
}

// TestLegacyMaterial_V01CapturedFixture decodes a real captured v0.1
// material predicate body. Catches any drift between what production
// wrote pre-cutover and what the decoder accepts — e.g., a future
// cryptoutil.DigestSet.UnmarshalJSON change that silently broke
// historical envelopes.
func TestLegacyMaterial_V01CapturedFixture(t *testing.T) {
	fixturePath := filepath.Join("testdata", "legacy_v01_material_predicate.json")
	body, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "v0.1 fixture must exist at %s", fixturePath)

	dec := newLegacyDecoder()
	require.NoError(t, dec.UnmarshalJSON(body),
		"captured v0.1 material predicate must decode cleanly")

	mats := dec.Materials()
	require.NotEmpty(t, mats, "fixture must contain at least one material")

	subs := dec.Subjects()
	require.NotEmpty(t, subs)
	for path, ds := range subs {
		require.NotEmpty(t, ds, "subject %q must carry a non-empty digest set", path)
	}

	// Round-trip stability.
	out, err := dec.MarshalJSON()
	require.NoError(t, err)
	var back map[string]cryptoutil.DigestSet
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, mats, back)
}

func TestLegacyMaterial_SubjectsSkipsNilDigest(t *testing.T) {
	dec := newLegacyDecoder()
	dec.materials = map[string]cryptoutil.DigestSet{
		"bad":  nil,
		"good": {cryptoutil.DigestValue{Hash: crypto.SHA256}: "ff"},
	}
	subs := dec.Subjects()
	require.Len(t, subs, 1)
	assert.NotContains(t, subs, "file:bad")
	assert.Contains(t, subs, "file:good")
}
