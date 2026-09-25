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

package githubaction

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sha256Set(t *testing.T, b string) cryptoutil.DigestSet {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(b), []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	return ds
}

// The type names the SHAPE of the body. A v0.1 policy (the signed release
// policies require github-action/v0.1 from `cilock run --attestations
// github-action`, which never records steps) must keep matching what that path
// emits, and a body that carries steps must never be labelled v0.1.
func TestTypeFollowsShape(t *testing.T) {
	bare := New(WithActionRef("actions/checkout@v4"))
	assert.Equal(t, LegacyV01Type, bare.Type(), "no v0.2 field set: the body is a v0.1 body")

	withYAML := New(WithActionYAMLDigest(sha256Set(t, "name: x\n")))
	assert.Equal(t, Type, withYAML.Type(), "an action.yml digest is a v0.2 field")

	withSteps := New()
	withSteps.Steps = []RunStep{{Index: 0, Name: "build", Shell: "bash"}}
	assert.Equal(t, Type, withSteps.Type(), "a steps array is a v0.2 field")
}

// A v0.1-shaped body must serialise exactly as v0.1 did: no new keys, so an
// existing v0.1 consumer sees byte-for-byte the same predicate.
func TestV01ShapeCarriesNoV02Keys(t *testing.T) {
	a := New(WithActionRef("actions/checkout@v4"), WithActionType("javascript"))
	b, err := json.Marshal(a)
	require.NoError(t, err)
	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &keys))
	for _, k := range []string{"steps", "actionyamldigest"} {
		assert.NotContains(t, keys, k)
	}
}

func TestStepWireNames(t *testing.T) {
	a := New(WithActionYAMLDigest(sha256Set(t, "name: x\n")))
	a.Steps = []RunStep{
		{Index: 0, Name: "one", Shell: "bash", WorkingDirectory: "sub", Digest: sha256Set(t, "echo 1"), Script: "echo 1", ExitCode: 0},
		{Index: 1, Name: "two", Shell: "bash", Skipped: true},
	}
	b, err := json.Marshal(a)
	require.NoError(t, err)

	var body struct {
		ActionYAMLDigest map[string]string `json:"actionyamldigest"`
		Steps            []map[string]any  `json:"steps"`
	}
	require.NoError(t, json.Unmarshal(b, &body))
	require.Len(t, body.Steps, 2)
	assert.NotEmpty(t, body.ActionYAMLDigest["sha256"])

	first := body.Steps[0]
	for _, k := range []string{"index", "name", "shell", "workingDirectory", "digest", "script", "exitCode"} {
		assert.Contains(t, first, k)
	}
	assert.NotContains(t, first, "skipped")

	second := body.Steps[1]
	assert.Equal(t, true, second["skipped"])
	assert.NotContains(t, second, "script", "a skipped step handed nothing to an interpreter")
	assert.NotContains(t, second, "digest")
}

// Schema() describes the v0.2 shape in the same diff that changes it.
func TestSchemaDescribesSteps(t *testing.T) {
	s := New().Schema()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	for _, want := range []string{`"steps"`, `"actionyamldigest"`, `"workingDirectory"`, `"exitCode"`, `"skipped"`} {
		assert.Contains(t, string(b), want)
	}
}

// Both predicate URIs resolve to a decoder, and each round-trips its own body.
func TestBothVersionsDecode(t *testing.T) {
	v01 := []byte(`{"actionref":"actions/checkout@v4","actiontype":"javascript","exitcode":0,"refpinned":false}`)
	v02 := []byte(`{"actionref":"./a","actiontype":"composite","exitcode":0,` +
		`"actionyamldigest":{"sha256":"aa"},` +
		`"steps":[{"index":0,"name":"b","shell":"bash","digest":{"sha256":"bb"},"script":"echo","exitCode":0}]}`)

	for _, tc := range []struct {
		typ  string
		body []byte
	}{{LegacyV01Type, v01}, {Type, v02}} {
		factory, ok := attestation.FactoryByType(tc.typ)
		require.True(t, ok, "no decoder registered for %s", tc.typ)
		dec := factory()
		require.NoError(t, json.Unmarshal(tc.body, dec))
		assert.Equal(t, tc.typ, dec.Type(), "a decoded body reports the version its shape is")
	}

	factory, _ := attestation.FactoryByType(Type)
	dec := factory().(*Attestor)
	require.NoError(t, json.Unmarshal(v02, dec))
	require.Len(t, dec.Steps, 1)
	assert.Equal(t, "echo", dec.Steps[0].Script)
	assert.Equal(t, "bb", dec.Steps[0].Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}])
}
