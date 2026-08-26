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

package alpsevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestConfigSnapshotBindsDigestToParsedBytes pins the single-read invariant.
//
// The prior shape read values and digest through separate opens of the same
// path (and each TOML key through its own open), so a file replaced between
// operations paired one version's values with another version's digest in
// signed evidence — demonstrated red against that shape with a seam that
// swapped the file between the value read and the digest read. The snapshot
// closes it by construction: the file is REPLACED and then DELETED after the
// load here, and both the values and the digest must still describe the
// original bytes, proving no operation ever touches the path again.
func TestConfigSnapshotBindsDigestToParsedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	v1 := "model = \"v1-model\"\nsandbox_mode = \"read-only\"\n"
	writeFile(t, path, v1)

	snap, _ := loadConfigSnapshot(path)
	require.NotNil(t, snap)

	// Swap the file for a different version, then remove it entirely. If any
	// later operation re-read the path, values or digest would change (or
	// vanish).
	writeFile(t, path, "model = \"v2-model\"\nsandbox_mode = \"danger-full-access\"\n")
	require.NoError(t, os.Remove(path))

	model, ok := snap.tomlString("", "model")
	require.True(t, ok)
	assert.Equal(t, "v1-model", model)

	sandbox, ok := snap.tomlString("", "sandbox_mode")
	require.True(t, ok)
	assert.Equal(t, "read-only", sandbox)

	src := snap.describe("user", "model", "sandbox_mode")
	require.NotNil(t, src)
	assert.Equal(t, sha256hex([]byte(v1)), src.SHA256,
		"the digest must be of exactly the bytes the values were parsed from")
}

// TestConfigSnapshotRefusesOversizeContent covers the bound at the snapshot
// layer: past configDigestLimit there is no digest AND no values, never one
// without the other.
func TestConfigSnapshotRefusesOversizeContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := make([]byte, configDigestLimit+1)
	copy(body, []byte("model = \"oversize\"\n"))
	require.NoError(t, os.WriteFile(path, body, 0o600))

	snap, _ := loadConfigSnapshot(path)
	require.NotNil(t, snap, "an oversize file is still present, so presence is still evidence")

	_, ok := snap.tomlString("", "model")
	assert.False(t, ok, "no value may be parsed from content that was not digested")
	_, ok = snap.jsonString("model")
	assert.False(t, ok)

	src := snap.describe("user")
	require.NotNil(t, src)
	assert.Empty(t, src.SHA256)
}

// TestConfigSnapshotRequiresARegularFile keeps the old describeConfig
// contract: directories, sockets, and absent paths are "no evidence".
func TestConfigSnapshotRequiresARegularFile(t *testing.T) {
	dir := t.TempDir()
	snap, denied := loadConfigSnapshot(dir)
	assert.Nil(t, snap, "a directory is not a config file")
	assert.True(t, denied, "a present non-regular tier must not masquerade as absence")
	snap, denied = loadConfigSnapshot(filepath.Join(dir, "absent.toml"))
	assert.Nil(t, snap)
	assert.False(t, denied, "an absent path is absence, not denial")
}

// TestTOMLStringDecodesEscapes is the regression for Codex round 2 on PR
// #8209: the old quote-matching scanner truncated `a\"b` at the escaped quote
// and recorded \u escapes literally, so a syntactically valid config could put
// a wrong value into signed evidence. Every escape TOML defines for basic
// strings must decode to its real value, and literal (single-quoted) strings
// must stay escape-free, in the top-level table and under a section alike.
func TestTOMLStringDecodesEscapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, path, `
model = "a\"b"
tab = "col1\tcol2"
accent = "café"
astral = "\U0001F680 launch"
literal = 'raw\no-escapes'

[profiles.work]
model = "pro\"file"
`)
	snap, _ := loadConfigSnapshot(path)
	require.NotNil(t, snap)

	for _, tc := range []struct {
		key  string
		want string
	}{
		{"model", `a"b`},
		{"tab", "col1\tcol2"},
		{"accent", "café"},
		{"astral", "\U0001F680 launch"},
		{"literal", `raw\no-escapes`},
	} {
		v, ok := snap.tomlString("", tc.key)
		require.Truef(t, ok, "key %s", tc.key)
		assert.Equalf(t, tc.want, v, "key %s", tc.key)
	}

	v, ok := snap.tomlString("profiles.work", "model")
	require.True(t, ok)
	assert.Equal(t, `pro"file`, v)
}

// TestTOMLStringRefusesUndecodableContent: an escape TOML does not define
// (here \x, invalid in TOML 1.0) must be refused, never recorded mangled or
// truncated — and refusal is file-wide, the same answer the agent's own TOML
// parser would give: a file it cannot parse configures nothing.
func TestTOMLStringRefusesUndecodableContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, path, "model = \"bad\\x41escape\"\nsandbox_mode = \"read-only\"\n")
	snap, _ := loadConfigSnapshot(path)
	require.NotNil(t, snap, "the file exists; its presence is still evidence")

	_, ok := snap.tomlString("", "model")
	assert.False(t, ok, "an undecodable string must be refused, not mangled")
	_, ok = snap.tomlString("", "sandbox_mode")
	assert.False(t, ok, "a file the parser refuses yields no values at all")
}

// TestJSONNullIsNotAParseableSettingsObject pins the shape check against Go's
// null-into-map decoding quirk: json.Unmarshal("null", &map) returns NO error
// and leaves the map nil, so a settings file containing the JSON document
// `null` read as "parseable object that sets nothing" and let a
// lower-precedence file answer for it. Every other non-object document — an
// array, a bare string, a number — already fails the map decode and blocks;
// null is the same class and must block the same way.
func TestJSONNullIsNotAParseableSettingsObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeFile(t, path, "null")

	snap, denied := loadConfigSnapshot(path)
	require.NotNil(t, snap)
	require.False(t, denied)

	assert.False(t, snap.jsonObjectParseable(),
		"a JSON null is not an object; what such a file sets is unknown and must block lower-precedence resolution")
	_, found := snap.jsonString("model")
	assert.False(t, found)
}
