// Copyright 2026 The Rookery Contributors
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

package commandrun

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizePath_ValidUTF8Unchanged(t *testing.T) {
	// Valid UTF-8 AND no backslash: pass through unchanged. Common case.
	cases := []string{
		"",
		"/",
		"/etc/passwd",
		"/usr/local/bin/git",
		"emoji 🚀 path",
		"unicode/ñoñó/path",
		"with spaces and tabs\t\n",
	}
	for _, c := range cases {
		assert.Equal(t, c, sanitizePath([]byte(c)),
			"valid-UTF-8 backslash-free input passes through: %q", c)
	}
}

// A path containing a literal backslash flips sanitizePath into escape
// mode (so unsanitizePath can be unambiguously the inverse). Linux paths
// with backslashes are exceedingly rare in practice, so the wire-format
// impact is essentially nil.
func TestSanitizePath_BackslashFlipsToEscapeMode(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("/foo\\bar"), "/foo\\\\bar"},
		{[]byte{'\\'}, "\\\\"},
		{[]byte{'\\', '\\'}, "\\\\\\\\"},
	}
	for _, c := range cases {
		got := sanitizePath(c.in)
		assert.Equal(t, c.want, got, "input %q", c.in)
		assert.Equal(t, c.in, unsanitizePath(got), "round-trip")
	}
}

func TestSanitizePath_InvalidBytesEscaped(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0xFF}, "\\xFF"},
		{[]byte{0xFF, 0xFE, 0xFD}, "\\xFF\\xFE\\xFD"},
		{[]byte("/etc/"), "/etc/"}, // valid → unchanged
		// Mixed: valid bytes pass, invalid escape, backslashes double
		// since the result is in the "contains escapes" regime.
		{[]byte("/etc/\xFFpasswd"), "/etc/\\xFFpasswd"},
		{[]byte("a\\b\xFFc"), "a\\\\b\\xFFc"},
		// 0xC3 starts a 2-byte sequence but 0x28 = '(' is not a valid
		// continuation, so 0xC3 alone is escaped and '(' passes through.
		{[]byte{0xC3, 0x28}, "\\xC3("},
		{[]byte{0x80}, "\\x80"}, // bare continuation byte
	}
	for _, c := range cases {
		got := sanitizePath(c.in)
		assert.Equal(t, c.want, got, "input %v", c.in)
		assert.True(t, utf8.ValidString(got),
			"output must always be valid UTF-8: %q", got)
	}
}

func TestUnsanitizePath_Inverse(t *testing.T) {
	// Round-trip every flavor of input.
	cases := [][]byte{
		[]byte(""),
		[]byte("/etc/passwd"),
		{0xFF},
		{0xFF, 0xFE, 0xFD},
		[]byte("/etc/\xFFpasswd"),
		[]byte("a\\b\xFFc"),
		[]byte("emoji 🚀 path"),
		[]byte("/path/with/back\\slash"), // valid UTF-8: unsanitize is identity
		// Long random-ish bytes
		bytes.Repeat([]byte{0xFF, 0x41, 0xFE}, 100),
	}
	for _, in := range cases {
		s := sanitizePath(in)
		back := unsanitizePath(s)
		// For valid-UTF-8 input, unsanitize is a no-op (no escapes were
		// applied). For invalid-UTF-8 input, unsanitize undoes the
		// escaping.
		if utf8.Valid(in) {
			assert.Equal(t, in, back, "valid UTF-8 round-trip: %q", in)
		} else {
			assert.Equal(t, in, back, "invalid UTF-8 round-trip: %v", in)
		}
	}
}

// pathHolder is a stand-in for any attestation struct that stores a
// sanitized path string and gets JSON-encoded. The original test used a
// ptrace-era FileLink type that the eBPF rewrite removed; the round-trip
// property under test depends only on the string field, not that type.
type pathHolder struct {
	SourcePath string
	LinkPath   string
	IsSymlink  bool
}

func TestSanitizePath_JSON_RoundTrip(t *testing.T) {
	// The motivating use case: sanitizePath output must survive
	// JSON encode → decode without further mutation.
	cases := [][]byte{
		[]byte("/normal/path"),
		{0xFF, 0xFE, 0xFD},
		[]byte("/etc/\xFFpasswd"),
		[]byte("emoji 🚀 path"),
		bytes.Repeat([]byte("a"), 100),
		bytes.Repeat([]byte{0xFF}, 50),
	}
	for _, raw := range cases {
		s := sanitizePath(raw)
		link := pathHolder{SourcePath: s, LinkPath: s, IsSymlink: false}
		b, err := json.Marshal(link)
		require.NoError(t, err)
		var back pathHolder
		require.NoError(t, json.Unmarshal(b, &back))
		assert.Equal(t, s, back.SourcePath,
			"JSON round-trip lossless for %q", raw)
		// And the raw bytes can be recovered.
		assert.Equal(t, raw, unsanitizePath(back.SourcePath),
			"unsanitize on JSON-decoded path returns original bytes")
	}
}

func TestUnsanitizePath_MalformedEscapes(t *testing.T) {
	// A path that LOOKS escaped but is malformed should pass through
	// rather than crash. The escaping function never produces these,
	// but a verifier reading external input might see them.
	cases := []struct {
		in   string
		want []byte
	}{
		{"trailing\\", []byte("trailing\\")},
		{"bad\\zhex", []byte("bad\\zhex")},
		{"bad\\xZZ", []byte("bad\\xZZ")},
		{"short\\x4", []byte("short\\x4")},
	}
	for _, c := range cases {
		got := unsanitizePath(c.in)
		assert.Equal(t, c.want, got, "malformed input %q", c.in)
	}
}

func TestSanitizePath_LongInput(t *testing.T) {
	// Stress test: ensure no quadratic blowup or off-by-one on long input.
	long := bytes.Repeat([]byte{0xFF, 0x41}, 2048)
	s := sanitizePath(long)
	require.True(t, utf8.ValidString(s))
	back := unsanitizePath(s)
	assert.Equal(t, long, back)
}

func TestSanitizePath_BackslashHeavy(t *testing.T) {
	// A path with multiple backslashes — flips into escape mode.
	in := []byte("/foo\\bar\\baz")
	s := sanitizePath(in)
	assert.Equal(t, "/foo\\\\bar\\\\baz", s, "every backslash is doubled in escape mode")
	back := unsanitizePath(s)
	assert.Equal(t, in, back, "round-trip")
}

func TestSanitizePath_Empty(t *testing.T) {
	assert.Equal(t, "", sanitizePath(nil))
	assert.Equal(t, "", sanitizePath([]byte{}))
	assert.Equal(t, []byte{}, unsanitizePath(""))
}

// TestSanitizePath_ControlBytesPassThrough — control bytes (including
// NUL) are valid UTF-8 codepoints, so sanitizePath returns them
// unchanged. Stripping NUL is readSyscallReg's job (it cuts at the
// first 0 byte BEFORE calling sanitizePath). Verify the JSON encoder
// handles control bytes without panic and round-trip is lossless.
func TestSanitizePath_ControlBytesPassThrough(t *testing.T) {
	// 0x01, 0x02, 0x7F are control codepoints — valid UTF-8 and pass
	// through. 0xFF is invalid UTF-8 and gets escaped. NUL is not in
	// this fixture because readSyscallReg strips it upstream.
	raw := []byte{0x01, 0x02, 0x7F, 0xFF}
	s := sanitizePath(raw)
	assert.True(t, utf8.ValidString(s), "output must be valid UTF-8: %q", s)
	link := pathHolder{SourcePath: s}
	b, err := json.Marshal(link)
	require.NoError(t, err)
	var back pathHolder
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, s, back.SourcePath, "JSON round-trip preserved")
	assert.Equal(t, raw, unsanitizePath(back.SourcePath),
		"unsanitize recovers raw bytes")
	assert.True(t, len(strings.TrimSpace(string(b))) > 0)
}
