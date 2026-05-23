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

//go:build linux

// Fuzz targets for the path-extraction logic in the trace attestor.
//
// The security boundary here is the conversion from "arbitrary bytes
// read out of a tracee's memory via ProcessVMReadv" to "Go string used
// as a key in maps + serialized into the attestation". An attacker
// controls every byte at that pointer — they can place NULs anywhere,
// fill MAX_PATH_LEN with non-NUL bytes, embed UTF-8 garbage, etc. We
// must never panic, never return a string the verifier will choke on,
// and never accidentally drop NULs into the JSON (which would let an
// attacker inject syntax via a clever path).
//
// Run with:
//   go test -run=Fuzz -fuzz=FuzzPathExtraction ./plugins/attestors/commandrun/

package commandrun

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// extractCString mirrors the inner logic of readSyscallReg without
// requiring a real ptraced PID. Given a byte slice that came out of
// tracee memory and a numBytes "valid up to" count, return the Go
// string the handler will use.
//
// Keep this function in sync with readSyscallReg in tracing_linux.go.
// If the production logic changes, mirror it here so the fuzz target
// keeps covering the real path.
func extractCString(data []byte, numBytes int) string {
	if numBytes <= 0 || len(data) == 0 {
		return ""
	}
	if numBytes > len(data) {
		numBytes = len(data)
	}
	// Same NUL-search the production code does.
	size := bytes.IndexByte(data, 0)
	if size < 0 {
		size = numBytes
	}
	return string(data[:size])
}

func FuzzPathExtraction(f *testing.F) {
	// Seed corpus: covers the boundary cases that motivate this fuzz
	// target. The fuzzer mutates these to find inputs that violate
	// invariants.
	seeds := []struct {
		buf      []byte
		numBytes int
	}{
		{[]byte(""), 0},
		{[]byte("\x00"), 1},
		{[]byte("/tmp/file\x00garbage"), 16},
		{[]byte("/no/null/terminator"), 19},
		{[]byte("\x00leading/null"), 14},
		{bytes.Repeat([]byte("a"), MAX_PATH_LEN), MAX_PATH_LEN},
		{bytes.Repeat([]byte{0xFF}, MAX_PATH_LEN), MAX_PATH_LEN},
		{append([]byte("/utf8/path/"), []byte{0xE2, 0x80, 0x93}...), 14}, // EN DASH
		{[]byte("\xC3\x28"), 2},                                          // invalid UTF-8 2-byte sequence
	}
	for _, s := range seeds {
		f.Add(s.buf, s.numBytes)
	}

	f.Fuzz(func(t *testing.T, buf []byte, numBytes int) {
		// Invariants the fuzz target asserts. Any violation = test fail.
		s := extractCString(buf, numBytes)

		// 1. No panic. (Implicit — if we reached here, no panic.)

		// 2. Returned string must not contain interior NULs. NULs in
		// a JSON-serialized path would let an attacker break out of
		// the string at the wire layer.
		if strings.ContainsRune(s, '\x00') {
			t.Fatalf("extractCString returned interior NUL: %q (input=%v, numBytes=%d)",
				s, buf, numBytes)
		}

		// 3. Returned string is a prefix of buf interpreted as bytes
		// (up to numBytes). The handler stores this as the path key —
		// no fancy decoding should have happened.
		if len(s) > len(buf) {
			t.Fatalf("returned string longer than input: %d vs %d", len(s), len(buf))
		}

		// 4. UTF-8 must be valid OR we explicitly accept the prefix.
		// We do NOT enforce UTF-8 validity here because Linux paths
		// are byte strings; we record what the kernel gave us. But the
		// JSON encoder will replace invalid runes with U+FFFD, so
		// document that behavior is intentional.
		_ = utf8.ValidString(s)
	})
}

// FuzzCleanString fuzzes the cleanString helper that the attestor uses
// on /proc/<pid>/comm and /proc/<pid>/cmdline. The function must:
//   - tolerate any input bytes
//   - return UTF-8-safe text (downstream JSON encode succeeds)
//   - not introduce information loss except for the documented NUL→' '
//     replacement and TrimSpace.
func FuzzCleanString(f *testing.F) {
	seeds := []string{
		"",
		"\x00",
		"normal command",
		"a\x00b\x00c", // cmdline-style
		"   leading_trailing   ",
		"\n\t\r\v",
		"emoji 🚀 path",
		"long " + strings.Repeat("x", 4096),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		out := cleanString(in)
		// 1. No NULs in output.
		if strings.ContainsRune(out, '\x00') {
			t.Fatalf("cleanString left NUL: %q", out)
		}
		// 2. Output is a subsequence of the NUL-substituted, trimmed input
		// (sanity — cleanString is just TrimSpace(Replace(s, NUL, " "))).
		expected := strings.TrimSpace(strings.ReplaceAll(in, "\x00", " "))
		if out != expected {
			t.Fatalf("cleanString invariant violated: in=%q out=%q expected=%q",
				in, out, expected)
		}
	})
}

// FuzzFilePathRoundTrip — issue #164 is fixed by sanitizePath /
// unsanitizePath. This target asserts the STRONG invariant: arbitrary
// raw kernel bytes → sanitizePath → FileLink JSON encode → decode →
// unsanitizePath → byte-for-byte equal to the original.
func FuzzFilePathRoundTrip(f *testing.F) {
	f.Add([]byte("/normal/path\x00ignored"), 12)
	f.Add([]byte{0xFF, 0xFE, 0xFD, 0x00}, 4)
	f.Add(bytes.Repeat([]byte("x"), MAX_PATH_LEN), MAX_PATH_LEN)
	f.Add([]byte("/path/with/back\\slash"), 21)
	f.Add([]byte{0xFF, '\\', 0xFE, '\\', 'x'}, 5)

	f.Fuzz(func(t *testing.T, buf []byte, numBytes int) {
		// Match the production extraction: NUL-terminate at first 0
		// byte, clamp to numBytes.
		end := numBytes
		if end < 0 {
			end = 0
		}
		if end > len(buf) {
			end = len(buf)
		}
		cut := bytes.IndexByte(buf[:end], 0)
		if cut < 0 {
			cut = end
		}
		raw := buf[:cut]

		s := sanitizePath(raw)
		if !utf8.ValidString(s) {
			t.Fatalf("sanitizePath produced invalid UTF-8: %q (raw=%v)", s, raw)
		}
		link := FileLink{SourcePath: s, LinkPath: s}
		b, err := json.Marshal(link)
		if err != nil {
			t.Fatalf("FileLink JSON encode failed: %v (raw=%v)", err, raw)
		}
		var back FileLink
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("FileLink JSON decode failed: %v (raw=%v)", err, raw)
		}
		if back.SourcePath != s {
			t.Fatalf("sanitized path mutated through JSON: in=%q out=%q",
				s, back.SourcePath)
		}
		recovered := unsanitizePath(back.SourcePath)
		if !bytes.Equal(recovered, raw) {
			t.Fatalf("round-trip lost bytes: in=%v out=%v (sanitized=%q)",
				raw, recovered, s)
		}
	})
}

// FuzzSanitizeUnsanitize — sanitize/unsanitize are mutual inverses
// for every input, independent of JSON.
func FuzzSanitizeUnsanitize(f *testing.F) {
	f.Add([]byte("/etc/passwd"))
	f.Add([]byte{0xFF, 0xFE, 0xFD})
	f.Add([]byte("a\\b\xFFc"))
	f.Add([]byte("/path/with/back\\slash"))
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte{0xFF}, 100))

	f.Fuzz(func(t *testing.T, raw []byte) {
		s := sanitizePath(raw)
		if !utf8.ValidString(s) {
			t.Fatalf("sanitizePath produced invalid UTF-8: %q (raw=%v)", s, raw)
		}
		back := unsanitizePath(s)
		if !bytes.Equal(back, raw) {
			t.Fatalf("sanitize/unsanitize not inverse: in=%v out=%v sanitized=%q",
				raw, back, s)
		}
	})
}

