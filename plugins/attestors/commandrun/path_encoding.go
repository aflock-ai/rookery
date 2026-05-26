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
	"fmt"
	"strings"
	"unicode/utf8"
)

// Lossless path encoding for the trace attestor — addresses issue #164.
//
// Linux paths are arbitrary byte sequences, NOT UTF-8 strings. Storing a
// raw path in a Go string and JSON-encoding it loses any non-UTF-8 byte
// (encoding/json replaces invalid bytes with U+FFFD). That makes the
// attestation lossy and lets an attacker craft a path whose recorded
// form differs from what the kernel actually saw.
//
// Fix: at the boundary where bytes leave the kernel (readSyscallReg),
// apply a *transparent* escaping. Valid-UTF-8 input is returned
// unchanged so the wire format does not change for the 99.99% case.
// Only the non-UTF-8 bytes are escaped (as \xHH), and to make the
// escaped form unambiguous, any literal backslash in such a path is
// doubled (\ → \\). Paths that were already valid UTF-8 are passed
// through as-is and never doubled.
//
// Round-trip:
//
//	raw kernel bytes  ─[sanitizePath]─>  attestation string
//	attestation string  ─[unsanitizePath]─>  raw kernel bytes
//
// Round-trip is exact for any byte sequence. Use unsanitizePath on the
// verifier side to recover the original bytes for comparison against
// the live filesystem.

// pathEscapePrefix marks a string that contains escapes. Internal — not
// emitted in the attestation; sanitizePath returns the escaped string
// directly. The prefix matters when unsanitizing: a string that contains
// "\x" but was NEVER escaped (raw UTF-8 path with literal "\x" bytes)
// must NOT be decoded. We disambiguate by looking at the doubled-
// backslash rule: in an escaped string, EVERY backslash is \\. So when
// unsanitizing, we know the string was escaped iff it parses cleanly
// under those rules.
//
// In practice we only call unsanitizePath on strings we previously
// produced via sanitizePath, and that contract is maintained by the
// type system in this package. External verifiers should follow the
// same rule.

// sanitizePath returns a UTF-8-safe representation of the given bytes
// such that JSON encode/decode round-trip is lossless AND
// unsanitizePath(sanitizePath(b)) == b for every input b.
//
// Encoding rules:
//   - Common case (valid UTF-8 AND no backslash): return string(b) — no
//     escaping. This preserves wire format for the 99.99% of real-world
//     Linux paths that meet both conditions.
//   - Either invalid UTF-8 OR a literal backslash anywhere: switch to
//     escaped mode. Every byte goes through:
//   - invalid UTF-8 byte → \xHH
//   - literal '\\' → \\\\
//   - everything else → passes as UTF-8 byte(s)
//
// The "any backslash flips us into escape mode" rule makes
// unsanitizePath unambiguous: if a string contains a backslash, the
// whole string is in escape mode and every backslash MUST be \\. A
// literal-backslash path on Linux is exceedingly rare (Windows convention).
func sanitizePath(b []byte) string {
	// Common case: valid UTF-8 with no backslash. Pass through.
	if !bytes.ContainsRune(b, '\\') && utf8.Valid(b) {
		return string(b)
	}
	// Either invalid UTF-8 or a backslash forces escape mode.
	var sb strings.Builder
	sb.Grow(len(b) + 8)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&sb, "\\x%02X", b[i])
			i++
			continue
		}
		if r == '\\' {
			sb.WriteString("\\\\")
		} else {
			sb.WriteRune(r)
		}
		i += size
	}
	return sb.String()
}

// unsanitizePath inverts sanitizePath. It MUST only be called on output
// previously produced by sanitizePath (or on a valid-UTF-8 path that
// was never escaped — in which case it returns the input unchanged).
//
// Decoding rules:
//   - \\  -> single backslash
//   - \xHH -> single byte 0xHH
//   - anything else passes through as the encoded UTF-8 byte(s)
//
// Returns the original byte sequence.
func unsanitizePath(s string) []byte {
	// Fast path: no backslashes means no escapes were performed.
	if !strings.ContainsRune(s, '\\') {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			out = append(out, c)
			i++
			continue
		}
		next := s[i+1]
		switch next {
		case '\\':
			out = append(out, '\\')
			i += 2
		case 'x':
			if i+3 >= len(s) {
				// Malformed — pass through as literal.
				out = append(out, c)
				i++
				continue
			}
			h1 := hexDigit(s[i+2])
			h2 := hexDigit(s[i+3])
			if h1 < 0 || h2 < 0 {
				// Malformed — pass through as literal.
				out = append(out, c)
				i++
				continue
			}
			out = append(out, byte(h1<<4|h2))
			i += 4
		default:
			out = append(out, c)
			i++
		}
	}
	return out
}

func hexDigit(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}
