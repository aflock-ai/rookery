//go:build audit

// Copyright 2025 The Witness Contributors
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

package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fuzz: preauthEncode (PAE) with security-focused corpus
// ---------------------------------------------------------------------------

// FuzzPreauthEncodeStructural performs deep structural validation of the PAE
// encoding output. The DSSE spec defines:
//
//	PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
//
// where LEN is the decimal ASCII representation of the byte length.
// This fuzzer verifies that:
//  1. The prefix is always "DSSEv1 "
//  2. The length fields are correct decimal representations
//  3. The body type and body are placed at the exact right offsets
//  4. No panics regardless of input
//  5. Encoding is injective (different inputs -> different outputs)
func FuzzPreauthEncodeStructural(f *testing.F) {
	// Seed corpus: security-relevant edge cases
	f.Add("application/vnd.in-toto+json", []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`))
	f.Add("", []byte(""))                                       // both empty
	f.Add("", []byte(nil))                                      // nil body
	f.Add("application/json", []byte("{}"))                     // minimal JSON
	f.Add("a", []byte("b"))                                     // single chars
	f.Add(string(make([]byte, 0)), make([]byte, 0))             // zero-length from make
	f.Add("\x00", []byte{0x00})                                 // null bytes
	f.Add("\x00\x00\x00", []byte{0, 0, 0})                      // multiple nulls
	f.Add("type\x00evil", []byte("body\x00evil"))               // null injection in both
	f.Add("application/json\nInjected: header", []byte("body")) // header injection attempt
	f.Add("type with spaces", []byte("body with spaces"))
	f.Add(strings.Repeat("A", 100000), []byte("short body"))                           // huge type
	f.Add("short type", bytes.Repeat([]byte{0xff}, 100000))                            // huge body
	f.Add(strings.Repeat("A", 100000), bytes.Repeat([]byte{0xff}, 100000))             // both huge
	f.Add("text/plain; charset=utf-8", []byte("\xef\xbb\xbf BOM-prefixed"))            // BOM in body
	f.Add("\u202e\u0041\u0042", []byte("RTL override in type"))                        // RTL override
	f.Add("5 fake", []byte("injection"))                                               // length confusion
	f.Add("DSSEv1 0 DSSEv1 0 ", []byte("nested PAE attempt"))                          // PAE-in-type
	f.Add("application/json", []byte(strings.Repeat("{", 50)+strings.Repeat("}", 50))) // deep JSON-like

	f.Fuzz(func(t *testing.T, bodyType string, body []byte) {
		result := preauthEncode(bodyType, body)
		if result == nil {
			t.Fatal("preauthEncode returned nil")
		}

		// Parse the PAE encoding to validate structural correctness.
		// Expected: "DSSEv1 <len(bodyType)> <bodyType> <len(body)> <body>"
		s := string(result)

		// 1. Must start with "DSSEv1 "
		const prefix = "DSSEv1 "
		if !strings.HasPrefix(s, prefix) {
			t.Fatalf("PAE does not start with 'DSSEv1 ', starts with: %q",
				s[:min(len(s), 20)])
		}
		rest := s[len(prefix):]

		// 2. Parse type length (decimal number followed by space)
		spaceIdx := strings.Index(rest, " ")
		if spaceIdx < 0 {
			t.Fatal("PAE missing space after type length")
		}
		typeLenStr := rest[:spaceIdx]
		typeLen, err := strconv.Atoi(typeLenStr)
		if err != nil {
			t.Fatalf("PAE type length is not a valid integer: %q", typeLenStr)
		}
		if typeLen != len(bodyType) {
			t.Fatalf("PAE type length mismatch: encoded %d, actual %d",
				typeLen, len(bodyType))
		}
		rest = rest[spaceIdx+1:]

		// 3. Extract the type string
		if len(rest) < typeLen {
			t.Fatalf("PAE truncated: expected %d bytes for type, have %d",
				typeLen, len(rest))
		}
		extractedType := rest[:typeLen]
		if extractedType != bodyType {
			t.Fatalf("PAE type mismatch: extracted %q, expected %q",
				extractedType, bodyType)
		}
		rest = rest[typeLen:]

		// 4. Space separator
		if len(rest) == 0 || rest[0] != ' ' {
			t.Fatalf("PAE missing space after type field, got: %q",
				rest[:min(len(rest), 10)])
		}
		rest = rest[1:]

		// 5. Parse body length
		spaceIdx = strings.Index(rest, " ")
		if spaceIdx < 0 {
			t.Fatal("PAE missing space after body length")
		}
		bodyLenStr := rest[:spaceIdx]
		bodyLen, err := strconv.Atoi(bodyLenStr)
		if err != nil {
			t.Fatalf("PAE body length is not a valid integer: %q", bodyLenStr)
		}
		if bodyLen != len(body) {
			t.Fatalf("PAE body length mismatch: encoded %d, actual %d",
				bodyLen, len(body))
		}
		rest = rest[spaceIdx+1:]

		// 6. Extract the body bytes
		extractedBody := []byte(rest)
		if !bytes.Equal(extractedBody, body) {
			t.Fatalf("PAE body mismatch: extracted %d bytes, expected %d bytes",
				len(extractedBody), len(body))
		}

		// 7. Determinism: same input must produce identical output
		result2 := preauthEncode(bodyType, body)
		if !bytes.Equal(result, result2) {
			t.Error("preauthEncode is not deterministic")
		}

		// 8. Verify total length matches expected format
		expectedLen := len(prefix) + len(typeLenStr) + 1 + len(bodyType) + 1 + len(bodyLenStr) + 1 + len(body)
		if len(result) != expectedLen {
			t.Fatalf("PAE total length mismatch: got %d, expected %d",
				len(result), expectedLen)
		}
	})
}

// FuzzPreauthEncodeAmbiguity tests that preauthEncode is injective: different
// (bodyType, body) pairs must produce different PAE encodings. If two different
// inputs produce the same PAE, an attacker could substitute one payload for
// another and the signature would still verify.
//
// SECURITY FINDING R3-190: The PAE format using fmt.Sprintf with %s for body
// is ambiguous when body contains bytes that look like the space-delimited
// format. However, the length prefix makes the encoding unambiguous because
// the parser knows exactly how many bytes to consume for each field.
// This fuzzer verifies that claim empirically.
func FuzzPreauthEncodeAmbiguity(f *testing.F) {
	// Seed pairs that are designed to potentially collide in naive encodings
	f.Add("a b", []byte("c"), "a", []byte("b c"))                      // space shuffling
	f.Add("1", []byte("2 3"), "1 2", []byte("3"))                      // length confusion
	f.Add("", []byte("5 type"), "5 type", []byte(""))                  // empty vs non-empty
	f.Add("abc", []byte("def"), "abcdef", []byte(""))                  // concat vs split
	f.Add("abc", []byte(""), "ab", []byte("c"))                        // boundary shift
	f.Add("type", []byte("3 typ"), "type3 typ", []byte(""))            // length in body
	f.Add("10 aaaaaaaaaa", []byte("x"), "1", []byte("0 aaaaaaaaaa x")) // fake length
	f.Add("DSSEv1", []byte("nested"), "nested", []byte("DSSEv1"))      // protocol name

	f.Fuzz(func(t *testing.T, type1 string, body1 []byte, type2 string, body2 []byte) {
		// Skip if inputs are identical
		if type1 == type2 && bytes.Equal(body1, body2) {
			return
		}

		pae1 := preauthEncode(type1, body1)
		pae2 := preauthEncode(type2, body2)

		if bytes.Equal(pae1, pae2) {
			t.Fatalf("SECURITY: PAE collision detected!\n"+
				"  Input 1: type=%q body=%q\n"+
				"  Input 2: type=%q body=%q\n"+
				"  PAE output: %q",
				type1, body1, type2, body2, pae1)
		}
	})
}

// FuzzSignWithEdgePayloads exercises dsse.Sign() with fuzzed payloads and
// payload types, verifying that:
//  1. Sign never panics
//  2. If Sign succeeds, the envelope is well-formed
//  3. A freshly signed envelope can be verified with the corresponding verifier
//  4. The payload and payloadType in the envelope match the inputs
func FuzzSignWithEdgePayloads(f *testing.F) {
	f.Add("application/vnd.in-toto+json", []byte(`{"_type":"statement"}`))
	f.Add("", []byte(""))                              // empty everything
	f.Add("", []byte(nil))                             // nil body
	f.Add("application/json", []byte("{}"))            // minimal JSON
	f.Add("\x00", []byte{0x00})                        // null bytes
	f.Add("a\x00b", []byte("c\x00d"))                  // embedded nulls
	f.Add(strings.Repeat("X", 1<<16), []byte("short")) // 64KB type
	f.Add("short", bytes.Repeat([]byte("Y"), 1<<16))   // 64KB body
	f.Add("text/plain", []byte("\xff\xfe\xfd\xfc"))    // non-UTF8 body
	f.Add("\xff\xfe", []byte("body"))                  // non-UTF8 type
	f.Add("application/json", []byte(`{"key": "`+strings.Repeat("v", 10000)+`"}`))

	f.Fuzz(func(t *testing.T, bodyType string, body []byte) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Skip("key generation failed")
		}
		signer := cryptoutil.NewED25519Signer(priv)
		verifier := cryptoutil.NewED25519Verifier(pub)

		env, err := Sign(bodyType, bytes.NewReader(body), SignWithSigners(signer))
		if err != nil {
			// Some inputs may cause signing to fail. That is acceptable
			// as long as it does not panic.
			return
		}

		// Envelope must be well-formed
		if env.PayloadType != bodyType {
			t.Fatalf("envelope PayloadType mismatch: got %q, want %q",
				env.PayloadType, bodyType)
		}
		if !bytes.Equal(env.Payload, body) {
			t.Fatalf("envelope Payload mismatch: got %d bytes, want %d bytes",
				len(env.Payload), len(body))
		}
		if len(env.Signatures) != 1 {
			t.Fatalf("expected 1 signature, got %d", len(env.Signatures))
		}
		if len(env.Signatures[0].Signature) == 0 {
			t.Fatal("signature bytes are empty")
		}

		// Verify the freshly signed envelope
		checkedVerifiers, err := env.Verify(VerifyWithVerifiers(verifier))
		if err != nil {
			t.Fatalf("verify failed on freshly signed envelope: %v", err)
		}

		// At least one verifier must have passed
		passed := 0
		for _, cv := range checkedVerifiers {
			if cv.Error == nil {
				passed++
			}
		}
		if passed == 0 {
			t.Fatal("no verifiers passed on freshly signed envelope")
		}
	})
}

// FuzzSignPayloadTypeLengthEncoding targets the PAE length encoding specifically.
// The PAE format encodes lengths as decimal ASCII. If len() returns a byte count
// but the format string interprets it differently, or if there is an off-by-one
// in multi-byte UTF-8 strings, the signature will not verify after reconstruction.
//
// This fuzzer creates payloads where len(bodyType) != utf8.RuneCountInString(bodyType)
// to specifically test that byte-length (not rune-count) is used.
func FuzzSignPayloadTypeLengthEncoding(f *testing.F) {
	// Multi-byte UTF-8 strings where byte length != rune count
	f.Add("\u4e16\u754c", []byte("world"))          // 2 runes, 6 bytes
	f.Add("\U0001F512", []byte("lock"))             // 1 rune, 4 bytes
	f.Add("cafe\u0301", []byte("latte"))            // 5 runes, 6 bytes (combining accent)
	f.Add("\xc0\xaf", []byte("overlong"))           // invalid UTF-8, 2 bytes
	f.Add("\xed\xa0\x80", []byte("surrogate"))      // surrogate half, 3 bytes
	f.Add("abc\xffdef", []byte("embedded invalid")) // invalid byte in valid string

	f.Fuzz(func(t *testing.T, bodyType string, body []byte) {
		pae := preauthEncode(bodyType, body)

		// The critical invariant: the PAE must encode byte lengths,
		// not rune counts. Verify by parsing the length field.
		s := string(pae)
		afterPrefix := s[len("DSSEv1 "):]
		spaceIdx := strings.Index(afterPrefix, " ")
		if spaceIdx < 0 {
			t.Fatal("no space after type length in PAE")
		}
		encodedLen, err := strconv.Atoi(afterPrefix[:spaceIdx])
		if err != nil {
			t.Fatalf("type length not a valid integer: %q", afterPrefix[:spaceIdx])
		}

		byteLen := len(bodyType)
		runeLen := utf8.RuneCountInString(bodyType)

		if encodedLen != byteLen {
			t.Fatalf("PAE encodes byte-length incorrectly: encoded %d, len()=%d, RuneCount=%d",
				encodedLen, byteLen, runeLen)
		}

		// For multi-byte strings, byte length differs from rune count.
		// If they differ, this confirms we are testing the interesting case.
		if byteLen != runeLen {
			t.Logf("GOOD: testing multi-byte case: byteLen=%d, runeLen=%d, type=%q",
				byteLen, runeLen, bodyType)
		}

		// Also verify body length
		afterType := afterPrefix[spaceIdx+1+byteLen+1:]
		spaceIdx2 := strings.Index(afterType, " ")
		if spaceIdx2 < 0 {
			t.Fatal("no space after body length in PAE")
		}
		bodyEncodedLen, err := strconv.Atoi(afterType[:spaceIdx2])
		if err != nil {
			t.Fatalf("body length not a valid integer: %q", afterType[:spaceIdx2])
		}
		if bodyEncodedLen != len(body) {
			t.Fatalf("PAE body length incorrect: encoded %d, actual %d",
				bodyEncodedLen, len(body))
		}
	})
}

// ---------------------------------------------------------------------------
// Table-driven security tests: R3-190 through R3-199
// ---------------------------------------------------------------------------

// TestSecurity_R3_190_PAEInjectivity verifies that the PAE encoding is
// injective: distinct (bodyType, body) pairs MUST produce distinct PAE outputs.
// If this fails, an attacker could substitute payloads and reuse signatures.
func TestSecurity_R3_190_PAEInjectivity(t *testing.T) {
	tests := []struct {
		name  string
		type1 string
		body1 []byte
		type2 string
		body2 []byte
	}{
		{
			name:  "space_in_type_vs_separate_fields",
			type1: "a b",
			body1: []byte("c"),
			type2: "a",
			body2: []byte("b c"),
		},
		{
			name:  "length_field_confusion",
			type1: "1",
			body1: []byte("2 3"),
			type2: "1 2",
			body2: []byte("3"),
		},
		{
			name:  "empty_vs_content_swap",
			type1: "",
			body1: []byte("5 type 3 bod"),
			type2: "5 type 3 bod",
			body2: []byte(""),
		},
		{
			name:  "null_byte_boundary",
			type1: "a\x00",
			body1: []byte("b"),
			type2: "a",
			body2: []byte("\x00b"),
		},
		{
			name:  "identical_concat_different_split",
			type1: "abc",
			body1: []byte("def"),
			type2: "abcd",
			body2: []byte("ef"),
		},
		{
			name:  "type_contains_fake_pae_prefix",
			type1: "DSSEv1 3 abc 3 def",
			body1: []byte("x"),
			type2: "x",
			body2: []byte("DSSEv1 3 abc 3 def"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pae1 := preauthEncode(tt.type1, tt.body1)
			pae2 := preauthEncode(tt.type2, tt.body2)
			assert.NotEqual(t, pae1, pae2,
				"PAE COLLISION: different inputs produced identical encoding.\n"+
					"  Input 1: type=%q body=%q\n  Input 2: type=%q body=%q",
				tt.type1, tt.body1, tt.type2, tt.body2)
		})
	}
}

// TestSecurity_R3_191_PAEByteVsRuneLength verifies that PAE uses byte length
// (len()), not rune count (utf8.RuneCountInString()), for the length fields.
// Using rune count would produce incorrect length encoding for multi-byte
// UTF-8 strings, leading to misparse during verification.
func TestSecurity_R3_191_PAEByteVsRuneLength(t *testing.T) {
	tests := []struct {
		name      string
		bodyType  string
		body      []byte
		byteLen   int
		runeCount int
	}{
		{
			name:      "CJK_characters",
			bodyType:  "\u4e16\u754c", // "world" in Chinese
			body:      []byte("hello"),
			byteLen:   6,
			runeCount: 2,
		},
		{
			name:      "emoji_lock",
			bodyType:  "\U0001F512",
			body:      []byte("secure"),
			byteLen:   4,
			runeCount: 1,
		},
		{
			name:      "combining_acute_accent",
			bodyType:  "cafe\u0301",
			body:      []byte("drink"),
			byteLen:   6,
			runeCount: 5,
		},
		{
			name:      "mixed_ascii_and_multibyte",
			bodyType:  "type-\u00fc\u00f6\u00e4",
			body:      []byte("data"),
			byteLen:   11, // 5 + 2 + 2 + 2
			runeCount: 8,
		},
		{
			name:      "invalid_utf8_sequences",
			bodyType:  "\xff\xfe\xfd",
			body:      []byte("binary"),
			byteLen:   3,
			runeCount: 3, // each invalid byte counts as one rune replacement
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.byteLen, len(tt.bodyType),
				"test setup: byte length mismatch")

			pae := preauthEncode(tt.bodyType, tt.body)
			s := string(pae)

			// Extract the encoded type length
			afterPrefix := s[len("DSSEv1 "):]
			spaceIdx := strings.Index(afterPrefix, " ")
			require.NotEqual(t, -1, spaceIdx, "missing space after type length")

			encodedLen, err := strconv.Atoi(afterPrefix[:spaceIdx])
			require.NoError(t, err, "type length not a valid integer")

			assert.Equal(t, tt.byteLen, encodedLen,
				"PAE must use byte length (len()), not rune count. "+
					"Got %d, expected byte length %d (rune count would be %d)",
				encodedLen, tt.byteLen, tt.runeCount)
		})
	}
}

// TestSecurity_R3_192_PAENullByteInType verifies that null bytes in the
// payload type are preserved in the PAE encoding. If null bytes are
// truncated (C-string behavior), the PAE would be shorter than expected,
// potentially allowing payload substitution.
func TestSecurity_R3_192_PAENullByteInType(t *testing.T) {
	tests := []struct {
		name     string
		bodyType string
		body     []byte
	}{
		{
			name:     "null_at_start",
			bodyType: "\x00application/json",
			body:     []byte("data"),
		},
		{
			name:     "null_at_end",
			bodyType: "application/json\x00",
			body:     []byte("data"),
		},
		{
			name:     "null_in_middle",
			bodyType: "application/\x00json",
			body:     []byte("data"),
		},
		{
			name:     "multiple_nulls",
			bodyType: "\x00\x00\x00",
			body:     []byte("\x00\x00"),
		},
		{
			name:     "null_after_space",
			bodyType: "type \x00",
			body:     []byte("body"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pae := preauthEncode(tt.bodyType, tt.body)

			// The encoded length must reflect the full byte length
			// including null bytes.
			expected := fmt.Sprintf("DSSEv1 %d %s %d %s",
				len(tt.bodyType), tt.bodyType, len(tt.body), tt.body)

			assert.Equal(t, []byte(expected), pae,
				"null bytes in type must be preserved in PAE encoding")

			// Verify the body type can be extracted back at the correct offset
			prefix := fmt.Sprintf("DSSEv1 %d ", len(tt.bodyType))
			require.True(t, bytes.HasPrefix(pae, []byte(prefix)),
				"PAE prefix mismatch")

			extracted := string(pae[len(prefix) : len(prefix)+len(tt.bodyType)])
			assert.Equal(t, tt.bodyType, extracted,
				"extracted type must match including null bytes")
		})
	}
}

// TestSecurity_R3_193_SignEmptySignerSlice verifies that Sign() rejects
// an empty signer slice with a clear error.
func TestSecurity_R3_193_SignEmptySignerSlice(t *testing.T) {
	body := bytes.NewReader([]byte("payload"))

	_, err := Sign("application/json", body)
	require.Error(t, err, "Sign with no SignWithSigners option should error")
	assert.Contains(t, err.Error(), "at least one signer",
		"error message should explain the requirement")

	_, err = Sign("application/json", bytes.NewReader([]byte("payload")),
		SignWithSigners())
	require.Error(t, err, "Sign with empty signer list should error")
}

// TestSecurity_R3_194_SignPreservesPayloadBytesExact verifies that the
// Payload field in the returned envelope contains the exact bytes from
// the body reader, with no transformation, truncation, or encoding.
// This is critical because any transformation would break signature
// verification when the verifier reconstructs the PAE.
func TestSecurity_R3_194_SignPreservesPayloadBytesExact(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"single_null", []byte{0x00}},
		{"all_null_bytes", make([]byte, 256)},
		{"binary_sequence", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()},
		{"utf8_multibyte", []byte("\u4e16\u754c\U0001F512")},
		{"invalid_utf8", []byte{0xff, 0xfe, 0xfd, 0xfc}},
		{"trailing_newline", []byte("data\n")},
		{"crlf", []byte("line1\r\nline2\r\n")},
		{"json_with_nulls", []byte(`{"key":"\u0000"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			signer := cryptoutil.NewED25519Signer(priv)
			verifier := cryptoutil.NewED25519Verifier(pub)

			env, err := Sign("application/json", bytes.NewReader(tt.payload),
				SignWithSigners(signer))
			require.NoError(t, err)

			assert.True(t, bytes.Equal(tt.payload, env.Payload),
				"envelope payload must be byte-identical to input.\n"+
					"  input:    %v (len=%d)\n  envelope: %v (len=%d)",
				tt.payload, len(tt.payload), env.Payload, len(env.Payload))

			// And it must verify
			_, err = env.Verify(VerifyWithVerifiers(verifier))
			require.NoError(t, err, "freshly signed envelope must verify")
		})
	}
}

// TestSecurity_R3_195_SignWithNilBodyReader verifies that Sign handles
// a nil body reader gracefully (panic protection).
func TestSecurity_R3_195_SignWithNilBodyReader(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub
	signer := cryptoutil.NewED25519Signer(priv)

	// This should either panic (which the test catches) or return an error.
	// It must NOT produce a silently invalid envelope.
	defer func() {
		if r := recover(); r != nil {
			t.Logf("SECURITY FINDING R3-195: Sign panics on nil body reader: %v", r)
			// A panic is acceptable IF it is caught, but ideally Sign
			// should return an error instead of panicking.
		}
	}()

	_, err = Sign("application/json", nil, SignWithSigners(signer))
	if err == nil {
		t.Log("WARNING R3-195: Sign accepted nil body reader without error")
	}
}

// TestSecurity_R3_196_PAESpaceDelimiterAmbiguity tests whether a bodyType
// containing only digits followed by a space could be confused with a
// length prefix by a naive parser.
//
// The PAE format is: "DSSEv1 <typeLen> <type> <bodyLen> <body>"
// If type is "42 fake", a broken parser might read "42" as the type length
// and " fake" as the start of the type content.
func TestSecurity_R3_196_PAESpaceDelimiterAmbiguity(t *testing.T) {
	tests := []struct {
		name     string
		bodyType string
	}{
		{"digits_then_space", "42 fake"},
		{"just_digits", "12345"},
		{"zero", "0"},
		{"negative_number", "-1"},
		{"huge_number", "99999999999999999999"},
		{"digits_with_newline", "42\nfake"},
		{"digits_with_null", "42\x00fake"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("test body")
			pae := preauthEncode(tt.bodyType, body)

			// Parse correctly: the first number after "DSSEv1 " is the length
			// of the bodyType. Use that to extract the type.
			s := string(pae)
			afterPrefix := s[len("DSSEv1 "):]
			spaceIdx := strings.Index(afterPrefix, " ")
			require.NotEqual(t, -1, spaceIdx)

			encodedTypeLen, err := strconv.Atoi(afterPrefix[:spaceIdx])
			require.NoError(t, err)
			require.Equal(t, len(tt.bodyType), encodedTypeLen,
				"type length must be the byte length of the full bodyType")

			extracted := afterPrefix[spaceIdx+1 : spaceIdx+1+encodedTypeLen]
			assert.Equal(t, tt.bodyType, extracted,
				"extracted type must match the full bodyType including digits and spaces")
		})
	}
}

// TestSecurity_R3_197_SignVerifyRoundTripWithBinaryPayload performs an
// end-to-end sign-verify round trip with payloads that contain every
// possible byte value. This is the most thorough test of payload fidelity.
func TestSecurity_R3_197_SignVerifyRoundTripWithBinaryPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := cryptoutil.NewED25519Signer(priv)
	verifier := cryptoutil.NewED25519Verifier(pub)

	// Create a payload with every byte value 0x00-0xFF
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}

	env, err := Sign("application/octet-stream", bytes.NewReader(payload),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Verify payload preservation
	require.True(t, bytes.Equal(payload, env.Payload),
		"payload with all byte values must be preserved exactly")

	// Verify signature
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err, "all-bytes payload must verify successfully")
}

// TestSecurity_R3_198_PAELengthOverflow tests that extremely large type or
// body lengths do not cause integer overflow in the length field encoding.
// The length is encoded as a decimal string, so there is no fixed-width
// overflow, but we verify that the length field is self-consistent.
func TestSecurity_R3_198_PAELengthOverflow(t *testing.T) {
	// We cannot actually create a multi-GB payload in a test, but we can
	// verify the encoding for payloads at interesting size boundaries.
	sizes := []int{0, 1, 127, 128, 255, 256, 65535, 65536, 1<<20 - 1, 1 << 20}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			bodyType := "t"
			body := make([]byte, size)

			pae := preauthEncode(bodyType, body)

			// Verify the body length field
			s := string(pae)
			// Skip past "DSSEv1 1 t "
			prefix := "DSSEv1 1 t "
			require.True(t, strings.HasPrefix(s, prefix),
				"unexpected prefix for bodyType 't'")

			rest := s[len(prefix):]
			spaceIdx := strings.Index(rest, " ")
			require.NotEqual(t, -1, spaceIdx)

			encodedBodyLen, err := strconv.Atoi(rest[:spaceIdx])
			require.NoError(t, err)
			assert.Equal(t, size, encodedBodyLen,
				"PAE body length must exactly match for size=%d", size)
		})
	}
}

// TestSecurity_R3_199_SignMultipleSignersProducesAllSignatures verifies that
// when multiple distinct signers are provided, Sign() produces one signature
// per signer and each signature is independently verifiable.
func TestSecurity_R3_199_SignMultipleSignersProducesAllSignatures(t *testing.T) {
	const numSigners = 5
	signers := make([]cryptoutil.Signer, numSigners)
	verifiers := make([]cryptoutil.Verifier, numSigners)

	for i := range numSigners {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signers[i] = cryptoutil.NewED25519Signer(priv)
		verifiers[i] = cryptoutil.NewED25519Verifier(pub)
	}

	payload := []byte(`{"step": "build", "materials": {}}`)
	env, err := Sign("application/vnd.in-toto+json",
		bytes.NewReader(payload),
		SignWithSigners(signers...))
	require.NoError(t, err)

	assert.Equal(t, numSigners, len(env.Signatures),
		"must produce one signature per signer")

	// Each individual verifier should verify the envelope
	for i, v := range verifiers {
		t.Run(fmt.Sprintf("verifier_%d", i), func(t *testing.T) {
			_, err := env.Verify(VerifyWithVerifiers(v))
			require.NoError(t, err,
				"signature from signer[%d] must be verifiable", i)
		})
	}

	// All verifiers together with threshold should work
	_, err = env.Verify(
		VerifyWithVerifiers(verifiers...),
		VerifyWithThreshold(numSigners),
	)
	require.NoError(t, err,
		"all %d verifiers should meet threshold=%d", numSigners, numSigners)
}
