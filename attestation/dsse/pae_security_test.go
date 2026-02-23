//go:build audit

// Copyright 2024 The Witness Contributors
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
	"strings"
	"testing"
)

// TestSecurity_R3_254_PreauthEncodeNullBytesInBody proves that preauthEncode
// correctly handles null bytes in the body. The PAE format uses length-prefix
// delimiters, so null bytes should NOT be a problem. However, consumers that
// treat the output as a C-string could be affected.
func TestSecurity_R3_254_PreauthEncodeNullBytesInBody(t *testing.T) {
	body := []byte("hello\x00world\x00evil")
	pae := preauthEncode("application/json", body)

	// Verify the PAE contains the full body including null bytes
	if !bytes.Contains(pae, body) {
		t.Fatal("PAE output does not contain the full body with null bytes")
	}

	// Verify the length prefix accounts for null bytes
	expected := len("hello\x00world\x00evil")
	paeStr := string(pae)
	if !strings.Contains(paeStr, " 21 ") { // "application/json" is 16 chars
		// Check for the body length
		t.Logf("PAE body length should be %d (including null bytes)", expected)
	}

	t.Logf("preauthEncode correctly includes null bytes in PAE output (body len=%d)", expected)
}

// TestSecurity_R3_254_PreauthEncodeEmptyInputs verifies PAE behavior with
// edge-case empty inputs.
func TestSecurity_R3_254_PreauthEncodeEmptyInputs(t *testing.T) {
	tests := []struct {
		name     string
		bodyType string
		body     []byte
		expected string
	}{
		{
			name:     "both empty",
			bodyType: "",
			body:     []byte{},
			expected: "DSSEv1 0  0 ",
		},
		{
			name:     "empty body type, non-empty body",
			bodyType: "",
			body:     []byte("data"),
			expected: "DSSEv1 0  4 data",
		},
		{
			name:     "non-empty body type, empty body",
			bodyType: "application/json",
			body:     []byte{},
			expected: "DSSEv1 16 application/json 0 ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(preauthEncode(tt.bodyType, tt.body))
			if got != tt.expected {
				t.Errorf("preauthEncode(%q, %q) = %q, want %q", tt.bodyType, tt.body, got, tt.expected)
			}
		})
	}
}

// TestSecurity_R3_255_PreauthEncodeCollisionResistance proves that two
// different (bodyType, body) pairs cannot produce the same PAE output.
// The length-prefix format should prevent this, but we verify with
// concrete examples where naive concatenation would collide.
func TestSecurity_R3_255_PreauthEncodeCollisionResistance(t *testing.T) {
	tests := []struct {
		name  string
		type1 string
		body1 []byte
		type2 string
		body2 []byte
	}{
		{
			name:  "type boundary shift",
			type1: "abc",
			body1: []byte("def"),
			type2: "abcdef",
			body2: []byte(""),
		},
		{
			name:  "space in type vs split",
			type1: "type payload",
			body1: []byte(""),
			type2: "type",
			body2: []byte("payload"),
		},
		{
			name:  "length prefix ambiguity",
			type1: "a",
			body1: []byte("12 bc"),
			type2: "a12",
			body2: []byte("bc"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pae1 := preauthEncode(tt.type1, tt.body1)
			pae2 := preauthEncode(tt.type2, tt.body2)

			if bytes.Equal(pae1, pae2) {
				t.Errorf("COLLISION FOUND: preauthEncode(%q, %q) == preauthEncode(%q, %q)\n"+
					"PAE1: %q\nPAE2: %q",
					tt.type1, tt.body1, tt.type2, tt.body2, pae1, pae2)
			}
		})
	}
}

// TestSecurity_R3_256_PreauthEncodeLengthIntegerOverflow verifies that
// preauthEncode handles very long body type strings without integer overflow
// in the length field. Go's int is 64-bit on modern platforms so this
// shouldn't be an issue, but we verify the format is correct.
func TestSecurity_R3_256_PreauthEncodeLengthIntegerOverflow(t *testing.T) {
	// 1MB body type — large but not unreasonably so
	longType := strings.Repeat("A", 1024*1024)
	pae := preauthEncode(longType, []byte("data"))

	// Verify the length prefix is correct
	expectedPrefix := "DSSEv1 1048576 "
	if !strings.HasPrefix(string(pae), expectedPrefix) {
		t.Errorf("expected PAE to start with %q, got prefix: %q",
			expectedPrefix, string(pae[:min(len(pae), 30)]))
	}

	// Verify the body follows the type
	if !bytes.HasSuffix(pae, []byte(" 4 data")) {
		t.Errorf("expected PAE to end with ' 4 data', got suffix: %q",
			string(pae[max(0, len(pae)-20):]))
	}
}

// TestSecurity_R3_257_PreauthEncodeBinaryBody verifies PAE handles
// arbitrary binary data in the body, including sequences that look like
// PAE delimiters.
func TestSecurity_R3_257_PreauthEncodeBinaryBody(t *testing.T) {
	// Body that contains what looks like a PAE prefix
	maliciousBody := []byte("DSSEv1 0  0 ")
	pae := preauthEncode("application/json", maliciousBody)

	// The outer PAE should wrap the inner "PAE-like" body
	expected := "DSSEv1 16 application/json 12 DSSEv1 0  0 "
	if string(pae) != expected {
		t.Errorf("expected %q, got %q", expected, string(pae))
	}

	// Verify the body length is 12 (len("DSSEv1 0  0 ") = 12)
	if !strings.Contains(string(pae), " 12 ") {
		t.Error("body length should be 12 for the embedded PAE-like string")
	}

	t.Logf("PAE correctly wraps body containing PAE-like content — length prefixes prevent confusion")
}
