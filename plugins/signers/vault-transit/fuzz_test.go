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

package hashivault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// FuzzVaultTransitKeyVersion exercises the key version parsing logic in
// LoadSignerVerifier and getPublicKeyBytes.  The production code:
//  1. Parses KeyVersion with strconv.ParseInt(ksp.KeyVersion, 10, 32)
//  2. In getPublicKeyBytes, if keyVersion == "0", reads "latest_version"
//     from the Vault response as json.Number and calls .String()
//  3. Looks up the version in a keys map
//
// This fuzz test ensures that:
//   - strconv.ParseInt never panics with arbitrary input
//   - The json.Number type assertion path is safe
//   - The keys map lookup handles missing/malformed versions
//   - parseReference never panics with arbitrary input
func FuzzVaultTransitKeyVersion(f *testing.F) {
	// Seed corpus: key version strings
	f.Add("0")
	f.Add("1")
	f.Add("2")
	f.Add("-1")
	f.Add("999999999")
	f.Add("2147483647")          // int32 max
	f.Add("2147483648")          // int32 max + 1 (overflow)
	f.Add("-2147483648")         // int32 min
	f.Add("-2147483649")         // int32 min - 1 (overflow)
	f.Add("9999999999999999999") // Exceeds int64 range
	f.Add("")
	f.Add("not_a_number")
	f.Add("1.5")
	f.Add("1e10")
	f.Add(" 1")
	f.Add("1 ")
	f.Add("\t1")
	f.Add("0x1")
	f.Add("0b1")
	f.Add("0o1")
	f.Add("+1")
	f.Add("00")
	f.Add("01")
	f.Add("-0")
	// Unicode digits
	f.Add("\u0661") // Arabic-Indic digit 1
	f.Add("\u00b2") // Superscript 2
	// Special characters
	f.Add("\x00")
	f.Add("\n")
	f.Add("\xff\xfe")
	// Very long numbers
	f.Add(strings.Repeat("9", 1000))
	f.Add(strings.Repeat("0", 1000))

	f.Fuzz(func(t *testing.T, keyVersion string) {
		// Test 1: strconv.ParseInt must not panic
		val, err := strconv.ParseInt(keyVersion, 10, 32)
		if err == nil {
			// ParseInt with bitSize=32 guarantees the result fits in int32.
			// Verify this invariant holds.
			if val > int64(int32(0x7fffffff)) || val < int64(int32(-0x80000000)) {
				t.Fatalf("ParseInt returned %d which overflows int32", val)
			}

			i32 := int32(val)
			// FormatInt round-trip
			formatted := strconv.FormatInt(int64(i32), 10)
			reparsed, err := strconv.ParseInt(formatted, 10, 32)
			if err != nil {
				t.Fatalf("round-trip failed: FormatInt(%d) = %q, ParseInt error: %v", i32, formatted, err)
			}
			if reparsed != int64(i32) {
				t.Fatalf("round-trip value mismatch: %d != %d", reparsed, i32)
			}
		}

		// Test 2: Simulate the getPublicKeyBytes key version logic
		// When keyVersion is "0", the code reads "latest_version" from the
		// Vault response and expects it to be json.Number.
		keyVersionStr := keyVersion
		if err == nil {
			keyVersionStr = strconv.FormatInt(int64(int32(val)), 10)
		} else {
			// Invalid version string -- LoadSignerVerifier would return error
			// but we continue to exercise the downstream logic
			keyVersionStr = "1" // Use a safe default to keep going
		}

		if keyVersionStr == "0" {
			// Simulate the latest_version path with various types
			testCases := []interface{}{
				json.Number("1"),
				json.Number("0"),
				json.Number("-1"),
				json.Number("999"),
				json.Number("not_a_number"),
				json.Number(""),
				"string_not_number",
				42,
				nil,
				true,
				3.14,
			}

			for _, tc := range testCases {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("panic in latest_version handling with type %T value %v: %v", tc, tc, r)
						}
					}()

					// Simulate the type assertion from getPublicKeyBytes
					latestVersionNum, ok := tc.(json.Number)
					if ok {
						ver := latestVersionNum.String()
						// Simulate the keys map lookup
						keysMap := map[string]interface{}{
							"1": map[string]interface{}{
								"public_key": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
							},
						}
						keyInfo, ok := keysMap[ver]
						if ok {
							keyMap, ok := keyInfo.(map[string]interface{})
							if ok {
								_, _ = keyMap["public_key"]
							}
						}
					}
				}()
			}
		} else {
			// Non-zero version -- direct key lookup
			keysMap := map[string]interface{}{
				keyVersionStr: map[string]interface{}{
					"public_key": "test-key",
				},
			}
			keyInfo, ok := keysMap[keyVersionStr]
			if ok {
				keyMap, ok := keyInfo.(map[string]interface{})
				if ok {
					_, _ = keyMap["public_key"].(string)
				}
			}
		}

		// Test 3: parseReference must not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseReference panicked with input %q: %v", keyVersion, r)
				}
			}()
			ref := fmt.Sprintf("hashivault://%s", keyVersion)
			_, _ = parseReference(ref)
		}()

		// Test 4: ValidReference must not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ValidReference panicked with input %q: %v", keyVersion, r)
				}
			}()
			ref := fmt.Sprintf("hashivault://%s", keyVersion)
			_ = ValidReference(ref)
		}()
	})
}
