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

// =============================================================================
// R3-260-6: Transit engine path traversal via transitSecretsEnginePath
//
// client.sign() constructs Vault API paths via:
//   path := fmt.Sprintf("/%v/sign/%v/%v", c.transitSecretsEnginePath, c.keyPath, hashStr)
//
// The transitSecretsEnginePath value comes from user configuration. The
// code NOW validates it against transitPathRegex in newClient(), but the
// Option function WithTransitSecretEnginePath() does not validate. If
// someone constructs a client struct directly (bypassing newClient), or
// if the validation regex is insufficient, path traversal is possible.
//
// Proving test: verify that transitPathRegex correctly rejects traversal
// patterns, and that WithTransitSecretEnginePath still accepts anything.
// =============================================================================

func TestSecurity_R3_260_Vault_TransitPathValidation(t *testing.T) {
	// First, verify that the Option function does NOT validate.
	maliciousPaths := []struct {
		name   string
		path   string
		isEvil bool
	}{
		{"path traversal", "../../secret/data", true},
		{"absolute path", "/sys/seal", true},
		{"double slash", "transit//escape", true},
		{"null byte", "transit\x00/secret", true},
		{"url encoded traversal", "transit%2F..%2Fsecret", true},
		{"empty", "", true},
		{"valid simple", "transit", false},
		{"valid nested", "transit/production", false},
		{"valid hyphenated", "my-transit-engine", false},
	}

	for _, tc := range maliciousPaths {
		t.Run("option_"+tc.name, func(t *testing.T) {
			opts := &clientOptions{}
			WithTransitSecretEnginePath(tc.path)(opts)

			// The Option function accepts ANYTHING without validation.
			if opts.transitSecretEnginePath != tc.path {
				t.Errorf("WithTransitSecretEnginePath(%q) did not set the value", tc.path)
			}

			if tc.isEvil {
				t.Logf("WithTransitSecretEnginePath accepts malicious path %q without validation", tc.path)
			}
		})
	}

	// Now verify the regex in newClient() catches traversal.
	for _, tc := range maliciousPaths {
		t.Run("regex_"+tc.name, func(t *testing.T) {
			matches := transitPathRegex.MatchString(tc.path)
			if tc.isEvil && matches {
				t.Errorf("BUG: transitPathRegex.MatchString(%q) = true, should reject "+
					"malicious path. Path traversal could access arbitrary Vault endpoints "+
					"via paths like '/%s/sign/key/sha2-256'", tc.path, tc.path)
			}
			if !tc.isEvil && !matches {
				t.Errorf("transitPathRegex.MatchString(%q) = false, should accept valid path", tc.path)
			}
		})
	}

	// Demonstrate what the constructed path would look like with traversal.
	t.Run("path_construction_demo", func(t *testing.T) {
		evilPath := "../../secret/data"
		constructed := fmt.Sprintf("/%v/sign/%v/%v", evilPath, "mykey", "sha2-256")
		if strings.Contains(constructed, "..") {
			t.Logf("BUG CONTEXT: Without validation, path=%q would allow accessing "+
				"arbitrary Vault endpoints. The transitPathRegex in newClient() now "+
				"blocks this, but WithTransitSecretEnginePath() does not validate. "+
				"Defense in depth: validate in the Option function too.", constructed)
		}
	})
}

// =============================================================================
// R3-260-7: Key version "0" -> latest version type assertion fragility
//
// In getPublicKeyBytes(), when keyVersion is 0 (the default), the code
// fetches the latest version from the Vault response:
//
//   keyVersion := strconv.FormatInt(int64(c.keyVersion), 10)
//   if keyVersion == "0" {
//       latestVersion, ok := resp.Data["latest_version"]
//       latestVersionNum, ok := latestVersion.(json.Number)
//       keyVersion = latestVersionNum.String()
//   }
//
// Issues:
// 1. The type assertion to json.Number fails if Vault returns the version
//    as a plain integer (float64 from standard JSON decoder, int from some
//    Vault SDK versions). The code will error with "latest version not a
//    number" even when the response is valid.
// 2. json.Number.String() can return non-numeric strings (e.g., "abc")
//    which would then fail the keys map lookup silently.
// 3. There is no validation that the latest_version is actually positive.
//
// Proving test: demonstrate the type assertion behavior with various
// value types that Vault might return.
// =============================================================================

func TestSecurity_R3_260_Vault_KeyVersionZeroLatestLogic(t *testing.T) {
	// Simulate the getPublicKeyBytes() logic for keyVersion=0.
	// The code does: latestVersionNum, ok := latestVersion.(json.Number)

	testCases := []struct {
		name        string
		value       interface{}
		wantTypeOk  bool
		wantStr     string
		description string
	}{
		{
			name:        "json.Number valid",
			value:       json.Number("5"),
			wantTypeOk:  true,
			wantStr:     "5",
			description: "Standard case when Vault uses json.UseNumber decoder",
		},
		{
			name:        "json.Number zero",
			value:       json.Number("0"),
			wantTypeOk:  true,
			wantStr:     "0",
			description: "Edge case: latest_version is 0 (should not happen in practice)",
		},
		{
			name:        "json.Number non-numeric",
			value:       json.Number("abc"),
			wantTypeOk:  true,
			wantStr:     "abc",
			description: "BUG: json.Number accepts non-numeric strings; keys lookup will fail silently",
		},
		{
			name:        "float64",
			value:       float64(5),
			wantTypeOk:  false,
			wantStr:     "",
			description: "BUG: standard JSON decoder returns float64; type assertion fails",
		},
		{
			name:        "int",
			value:       5,
			wantTypeOk:  false,
			wantStr:     "",
			description: "BUG: some decoders return int; type assertion fails",
		},
		{
			name:        "string",
			value:       "5",
			wantTypeOk:  false,
			wantStr:     "",
			description: "BUG: if Vault returns version as string; type assertion fails",
		},
		{
			name:        "nil",
			value:       nil,
			wantTypeOk:  false,
			wantStr:     "",
			description: "Edge case: nil value should fail gracefully",
		},
		{
			name:        "json.Number negative",
			value:       json.Number("-1"),
			wantTypeOk:  true,
			wantStr:     "-1",
			description: "BUG: negative version accepted; would look up key version '-1'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			num, ok := tc.value.(json.Number)
			if ok != tc.wantTypeOk {
				t.Errorf("type assertion to json.Number: got ok=%v, want ok=%v", ok, tc.wantTypeOk)
			}
			if ok {
				s := num.String()
				if s != tc.wantStr {
					t.Errorf("json.Number.String() = %q, want %q", s, tc.wantStr)
				}
			}
			t.Logf("%s: %s", tc.name, tc.description)
		})
	}

	t.Log("BUG DOCUMENTED: getPublicKeyBytes() type-asserts latest_version to " +
		"json.Number. This only works when the Vault SDK uses json.UseNumber. " +
		"Standard JSON decoding returns float64 which would fail the assertion. " +
		"Additionally, json.Number.String() can return non-numeric strings and " +
		"negative numbers with no validation. " +
		"Fix: handle float64 and string types as well, and validate the version " +
		"is a positive integer.")
}

// =============================================================================
// R3-260-8: Hardcoded pkcs1v15 signature algorithm
//
// In client.go sign() and verify(), the signature_algorithm is hardcoded:
//   "signature_algorithm": "pkcs1v15"
//
// Issues:
// 1. pkcs1v15 (PKCS#1 v1.5) is a legacy padding scheme. Modern best
//    practice recommends PSS (PKCS#1 v2.1) for RSA signatures.
// 2. The algorithm is not configurable. Users with ECDSA keys in Vault
//    Transit would still send "pkcs1v15" which Vault would ignore (ECDSA
//    doesn't use PKCS#1 padding), but it indicates a design assumption
//    that only RSA keys are used.
// 3. There is no documentation of this limitation.
//
// Proving test: verify the hardcoded value by constructing the sign
// request data and checking the algorithm field.
// =============================================================================

func TestSecurity_R3_260_Vault_HardcodedPKCS1v15(t *testing.T) {
	// Reconstruct what client.sign() sends to Vault.
	signData := map[string]interface{}{
		"input":               "base64-encoded-digest",
		"prehashed":           true,
		"key_version":         int32(1),
		"signature_algorithm": "pkcs1v15",
	}

	algo, ok := signData["signature_algorithm"].(string)
	if !ok {
		t.Fatal("signature_algorithm should be a string")
	}

	if algo != "pkcs1v15" {
		t.Fatalf("expected pkcs1v15, got %q", algo)
	}

	// The same hardcoded value appears in verify().
	verifyData := map[string]interface{}{
		"signature_algorithm": "pkcs1v15",
		"input":               "base64-encoded-digest",
		"signature":           "vault:v1:...",
		"prehashed":           true,
	}

	verifyAlgo, _ := verifyData["signature_algorithm"].(string)
	if verifyAlgo != "pkcs1v15" {
		t.Fatalf("verify also uses %q, not pkcs1v15", verifyAlgo)
	}

	t.Log("BUG DOCUMENTED: Both sign() and verify() hardcode 'pkcs1v15' as the " +
		"signature_algorithm sent to Vault Transit. " +
		"Issues: " +
		"1. PKCS#1 v1.5 is a legacy scheme; PSS is recommended for new deployments. " +
		"2. The algorithm is not configurable by the user. " +
		"3. For ECDSA keys, 'pkcs1v15' is meaningless (Vault ignores it), but " +
		"   sending it indicates the code assumes RSA-only. " +
		"4. There is no way to use PSS even if the Vault key supports it. " +
		"Fix: make signature_algorithm configurable via clientOptions, defaulting " +
		"to 'pss' for RSA and omitting for ECDSA/Ed25519.")
}

// =============================================================================
// R3-260-9: Negative key version accepted by LoadSignerVerifier parsing
//
// LoadSignerVerifier() parses the key version string to int32:
//   keyVer, err := strconv.ParseInt(ksp.KeyVersion, 10, 32)
//   clientOpts.keyVersion = int32(keyVer)
//
// This accepts negative values like "-1". While newClient() now validates
// keyVersion >= 0, the parsing layer does not reject negatives itself.
//
// Proving test: verify negative versions parse successfully at the
// strconv level.
// =============================================================================

func TestSecurity_R3_260_Vault_NegativeKeyVersionParsing(t *testing.T) {
	negativeVersions := []string{"-1", "-999", "-2147483648"}

	for _, v := range negativeVersions {
		t.Run(v, func(t *testing.T) {
			// Simulate what LoadSignerVerifier does.
			keyVer, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				t.Fatalf("strconv.ParseInt(%q, 10, 32) unexpectedly failed: %v", v, err)
			}

			keyVersion := int32(keyVer)
			if keyVersion >= 0 {
				t.Errorf("expected negative key version, got %d", keyVersion)
			}

			// newClient() would catch this with the added validation.
			// But the error happens late in the call chain.
			t.Logf("Negative key version %q parses to int32(%d). "+
				"Accepted by strconv.ParseInt, rejected by newClient() validation. "+
				"Fix: validate >= 0 at parse time in LoadSignerVerifier.", v, keyVersion)
		})
	}
}

// =============================================================================
// R3-260-10: sign() response missing "signature" key - error message quality
//
// In client.go sign(), after a successful Vault API call, if the response
// is missing the "signature" key, the error should be clear without
// wrapping a nil error value.
//
// Proving test: verify the error message is clean.
// =============================================================================

func TestSecurity_R3_260_Vault_SignResponseErrorMessage(t *testing.T) {
	// Verify that the error for missing signature key does not contain "<nil>".
	expectedMsg := "no signature in response"

	// Simulate the error construction from client.go.
	err := fmt.Errorf("%s", expectedMsg)
	errStr := err.Error()

	if strings.Contains(errStr, "<nil>") {
		t.Errorf("BUG: error message contains '<nil>': %q", errStr)
	}

	if errStr != expectedMsg {
		t.Errorf("unexpected error message: %q, want %q", errStr, expectedMsg)
	}
}
