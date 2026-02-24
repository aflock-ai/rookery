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

package environment

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// TestSecurity_R3_124_CaseSensitiveExactMatchBypass proves that exact-match entries
// in the default sensitive environment variable list can be bypassed by using
// different casing. The filter/obfuscate functions perform case-sensitive exact
// matching for non-glob entries, but glob patterns are matched case-insensitively.
//
// This means env vars like "aws_access_key_id" (lowercase) slip through both
// the exact match and all glob patterns, leaking the credential into attestations.
//
// Severity: MEDIUM - Requires attacker control over env var naming, which is
// unusual in standard CI but possible in custom environments.
func TestSecurity_R3_124_CaseSensitiveExactMatchBypass(t *testing.T) {
	sensitiveList := attestation.DefaultSensitiveEnvList()

	// These vars are in the exact-match list but NOT covered by any glob pattern.
	// Lowercase versions should still be caught but currently are NOT.
	tests := []struct {
		name        string
		envVar      string
		shouldCatch bool // true = the var should be filtered/obfuscated
		description string
	}{
		{
			name:        "uppercase AWS_ACCESS_KEY_ID is caught by exact match",
			envVar:      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			shouldCatch: true,
			description: "exact match works for original case",
		},
		{
			name:        "lowercase aws_access_key_id bypasses filter",
			envVar:      "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
			shouldCatch: true, // SHOULD be caught, but currently isn't
			description: "lowercase of exact-match-only entry, no glob covers it",
		},
		{
			name:        "mixed case Aws_Access_Key_Id bypasses filter",
			envVar:      "Aws_Access_Key_Id=AKIAIOSFODNN7EXAMPLE",
			shouldCatch: true, // SHOULD be caught, but currently isn't
			description: "mixed case of exact-match-only entry",
		},
		{
			name:        "lowercase google_application_credentials bypasses filter",
			envVar:      "google_application_credentials=/path/to/creds.json",
			shouldCatch: true, // SHOULD be caught, but currently isn't
			description: "GCP credential file path leaks in attestation",
		},
		{
			name:        "uppercase AZURE_CLIENT_ID is caught",
			envVar:      "AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000",
			shouldCatch: true,
			description: "exact match works for original case",
		},
		{
			name:        "lowercase azure_client_id bypasses filter",
			envVar:      "azure_client_id=00000000-0000-0000-0000-000000000000",
			shouldCatch: true, // SHOULD be caught, but currently isn't
			description: "Azure client ID leaks in attestation",
		},
		{
			name:        "glob-covered vars ARE caught case-insensitively",
			envVar:      "my_custom_token=secretvalue",
			shouldCatch: true,
			description: "glob *TOKEN* catches this because both are uppercased",
		},
		{
			name:        "lowercase secret var caught by glob",
			envVar:      "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			shouldCatch: true,
			description: "*SECRET* glob catches this case-insensitively",
		},
	}

	// Test FILTER mode
	t.Run("FilterMode", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var allowed []string
				FilterEnvironmentArray(
					[]string{tt.envVar},
					sensitiveList,
					map[string]struct{}{}, // no excludes
					func(key, val, orig string) {
						allowed = append(allowed, key+"="+val)
					},
				)

				wasCaught := len(allowed) == 0
				if wasCaught != tt.shouldCatch {
					if tt.shouldCatch && !wasCaught {
						t.Errorf("SECURITY BUG: %s — env var %q leaked through filter (%s)",
							tt.name, tt.envVar, tt.description)
					} else {
						t.Errorf("unexpected filter result for %q: caught=%v, shouldCatch=%v",
							tt.envVar, wasCaught, tt.shouldCatch)
					}
				}
			})
		}
	})

	// Test OBFUSCATE mode
	t.Run("ObfuscateMode", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var results []string
				ObfuscateEnvironmentArray(
					[]string{tt.envVar},
					sensitiveList,
					map[string]struct{}{}, // no excludes
					func(key, val, orig string) {
						results = append(results, key+"="+val)
					},
				)

				if len(results) == 0 {
					t.Fatalf("obfuscate should always call onAllowed, got 0 results")
				}

				wasObfuscated := false
				for _, r := range results {
					if contains(r, "******") {
						wasObfuscated = true
					}
				}

				if wasObfuscated != tt.shouldCatch {
					if tt.shouldCatch && !wasObfuscated {
						t.Errorf("SECURITY BUG: %s — env var %q value NOT obfuscated (%s)",
							tt.name, tt.envVar, tt.description)
					} else {
						t.Errorf("unexpected obfuscate result for %q: obfuscated=%v, shouldCatch=%v",
							tt.envVar, wasObfuscated, tt.shouldCatch)
					}
				}
			})
		}
	})
}

// TestSecurity_R3_124_DefaultListMixedCase proves that the default sensitive list
// itself has mixed-case entries (e.g., binance_api in lowercase) which only match
// if the env var uses the exact same case.
func TestSecurity_R3_124_DefaultListMixedCase(t *testing.T) {
	sensitiveList := attestation.DefaultSensitiveEnvList()

	// binance_api is lowercase in the default list
	// BINANCE_API (uppercase) should also be caught
	tests := []struct {
		envVar      string
		shouldCatch bool
	}{
		{"binance_api=key123", true},      // exact match
		{"BINANCE_API=key123", true},      // uppercase — should be caught
		{"Binance_Api=key123", true},      // mixed — should be caught
		{"binance_secret=key123", true},   // exact match
		{"BINANCE_SECRET=key123", true},   // caught by *SECRET* glob
		{"square_access_token=tok", true}, // exact match
		{"SQUARE_ACCESS_TOKEN=tok", true}, // caught by *TOKEN* glob
		{"square_oauth_secret=sec", true}, // exact match
		{"SQUARE_OAUTH_SECRET=sec", true}, // caught by *SECRET* glob
	}

	for _, tt := range tests {
		t.Run(tt.envVar, func(t *testing.T) {
			var allowed []string
			FilterEnvironmentArray(
				[]string{tt.envVar},
				sensitiveList,
				map[string]struct{}{},
				func(key, val, orig string) {
					allowed = append(allowed, key+"="+val)
				},
			)

			wasCaught := len(allowed) == 0
			if wasCaught != tt.shouldCatch {
				t.Errorf("env var %q: caught=%v, shouldCatch=%v", tt.envVar, wasCaught, tt.shouldCatch)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
