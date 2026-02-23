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

package environment

import (
	"strings"
	"testing"
)

// FuzzFilterEnvironmentArray exercises FilterEnvironmentArray with random glob
// patterns and environment variable lists.  The function compiles glob patterns
// from the blockList and matches them against variable keys.  Invalid globs
// must be skipped without panicking, and nil/empty inputs must be safe.
func FuzzFilterEnvironmentArray(f *testing.F) {
	// Seed corpus: (envVar, blockPattern, excludeKey)
	f.Add("HOME=/Users/test", "*HOME*", "")
	f.Add("PATH=/usr/bin", "PATH", "")
	f.Add("SECRET_KEY=abc123", "*SECRET*", "")
	f.Add("MY_TOKEN=xyz", "*TOKEN*", "MY_TOKEN")
	f.Add("", "", "")
	f.Add("=", "*", "")
	f.Add("KEY=", "KEY", "")
	f.Add("=VALUE", "", "")
	f.Add("NO_EQUALS", "NO_EQUALS", "")
	f.Add("MULTI=EQUALS=SIGNS=HERE", "MULTI", "")
	// Glob edge cases
	f.Add("FOO=bar", "[", "")        // Invalid glob pattern
	f.Add("FOO=bar", "[abc", "")     // Unclosed bracket
	f.Add("FOO=bar", "***", "")      // Multiple wildcards
	f.Add("FOO=bar", "?", "")        // Single char wildcard
	f.Add("FOO=bar", "{a,b}", "")    // Alternation
	f.Add("FOO=bar", "\\*", "")      // Escaped wildcard
	f.Add("FOO=bar", "*FOO*", "FOO") // In exclude list
	// Unicode / special chars
	f.Add("UNICODE_\u00e9=val", "*\u00e9*", "")
	f.Add("\xff\xfe=bad", "*", "")
	f.Add("KEY\x00=val", "KEY\x00", "")
	f.Add("KEY\n=val\n", "*\n*", "")
	// Very long values
	f.Add(strings.Repeat("A", 1000)+"="+strings.Repeat("B", 1000), strings.Repeat("A", 1000), "")

	f.Fuzz(func(t *testing.T, envVar, blockPattern, excludeKey string) {
		variables := []string{envVar}
		// Also test with multiple variables
		if len(envVar) > 0 {
			variables = append(variables, "EXTRA_VAR=extra_value")
		}

		blockList := make(map[string]struct{})
		if blockPattern != "" {
			blockList[blockPattern] = struct{}{}
		}

		excludeKeys := make(map[string]struct{})
		if excludeKey != "" {
			excludeKeys[excludeKey] = struct{}{}
		}

		// Must not panic under any circumstances
		var collected []string
		FilterEnvironmentArray(variables, blockList, excludeKeys, func(key, val, orig string) {
			collected = append(collected, key+"="+val)
		})

		// Empty blockList -- all should be allowed
		var allAllowed []string
		FilterEnvironmentArray(variables, map[string]struct{}{}, map[string]struct{}{}, func(key, val, orig string) {
			allAllowed = append(allAllowed, key+"="+val)
		})
		if len(allAllowed) < len(variables) {
			t.Fatalf("with empty blocklist, expected at least %d allowed vars, got %d", len(variables), len(allAllowed))
		}

		// Nil blockList -- should not panic
		FilterEnvironmentArray(variables, nil, nil, func(key, val, orig string) {})

		// Empty variables list
		FilterEnvironmentArray(nil, blockList, excludeKeys, func(key, val, orig string) {
			t.Fatalf("callback should not be called with nil variables")
		})
	})
}

// FuzzObfuscateEnvironmentArray exercises ObfuscateEnvironmentArray similarly.
// The obfuscation path replaces values with "******" for matching keys rather
// than filtering them out.  Every variable should still call onAllowed, but
// sensitive ones should have their value replaced.
func FuzzObfuscateEnvironmentArray(f *testing.F) {
	// Seed corpus
	f.Add("HOME=/Users/test", "*HOME*", "")
	f.Add("SECRET_KEY=abc123", "*SECRET*", "")
	f.Add("MY_TOKEN=xyz", "*TOKEN*", "MY_TOKEN")
	f.Add("", "", "")
	f.Add("=", "*", "")
	f.Add("KEY=", "KEY", "")
	f.Add("=VALUE", "", "")
	f.Add("NO_EQUALS", "NO_EQUALS", "")
	// Glob edge cases
	f.Add("FOO=bar", "[", "")
	f.Add("FOO=bar", "[abc", "")
	f.Add("FOO=bar", "***", "")
	f.Add("FOO=bar", "?", "")
	f.Add("FOO=bar", "{a,b}", "")
	f.Add("FOO=bar", "\\*", "")
	// Unicode / special chars
	f.Add("UNICODE_\u00e9=val", "*\u00e9*", "")
	f.Add("\xff\xfe=bad", "*", "")
	f.Add("KEY\x00=val", "KEY\x00", "")
	// Very long
	f.Add(strings.Repeat("A", 1000)+"="+strings.Repeat("B", 1000), strings.Repeat("A", 1000), "")

	f.Fuzz(func(t *testing.T, envVar, obfuscatePattern, excludeKey string) {
		variables := []string{envVar}

		obfuscateList := make(map[string]struct{})
		if obfuscatePattern != "" {
			obfuscateList[obfuscatePattern] = struct{}{}
		}

		excludeKeys := make(map[string]struct{})
		if excludeKey != "" {
			excludeKeys[excludeKey] = struct{}{}
		}

		// Must not panic under any circumstances
		callCount := 0
		ObfuscateEnvironmentArray(variables, obfuscateList, excludeKeys, func(key, val, orig string) {
			callCount++
			// When a key matches the obfuscate list and is not excluded,
			// the value must be "******"
			if obfuscatePattern != "" && !strings.Contains(obfuscatePattern, "*") {
				// For exact-match patterns, we can verify the invariant
				envKey, _ := splitVariable(envVar)
				if envKey == obfuscatePattern && excludeKey != envKey {
					if val != "******" {
						t.Errorf("expected obfuscated value '******' for key %q matching pattern %q, got %q", envKey, obfuscatePattern, val)
					}
				}
			}
		})

		// ObfuscateEnvironmentArray should always call onAllowed for every variable
		if callCount != len(variables) {
			t.Fatalf("expected onAllowed called %d times, got %d", len(variables), callCount)
		}

		// Nil obfuscateList -- should not panic, all pass through unmodified
		ObfuscateEnvironmentArray(variables, nil, nil, func(key, val, orig string) {})

		// Empty variables list
		ObfuscateEnvironmentArray(nil, obfuscateList, excludeKeys, func(key, val, orig string) {
			t.Fatalf("callback should not be called with nil variables")
		})
	})
}
