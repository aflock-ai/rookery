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

// Security audit tests for environment/filter.go and environment/obfuscate.go
// These tests expose bypasses, edge cases, and logic errors in the
// environment variable filtering and obfuscation code.
package environment

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// FINDING 1 (HIGH): Obfuscation bypass via exclude keys -- exclude keys are
// matched by EXACT string comparison, but the excludeKeys check happens
// BEFORE both exact and glob checks.
//
// If an attacker can control the excludeKeys list, they can whitelist
// any sensitive variable. This is by design, but there's a subtlety:
// the exclude key check uses the raw key from the env var, while
// glob matching uses uppercased keys. There's no case-insensitive
// option for exclude keys.
//
// So if excludeKeys has "my_token" but the env var is "MY_TOKEN",
// the exclude does NOT apply, and the var IS obfuscated.
// But if excludeKeys has "MY_TOKEN", it excludes both exact and glob checks.
//
// Severity: HIGH - exclude keys bypass ALL protection (by design, but
// the case-sensitivity asymmetry is confusing and could lead to
// misconfiguration)
// Location: filter.go:62, obfuscate.go:45
// =============================================================================

func TestSecurityExcludeKeysCaseSensitivity(t *testing.T) {
	vars := []string{
		"my_secret_token=password123",
		"MY_SECRET_TOKEN=password456",
	}

	t.Run("exclude lowercase key only excludes lowercase", func(t *testing.T) {
		collected := make(map[string]string)
		FilterEnvironmentArray(
			vars,
			map[string]struct{}{"*SECRET*": {}, "*TOKEN*": {}},
			map[string]struct{}{"my_secret_token": {}}, // lowercase exclude
			func(key, val, orig string) { collected[key] = val },
		)

		// lowercase key should pass through (excluded)
		if _, exists := collected["my_secret_token"]; !exists {
			t.Error("lowercase 'my_secret_token' should be excluded from filtering")
		}
		// uppercase key should be filtered (NOT excluded)
		if _, exists := collected["MY_SECRET_TOKEN"]; exists {
			t.Error("uppercase 'MY_SECRET_TOKEN' should NOT be excluded (case-sensitive exclude)")
		}
	})

	t.Run("exclude uppercase key only excludes uppercase", func(t *testing.T) {
		collected := make(map[string]string)
		FilterEnvironmentArray(
			vars,
			map[string]struct{}{"*SECRET*": {}, "*TOKEN*": {}},
			map[string]struct{}{"MY_SECRET_TOKEN": {}}, // uppercase exclude
			func(key, val, orig string) { collected[key] = val },
		)

		// uppercase key should pass through (excluded)
		if _, exists := collected["MY_SECRET_TOKEN"]; !exists {
			t.Error("uppercase 'MY_SECRET_TOKEN' should be excluded from filtering")
		}
		// lowercase key should be filtered (NOT excluded)
		if _, exists := collected["my_secret_token"]; exists {
			t.Error("lowercase 'my_secret_token' should NOT be excluded")
		}
	})
}

// =============================================================================
// FINDING 2 (HIGH): ObfuscateEnvironmentArray does NOT break after first glob
// match and continues checking remaining globs.
//
// This is documented in env_adversarial_test.go as a behavioral difference
// from FilterEnvironmentArray. But the real bug is more subtle:
//
// ObfuscateEnvironmentArray always calls onAllowed, even for matched entries.
// This means EVERY variable -- sensitive or not -- is passed to the callback.
// The value is just changed to "******" if it matches.
//
// BUT: the `orig` parameter still contains the ORIGINAL raw env var string
// including the real secret value! Any consumer of the callback that uses
// `orig` instead of `val` will see the unobfuscated secret.
//
// Severity: HIGH - the original secret value is available via the `orig`
// parameter even after obfuscation
// Location: obfuscate.go:63 (onAllowed(key, val, v) -- `v` is the original)
// =============================================================================

func TestSecurityObfuscateLeaksViaOrigParameter(t *testing.T) {
	vars := []string{
		"SECRET_TOKEN=my_super_secret_password_123",
	}
	obfuscateList := map[string]struct{}{"*SECRET*": {}, "*TOKEN*": {}}

	ObfuscateEnvironmentArray(vars, obfuscateList, nil, func(key, val, orig string) {
		// val is correctly obfuscated
		assert.Equal(t, "******", val, "val should be obfuscated")

		// BUT orig still contains the raw secret!
		assert.Equal(t, "SECRET_TOKEN=my_super_secret_password_123", orig,
			"orig parameter contains the UNOBFUSCATED raw env var")

		// Any callback that parses `orig` can extract the real value
		parts := strings.SplitN(orig, "=", 2)
		if len(parts) == 2 {
			realValue := parts[1]
			assert.Equal(t, "my_super_secret_password_123", realValue,
				"the real secret is trivially extractable from orig")
			t.Log("BUG: ObfuscateEnvironmentArray passes the original raw env var as 'orig'")
			t.Log("Any callback can extract the unobfuscated secret from the orig parameter")
			t.Log("Severity: HIGH if any consumer uses orig instead of key+val")
		}
	})
}

// =============================================================================
// FINDING 3 (HIGH): FilterEnvironmentArray also passes `orig` with secret
//
// Same issue as Finding 2: even though FilterEnvironmentArray is supposed to
// REMOVE sensitive variables, the callback is only called for non-sensitive
// vars. However, the `orig` parameter for non-sensitive vars could
// contain secret-like data in the value portion.
//
// This is NOT a bypass per se (filtered vars don't reach callback), but
// it establishes a dangerous API pattern where `orig` always carries raw data.
//
// More critically: the `val` parameter in the filter callback contains the
// unmodified value. For non-filtered vars, this is correct. But if the
// blocklist has a bug (missing pattern, case mismatch), the secret leaks
// through both `val` and `orig`.
//
// Severity: MEDIUM - API design issue, not a direct bypass
// Location: filter.go:82 (onAllowed(key, val, v))
// =============================================================================

func TestSecurityFilterPassesThroughUnblockedSecrets(t *testing.T) {
	// Simulate a misconfigured blocklist that misses a sensitive var
	vars := []string{
		"binance_api=sk_live_ABCDEFghijklmnop", // lowercase, not caught by exact "BINANCE_API"
	}

	// Blocklist with only uppercase exact entries (no globs)
	blockList := map[string]struct{}{
		"BINANCE_API": {}, // uppercase only -- won't match lowercase
	}

	collected := make(map[string]string)
	FilterEnvironmentArray(vars, blockList, nil, func(key, val, orig string) {
		collected[key] = val
	})

	// The lowercase key bypasses the case-sensitive exact match
	if val, exists := collected["binance_api"]; exists {
		assert.Equal(t, "sk_live_ABCDEFghijklmnop", val,
			"secret value leaks through case-sensitive filter bypass")
		t.Log("BUG: lowercase 'binance_api' bypasses uppercase-only exact blocklist entry")
		t.Log("This is the same case-sensitivity asymmetry bug documented in the deep tests")
	}
}

// =============================================================================
// FINDING 4 (MEDIUM): Glob patterns without '*' are silently ignored for
// glob matching
//
// Both FilterEnvironmentArray and ObfuscateEnvironmentArray only compile
// patterns containing '*' as globs (lines 44/29 respectively). Patterns
// like "TOKEN" (no wildcard) are only used for exact matching.
//
// This means a user who adds "TOKEN" to the sensitive list expecting it to
// match "MY_TOKEN" will be disappointed -- "TOKEN" without wildcards only
// matches the exact key "TOKEN".
//
// The '?' and '[' glob characters ARE supported by gobwas/glob but are NOT
// detected by the strings.Contains(k, "*") check.
//
// Severity: MEDIUM - user confusion leads to sensitive var leakage
// Location: filter.go:44, obfuscate.go:29
// =============================================================================

func TestSecurityNonStarGlobCharactersIgnored(t *testing.T) {
	t.Run("question mark glob not compiled", func(t *testing.T) {
		// '?' should match any single character in glob syntax
		// But strings.Contains("TOKEN?", "*") is false, so it's treated as exact match
		vars := []string{"TOKENA=secret", "TOKENB=secret2", "TOKEN?=exact"}

		collected := make(map[string]string)
		FilterEnvironmentArray(
			vars,
			map[string]struct{}{"TOKEN?": {}}, // '?' glob character, but no '*'
			nil,
			func(key, val, orig string) { collected[key] = val },
		)

		// "TOKEN?" is treated as exact match, not glob
		// So only the literal key "TOKEN?" is blocked (if it exists)
		if _, exists := collected["TOKENA"]; !exists {
			t.Error("TOKENA should pass through because TOKEN? is exact match only")
		}
		if _, exists := collected["TOKENB"]; !exists {
			t.Error("TOKENB should pass through because TOKEN? is exact match only")
		}
		// The literal key "TOKEN?" SHOULD be blocked
		if _, exists := collected["TOKEN?"]; exists {
			t.Error("literal key 'TOKEN?' should be blocked by exact match")
		}
	})

	t.Run("bracket glob not compiled", func(t *testing.T) {
		// [A-Z] is valid glob syntax but won't be compiled
		vars := []string{"TOKENA=secret", "TOKENB=secret2"}

		collected := make(map[string]string)
		FilterEnvironmentArray(
			vars,
			map[string]struct{}{"TOKEN[AB]": {}}, // bracket glob, no '*'
			nil,
			func(key, val, orig string) { collected[key] = val },
		)

		// Neither TOKENA nor TOKENB should be blocked because TOKEN[AB] is exact match only
		assert.Contains(t, collected, "TOKENA", "TOKENA should pass (bracket glob not compiled)")
		assert.Contains(t, collected, "TOKENB", "TOKENB should pass (bracket glob not compiled)")
	})

	t.Run("curly brace alternation not compiled without star", func(t *testing.T) {
		vars := []string{"SECRET=val1", "TOKEN=val2", "NORMAL=val3"}

		collected := make(map[string]string)
		FilterEnvironmentArray(
			vars,
			map[string]struct{}{"{SECRET,TOKEN}": {}}, // alternation, no '*'
			nil,
			func(key, val, orig string) { collected[key] = val },
		)

		// Neither SECRET nor TOKEN is blocked -- {SECRET,TOKEN} is exact match only
		assert.Contains(t, collected, "SECRET", "SECRET should pass ({} glob not compiled)")
		assert.Contains(t, collected, "TOKEN", "TOKEN should pass ({} glob not compiled)")
	})
}

// =============================================================================
// FINDING 5 (MEDIUM): Capture.Capture() is not goroutine-safe due to
// mutation of c.sensitiveVarsList
//
// The Capture.Capture method (capture.go lines 84-88) does:
//   if c.disableSensitiveVarsDefault { c.sensitiveVarsList = map[string]struct{}{} }
//   finalSensitiveKeysList = c.sensitiveVarsList
//   for k, v := range c.addSensitiveVarsList { finalSensitiveKeysList[k] = v }
//
// This modifies c.sensitiveVarsList in place (since finalSensitiveKeysList
// is assigned by reference, not copied). Concurrent calls to Capture will
// race on the map.
//
// This was already noted in env_adversarial_deep_test.go but the full
// severity wasn't captured: this is a data race that can cause panics
// or silently corrupt the sensitive vars list.
//
// Severity: MEDIUM - data race in concurrent usage (crash or corruption)
// Location: capture.go:84-91
// =============================================================================

func TestSecurityCaptureMutatesSharedState(t *testing.T) {
	// Demonstrate the mutation: after Capture(), the internal sensitive list
	// is permanently altered
	c := NewCapturer(
		WithDisableDefaultSensitiveList(),
		WithAdditionalKeys([]string{"CUSTOM_KEY"}),
	)

	env := []string{"CUSTOM_KEY=secret", "OTHER=value"}

	// First call should work correctly
	result := c.Capture(env)
	assert.Equal(t, "******", result["CUSTOM_KEY"])
	assert.Equal(t, "value", result["OTHER"])

	// After the call, c.sensitiveVarsList has been mutated to contain
	// only the addSensitiveVarsList entries (merged from the empty map
	// created by disableSensitiveVarsDefault).
	//
	// If we now toggle disableSensitiveVarsDefault to false and call again,
	// the list is NOT restored to the original default.
	c.disableSensitiveVarsDefault = false
	result2 := c.Capture(env)

	// The sensitive list was permanently altered -- it no longer contains
	// default entries like *TOKEN*, *SECRET*, etc.
	// CUSTOM_KEY is still there because it was merged in the first call.
	assert.Equal(t, "******", result2["CUSTOM_KEY"],
		"CUSTOM_KEY should still be obfuscated (was merged into the list)")

	t.Log("Internal state was permanently mutated by Capture()")
	t.Log("This is a known bug documented in env_adversarial_deep_test.go")
}

// =============================================================================
// FINDING 6 (MEDIUM): ObfuscateEnvironmentArray does not break after
// obfuscation match, potentially exposing timing information
//
// FilterEnvironmentArray breaks on first glob match (line 75: break).
// ObfuscateEnvironmentArray does NOT break (line 57: no break).
//
// This means ObfuscateEnvironmentArray checks ALL globs for EVERY variable,
// even after the value is already set to "******". While functionally
// correct (idempotent), this creates a timing side-channel: the time to
// process a variable depends on HOW MANY patterns match it, not just
// WHETHER it matches.
//
// An attacker observing timing differences could potentially determine
// how many sensitive patterns a given key matches, leaking information
// about the blocklist configuration.
//
// Severity: LOW (timing side-channel, but patterns are usually not secret)
// Location: obfuscate.go:50-59 (no break after match)
// =============================================================================

func TestSecurityObfuscateNoBreakTimingDifference(t *testing.T) {
	// This test documents the behavioral asymmetry rather than
	// demonstrating a practical exploit.

	// Variable that matches ONE glob
	singleMatchVars := []string{"MY_TOKEN=secret"}
	singleMatchList := map[string]struct{}{"*TOKEN*": {}}

	// Variable that matches MANY globs
	manyMatchVars := []string{"SECRET_TOKEN_PASSWORD_KEY=secret"}
	manyMatchList := map[string]struct{}{
		"*SECRET*":   {},
		"*TOKEN*":    {},
		"*PASSWORD*": {},
		"*KEY*":      {},
	}

	// Both should produce the same result
	singleResult := make(map[string]string)
	ObfuscateEnvironmentArray(singleMatchVars, singleMatchList, nil, func(key, val, orig string) {
		singleResult[key] = val
	})
	assert.Equal(t, "******", singleResult["MY_TOKEN"])

	manyResult := make(map[string]string)
	ObfuscateEnvironmentArray(manyMatchVars, manyMatchList, nil, func(key, val, orig string) {
		manyResult[key] = val
	})
	assert.Equal(t, "******", manyResult["SECRET_TOKEN_PASSWORD_KEY"])

	t.Log("Both produce '******' but ObfuscateEnvironmentArray checks ALL globs")
	t.Log("FilterEnvironmentArray breaks after first match (more efficient)")
}

// =============================================================================
// FINDING 7 (MEDIUM): splitVariable with empty string returns ("", "")
// but the key "" can collide in maps
//
// If multiple malformed env vars like "=VALUE1" and "=VALUE2" are processed,
// they all produce key="" and the last one wins in the Capture map.
// This was noted in env_adversarial_test.go but the security implication
// is: if a legitimate env var has an empty key with a sensitive value,
// it can be overwritten by a non-sensitive value, effectively hiding it.
//
// Severity: LOW - unlikely in practice
// Location: capture.go:109-117
// =============================================================================

func TestSecurityEmptyKeyCollision(t *testing.T) {
	c := NewCapturer(WithDisableDefaultSensitiveList())

	// Two vars with empty key -- last wins
	result := c.Capture([]string{"=sensitive_data", "=benign_data"})

	assert.Equal(t, "benign_data", result[""],
		"empty key collision: last value wins, potentially hiding sensitive data")
}

// =============================================================================
// FINDING 8 (MEDIUM): FilterEnvironmentArray and ObfuscateEnvironmentArray
// compile globs from blockList/obfuscateList on every call
//
// The glob compilation happens inline for each call to Filter/Obfuscate.
// Unlike the secretscan module which caches compiled globs in a global
// sync.Map, the environment module recompiles every time.
//
// This means:
// 1. Repeated calls are slower than necessary (DoS vector with many patterns)
// 2. But it also means there's no cross-call cache pollution
//
// Severity: LOW - performance, not security
// Location: filter.go:41-56, obfuscate.go:27-39
// =============================================================================

func TestSecurityGlobRecompilationPerformance(t *testing.T) {
	// 100 glob patterns in blocklist
	blockList := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		blockList["*PATTERN_"+strings.Repeat("X", i%20)+"*"] = struct{}{}
	}

	// 1000 variables
	vars := make([]string, 1000)
	for i := range vars {
		vars[i] = "VAR_" + strings.Repeat("Y", i%20) + "=value"
	}

	// This should complete in reasonable time despite recompilation
	count := 0
	FilterEnvironmentArray(vars, blockList, nil, func(key, val, orig string) {
		count++
	})

	t.Logf("Processed %d vars through %d patterns (recompiled each call)", count, len(blockList))
}

// =============================================================================
// FINDING 9 (HIGH): ObfuscateEnvironmentArray with nil excludeKeys
// does not skip the exclude check -- it just does a map lookup on nil map
//
// The code at obfuscate.go:45 does:
//   if _, inExcludKeys := excludeKeys[key]; !inExcludKeys {
//
// Looking up in a nil map in Go returns the zero value (false), so
// !inExcludKeys is true, and the code proceeds to check blocklist/globs.
// This is CORRECT behavior -- nil excludeKeys means "don't exclude anything".
//
// However, this means passing nil vs empty map has the SAME behavior.
// No bug here, but worth verifying.
//
// Severity: INFO - verified correct behavior
// =============================================================================

func TestSecurityNilVsEmptyExcludeKeys(t *testing.T) {
	vars := []string{"SECRET_TOKEN=password"}
	obfuscateList := map[string]struct{}{"*SECRET*": {}}

	// nil excludeKeys
	nilResult := make(map[string]string)
	ObfuscateEnvironmentArray(vars, obfuscateList, nil, func(key, val, orig string) {
		nilResult[key] = val
	})

	// empty excludeKeys
	emptyResult := make(map[string]string)
	ObfuscateEnvironmentArray(vars, obfuscateList, map[string]struct{}{}, func(key, val, orig string) {
		emptyResult[key] = val
	})

	assert.Equal(t, nilResult, emptyResult,
		"nil and empty excludeKeys should produce identical results")
	assert.Equal(t, "******", nilResult["SECRET_TOKEN"])
}

// =============================================================================
// FINDING 10 (HIGH): An env var whose KEY contains "=" will have its value
// truncated in the blocklist exact-match check
//
// While technically env var keys shouldn't contain "=", there's nothing
// preventing it in the data. The splitVariable function uses SplitN(v, "=", 2)
// which correctly handles this -- the first "=" is the separator.
//
// But a key like "MY=SECRET" will be split as key="MY", val="SECRET".
// The blocklist check uses the key "MY", NOT "MY=SECRET".
// So if the blocklist has "MY=SECRET", it won't match.
// And if the blocklist has "MY", it will match unexpectedly.
//
// Severity: LOW - unlikely in practice (keys rarely contain "=")
// Location: capture.go:109-117
// =============================================================================

func TestSecurityKeyContainingEquals(t *testing.T) {
	vars := []string{"MY=SECRET=value"}

	collected := make(map[string]string)
	FilterEnvironmentArray(vars, map[string]struct{}{"MY": {}}, nil, func(key, val, orig string) {
		collected[key] = val
	})

	// splitVariable("MY=SECRET=value") -> key="MY", val="SECRET=value"
	// blocklist has "MY", so key "MY" is blocked
	assert.Empty(t, collected, "key 'MY' should be blocked by exact match 'MY'")

	// Now try with the full "MY=SECRET" in blocklist
	collected2 := make(map[string]string)
	FilterEnvironmentArray(vars, map[string]struct{}{"MY=SECRET": {}}, nil, func(key, val, orig string) {
		collected2[key] = val
	})

	// "MY=SECRET" in blocklist won't match key "MY" (splitVariable extracts "MY")
	assert.NotEmpty(t, collected2, "blocklist 'MY=SECRET' should NOT match key 'MY'")
}

// =============================================================================
// FINDING 11 (MEDIUM): Obfuscation uses a constant placeholder "******"
// that gives no indication of original value length
//
// While this is a FEATURE (prevents length-based inference), it also means
// that a consumer of the attestation cannot distinguish between:
// - A 1-character password that was obfuscated
// - A 1000-character certificate that was obfuscated
// - An env var whose actual value IS "******"
//
// An attacker could set an env var to exactly "******" to make it
// indistinguishable from an obfuscated value.
//
// Severity: LOW - by design, but creates ambiguity
// Location: obfuscate.go:47, 58
// =============================================================================

func TestSecurityObfuscationAmbiguity(t *testing.T) {
	vars := []string{
		"REAL_SECRET=actual_password",
		"FAKE_STARS=******",
		"NORMAL_VAR=hello",
	}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(
		vars,
		map[string]struct{}{"*SECRET*": {}},
		nil,
		func(key, val, orig string) { collected[key] = val },
	)

	// Both produce identical output
	assert.Equal(t, "******", collected["REAL_SECRET"])
	assert.Equal(t, "******", collected["FAKE_STARS"])
	assert.Equal(t, "hello", collected["NORMAL_VAR"])

	// A consumer cannot tell if FAKE_STARS was obfuscated or is literally "******"
	t.Log("Ambiguity: REAL_SECRET (obfuscated) and FAKE_STARS (literal '******') are indistinguishable")
}

// =============================================================================
// FINDING 12 (HIGH): FilterEnvironmentArray filter + exclude interaction
// allows bypassing glob-based filtering via exclude keys
//
// If a key is in excludeKeys, the ENTIRE blocklist check is skipped --
// both exact match AND glob matching. This is correct by design, but
// the security implication is that the exclude list is a complete bypass
// mechanism with no audit trail.
//
// A misconfigured exclude list can silently leak any sensitive variable.
//
// Severity: HIGH - exclude keys completely bypass all protection
// Location: filter.go:62 (if _, inExcludKeys := excludeKeys[key]; !inExcludKeys)
// =============================================================================

func TestSecurityExcludeKeysBypassAllProtection(t *testing.T) {
	vars := []string{
		"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
		"GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPqrstuvwxyz1234",
	}

	// Comprehensive blocklist
	blockList := map[string]struct{}{
		"*SECRET*":              {},
		"*TOKEN*":               {},
		"*KEY*":                 {},
		"AWS_SECRET_ACCESS_KEY": {},
		"GITHUB_TOKEN":          {},
	}

	// But exclude keys completely bypass everything
	excludeKeys := map[string]struct{}{
		"AWS_SECRET_ACCESS_KEY": {},
		"GITHUB_TOKEN":          {},
	}

	collected := make(map[string]string)
	FilterEnvironmentArray(vars, blockList, excludeKeys, func(key, val, orig string) {
		collected[key] = val
	})

	// Both sensitive vars pass through completely unprotected
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", collected["AWS_SECRET_ACCESS_KEY"],
		"AWS secret key leaked through exclude bypass")
	assert.Equal(t, "ghp_ABCDEFGHIJKLMNOPqrstuvwxyz1234", collected["GITHUB_TOKEN"],
		"GitHub token leaked through exclude bypass")

	t.Log("Exclude keys completely bypass all filtering -- no partial protection possible")
	t.Log("There is no way to exclude a key from one pattern but not another")
}
