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

// Security audit tests for secretscan -- R3-160 through R3-164.
//
// Each test targets a specific, provable flaw in the secret scanning logic.
// Tests are designed to FAIL if the bug is present and PASS once fixed.
package secretscan

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// R3-160: checkDecodedContentForSensitiveValues leaks secret values via
// strings.Replace with count=1
//
// SECURITY IMPACT:
//   When a decoded line is shorter than 40 characters and contains the same
//   secret value more than once, the code at envscan.go:327 calls:
//       match = strings.Replace(line, matchValue, "[REDACTED]", 1)
//   The fourth argument (1) means "replace only the FIRST occurrence."
//   The second and subsequent occurrences of the secret remain in cleartext
//   in the Finding.Match field, which is serialized into the attestation JSON.
//
//   This means the actual secret value is exposed in the final attestation
//   output, completely defeating the purpose of the redaction logic.
//
// AFFECTED CODE: envscan.go lines 326-327 (short line path)
//                envscan.go lines 329-333 (long line path, same issue)
// =============================================================================

func TestSecurity_R3_160_RedactionLeaksDuplicateSecret(t *testing.T) {
	a := New()

	const envKey = "TEST_R3_160_TOKEN"
	const secretVal = "s3cr3t_val" // 10 chars, above minSensitiveValueLength (4)

	os.Setenv(envKey, secretVal)
	defer os.Unsetenv(envKey)

	sensitiveVars := map[string]struct{}{envKey: {}}
	processedMap := make(map[string]struct{})

	// Construct a short line (< 40 chars) with the secret appearing twice.
	// "s3cr3t_val s3cr3t_val" = 21 chars, well under 40.
	decodedContent := secretVal + " " + secretVal

	findings := a.checkDecodedContentForSensitiveValues(
		decodedContent,
		"test-source",
		"base64",
		sensitiveVars,
		processedMap,
	)

	require.NotEmpty(t, findings,
		"Should detect the sensitive env var in decoded content")

	matchField := findings[0].Match

	// BUG: strings.Replace(line, matchValue, "[REDACTED]", 1) only replaces
	// the first occurrence. The second "s3cr3t_val" remains unredacted.
	//
	// The fix: use strings.ReplaceAll(line, matchValue, "[REDACTED]")
	// or use -1 as the count argument.
	assert.NotContains(t, matchField, secretVal,
		"Finding.Match MUST NOT contain the raw secret value. "+
			"strings.Replace with count=1 only redacts the first occurrence; "+
			"additional occurrences leak the actual secret into the attestation output. "+
			"Got: %q", matchField)
}

// =============================================================================
// R3-161: checkDecodedContentForSensitiveValues leaks secret in the long-line
// path (>= 40 chars) via the same strings.Replace(count=1) bug
//
// SECURITY IMPACT:
//   Same root cause as R3-160 but in the else branch (envscan.go:329-333).
//   When the line is >= 40 chars, the code extracts a context window of
//   10 chars on each side of the match, then calls strings.Replace with
//   count=1. If the context window happens to contain the secret twice
//   (e.g., the secret is repeated adjacently), the second occurrence leaks.
//
// AFFECTED CODE: envscan.go lines 329-333
// =============================================================================

func TestSecurity_R3_161_RedactionLeaksLongLineContext(t *testing.T) {
	a := New()

	const envKey = "TEST_R3_161_KEY"
	// Use a short secret so two copies fit within the extraction window.
	// The context extraction grabs matchValue+10 chars on each side.
	const secretVal = "XYZZY" // 5 chars, above minimum

	os.Setenv(envKey, secretVal)
	defer os.Unsetenv(envKey)

	sensitiveVars := map[string]struct{}{envKey: {}}
	processedMap := make(map[string]struct{})

	// Build a line >= 40 chars where the secret appears twice, adjacent.
	// The context window (valueIndex-10 to valueIndex+len(value)+10) will
	// encompass both copies.
	padding := strings.Repeat("A", 20)
	decodedContent := padding + secretVal + secretVal + padding
	// Total: 20 + 5 + 5 + 20 = 50 chars >= 40

	findings := a.checkDecodedContentForSensitiveValues(
		decodedContent,
		"test-source",
		"hex",
		sensitiveVars,
		processedMap,
	)

	require.NotEmpty(t, findings,
		"Should detect the sensitive env var in decoded content")

	matchField := findings[0].Match

	// The extracted context will contain both copies of XYZZY but
	// strings.Replace only redacts the first one.
	assert.NotContains(t, matchField, secretVal,
		"Finding.Match MUST NOT contain the raw secret after redaction. "+
			"Long-line context extraction uses strings.Replace(ctx, val, '[REDACTED]', 1) "+
			"which only replaces the first occurrence. Got: %q", matchField)
}

// =============================================================================
// R3-162: findPatternMatchesWithRedaction context window leaks adjacent secrets
//
// SECURITY IMPACT:
//   When a secret is found in content, the function extracts a context window
//   of redactionMatchContextSize (15) characters before and after the match.
//   The match itself is replaced with [SENSITIVE-VALUE], but the context chars
//   are NOT checked for sensitive content.
//
//   If two different secrets appear within 15 characters of each other, the
//   context window for one secret's finding will contain part or all of the
//   adjacent secret in cleartext.
//
//   This leaks secret material into the Finding.Match field, which is stored
//   in the attestation and may be displayed in UIs or logged.
//
// AFFECTED CODE: envscan.go lines 147-168 (findPatternMatchesWithRedaction)
// =============================================================================

func TestSecurity_R3_162_ContextWindowLeaksAdjacentSecret(t *testing.T) {
	a := New()

	// Two different secrets, placed close together.
	secret1 := "AAAA_FIRST_SECRET_AAAA" // 22 chars
	secret2 := "BBBB_SECOND_SECRET_BBBB" // 23 chars

	// Separate them by only 3 characters -- well within the 15-char context window.
	content := secret1 + "---" + secret2

	// Search for secret1. The suffix context will extend 15 chars past the end
	// of secret1, capturing "---BBBB_SECOND_" (15 chars) of secret2.
	matches := a.findPatternMatchesWithRedaction(content, secret1)
	require.Len(t, matches, 1, "Should find exactly one match for secret1")

	matchContext := matches[0].matchContext

	// The matchContext format is: [prefix_context][SENSITIVE-VALUE][suffix_context]
	// The suffix_context should NOT contain material from secret2.
	assert.NotContains(t, matchContext, "BBBB",
		"Context window after redacted match leaks adjacent secret data. "+
			"The %d-char suffix context overlaps into the next secret. "+
			"Fix: redact or eliminate context windows, or validate context "+
			"against the sensitive values list. Got: %q",
		redactionMatchContextSize, matchContext)
}

// =============================================================================
// R3-163: isEnvironmentVariableSensitive exact match is case-sensitive but
// DefaultSensitiveEnvList contains lowercase entries that real CI systems
// export in uppercase
//
// SECURITY IMPACT:
//   The DefaultSensitiveEnvList (sensitive_env_vars.go) contains lowercase
//   exact entries like "binance_api", "binance_secret", "square_access_token",
//   and "square_oauth_secret". These are NOT glob patterns (no wildcards).
//
//   The isEnvironmentVariableSensitive function (envscan.go:52-87) does:
//   1. Exact map lookup (case-sensitive): sensitiveEnvVars[key]
//   2. Glob matching (case-INsensitive): uppercases both pattern and key
//
//   Problem: The exact lookup at step 1 is case-sensitive. If a CI system
//   exports "BINANCE_API" (uppercase), the exact match for "binance_api"
//   fails. And no glob pattern catches it because:
//   - *TOKEN* doesn't match (no "TOKEN" substring)
//   - *SECRET* doesn't match (no "SECRET" substring)
//   - *API_KEY* doesn't match (has "API" but not "API_KEY")
//   - *PASSWORD* doesn't match
//
//   Result: BINANCE_API environment variable value is NOT detected as
//   sensitive, and its value will not be scanned for leakage.
//
// AFFECTED CODE: envscan.go lines 52-54 (exact match), sensitive_env_vars.go
// =============================================================================

func TestSecurity_R3_163_CaseSensitiveExactMatchBypass(t *testing.T) {
	// Test with the actual DefaultSensitiveEnvList to prove the bypass.
	sensitiveVars := defaultSensitiveList()

	// These exact lowercase entries exist in DefaultSensitiveEnvList.
	// Their uppercase equivalents should ALSO be detected as sensitive,
	// because real CI environments commonly use uppercase env var names.
	caseBypasses := []struct {
		listed    string // as it appears in DefaultSensitiveEnvList
		uppercase string // how CI systems often export it
		caughtBy  string // which glob should catch it (if any)
	}{
		// binance_api is listed in lowercase. Uppercase BINANCE_API is NOT
		// caught by any glob: no TOKEN, SECRET, API_KEY, PASSWORD substring.
		{"binance_api", "BINANCE_API", "none -- no glob catches this"},

		// square_access_token is listed in lowercase. Uppercase version IS
		// caught by *TOKEN* glob, so this one is actually OK.
		{"square_access_token", "SQUARE_ACCESS_TOKEN", "*TOKEN*"},

		// square_oauth_secret is listed in lowercase. Uppercase version IS
		// caught by *SECRET* glob, so this one is also OK.
		{"square_oauth_secret", "SQUARE_OAUTH_SECRET", "*SECRET*"},
	}

	for _, tc := range caseBypasses {
		t.Run(tc.uppercase, func(t *testing.T) {
			// Verify the lowercase version IS in the list.
			_, listed := sensitiveVars[tc.listed]
			require.True(t, listed, "%q should be in DefaultSensitiveEnvList", tc.listed)

			// The uppercase version should also be detected.
			detected := isEnvironmentVariableSensitive(tc.uppercase, sensitiveVars)

			// BINANCE_API is the one that actually bypasses detection.
			if tc.uppercase == "BINANCE_API" {
				assert.True(t, detected,
					"BINANCE_API (uppercase) is NOT detected as sensitive. "+
						"The exact entry 'binance_api' is case-sensitive and fails. "+
						"No glob pattern (*TOKEN*, *SECRET*, *API_KEY*, *PASSWORD*, etc.) "+
						"catches 'BINANCE_API' either. "+
						"Fix: normalize exact entries to uppercase, or add case-insensitive "+
						"exact matching.")
			} else {
				// These should be caught by glob patterns even without exact match.
				if !detected {
					t.Errorf("%s not detected even though %s glob should catch it",
						tc.uppercase, tc.caughtBy)
				}
			}
		})
	}
}

// =============================================================================
// R3-164: compiledGlobCache is a process-global sync.Map with no eviction,
// causing unbounded memory growth across attestation runs
//
// SECURITY IMPACT:
//   The compiledGlobCache (envscan.go:35) is a package-level sync.Map that
//   caches compiled glob patterns. Every unique pattern ever compiled is
//   stored forever. In a long-running daemon (e.g., a CI controller that
//   runs attestations continuously), each unique sensitive env var pattern
//   adds an entry that is never removed.
//
//   Denial of service: An attacker who can influence the sensitive env var
//   configuration (e.g., via policy files) can force compilation of an
//   unbounded number of unique glob patterns, exhausting memory.
//
//   Stale cache: Patterns from previous attestation contexts persist into
//   subsequent runs. While this doesn't directly cause false negatives
//   (the cached patterns are still correct for their original strings),
//   it means the process's memory footprint only grows, never shrinks.
//
// AFFECTED CODE: envscan.go line 35 (compiledGlobCache)
// =============================================================================

func TestSecurity_R3_164_GlobCacheUnboundedGrowth(t *testing.T) {
	// Reset the global cache to a known state.
	compiledGlobCache = sync.Map{}

	countEntries := func() int {
		count := 0
		compiledGlobCache.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
		return count
	}

	require.Equal(t, 0, countEntries(), "cache should start empty")

	// Simulate 500 attestation runs, each with a unique glob pattern.
	// In a real scenario, these could come from different policy files
	// or user configurations across many CI jobs.
	const numRuns = 500
	for i := 0; i < numRuns; i++ {
		pattern := "*UNIQUE_PATTERN_" + strings.Repeat("X", i%100) + "_" + string(rune('A'+(i%26))) + "*"
		sensitive := map[string]struct{}{pattern: {}}
		_ = isEnvironmentVariableSensitive("SOME_KEY", sensitive)
	}

	finalCount := countEntries()

	// The cache should have been bounded (e.g., LRU eviction, or scoped
	// to an attestation run). Instead, it grows without limit.
	//
	// A properly bounded cache would have at most N entries (for some
	// configured maximum N). We assert that the cache should not exceed
	// a reasonable bound -- say 100 entries. If it does, the unbounded
	// growth bug is confirmed.
	const maxAcceptableEntries = 100
	assert.LessOrEqual(t, finalCount, maxAcceptableEntries,
		"compiledGlobCache grew to %d entries after %d runs with no eviction. "+
			"The global sync.Map caches every unique pattern forever, causing "+
			"unbounded memory growth in long-running processes. "+
			"Fix: scope the cache to an Attestor instance, or implement LRU eviction.",
		finalCount, numRuns)
}

// =============================================================================
// Helper: defaultSensitiveList re-export for test access
// (the public function is in the attestation package; we access it via the attestor)
// =============================================================================

func defaultSensitiveList() map[string]struct{} {
	a := New()
	return a.getSensitiveEnvVarsList()
}
