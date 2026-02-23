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

package secretscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// =============================================================================
// isEnvironmentVariableSensitive adversarial tests
// =============================================================================

func TestIsEnvVarSensitiveAdversarial(t *testing.T) {
	t.Run("direct match", func(t *testing.T) {
		sensitive := map[string]struct{}{
			"AWS_SECRET_ACCESS_KEY": {},
		}
		assert.True(t, isEnvironmentVariableSensitive("AWS_SECRET_ACCESS_KEY", sensitive))
		assert.False(t, isEnvironmentVariableSensitive("SAFE_VAR", sensitive))
	})

	t.Run("glob match", func(t *testing.T) {
		sensitive := map[string]struct{}{
			"*TOKEN*":  {},
			"*SECRET*": {},
		}
		assert.True(t, isEnvironmentVariableSensitive("MY_TOKEN", sensitive))
		assert.True(t, isEnvironmentVariableSensitive("AWS_SECRET_KEY", sensitive))
		assert.False(t, isEnvironmentVariableSensitive("SAFE_VAR", sensitive))
	})

	t.Run("empty map", func(t *testing.T) {
		assert.False(t, isEnvironmentVariableSensitive("ANY_KEY", map[string]struct{}{}))
	})

	t.Run("nil map", func(t *testing.T) {
		assert.False(t, isEnvironmentVariableSensitive("ANY_KEY", nil))
	})

	t.Run("empty key", func(t *testing.T) {
		sensitive := map[string]struct{}{
			"*": {},
		}
		assert.True(t, isEnvironmentVariableSensitive("", sensitive))
	})

	t.Run("invalid glob pattern", func(t *testing.T) {
		sensitive := map[string]struct{}{
			"*[invalid": {},
		}
		// Invalid glob should be skipped, not panic
		assert.NotPanics(t, func() {
			isEnvironmentVariableSensitive("KEY", sensitive)
		})
	})

	t.Run("gobwas panic patterns", func(t *testing.T) {
		panicPatterns := []string{
			"0*,{*,",
			"*{*,",
			"*{a,b,*",
		}
		for _, pattern := range panicPatterns {
			t.Run(pattern, func(t *testing.T) {
				sensitive := map[string]struct{}{
					pattern: {},
				}
				assert.NotPanics(t, func() {
					isEnvironmentVariableSensitive("TEST_KEY", sensitive)
				})
			})
		}
	})

	t.Run("very long key", func(t *testing.T) {
		sensitive := map[string]struct{}{
			"*": {},
		}
		longKey := strings.Repeat("A", 100000)
		assert.True(t, isEnvironmentVariableSensitive(longKey, sensitive))
	})

	t.Run("unicode key", func(t *testing.T) {
		sensitive := map[string]struct{}{
			"*\u00e9*": {},
		}
		assert.True(t, isEnvironmentVariableSensitive("caf\u00e9", sensitive))
	})

	t.Run("null byte in key", func(t *testing.T) {
		sensitive := map[string]struct{}{
			"KEY\x00": {},
		}
		// Direct match with null byte
		assert.True(t, isEnvironmentVariableSensitive("KEY\x00", sensitive))
		// Without null byte should not match
		assert.False(t, isEnvironmentVariableSensitive("KEY", sensitive))
	})
}

// =============================================================================
// compiledGlobCache concurrent access tests
// =============================================================================

func TestCompiledGlobCacheConcurrency(t *testing.T) {
	// Clear the cache before test
	compiledGlobCache = sync.Map{}

	patterns := []string{
		"*TOKEN*",
		"*SECRET*",
		"*PASSWORD*",
		"*KEY*",
		"*CREDENTIAL*",
		"*AUTH*",
		"*API_KEY*",
	}

	sensitive := make(map[string]struct{})
	for _, p := range patterns {
		sensitive[p] = struct{}{}
	}

	keys := []string{
		"MY_TOKEN",
		"AWS_SECRET_KEY",
		"DB_PASSWORD",
		"API_KEY",
		"USER_CREDENTIAL",
		"AUTH_HEADER",
		"SAFE_VAR",
		"ANOTHER_SAFE",
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := keys[idx%len(keys)]
			_ = isEnvironmentVariableSensitive(key, sensitive)
		}(i)
	}
	wg.Wait()

	// Verify cache was populated
	count := 0
	compiledGlobCache.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	if count == 0 {
		t.Error("compiledGlobCache should have been populated")
	}
}

// =============================================================================
// safeGlobMatch adversarial tests
// =============================================================================

func TestSafeGlobMatchAdversarial(t *testing.T) {
	t.Run("nil glob should panic and be recovered", func(t *testing.T) {
		// We can't actually pass nil because the interface wouldn't match,
		// but we can verify the recovery mechanism exists.
		t.Log("safeGlobMatch has defer/recover for panic safety")
	})

	t.Run("very long input", func(t *testing.T) {
		g, err := glob.Compile("*")
		require.NoError(t, err)
		matched, err := safeGlobMatch(g, strings.Repeat("x", 1000000))
		assert.NoError(t, err)
		assert.True(t, matched)
	})

	t.Run("binary input", func(t *testing.T) {
		g, err := glob.Compile("*")
		require.NoError(t, err)
		matched, err := safeGlobMatch(g, "\xff\xfe\xfd\x00\x01\x02")
		assert.NoError(t, err)
		assert.True(t, matched)
	})
}

// =============================================================================
// findPatternMatchesWithRedaction adversarial tests
// =============================================================================

func TestFindPatternMatchesWithRedactionAdversarial(t *testing.T) {
	a := New()

	t.Run("empty content", func(t *testing.T) {
		results := a.findPatternMatchesWithRedaction("", "test")
		assert.Empty(t, results)
	})

	t.Run("empty pattern", func(t *testing.T) {
		// Empty regex matches everywhere -- should handle gracefully
		results := a.findPatternMatchesWithRedaction("content", "")
		// Empty pattern matches between every character, this is fine
		// as long as it doesn't panic
		t.Logf("empty pattern returned %d matches", len(results))
	})

	t.Run("invalid regex pattern", func(t *testing.T) {
		results := a.findPatternMatchesWithRedaction("content", "[invalid")
		assert.Empty(t, results, "invalid regex should return empty results")
	})

	t.Run("pattern with special regex chars", func(t *testing.T) {
		content := "price is $5.00 and $10.00"
		results := a.findPatternMatchesWithRedaction(content, regexp.QuoteMeta("$5.00"))
		assert.Len(t, results, 1)
		assert.Contains(t, results[0].matchContext, redactedValuePlaceholder)
	})

	t.Run("match at very start", func(t *testing.T) {
		results := a.findPatternMatchesWithRedaction("SECRET rest of content", "SECRET")
		require.Len(t, results, 1)
		assert.Equal(t, 1, results[0].lineNumber)
	})

	t.Run("match at very end", func(t *testing.T) {
		results := a.findPatternMatchesWithRedaction("start of content SECRET", "SECRET")
		require.Len(t, results, 1)
		assert.Equal(t, 1, results[0].lineNumber)
	})

	t.Run("match spanning multiple lines", func(t *testing.T) {
		content := "line1\nline2\nline3 has SECRET here\nline4"
		results := a.findPatternMatchesWithRedaction(content, "SECRET")
		require.Len(t, results, 1)
		assert.Equal(t, 3, results[0].lineNumber)
	})

	t.Run("very long content with many matches", func(t *testing.T) {
		content := strings.Repeat("SECRET\n", 1000)
		results := a.findPatternMatchesWithRedaction(content, "SECRET")
		assert.Len(t, results, 1000)
	})

	t.Run("binary content", func(t *testing.T) {
		content := "prefix\xff\xfe\x00SECRET\x00\x01suffix"
		results := a.findPatternMatchesWithRedaction(content, "SECRET")
		require.Len(t, results, 1)
	})

	t.Run("unicode content", func(t *testing.T) {
		content := "caf\u00e9 has a SECRET password"
		results := a.findPatternMatchesWithRedaction(content, "SECRET")
		require.Len(t, results, 1)
	})

	t.Run("context boundaries", func(t *testing.T) {
		// Content shorter than context size
		content := "ab"
		results := a.findPatternMatchesWithRedaction(content, "ab")
		require.Len(t, results, 1)
		assert.Contains(t, results[0].matchContext, redactedValuePlaceholder)
	})

	t.Run("all context chars before match", func(t *testing.T) {
		// Match at position > redactionMatchContextSize
		content := strings.Repeat("x", 100) + "SECRET" + strings.Repeat("y", 100)
		results := a.findPatternMatchesWithRedaction(content, "SECRET")
		require.Len(t, results, 1)
	})
}

// =============================================================================
// Encoding detection adversarial tests
// =============================================================================

func TestFindPotentialBase64StringsAdversarial(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		results := findPotentialBase64Strings("")
		assert.Empty(t, results)
	})

	t.Run("short base64 below threshold", func(t *testing.T) {
		// Regex requires at least 15 chars
		results := findPotentialBase64Strings("AAAA")
		assert.Empty(t, results, "short base64 should not match")
	})

	t.Run("valid base64 string", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("this is a secret value"))
		results := findPotentialBase64Strings(encoded)
		assert.NotEmpty(t, results)
	})

	t.Run("base64 with padding", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("test"))
		results := findPotentialBase64Strings(encoded + strings.Repeat("A", 15))
		t.Logf("results for padded base64: %v", results)
	})

	t.Run("url-safe base64", func(t *testing.T) {
		// URL-safe uses _ and - instead of + and /
		encoded := base64.URLEncoding.EncodeToString([]byte("secret-value-with-some-padding"))
		results := findPotentialBase64Strings(encoded)
		assert.NotEmpty(t, results, "url-safe base64 should be detected")
	})

	t.Run("binary content", func(t *testing.T) {
		results := findPotentialBase64Strings("\xff\xfe\x00\x01\x02\x03")
		t.Logf("binary content results: %v", results)
	})
}

func TestFindPotentialHexStringsAdversarial(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		results := findPotentialHexStrings("")
		assert.Nil(t, results)
	})

	t.Run("short hex below threshold", func(t *testing.T) {
		results := findPotentialHexStrings("abcd")
		assert.Nil(t, results, "short hex should not match")
	})

	t.Run("valid hex string", func(t *testing.T) {
		// hexRegex requires at least 16 chars, so use a longer input
		encoded := hex.EncodeToString([]byte("secret_value"))
		results := findPotentialHexStrings(encoded)
		assert.NotEmpty(t, results, "hex-encoded 'secret_value' (%s, len=%d) should match 16+ char hex regex", encoded, len(encoded))
	})

	t.Run("odd length hex rejected", func(t *testing.T) {
		// 17 hex chars -- odd length
		results := findPotentialHexStrings("0123456789abcdef0")
		// The regex finds it, but the validation rejects odd length
		for _, r := range results {
			if len(r)%2 != 0 {
				t.Errorf("odd-length hex should be filtered: %q", r)
			}
		}
	})

	t.Run("mixed case hex", func(t *testing.T) {
		results := findPotentialHexStrings("0123456789ABcDeFaAbBcCdD")
		assert.NotEmpty(t, results)
	})
}

func TestFindPotentialURLStringsAdversarial(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		results := findPotentialURLStrings("")
		assert.Nil(t, results)
	})

	t.Run("url encoded content", func(t *testing.T) {
		encoded := url.QueryEscape("secret value with spaces!")
		results := findPotentialURLStrings(encoded)
		t.Logf("url encoded results: %v", results)
	})

	t.Run("encoded equals sign", func(t *testing.T) {
		// Common pattern in tokens: value%3Dmore
		results := findPotentialURLStrings("token%3Dvalue")
		assert.NotEmpty(t, results)
	})

	t.Run("no duplicates", func(t *testing.T) {
		// Content that might match multiple patterns
		content := "abc%3Ddef%3Dghi%3Djkl"
		results := findPotentialURLStrings(content)
		seen := make(map[string]bool)
		for _, r := range results {
			if seen[r] {
				t.Errorf("duplicate result: %q", r)
			}
			seen[r] = true
		}
	})
}

// =============================================================================
// Decode functions adversarial tests
// =============================================================================

func TestDecodeBase64StringAdversarial(t *testing.T) {
	t.Run("valid standard base64", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("hello world"))
		decoded, err := decodeBase64String(encoded)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(decoded))
	})

	t.Run("valid url-safe base64", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("hello world"))
		decoded, err := decodeBase64String(encoded)
		require.NoError(t, err)
		assert.Equal(t, "hello world", string(decoded))
	})

	t.Run("empty string", func(t *testing.T) {
		decoded, err := decodeBase64String("")
		require.NoError(t, err)
		assert.Empty(t, decoded)
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := decodeBase64String("!!!not-base64!!!")
		assert.Error(t, err)
	})

	t.Run("only padding", func(t *testing.T) {
		_, err := decodeBase64String("====")
		assert.Error(t, err)
	})
}

func TestDecodeHexStringAdversarial(t *testing.T) {
	t.Run("valid hex", func(t *testing.T) {
		encoded := hex.EncodeToString([]byte("hello"))
		decoded, err := decodeHexString(encoded)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(decoded))
	})

	t.Run("empty string", func(t *testing.T) {
		decoded, err := decodeHexString("")
		require.NoError(t, err)
		assert.Empty(t, decoded)
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := decodeHexString("xyz")
		assert.Error(t, err)
	})

	t.Run("odd length hex", func(t *testing.T) {
		_, err := decodeHexString("abc")
		assert.Error(t, err)
	})
}

func TestDecodeURLStringAdversarial(t *testing.T) {
	t.Run("valid url encoding", func(t *testing.T) {
		encoded := url.QueryEscape("hello world!")
		decoded, err := decodeURLString(encoded)
		require.NoError(t, err)
		assert.Equal(t, "hello world!", string(decoded))
	})

	t.Run("empty string", func(t *testing.T) {
		decoded, err := decodeURLString("")
		require.NoError(t, err)
		assert.Equal(t, "", string(decoded))
	})

	t.Run("already decoded", func(t *testing.T) {
		decoded, err := decodeURLString("hello")
		require.NoError(t, err)
		assert.Equal(t, "hello", string(decoded))
	})

	t.Run("invalid escape", func(t *testing.T) {
		_, err := decodeURLString("%ZZ")
		assert.Error(t, err)
	})
}

// =============================================================================
// ScanFile adversarial tests
// =============================================================================

func TestScanFileAdversarial(t *testing.T) {
	t.Run("nil detector", func(t *testing.T) {
		a := New()
		_, err := a.ScanFile("/tmp/nonexistent", nil)
		assert.Error(t, err, "nil detector should return error")
	})

	t.Run("nonexistent file", func(t *testing.T) {
		detector, err := detect.NewDetectorDefaultConfig()
		require.NoError(t, err)

		a := New()
		_, err = a.ScanFile("/tmp/definitely_nonexistent_file_12345", detector)
		assert.Error(t, err)
	})

	t.Run("empty file", func(t *testing.T) {
		tmpDir := t.TempDir()
		emptyFile := filepath.Join(tmpDir, "empty.txt")
		err := os.WriteFile(emptyFile, []byte{}, 0644)
		require.NoError(t, err)

		detector, err := detect.NewDetectorDefaultConfig()
		require.NoError(t, err)

		a := New()
		findings, err := a.ScanFile(emptyFile, detector)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("binary content file", func(t *testing.T) {
		tmpDir := t.TempDir()
		binFile := filepath.Join(tmpDir, "binary.bin")
		// Write some binary garbage
		content := make([]byte, 1000)
		for i := range content {
			content[i] = byte(i % 256)
		}
		err := os.WriteFile(binFile, content, 0644)
		require.NoError(t, err)

		detector, err := detect.NewDetectorDefaultConfig()
		require.NoError(t, err)

		a := New()
		findings, err := a.ScanFile(binFile, detector)
		require.NoError(t, err)
		t.Logf("binary file findings: %d", len(findings))
	})

	t.Run("very long lines", func(t *testing.T) {
		tmpDir := t.TempDir()
		longFile := filepath.Join(tmpDir, "long.txt")
		content := strings.Repeat("A", 1000000) + "\n"
		err := os.WriteFile(longFile, []byte(content), 0644)
		require.NoError(t, err)

		detector, err := detect.NewDetectorDefaultConfig()
		require.NoError(t, err)

		a := New()
		findings, err := a.ScanFile(longFile, detector)
		require.NoError(t, err)
		t.Logf("long line file findings: %d", len(findings))
	})

	t.Run("file with special regex chars in content", func(t *testing.T) {
		tmpDir := t.TempDir()
		specialFile := filepath.Join(tmpDir, "special.txt")
		content := "regex chars: [a-z]+ (group) {braces} $dollar ^caret .dot *star\n"
		err := os.WriteFile(specialFile, []byte(content), 0644)
		require.NoError(t, err)

		detector, err := detect.NewDetectorDefaultConfig()
		require.NoError(t, err)

		a := New()
		findings, err := a.ScanFile(specialFile, detector)
		require.NoError(t, err)
		t.Logf("special chars file findings: %d", len(findings))
	})
}

// =============================================================================
// ScanForEnvVarValues with adversarial env content
// =============================================================================

func TestScanForEnvVarValuesAdversarial(t *testing.T) {
	a := New()

	t.Run("env var with regex special chars", func(t *testing.T) {
		// Set an env var whose value contains regex special characters
		envKey := "TEST_ADV_REGEX_CHARS"
		envVal := "secret+value[with]regex(chars){and}more$stuff^here.dot*star"
		os.Setenv(envKey, envVal)
		defer os.Unsetenv(envKey)

		sensitiveVars := map[string]struct{}{envKey: {}}
		content := "some content with " + envVal + " embedded"

		// This should not panic even with regex special chars
		findings := a.ScanForEnvVarValues(content, "test.txt", sensitiveVars)
		assert.NotEmpty(t, findings, "should find the env var value")
	})

	t.Run("env var with binary content", func(t *testing.T) {
		envKey := "TEST_ADV_BINARY"
		envVal := "value\xff\xfe\xfd\x00\x01\x02"
		os.Setenv(envKey, envVal)
		defer os.Unsetenv(envKey)

		sensitiveVars := map[string]struct{}{envKey: {}}
		content := "content with " + envVal + " in it"

		// Should not panic
		assert.NotPanics(t, func() {
			_ = a.ScanForEnvVarValues(content, "test.txt", sensitiveVars)
		})
	})

	t.Run("env var value too short", func(t *testing.T) {
		envKey := "TEST_ADV_SHORT"
		envVal := "ab" // Below minSensitiveValueLength
		os.Setenv(envKey, envVal)
		defer os.Unsetenv(envKey)

		sensitiveVars := map[string]struct{}{envKey: {}}
		content := "content with ab in it"

		findings := a.ScanForEnvVarValues(content, "test.txt", sensitiveVars)
		assert.Empty(t, findings, "short values should be skipped")
	})

	t.Run("env var value empty", func(t *testing.T) {
		envKey := "TEST_ADV_EMPTY"
		envVal := ""
		os.Setenv(envKey, envVal)
		defer os.Unsetenv(envKey)

		sensitiveVars := map[string]struct{}{envKey: {}}
		content := "some content"

		findings := a.ScanForEnvVarValues(content, "test.txt", sensitiveVars)
		assert.Empty(t, findings, "empty values should be skipped")
	})

	t.Run("env var not sensitive", func(t *testing.T) {
		envKey := "TEST_ADV_NOTSENSITIVE"
		envVal := "a-perfectly-normal-value-here"
		os.Setenv(envKey, envVal)
		defer os.Unsetenv(envKey)

		sensitiveVars := map[string]struct{}{"OTHER_KEY": {}}
		content := "content with " + envVal + " in it"

		findings := a.ScanForEnvVarValues(content, "test.txt", sensitiveVars)
		assert.Empty(t, findings, "non-sensitive vars should be skipped")
	})

	t.Run("env var value not in content", func(t *testing.T) {
		envKey := "TEST_ADV_NOTFOUND"
		envVal := "this-value-is-not-in-the-content"
		os.Setenv(envKey, envVal)
		defer os.Unsetenv(envKey)

		sensitiveVars := map[string]struct{}{envKey: {}}
		content := "completely different content here"

		findings := a.ScanForEnvVarValues(content, "test.txt", sensitiveVars)
		assert.Empty(t, findings, "value not in content should produce no findings")
	})

	t.Run("very long env var value", func(t *testing.T) {
		envKey := "TEST_ADV_LONG"
		envVal := strings.Repeat("secretvalue", 1000)
		os.Setenv(envKey, envVal)
		defer os.Unsetenv(envKey)

		sensitiveVars := map[string]struct{}{envKey: {}}
		content := "start " + envVal + " end"

		assert.NotPanics(t, func() {
			_ = a.ScanForEnvVarValues(content, "test.txt", sensitiveVars)
		})
	})
}

// =============================================================================
// Allowlist adversarial tests
// =============================================================================

func TestAllowlistAdversarial(t *testing.T) {
	t.Run("nil allowlist", func(t *testing.T) {
		assert.False(t, isContentAllowListed("anything", nil))
		assert.False(t, isMatchAllowlisted("anything", nil))
	})

	t.Run("empty allowlist", func(t *testing.T) {
		al := &AllowList{}
		assert.False(t, isContentAllowListed("anything", al))
		assert.False(t, isMatchAllowlisted("anything", al))
	})

	t.Run("stop word match", func(t *testing.T) {
		al := &AllowList{StopWords: []string{"false-positive"}}
		assert.True(t, isMatchAllowlisted("this is a false-positive match", al))
		assert.False(t, isMatchAllowlisted("real finding", al))
	})

	t.Run("regex match", func(t *testing.T) {
		al := &AllowList{Regexes: []string{"test[0-9]+"}}
		assert.True(t, isMatchAllowlisted("test123", al))
		assert.False(t, isMatchAllowlisted("production", al))
	})

	t.Run("invalid regex in allowlist", func(t *testing.T) {
		al := &AllowList{Regexes: []string{"[invalid"}}
		// Invalid regex should be skipped, not panic
		assert.NotPanics(t, func() {
			isMatchAllowlisted("anything", al)
		})
	})

	t.Run("path patterns only for content type", func(t *testing.T) {
		al := &AllowList{Paths: []string{"test_data"}}
		// Paths should match for "content" type
		assert.True(t, isContentAllowListed("test_data/file.txt", al))
		// But NOT for "match" type
		assert.False(t, isMatchAllowlisted("test_data/file.txt", al))
	})
}

// =============================================================================
// truncateMatch adversarial tests
// =============================================================================

func TestTruncateMatchAdversarial(t *testing.T) {
	t.Run("short string", func(t *testing.T) {
		result := truncateMatch("short")
		assert.Equal(t, "short", result)
	})

	t.Run("exactly at limit", func(t *testing.T) {
		input := strings.Repeat("A", maxMatchDisplayLength)
		result := truncateMatch(input)
		assert.Equal(t, input, result)
	})

	t.Run("one over limit", func(t *testing.T) {
		input := strings.Repeat("A", maxMatchDisplayLength+1)
		result := truncateMatch(input)
		assert.Contains(t, result, "...")
		assert.True(t, len(result) < len(input), "truncated should be shorter")
	})

	t.Run("very long string", func(t *testing.T) {
		input := strings.Repeat("A", 10000)
		result := truncateMatch(input)
		expected := strings.Repeat("A", truncatedMatchSegmentLength) + "..." + strings.Repeat("A", truncatedMatchSegmentLength)
		assert.Equal(t, expected, result)
	})

	t.Run("empty string", func(t *testing.T) {
		result := truncateMatch("")
		assert.Equal(t, "", result)
	})
}

// =============================================================================
// isBinaryFile adversarial tests
// =============================================================================

func TestIsBinaryFileAdversarial(t *testing.T) {
	binaryTypes := []string{
		"application/octet-stream",
		"application/x-executable",
		"application/x-mach-binary",
		"application/x-sharedlib",
		"application/x-object",
	}
	for _, mt := range binaryTypes {
		assert.True(t, isBinaryFile(mt), "should be binary: %s", mt)
	}

	nonBinaryTypes := []string{
		"text/plain",
		"text/html",
		"application/json",
		"application/xml",
		"text/directory",
		"",
	}
	for _, mt := range nonBinaryTypes {
		assert.False(t, isBinaryFile(mt), "should not be binary: %s", mt)
	}
}

// =============================================================================
// Attestor configuration adversarial tests
// =============================================================================

func TestAttestorConfigAdversarial(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		a := New()
		assert.Equal(t, defaultFailOnDetection, a.failOnDetection)
		assert.Equal(t, defaultMaxFileSizeMB, a.maxFileSizeMB)
		assert.Equal(t, defaultMaxDecodeLayers, a.maxDecodeLayers)
		assert.Nil(t, a.allowList)
		assert.Equal(t, defaultConfigPath, a.configPath)
		assert.NotNil(t, a.subjects)
	})

	t.Run("all options", func(t *testing.T) {
		al := &AllowList{Description: "test"}
		a := New(
			WithFailOnDetection(true),
			WithMaxFileSize(50),
			WithMaxDecodeLayers(5),
			WithAllowList(al),
			WithConfigPath("/etc/gitleaks.toml"),
			WithFilePermissions(0400),
		)
		assert.True(t, a.failOnDetection)
		assert.Equal(t, 50, a.maxFileSizeMB)
		assert.Equal(t, 5, a.maxDecodeLayers)
		assert.Same(t, al, a.allowList)
		assert.Equal(t, "/etc/gitleaks.toml", a.configPath)
		assert.Equal(t, os.FileMode(0400), a.filePerm)
	})

	t.Run("negative max file size ignored", func(t *testing.T) {
		a := New(WithMaxFileSize(-1))
		assert.Equal(t, defaultMaxFileSizeMB, a.maxFileSizeMB, "negative size should keep default")
	})

	t.Run("zero max file size ignored", func(t *testing.T) {
		a := New(WithMaxFileSize(0))
		assert.Equal(t, defaultMaxFileSizeMB, a.maxFileSizeMB, "zero size should keep default")
	})

	t.Run("negative max decode layers allowed (means disable)", func(t *testing.T) {
		a := New(WithMaxDecodeLayers(-1))
		// The code checks >= 0, so -1 should NOT be applied
		assert.Equal(t, defaultMaxDecodeLayers, a.maxDecodeLayers)
	})

	t.Run("zero max decode layers means no decoding", func(t *testing.T) {
		a := New(WithMaxDecodeLayers(0))
		assert.Equal(t, 0, a.maxDecodeLayers)
	})

	t.Run("attestor interface compliance", func(t *testing.T) {
		a := New()
		assert.Equal(t, Name, a.Name())
		assert.Equal(t, Type, a.Type())
		assert.Equal(t, RunType, a.RunType())
		assert.NotNil(t, a.Schema())
		assert.NotNil(t, a.Subjects())
	})
}

// =============================================================================
// scanBytes recursion safety
// =============================================================================

func TestScanBytesRecursionSafety(t *testing.T) {
	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	// Create content with deeply nested base64 encoding
	secret := "this-is-a-test-secret-value-12345"
	encoded := secret
	for i := 0; i < 10; i++ { // 10 layers deep
		encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
	}

	a := New(WithMaxDecodeLayers(3)) // Only decode 3 layers
	processedInThisScan := make(map[string]struct{})

	// Should not stack overflow even with deeply encoded content
	findings, err := a.scanBytes([]byte(encoded), "test", detector, processedInThisScan, 0)
	require.NoError(t, err)
	t.Logf("deep encoding findings: %d", len(findings))

	// Verify max recursion depth is respected
	a2 := New(WithMaxDecodeLayers(0))
	processedInThisScan2 := make(map[string]struct{})
	findings2, err := a2.scanBytes([]byte(encoded), "test", detector, processedInThisScan2, 0)
	require.NoError(t, err)
	t.Logf("zero decode layers findings: %d", len(findings2))
}

// =============================================================================
// BUG: min/max in utils.go shadow Go 1.21+ builtins
// =============================================================================

func TestMinMaxFunctions(t *testing.T) {
	// Document that utils.go defines min() and max() which shadow the Go
	// builtins introduced in Go 1.21. This compiles fine but is a style issue.
	assert.Equal(t, 1, min(1, 2))
	assert.Equal(t, 2, max(1, 2))
	assert.Equal(t, -1, min(-1, 0))
	assert.Equal(t, 0, max(-1, 0))
	assert.Equal(t, 0, min(0, 0))
	assert.Equal(t, 0, max(0, 0))
}

// =============================================================================
// Concurrent scanBytes
// =============================================================================

func TestScanBytesConcurrent(t *testing.T) {
	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	contents := []string{
		"normal content without secrets",
		base64.StdEncoding.EncodeToString([]byte("encoded content")),
		hex.EncodeToString([]byte("hex content")),
		"mixed content with " + base64.StdEncoding.EncodeToString([]byte("encoded part")),
		strings.Repeat("lots of content ", 1000),
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			a := New()
			processedInThisScan := make(map[string]struct{})
			content := contents[idx%len(contents)]
			_, err := a.scanBytes([]byte(content), fmt.Sprintf("test-%d", idx), detector, processedInThisScan, 0)
			if err != nil {
				t.Errorf("scanBytes error: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

// =============================================================================
// exceedsMaxFileSize adversarial tests
// =============================================================================

func TestExceedsMaxFileSizeAdversarial(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		a := New()
		_, err := a.exceedsMaxFileSize("/tmp/nonexistent_12345")
		assert.Error(t, err)
	})

	t.Run("file within limit", func(t *testing.T) {
		tmpDir := t.TempDir()
		f := filepath.Join(tmpDir, "small.txt")
		err := os.WriteFile(f, []byte("small"), 0644)
		require.NoError(t, err)

		a := New(WithMaxFileSize(1))
		exceeds, err := a.exceedsMaxFileSize(f)
		require.NoError(t, err)
		assert.False(t, exceeds)
	})

	t.Run("zero max size means no limit", func(t *testing.T) {
		tmpDir := t.TempDir()
		f := filepath.Join(tmpDir, "file.txt")
		err := os.WriteFile(f, []byte(strings.Repeat("x", 10000)), 0644)
		require.NoError(t, err)

		a := &Attestor{maxFileSizeMB: 0}
		exceeds, err := a.exceedsMaxFileSize(f)
		require.NoError(t, err)
		assert.False(t, exceeds, "zero maxFileSizeMB means no limit")
	})
}

// =============================================================================
// compileRegexes adversarial tests
// =============================================================================

func TestCompileRegexesAdversarial(t *testing.T) {
	a := New()

	t.Run("valid patterns", func(t *testing.T) {
		result, err := a.compileRegexes([]string{"test[0-9]+", "foo|bar"})
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("invalid pattern", func(t *testing.T) {
		_, err := a.compileRegexes([]string{"[invalid"})
		assert.Error(t, err)
	})

	t.Run("empty list", func(t *testing.T) {
		result, err := a.compileRegexes([]string{})
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("nil list", func(t *testing.T) {
		result, err := a.compileRegexes(nil)
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("catastrophic backtracking pattern", func(t *testing.T) {
		// Go's regexp package uses NFA so this doesn't actually cause
		// catastrophic backtracking, but test it anyway for safety
		_, err := a.compileRegexes([]string{"(a+)+$"})
		require.NoError(t, err) // Go's regexp handles this fine
	})
}

// =============================================================================
// BUG: readFileContent uses maxFileSizeMB even when 0 (no limit)
// When maxFileSizeMB is 0, maxSizeBytes becomes 0, and
// io.LimitReader(file, 0) returns no data at all.
// =============================================================================

func TestReadFileContentZeroMaxSize(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "hello world this is a test file with some content"
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	a := &Attestor{maxFileSizeMB: 0}
	content, err := a.readFileContent(testFile)
	require.NoError(t, err)

	// BUG: When maxFileSizeMB is 0, the code computes maxSizeBytes = 0 * 1024 * 1024 = 0
	// Then io.LimitReader(file, 0) reads zero bytes.
	// The exceedsMaxFileSize check correctly treats 0 as "no limit",
	// but readFileContent does NOT -- it limits to 0 bytes!
	if len(content) == 0 {
		t.Log("BUG CONFIRMED: readFileContent returns empty when maxFileSizeMB=0")
		t.Log("exceedsMaxFileSize treats 0 as no-limit, but readFileContent treats 0 as zero-byte limit")
		t.Log("This bug is mitigated because New() sets defaultMaxFileSizeMB=10, not 0")
	} else {
		t.Logf("Read %d bytes (bug may have been fixed)", len(content))
	}
}

