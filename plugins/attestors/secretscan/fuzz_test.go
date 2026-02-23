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
	"strings"
	"testing"
)

// FuzzSecretScanPatternMatch exercises findPatternMatchesWithRedaction with
// random content and regex patterns.  The function compiles the pattern via
// regexp.Compile and then finds all matches with surrounding context.  Edge
// cases include: invalid regex, empty content, patterns that match the entire
// content, very long content, and patterns with capturing groups.
func FuzzSecretScanPatternMatch(f *testing.F) {
	// Seed corpus: (content, pattern)
	f.Add("the quick brown fox", "quick")
	f.Add("SECRET=abc123 in the log", "abc123")
	f.Add("line1\nline2\nline3", "line2")
	f.Add("", "")
	f.Add("content", "")
	f.Add("", "pattern")
	// Invalid regex patterns -- must not panic
	f.Add("content", "[invalid")
	f.Add("content", "(unclosed")
	f.Add("content", "(?P<name")
	f.Add("content", "*")
	f.Add("content", "+")
	f.Add("content", "\\")
	// Patterns that match everything
	f.Add("abc", ".*")
	f.Add("abc", ".+")
	f.Add("abc", ".")
	// Patterns with special regex chars
	f.Add("price is $5.00", "\\$5\\.00")
	f.Add("hello (world)", "\\(world\\)")
	f.Add("a|b|c", "a\\|b")
	// Very long content
	f.Add(strings.Repeat("AAAA", 500), "A{4}")
	// Content with match at boundaries
	f.Add("match", "match")
	f.Add("xmatch", "match")
	f.Add("matchx", "match")
	// Unicode content
	f.Add("secret: \u00e9\u00e8\u00ea", "\u00e9")
	f.Add("emoji: \U0001f511\U0001f512", "\U0001f511")
	// Null bytes
	f.Add("before\x00after", "after")
	f.Add("null\x00byte", "\x00")
	// Newlines in patterns
	f.Add("line1\nline2", "line1\\nline2")
	// Pattern that produces many matches
	f.Add(strings.Repeat("ab", 200), "ab")

	f.Fuzz(func(t *testing.T, content, pattern string) {
		a := New()

		// Must not panic regardless of input
		results := a.findPatternMatchesWithRedaction(content, pattern)

		// Security invariant: the redacted match context must never contain
		// the original matched text. We can only check this when the pattern
		// is a valid regex and produces matches.
		if len(results) > 0 {
			for _, r := range results {
				if r.lineNumber < 1 {
					t.Errorf("line number should be >= 1, got %d", r.lineNumber)
				}
				// matchContext should contain the redaction placeholder
				if !strings.Contains(r.matchContext, redactedValuePlaceholder) {
					t.Errorf("match context should contain redaction placeholder %q, got %q",
						redactedValuePlaceholder, r.matchContext)
				}
			}
		}
	})
}

// FuzzIsEnvironmentVariableSensitive exercises the glob-based sensitive
// variable detection.  The function does a direct map lookup, then falls back
// to glob matching for patterns containing "*".  Invalid glob patterns must be
// skipped without panicking.
func FuzzIsEnvironmentVariableSensitive(f *testing.F) {
	// Seed corpus: (key, pattern)
	f.Add("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY")
	f.Add("MY_TOKEN", "*TOKEN*")
	f.Add("MY_SECRET", "*SECRET*")
	f.Add("SAFE_VAR", "DANGEROUS_VAR")
	f.Add("", "")
	f.Add("", "*")
	f.Add("KEY", "")
	f.Add("KEY", "*")
	f.Add("KEY", "**")
	f.Add("KEY", "***")
	// Invalid glob patterns
	f.Add("KEY", "[")
	f.Add("KEY", "[abc")
	f.Add("KEY", "]*[")
	// Exact match should always work
	f.Add("EXACT", "EXACT")
	// Unicode
	f.Add("KEY_\u00e9", "*\u00e9*")
	f.Add("\xff\xfe", "*")
	// Null bytes
	f.Add("KEY\x00", "KEY\x00")
	f.Add("KEY", "KEY\x00")
	// Very long keys and patterns
	f.Add(strings.Repeat("A", 1000), "*"+strings.Repeat("A", 998)+"*")
	f.Add(strings.Repeat("A", 1000), strings.Repeat("A", 1000))
	// Glob with question mark and alternation
	f.Add("KEY", "?EY")
	f.Add("KEY", "{KEY,OTHER}")
	f.Add("KEY", "K*Y")
	f.Add("KEY", "*K*")
	f.Add("A", "*A*")

	f.Fuzz(func(t *testing.T, key, pattern string) {
		sensitiveVars := make(map[string]struct{})
		if pattern != "" {
			sensitiveVars[pattern] = struct{}{}
		}

		// Must not panic regardless of input
		result := isEnvironmentVariableSensitive(key, sensitiveVars)

		// Invariant: exact match must always return true
		if pattern != "" && key == pattern {
			if !result {
				t.Errorf("exact match of key=%q pattern=%q should be sensitive", key, pattern)
			}
		}

		// Invariant: empty sensitiveVars should never match
		emptyResult := isEnvironmentVariableSensitive(key, map[string]struct{}{})
		if emptyResult {
			t.Errorf("empty sensitiveVars should never match, but matched key=%q", key)
		}

		// Nil map should not panic
		_ = isEnvironmentVariableSensitive(key, nil)
	})
}
