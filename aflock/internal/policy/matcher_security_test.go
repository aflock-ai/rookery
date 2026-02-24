//go:build audit

package policy

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurity_R3_241_GlobRegexDualMatchFixed verifies that MatchToolPattern
// no longer falls through from glob to regex, preventing special regex characters
// (|, ., +, etc.) from widening matches.
//
// Previously: MatchToolPattern used glob OR regex fallback. Characters like "|"
// (literal in glob, alternation in regex) would widen matches for allow rules.
// Fixed: MatchToolPattern now uses glob ONLY for command pattern matching.
func TestSecurity_R3_241_GlobRegexDualMatchFixed(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name       string
		pattern    string
		toolName   string
		input      string
		wantGlob   bool
		wantRegex  bool
		wantResult bool // After fix: should match MatchGlob only
		desc       string
	}{
		{
			name:       "pipe character no longer creates regex alternation",
			pattern:    "Bash:git log|rm -rf /",
			toolName:   "Bash",
			input:      "rm -rf /",
			wantGlob:   false, // glob treats | as literal, won't match
			wantRegex:  true,  // regex WOULD match, but no longer used
			wantResult: false, // FIXED: glob-only, no regex fallback
			desc:       "Bash:git log|rm -rf / no longer allows rm -rf / via regex",
		},
		{
			name:       "dot no longer matches any character",
			pattern:    "Bash:ls src/main.go",
			toolName:   "Bash",
			input:      "ls src/mainXgo",
			wantGlob:   false, // glob treats . as literal
			wantRegex:  true,  // regex WOULD match, but no longer used
			wantResult: false, // FIXED: glob-only
			desc:       "Bash:ls src/main.go no longer allows ls src/mainXgo",
		},
		{
			name:       "parentheses no longer create regex groups",
			pattern:    "Bash:echo (hello)",
			toolName:   "Bash",
			input:      "echo hello",
			wantGlob:   false, // glob treats () as literal
			wantRegex:  true,  // regex WOULD match, but no longer used
			wantResult: false, // FIXED: glob-only
			desc:       "No regex grouping interpretation",
		},
		{
			name:       "plus no longer is one-or-more quantifier",
			pattern:    "Bash:ls a+b",
			toolName:   "Bash",
			input:      "ls aaab",
			wantGlob:   false, // glob treats + as literal
			wantRegex:  true,  // regex WOULD match, but no longer used
			wantResult: false, // FIXED: glob-only
			desc:       "Bash:ls a+b no longer allows ls aaab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify glob alone doesn't match
			_, patternCmd, _ := ParseToolPattern(tt.pattern)
			globResult := m.MatchGlob(patternCmd, tt.input)
			assert.Equal(t, tt.wantGlob, globResult, "glob matching mismatch")

			// Verify regex alone would match (proving the old bug existed)
			regexResult := m.MatchRegex(patternCmd, tt.input)
			assert.Equal(t, tt.wantRegex, regexResult, "regex matching mismatch — the old bug path")

			// Verify MatchToolPattern now uses glob-only (fix confirmed)
			result := m.MatchToolPattern(tt.pattern, tt.toolName, tt.input)
			assert.Equal(t, tt.wantResult, result,
				"FIXED R3-241: MatchToolPattern should use glob-only, not fall through to regex")
		})
	}
}

// TestSecurity_R3_241_AllowListRegexAlternationFixed verifies the fix for R3-241:
// an allow list entry with pipe character no longer lets unintended commands through.
func TestSecurity_R3_241_AllowListRegexAlternationFixed(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash:git log|cat /etc/shadow"},
		},
	}

	eval := NewEvaluator(policy)

	// The intended command "git log|cat /etc/shadow" should be allowed (glob literal match)
	intendedInput, _ := json.Marshal(aflock.BashToolInput{Command: "git log|cat /etc/shadow"})
	decision, _ := eval.EvaluatePreToolUse("Bash", intendedInput)
	assert.Equal(t, aflock.DecisionAllow, decision, "intended pipe command should be allowed")

	// FIXED: "cat /etc/shadow" alone is now correctly denied
	dangerousInput, _ := json.Marshal(aflock.BashToolInput{Command: "cat /etc/shadow"})
	decision, reason := eval.EvaluatePreToolUse("Bash", dangerousInput)
	assert.Equal(t, aflock.DecisionDeny, decision,
		"FIXED R3-241: 'cat /etc/shadow' must be denied — no regex alternation bypass")
	assert.Contains(t, reason, "not in allow list",
		"should deny because command doesn't match glob pattern")
}

// TestSecurity_R3_242_AutoAnchorBypassFixed verifies the fix for R3-242:
// MatchRegex now uses HasPrefix("^")/HasSuffix("$") instead of Contains,
// so ^ in character classes (e.g., [^x]) no longer bypasses auto-anchoring.
func TestSecurity_R3_242_AutoAnchorBypassFixed(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name      string
		pattern   string
		input     string
		wantMatch bool
		desc      string
	}{
		{
			name:      "caret in char class no longer prevents auto-anchoring",
			pattern:   "[^x]rm",
			input:     "format disk",
			wantMatch: false, // FIXED: now auto-anchored, no substring match
			desc:      "Pattern [^x]rm is auto-anchored, won't match substring in 'format disk'",
		},
		{
			name:      "char class negation still works for full match",
			pattern:   "[^x]rm",
			input:     "arm",
			wantMatch: true, // full match: "arm" matches ^([^x]rm)$
			desc:      "Full match still works correctly",
		},
		{
			name:      "dollar in character class no longer prevents anchoring",
			pattern:   "test[$]",
			input:     "my test$ value",
			wantMatch: false, // FIXED: auto-anchored, no substring match
			desc:      "Pattern test[$] is auto-anchored, won't match substring",
		},
		{
			name:      "dollar in char class full match works",
			pattern:   "test[$]",
			input:     "test$",
			wantMatch: true, // full match: "test$" matches ^(test[$])$
			desc:      "Full match with $ in char class still works",
		},
		{
			name:      "normal pattern still auto-anchored",
			pattern:   "rm",
			input:     "format disk",
			wantMatch: false, // auto-anchored to ^(rm)$ — no substring match
			desc:      "Without ^/$, pattern is auto-anchored to prevent substring match",
		},
		{
			name:      "explicit anchors still respected",
			pattern:   "^hello.*world$",
			input:     "hello beautiful world",
			wantMatch: true, // has anchors, used as-is
			desc:      "Explicit anchors are still respected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.MatchRegex(tt.pattern, tt.input)
			assert.Equal(t, tt.wantMatch, result,
				"pattern %q against %q: %s", tt.pattern, tt.input, tt.desc)
		})
	}
}

// TestSecurity_R3_243_ParseToolPatternColonInURL verifies that ParseToolPattern
// correctly handles colons in URL patterns (e.g., WebFetch:https://example.com:8080).
func TestSecurity_R3_243_ParseToolPatternColonInURL(t *testing.T) {
	tests := []struct {
		pattern    string
		wantTool   string
		wantCmd    string
		wantHasCmd bool
	}{
		{
			pattern:    "WebFetch:https://example.com:8080/*",
			wantTool:   "WebFetch",
			wantCmd:    "https://example.com:8080/*",
			wantHasCmd: true,
		},
		{
			pattern:    "Bash:git commit -m 'fix: bug'",
			wantTool:   "Bash",
			wantCmd:    "git commit -m 'fix: bug'",
			wantHasCmd: true,
		},
		{
			pattern:    "Read:/path/to/file",
			wantTool:   "Read",
			wantCmd:    "/path/to/file",
			wantHasCmd: true,
		},
		{
			pattern:    "Bash",
			wantTool:   "Bash",
			wantCmd:    "",
			wantHasCmd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			tool, cmd, hasCmd := ParseToolPattern(tt.pattern)
			assert.Equal(t, tt.wantTool, tool, "tool name")
			assert.Equal(t, tt.wantCmd, cmd, "command pattern")
			assert.Equal(t, tt.wantHasCmd, hasCmd, "has command")
		})
	}
}

// TestSecurity_R3_244_GlobCompileFailureSilentDenyBypass proves that when a glob
// pattern fails to compile, MatchGlob silently returns false. For deny rules,
// this means the deny is silently skipped.
//
// Impact: LOW — Glob compilation failures are unlikely in well-formed policies,
// but if they occur in a deny pattern, the denied tool/file is silently allowed.
func TestSecurity_R3_244_GlobCompileFailureSilentDenyBypass(t *testing.T) {
	m := NewMatcher()

	// Malformed glob patterns that fail to compile
	badPatterns := []string{
		"[",    // unclosed character class
		"[z-a", // invalid range
	}

	for _, pattern := range badPatterns {
		result := m.MatchGlob(pattern, "anything")
		assert.False(t, result, "bad pattern %q should return false", pattern)
		// The concern: if this pattern is in a deny list, the deny is silently skipped.
		// There's no error returned or logged.
	}

	// Prove the impact: a deny list with a bad pattern silently allows the tool
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Bash:["}, // malformed deny pattern
		},
	}

	eval := NewEvaluator(policy)
	input, _ := json.Marshal(aflock.BashToolInput{Command: "rm -rf /"})
	decision, _ := eval.EvaluatePreToolUse("Bash", input)

	// The malformed deny pattern silently fails, so the command is allowed
	if decision == aflock.DecisionAllow {
		t.Logf("SECURITY FINDING R3-244: Malformed deny pattern 'Bash:[' silently " +
			"failed to compile, allowing 'rm -rf /'. Glob compilation errors should " +
			"be logged or cause deny patterns to fail-closed.")
	}
}

// TestSecurity_R3_245_MatchGlobCacheCollision proves that the glob cache uses
// pattern strings as keys. The **/ root pattern expansion creates derived patterns
// that could collide with explicit patterns in the cache.
//
// Impact: LOW — If a policy has both "**/*.go" and "*.go" patterns, the **/ expansion
// creates a "*.go" entry that overwrites any previous "*.go" entry (or vice versa).
// Since the compiled glob should be identical, this is benign. But if there were
// a pattern where the derived version differs from the explicit version, results
// would be inconsistent.
func TestSecurity_R3_245_MatchGlobCacheCollision(t *testing.T) {
	m := NewMatcher()

	// First, match with **/*.go which creates a cached "*.go" derived pattern
	result1 := m.MatchGlob("**/*.go", "main.go")
	require.True(t, result1, "**/*.go should match main.go via root pattern expansion")

	// Now, the cache has both "**/*.go" and "*.go" from the expansion.
	// Matching "*.go" directly should be consistent.
	result2 := m.MatchGlob("*.go", "main.go")
	require.True(t, result2, "*.go should match main.go")

	// Verify that the expansion works for nested paths too
	result3 := m.MatchGlob("**/*.go", "pkg/foo/bar.go")
	require.True(t, result3, "**/*.go should match nested path")

	// Edge case: non-standard pattern with **/ prefix
	result4 := m.MatchGlob("**/secret*", "secrets.yaml")
	require.True(t, result4, "**/secret* should match root-level secrets.yaml via expansion")
}

// TestSecurity_R3_246_EmptyInputMatchToolPattern verifies behavior when tool
// input is empty string, which happens when extractInputForMatching fails to
// parse the JSON input.
func TestSecurity_R3_246_EmptyInputMatchToolPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name    string
		pattern string
		tool    string
		input   string
		want    bool
	}{
		{
			name:    "pattern with command, empty input - glob star matches empty",
			pattern: "Bash:*",
			tool:    "Bash",
			input:   "",
			want:    true, // "*" glob matches empty string
		},
		{
			name:    "pattern with specific command, empty input",
			pattern: "Bash:git *",
			tool:    "Bash",
			input:   "",
			want:    false,
		},
		{
			name:    "tool-only pattern, empty input is fine",
			pattern: "Bash",
			tool:    "Bash",
			input:   "",
			want:    true, // No command check needed
		},
		{
			name:    "empty pattern and empty input",
			pattern: "Bash:",
			tool:    "Bash",
			input:   "",
			want:    true, // Empty command pattern matches empty input
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.MatchToolPattern(tt.pattern, tt.tool, tt.input)
			assert.Equal(t, tt.want, result,
				"pattern=%q tool=%q input=%q", tt.pattern, tt.tool, tt.input)
		})
	}
}

// TestSecurity_R3_241_DenyListNoLongerWidenedByRegex verifies that after the fix,
// deny patterns with dots no longer widen via regex interpretation.
func TestSecurity_R3_241_DenyListNoLongerWidenedByRegex(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Bash:rm tmp.bak"},
		},
	}

	eval := NewEvaluator(policy)

	// "rm tmp.bak" should be denied (exact glob match)
	exactInput, _ := json.Marshal(aflock.BashToolInput{Command: "rm tmp.bak"})
	decision, _ := eval.EvaluatePreToolUse("Bash", exactInput)
	assert.Equal(t, aflock.DecisionDeny, decision, "exact match should deny")

	// FIXED: "rm tmpXbak" is no longer denied — glob treats . as literal
	dotInput, _ := json.Marshal(aflock.BashToolInput{Command: "rm tmpXbak"})
	decision, _ = eval.EvaluatePreToolUse("Bash", dotInput)
	assert.Equal(t, aflock.DecisionAllow, decision,
		"FIXED R3-241: 'rm tmpXbak' should be allowed — glob treats . as literal, no regex fallback")
}
