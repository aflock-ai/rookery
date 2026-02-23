package policy

import (
	"testing"
)

// ---------------------------------------------------------------------------
// MatchGlob
// ---------------------------------------------------------------------------

func TestMatchGlob(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Exact matches
		{"foo.go", "foo.go", true},
		{"foo.go", "bar.go", false},

		// Single wildcard
		{"*.go", "main.go", true},
		{"*.go", "main.txt", false},
		{"foo.*", "foo.go", true},
		{"foo.*", "bar.go", false},

		// Double star patterns
		{"**/*.go", "internal/policy/evaluator.go", true},
		{"**/*.go", "main.go", true}, // Our special handling for root-level files
		{"**/*.go", "main.txt", false},
		{"**/test/**", "a/test/b", true},
		{"**/secrets/**", "config/secrets/key.pem", true},

		// Directory patterns
		{"src/**", "src/main.go", true},
		{"src/**", "src/internal/foo.go", true},
		{"src/**", "lib/main.go", false},

		// Specific file patterns
		{".env", ".env", true},
		{"**/.env", "src/.env", true},
		{"**/.env", ".env", true},

		// Root-level ** fallback for different extensions
		{"**/*.ts", "index.ts", true},
		{"**/*.ts", "src/app.ts", true},
		{"**/*.ts", "index.go", false},
		{"**/*.json", "package.json", true},
		{"**/*.json", "nested/config.json", true},

		// Wildcard in middle of filename
		{"**/test_*.go", "test_foo.go", true},
		{"**/test_*.go", "pkg/test_bar.go", true},
		{"**/test_*.go", "pkg/main.go", false},

		// Absolute paths
		{"/etc/**", "/etc/passwd", true},
		{"/etc/**", "/etc/ssh/config", true},
		{"/etc/**", "/var/log/syslog", false},

		// Single character wildcard
		{"?.go", "a.go", true},
		{"?.go", "ab.go", false},

		// Deeply nested double star
		{"src/**/test/**/*.go", "src/pkg/test/unit/foo.go", true},
		{"src/**/test/**/*.go", "src/test/foo.go", false}, // gobwas/glob ** requires at least one segment
		{"src/**/test/**/*.go", "lib/test/foo.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := m.MatchGlob(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchGlob_InvalidPattern(t *testing.T) {
	m := NewMatcher()

	// Invalid glob pattern should return false, not panic
	got := m.MatchGlob("[invalid", "anything")
	if got != false {
		t.Errorf("MatchGlob with invalid pattern should return false, got %v", got)
	}
}

func TestMatchGlob_CachesCompiledPattern(t *testing.T) {
	m := NewMatcher()

	// First call compiles and caches
	m.MatchGlob("*.go", "main.go")

	if _, ok := m.globs["*.go"]; !ok {
		t.Error("glob pattern should be cached after first use")
	}

	// Second call should use cache and still produce correct results
	if !m.MatchGlob("*.go", "foo.go") {
		t.Error("cached glob should still match")
	}
	if m.MatchGlob("*.go", "foo.txt") {
		t.Error("cached glob should still not match non-matching values")
	}
}

func TestMatchGlob_RootFallbackCaching(t *testing.T) {
	m := NewMatcher()

	// Use the **/ pattern that triggers root fallback
	m.MatchGlob("**/*.go", "main.go")

	// After fallback, the derived *.go pattern should also be cached
	if _, ok := m.globs["*.go"]; !ok {
		t.Error("root fallback pattern *.go should be cached")
	}
}

// ---------------------------------------------------------------------------
// MatchRegex
// ---------------------------------------------------------------------------

func TestMatchRegex(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Unanchored patterns use full-string matching (R3-127 fix).
		// Use .* for prefix/suffix matching when needed.
		{`rm\s+-rf`, "rm -rf", true},        // full match
		{`rm\s+-rf`, "rm -rf /tmp", false},  // trailing content — need .*
		{`rm\s+-rf.*`, "rm -rf /tmp", true}, // explicit .* for trailing
		{`rm\s+-rf`, "rm /tmp", false},
		{`git\s+push`, "git push", true},              // full match
		{`git\s+push`, "git push origin main", false}, // trailing — need .*
		{`git\s+push.*`, "git push origin main", true},

		// Patterns with explicit anchors (^ or $) are used as-is.
		{`^sudo\s+`, "sudo rm -rf", true},
		{`^sudo\s+`, "nosudo command", false},
		{`\d+$`, "abc123", true}, // anchored with $

		// Unanchored: full-string match only
		{`\d+`, "123", true},        // whole string is digits
		{`\d+`, "abc123def", false}, // no longer substring match

		{`\d+`, "abcdef", false},

		// Fully anchored patterns
		{`^$`, "", true},
		{`^$`, "notempty", false},
		{`.*password.*`, "set password=secret", true},
		{`.*password.*`, "set username=admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := m.MatchRegex(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchRegex(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchRegex_InvalidPattern(t *testing.T) {
	m := NewMatcher()

	// Invalid regex should return false, not panic
	got := m.MatchRegex("[invalid(", "anything")
	if got != false {
		t.Errorf("MatchRegex with invalid pattern should return false, got %v", got)
	}
}

func TestMatchRegex_CachesCompiledPattern(t *testing.T) {
	m := NewMatcher()

	// Use an anchored pattern so the behavior is explicit
	m.MatchRegex(`^rm\s+`, "rm -rf")

	if _, ok := m.regexes[`^rm\s+`]; !ok {
		t.Error("regex pattern should be cached after first use")
	}

	// Second call should use cache
	if !m.MatchRegex(`^rm\s+`, "rm foo") {
		t.Error("cached regex should still work")
	}
}

// ---------------------------------------------------------------------------
// MatchAny
// ---------------------------------------------------------------------------

func TestMatchAny(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name     string
		patterns []string
		value    string
		want     bool
	}{
		{"first pattern matches", []string{"*.go", "*.ts"}, "main.go", true},
		{"second pattern matches", []string{"*.go", "*.ts"}, "main.ts", true},
		{"no patterns match", []string{"*.go", "*.ts"}, "main.py", false},
		{"empty patterns", []string{}, "anything", false},
		{"single pattern matches", []string{"*.go"}, "main.go", true},
		{"single pattern no match", []string{"*.go"}, "main.ts", false},
		{"directory pattern in set", []string{"src/**", "lib/**"}, "src/main.go", true},
		{"none of multiple patterns match", []string{"*.go", "*.ts", "*.rs"}, "main.py", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchAny(tt.patterns, tt.value)
			if got != tt.want {
				t.Errorf("MatchAny(%v, %q) = %v, want %v", tt.patterns, tt.value, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseToolPattern
// ---------------------------------------------------------------------------

func TestParseToolPattern(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		wantTool   string
		wantCmd    string
		wantHasCmd bool
	}{
		{"tool name only", "Read", "Read", "", false},
		{"tool with command", "Bash:rm *", "Bash", "rm *", true},
		{"tool with git command", "Bash:git push*", "Bash", "git push*", true},
		{"mcp tool with action", "mcp__github:create_issue", "mcp__github", "create_issue", true},
		{"empty string", "", "", "", false},
		{"colon at end", "Bash:", "Bash", "", true},
		{"multiple colons", "Bash:git:push", "Bash", "git:push", true},
		{"just a colon", ":", "", "", true},
		{"wildcard tool", "*", "*", "", false},
		{"wildcard tool with command", "*:rm *", "*", "rm *", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool, cmd, hasCmd := ParseToolPattern(tt.pattern)
			if tool != tt.wantTool {
				t.Errorf("tool = %q, want %q", tool, tt.wantTool)
			}
			if cmd != tt.wantCmd {
				t.Errorf("cmd = %q, want %q", cmd, tt.wantCmd)
			}
			if hasCmd != tt.wantHasCmd {
				t.Errorf("hasCmd = %v, want %v", hasCmd, tt.wantHasCmd)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MatchToolPattern
// ---------------------------------------------------------------------------

func TestMatchToolPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name     string
		pattern  string
		toolName string
		input    string
		want     bool
	}{
		// Simple tool name match
		{"exact tool match", "Read", "Read", "", true},
		{"exact tool no match", "Read", "Write", "", false},

		// Tool name only matches regardless of input
		{"tool only ignores input", "Read", "Read", "/etc/passwd", true},

		// Tool with command pattern (glob)
		{"bash rm glob match", "Bash:rm *", "Bash", "rm -rf /tmp", true},
		{"bash rm glob no match", "Bash:rm *", "Bash", "ls -la", false},
		{"different tool same command", "Bash:rm *", "Read", "rm -rf", false},

		// Glob patterns in tool name
		{"wildcard tool match", "mcp__*", "mcp__github", "", true},
		{"wildcard tool no match", "mcp__*", "Bash", "", false},

		// Git commands
		{"git push match", "Bash:git push*", "Bash", "git push origin main", true},
		{"git pull no match", "Bash:git push*", "Bash", "git pull", false},
		{"git push force", "Bash:git push --force*", "Bash", "git push --force origin main", true},

		// R3-241: MatchToolPattern uses glob-only, no regex fallback.
		// Regex metacharacters are treated as glob literals.
		{"regex chars as glob literals no match", `Bash:rm\s+-rf`, "Bash", "rm -rf", false},
		{"regex chars as glob literals no match 2", `Bash:rm\s+-rf`, "Bash", "rm -rf /", false},
		{"regex chars as glob literals no match 3", `Bash:rm\s+-rf.*`, "Bash", "rm -rf /", false},
		{"regex chars as glob literal no match 4", `Bash:rm\s+-rf`, "Bash", "rm /tmp", false},

		// Complex tool patterns
		{"double wildcard in tool", "*", "AnyTool", "", true},
		{"empty input with command pattern", "Bash:ls", "Bash", "", false},
		{"exact command match", "Bash:echo hello", "Bash", "echo hello", true},

		// File path patterns
		{"read file pattern", "Read:**/*.go", "Read", "src/main.go", true},
		{"read file pattern no match", "Read:**/*.go", "Read", "src/main.ts", false},

		// MCP with write action
		{"mcp write action", "mcp__slack:*write*", "mcp__slack", "channel_write", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchToolPattern(tt.pattern, tt.toolName, tt.input)
			if got != tt.want {
				t.Errorf("MatchToolPattern(%q, %q, %q) = %v, want %v",
					tt.pattern, tt.toolName, tt.input, got, tt.want)
			}
		})
	}
}

func TestMatchToolPattern_GlobOnlyNoRegexFallback(t *testing.T) {
	m := NewMatcher()

	// R3-241: MatchToolPattern uses glob-only matching. No regex fallback.
	// Regex metacharacters (\s, +, etc.) are treated as glob literals.

	// Regex-style pattern does NOT match via glob (no regex fallback)
	got := m.MatchToolPattern(`Bash:rm\s+-rf.*`, "Bash", "rm -rf /")
	if got {
		t.Error("MatchToolPattern should NOT fall back to regex (R3-241 fix)")
	}

	// Regex-style pattern does NOT match via glob
	got = m.MatchToolPattern(`Bash:rm\s+-rf`, "Bash", "rm -rf")
	if got {
		t.Error("MatchToolPattern should NOT match regex patterns (R3-241 fix)")
	}

	// Glob pattern still matches normally
	got = m.MatchToolPattern("Bash:rm *", "Bash", "rm -rf /tmp")
	if !got {
		t.Error("MatchToolPattern should match via glob")
	}
}

// ---------------------------------------------------------------------------
// Matcher caching across all types
// ---------------------------------------------------------------------------

func TestMatcherCaching(t *testing.T) {
	m := NewMatcher()

	// First calls compile and cache
	m.MatchGlob("*.go", "main.go")
	m.MatchRegex(`^rm\s+`, "rm -rf")

	if _, ok := m.globs["*.go"]; !ok {
		t.Error("glob pattern should be cached")
	}
	if _, ok := m.regexes[`^rm\s+`]; !ok {
		t.Error("regex pattern should be cached")
	}

	// Second calls should use cache
	if !m.MatchGlob("*.go", "foo.go") {
		t.Error("cached glob should still work")
	}
	if !m.MatchRegex(`^rm\s+`, "rm foo") {
		t.Error("cached regex should still work")
	}
}

func TestNewMatcher(t *testing.T) {
	m := NewMatcher()

	if m.globs == nil {
		t.Error("globs map should be initialized")
	}
	if m.regexes == nil {
		t.Error("regexes map should be initialized")
	}
	if len(m.globs) != 0 {
		t.Error("globs map should be empty initially")
	}
	if len(m.regexes) != 0 {
		t.Error("regexes map should be empty initially")
	}
}
