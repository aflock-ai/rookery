package policy

import (
	"testing"
)

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

func TestMatchRegex(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{`rm\s+-rf`, "rm -rf /tmp", true},
		{`rm\s+-rf`, "rm /tmp", false},
		{`git\s+push`, "git push origin main", true},
		{`^sudo\s+`, "sudo rm -rf", true},
		{`^sudo\s+`, "nosudo command", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := m.MatchRegex(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchRegex(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		patterns []string
		value    string
		want     bool
	}{
		{[]string{"*.go", "*.ts"}, "main.go", true},
		{[]string{"*.go", "*.ts"}, "main.ts", true},
		{[]string{"*.go", "*.ts"}, "main.py", false},
		{[]string{}, "anything", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := m.MatchAny(tt.patterns, tt.value)
			if got != tt.want {
				t.Errorf("MatchAny(%v, %q) = %v, want %v", tt.patterns, tt.value, got, tt.want)
			}
		})
	}
}

func TestParseToolPattern(t *testing.T) {
	tests := []struct {
		pattern    string
		wantTool   string
		wantCmd    string
		wantHasCmd bool
	}{
		{"Read", "Read", "", false},
		{"Bash:rm *", "Bash", "rm *", true},
		{"Bash:git push*", "Bash", "git push*", true},
		{"mcp__github:create_issue", "mcp__github", "create_issue", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
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

func TestMatchToolPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		pattern  string
		toolName string
		input    string
		want     bool
	}{
		// Simple tool name match
		{"Read", "Read", "", true},
		{"Read", "Write", "", false},

		// Tool with command pattern
		{"Bash:rm *", "Bash", "rm -rf /tmp", true},
		{"Bash:rm *", "Bash", "ls -la", false},
		{"Bash:rm *", "Read", "rm -rf", false}, // Different tool

		// Glob patterns in tool name
		{"mcp__*", "mcp__github", "", true},
		{"mcp__*", "Bash", "", false},

		// Git commands
		{"Bash:git push*", "Bash", "git push origin main", true},
		{"Bash:git push*", "Bash", "git pull", false},
		{"Bash:git push --force*", "Bash", "git push --force origin main", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.toolName, func(t *testing.T) {
			got := m.MatchToolPattern(tt.pattern, tt.toolName, tt.input)
			if got != tt.want {
				t.Errorf("MatchToolPattern(%q, %q, %q) = %v, want %v",
					tt.pattern, tt.toolName, tt.input, got, tt.want)
			}
		})
	}
}

func TestMatcherCaching(t *testing.T) {
	m := NewMatcher()

	// First call compiles and caches
	m.MatchGlob("*.go", "main.go")
	m.MatchRegex(`rm\s+`, "rm -rf")

	// Verify patterns are cached
	if _, ok := m.globs["*.go"]; !ok {
		t.Error("glob pattern should be cached")
	}
	if _, ok := m.regexes[`rm\s+`]; !ok {
		t.Error("regex pattern should be cached")
	}

	// Second call should use cache
	if !m.MatchGlob("*.go", "foo.go") {
		t.Error("cached glob should still work")
	}
	if !m.MatchRegex(`rm\s+`, "rm foo") {
		t.Error("cached regex should still work")
	}
}
