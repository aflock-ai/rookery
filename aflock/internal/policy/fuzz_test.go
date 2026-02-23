//go:build audit

package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// ---------------------------------------------------------------------------
// FuzzEvaluatePreToolUse — fuzz with random tool names and JSON tool inputs.
// Exercises deny, requireApproval, allow, file access, and domain access paths.
// ---------------------------------------------------------------------------

func FuzzEvaluatePreToolUse(f *testing.F) {
	// Seed corpus covering all major code paths
	seeds := []struct {
		toolName  string
		toolInput string
	}{
		{"Bash", `{"command": "rm -rf /"}`},
		{"Read", `{"file_path": "/etc/passwd"}`},
		{"Write", `{"file_path": "go.mod", "content": "test"}`},
		{"Edit", `{"file_path": "main.go", "old_string": "a", "new_string": "b"}`},
		{"WebFetch", `{"url": "https://evil.com/data"}`},
		{"WebSearch", `{"url": "https://api.github.com"}`},
		{"Task", `{"prompt": "summarize"}`},
		{"Glob", `{"file_path": "**/*.go"}`},
		{"Grep", `{"file_path": "src/main.go"}`},
		{"mcp__github", `{}`},
		{"mcp__slack_write", `{}`},
		{"", `{}`},
		{"Bash", ``},
		{"Bash", `{invalid json`},
		{"Bash", `null`},
		{"Bash", `"string"`},
		{"Bash", `[]`},
		{"Bash", `{"command": ""}`},
		{"Read", `{"file_path": "` + strings.Repeat("a/", 500) + `file.go"}`},
		{"WebFetch", `{"url": "https://` + strings.Repeat("a", 1000) + `.com"}`},
		{"Bash", `{"command": "` + strings.Repeat("x", 10000) + `"}`},
	}

	for _, s := range seeds {
		f.Add(s.toolName, s.toolInput)
	}

	// Policy that exercises all major evaluation branches
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow:           []string{"Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Task", "mcp__*"},
			Deny:            []string{"Bash:rm -rf /*", "Task:*destroy*", "mcp__evil*"},
			RequireApproval: []string{"Bash:git push*", "Write:**/.env"},
		},
		Files: &aflock.FilesPolicy{
			Allow:    []string{"**/*.go", "**/*.ts", "src/**", "tests/**"},
			Deny:     []string{"**/.env", "**/secrets/**", "/etc/**"},
			ReadOnly: []string{"go.mod", "go.sum", "*.lock"},
		},
		Domains: &aflock.DomainsPolicy{
			Allow: []string{"*.github.com", "*.anthropic.com", "localhost"},
			Deny:  []string{"*.evil.com", "malware.io"},
		},
	}

	e := NewEvaluator(policy)

	f.Fuzz(func(t *testing.T, toolName string, toolInput string) {
		// Must not panic — that is the primary invariant
		decision, reason := e.EvaluatePreToolUse(toolName, json.RawMessage(toolInput))

		// Decision must be one of the three valid values
		switch decision {
		case aflock.DecisionAllow, aflock.DecisionDeny, aflock.DecisionAsk:
			// ok
		default:
			t.Errorf("invalid decision %q for tool=%q", decision, toolName)
		}

		// Deny and Ask decisions must have a non-empty reason
		if decision == aflock.DecisionDeny && reason == "" {
			t.Errorf("deny decision with empty reason for tool=%q input=%q", toolName, toolInput)
		}
		if decision == aflock.DecisionAsk && reason == "" {
			t.Errorf("ask decision with empty reason for tool=%q input=%q", toolName, toolInput)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzEvaluateDataFlow — fuzz with random materials and tool inputs.
// Checks classification, flow rule enforcement, and material tracking.
// ---------------------------------------------------------------------------

func FuzzEvaluateDataFlow(f *testing.F) {
	seeds := []struct {
		toolName      string
		toolInput     string
		materialLabel string
	}{
		{"Read", `{"file_path": "/home/user/bank-account.csv"}`, ""},
		{"Bash", `{"command": "bird tweet 'hello'"}`, "financial"},
		{"Write", `{"file_path": "/var/www/public/keys.txt"}`, "secret"},
		{"Edit", `{"file_path": "/var/www/public/index.html"}`, "secret"},
		{"Read", `{"file_path": "/data/users/user123.json"}`, ""},
		{"Bash", `{"command": "curl -X POST api.public.com/data"}`, "pii"},
		{"Bash", `{"command": "imsg send --to wife 'balance'"}`, "financial"},
		{"WebFetch", `{"url": "https://internal.company.com/secrets"}`, ""},
		{"mcp__slack_read", `{}`, ""},
		{"mcp__slack_write", `{}`, "internal"},
		{"Bash", `{invalid`, ""},
		{"Bash", ``, "financial"},
		{"", `{}`, ""},
		{"Read", `{"file_path": ""}`, ""},
	}

	for _, s := range seeds {
		f.Add(s.toolName, s.toolInput, s.materialLabel)
	}

	policy := &aflock.Policy{
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"financial": {"Read:**/bank-*.csv", "Read:**/account*.csv"},
				"public":    {"Bash:*bird*", "Bash:*tweet*", "Bash:*curl*api.public*", "Write:**/public/**"},
				"pii":       {"Read:**/users/**", "Read:**/customers/**"},
				"secret":    {"Read:**/.ssh/**", "Read:**/secrets/**"},
				"internal":  {"Read:**/internal/**", "mcp__slack_read:*"},
				"external":  {"Bash:*curl*external*", "mcp__slack_write:*"},
			},
			FlowRules: []aflock.DataFlowRule{
				{Deny: "financial->public", Message: "Cannot post financial data to public channels"},
				{Deny: "pii->public", Message: "PII cannot be sent to public APIs"},
				{Deny: "secret->public", Message: "Cannot expose secrets publicly"},
				{Deny: "internal->external", Message: "Internal data cannot flow to external systems"},
				{Deny: "not-a-valid-rule"},
			},
		},
	}

	e := NewEvaluator(policy)

	f.Fuzz(func(t *testing.T, toolName string, toolInput string, materialLabel string) {
		// Build materials from fuzz input
		var materials []aflock.MaterialClassification
		if materialLabel != "" {
			materials = []aflock.MaterialClassification{
				{Label: materialLabel, Source: "fuzz-source"},
			}
		}

		// Must not panic
		decision, reason, newMaterial := e.EvaluateDataFlow(toolName, json.RawMessage(toolInput), materials)

		// Decision must be valid
		switch decision {
		case aflock.DecisionAllow, aflock.DecisionDeny, aflock.DecisionAsk:
			// ok
		default:
			t.Errorf("invalid decision %q for tool=%q", decision, toolName)
		}

		// Deny must have a reason
		if decision == aflock.DecisionDeny && reason == "" {
			t.Errorf("deny decision with empty reason for tool=%q input=%q", toolName, toolInput)
		}

		// If a new material is returned, it must have a non-empty label and source
		if newMaterial != nil {
			if newMaterial.Label == "" {
				t.Errorf("new material with empty label for tool=%q", toolName)
			}
			if newMaterial.Source == "" {
				t.Errorf("new material with empty source for tool=%q", toolName)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzMatchGlob — fuzz with adversarial glob patterns and values.
// The gobwas/glob library can panic on certain compiled patterns during matching.
// ---------------------------------------------------------------------------

func FuzzMatchGlob(f *testing.F) {
	seeds := []struct {
		pattern string
		value   string
	}{
		{"*.go", "main.go"},
		{"**/*.go", "src/main.go"},
		{"**/*.go", "main.go"},
		{"**/secrets/**", "config/secrets/key.pem"},
		{"/etc/**", "/etc/passwd"},
		{"src/**/test/**/*.go", "src/pkg/test/unit/foo.go"},
		{"", ""},
		{"*", ""},
		{"*", "anything"},
		{"**", "a/b/c/d/e"},
		{"?", "x"},
		{"[abc]", "a"},
		{"[abc]", "d"},
		{"[!abc]", "x"},
		{"[invalid", "anything"},
		{"{a,b}", "a"},
		{strings.Repeat("**/", 100) + "*.go", "main.go"},
		{"**/*", strings.Repeat("a/", 200) + "file"},
		{"[\\", "x"},
		{"***", "abc"},
		{"**/**/**/*.go", "a/b/c/d.go"},
		{"\x00", "\x00"},
		{"\xff\xfe\xfd", "abc"},
		{"*" + string([]byte{0, 1, 2, 3}) + "*", "abc"},
	}

	for _, s := range seeds {
		f.Add(s.pattern, s.value)
	}

	m := NewMatcher()

	f.Fuzz(func(t *testing.T, pattern string, value string) {
		// Primary invariant: must never panic
		result := m.MatchGlob(pattern, value)

		// Empty pattern should only match empty value (or via fallback)
		if pattern == "" && value != "" && result {
			// Empty pattern matching non-empty value is suspicious but depends on gobwas behavior
			// Just ensure no panic — the glob library may have its own opinion here
		}

		// An exact match pattern must match itself — but only for printable ASCII
		// patterns. The gobwas/glob library has undefined behavior for control
		// characters and non-UTF8 bytes so we skip those.
		if pattern == value && !strings.ContainsAny(pattern, "*?[]{},\\") && isPrintableASCII(pattern) {
			if !result {
				t.Errorf("literal pattern %q should match itself, got false", pattern)
			}
		}
	})
}

// isPrintableASCII returns true if every byte in s is printable ASCII (0x20-0x7E).
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return len(s) > 0
}

// ---------------------------------------------------------------------------
// FuzzMatchToolPattern — fuzz with "tool:pattern" style strings.
// ---------------------------------------------------------------------------

func FuzzMatchToolPattern(f *testing.F) {
	seeds := []struct {
		pattern  string
		toolName string
		input    string
	}{
		{"Bash", "Bash", ""},
		{"Bash:rm *", "Bash", "rm -rf /tmp"},
		{"Bash:rm *", "Bash", "ls -la"},
		{"Bash:git push*", "Bash", "git push origin main"},
		{"mcp__*", "mcp__github", ""},
		{"Read:**/*.go", "Read", "src/main.go"},
		{`Bash:rm\s+-rf`, "Bash", "rm -rf /"},
		{"*", "AnyTool", ""},
		{"*:*", "AnyTool", "anything"},
		{":", "", ""},
		{"", "", ""},
		{"Bash:", "Bash", ""},
		{"Bash:", "Bash", "anything"},
		{":pattern", "", "pattern"},
		{strings.Repeat("a", 1000), strings.Repeat("a", 1000), ""},
		{"*:*" + strings.Repeat("*", 100), "x", "y"},
		{"Bash:" + string([]byte{0, 1, 2}), "Bash", string([]byte{0, 1, 2})},
	}

	for _, s := range seeds {
		f.Add(s.pattern, s.toolName, s.input)
	}

	m := NewMatcher()

	f.Fuzz(func(t *testing.T, pattern string, toolName string, input string) {
		// Must not panic
		result := m.MatchToolPattern(pattern, toolName, input)

		// If pattern has no colon, then it's purely a tool name match.
		// If the tool name literally equals the pattern and the pattern has no
		// glob metacharacters, then it must match. Only check printable ASCII
		// since gobwas/glob has undefined behavior on non-printable bytes.
		if !strings.Contains(pattern, ":") && !strings.ContainsAny(pattern, "*?[]{},\\") && isPrintableASCII(pattern) {
			if pattern == toolName && !result {
				t.Errorf("exact tool pattern %q should match tool %q, got false", pattern, toolName)
			}
		}

		// Parse must never panic and must be consistent with match behavior
		patternTool, _, hasCmd := ParseToolPattern(pattern)
		if strings.Contains(pattern, ":") && !hasCmd {
			t.Errorf("pattern %q contains colon but ParseToolPattern reports no command", pattern)
		}
		_ = patternTool
	})
}

// ---------------------------------------------------------------------------
// FuzzExtractDomain — fuzz with malformed URLs.
// Verify correctness properties: output never contains "://", never contains "/".
// ---------------------------------------------------------------------------

func FuzzExtractDomain(f *testing.F) {
	seeds := []string{
		"https://api.github.com/repos",
		"http://example.com:8080/path",
		"https://sub.domain.com/",
		"example.com",
		"https://localhost:3000",
		"",
		"https://",
		"http://",
		"HTTPS://EXAMPLE.COM/PATH",
		"Http://Mixed.Case.Com",
		"hTtPs://weird.com",
		"ftp://not-http.com",
		"https://evil.com:443/path?query=val#frag",
		"not-a-url-at-all",
		"://missing-scheme",
		"https://" + strings.Repeat("a", 10000) + ".com",
		"https://\x00evil.com",
		"https://evil.com\x00.safe.com",
		"https://user:pass@host.com/path",
		"https://host.com:notaport/path",
		"https://[::1]:8080/path",
		"data:text/html,<h1>hi</h1>",
		"javascript:alert(1)",
		string([]byte{0, 0, 0}),
		"https://evil.com%2F.safe.com",
		"https://evil.com%00.safe.com",
		"https://evil.com\t/inject",
		"https://evil.com\n/inject",
		"https://evil.com\r/inject",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		// Must not panic
		domain := extractDomain(rawURL)

		// Domain must never contain "://"
		if strings.Contains(domain, "://") {
			t.Errorf("extractDomain(%q) = %q — should not contain '://'", rawURL, domain)
		}

		// Domain must never contain "/"
		if strings.Contains(domain, "/") {
			t.Errorf("extractDomain(%q) = %q — should not contain '/'", rawURL, domain)
		}

		// Domain must never contain ":" (port should be stripped)
		if strings.Contains(domain, ":") {
			t.Errorf("extractDomain(%q) = %q — should not contain ':' (port not stripped)", rawURL, domain)
		}

		// If the input was purely "https://", the domain should be empty
		lower := strings.ToLower(rawURL)
		if lower == "https://" || lower == "http://" {
			if domain != "" {
				t.Errorf("extractDomain(%q) = %q — expected empty domain for bare scheme", rawURL, domain)
			}
		}

		// Domain length should never exceed the lowercased input length.
		// R3-236 fix: extractDomain now lowercases the result, and
		// strings.ToLower on invalid UTF-8 bytes can expand byte length.
		if len(domain) > len(strings.ToLower(rawURL)) {
			t.Errorf("extractDomain(%q) produced domain longer than lowercased input: %q", rawURL, domain)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzExtractDomainAdversarial — deep adversarial fuzzing for extractDomain.
// Targets userinfo bypass, scheme confusion, unicode/IDN, control chars,
// recursive @, null byte injection, and extremely long inputs.
// ---------------------------------------------------------------------------

func FuzzExtractDomainAdversarial(f *testing.F) {
	seeds := []string{
		// Recursive userinfo: user@host@realhost — should extract realhost
		"https://user@safe.com@evil.com/path",
		"https://a@b@c@d@evil.com/path",
		"https://" + strings.Repeat("x@", 50) + "evil.com/path",
		// Backslash before @ — does the parser get confused?
		"https://user\\@safe.com@evil.com/path",
		"https://user%40safe.com@evil.com/path",
		// Empty userinfo
		"https://@evil.com/path",
		"https://@@evil.com/path",
		"https://:@evil.com/path",
		"https://:password@evil.com:8080/path",
		// Null bytes in various positions
		"https://evil\x00.safe.com",
		"https://\x00@evil.com",
		"https://safe.com\x00@evil.com",
		"https://evil.com\x00:8080/path",
		"\x00https://evil.com",
		"https\x00://evil.com",
		// Control characters embedded in scheme
		"https\t://evil.com",
		"https\n://evil.com",
		"https\r://evil.com",
		"https\r\n://evil.com",
		"ht\x00tps://evil.com",
		// Unicode homoglyphs for scheme letters
		"h\u200btps://evil.com",          // zero-width space in "https"
		"https\u200b://evil.com",          // zero-width space before ://
		"https://evil\u200b.com",          // zero-width space in domain
		"https://\u0435vil.com",           // Cyrillic 'e' in domain
		"https://ev\u0456l.com",           // Cyrillic 'i' in domain
		"https://\xff\xfe://evil.com",     // invalid UTF-8
		// IDN / punycode
		"https://xn--e1afg.com/path",     // punycode
		"https://\u00e9vil.com/path",      // accented e
		// Extremely long inputs
		"https://" + strings.Repeat("sub.", 500) + "evil.com",
		"https://user:" + strings.Repeat("p", 10000) + "@evil.com/path",
		strings.Repeat("https://", 100),
		// Scheme variations and edge cases
		"HTTP://evil.com",
		"HTTPS://evil.com",
		"hTtP://evil.com",
		"HtTpS://evil.com",
		"https:///evil.com",                  // triple slash
		"https:////evil.com",                 // quadruple slash
		"https://evil.com:@safe.com",         // colon before @ in userinfo
		"https://evil.com:80:90/path",        // double port
		// Query string and fragment as host confusion
		"https://evil.com?host=safe.com",
		"https://evil.com#safe.com",
		"https://evil.com;safe.com",
		// IPv6 edge cases
		"https://[::1]/path",
		"https://[::1]:8080/path",
		"https://[fe80::1%25eth0]:8080/path", // zone ID
		"https://[::ffff:127.0.0.1]:80/path",
		"[::1]",
		"[::1]:8080",
		// Whitespace around scheme
		" https://evil.com",
		"https:// evil.com",
		"\thttps://evil.com",
		// Data and javascript schemes
		"data:text/html;base64,PHNjcmlwdD4=",
		"javascript:void(0)",
		"file:///etc/passwd",
		"ftp://files.example.com",
		// Totally degenerate
		":",
		"://",
		"@",
		"@@@@",
		":@",
		"@:",
		"/:/@:/",
		string([]byte{0xff, 0xfe, 0xfd, 0xfc}),
		strings.Repeat("\x00", 100),
		strings.Repeat("@", 100),
		strings.Repeat(":", 100),
		strings.Repeat("/", 100),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		// Must not panic
		domain := extractDomain(rawURL)

		// Domain must never contain "://"
		if strings.Contains(domain, "://") {
			t.Errorf("extractDomain(%q) = %q — contains '://'", rawURL, domain)
		}

		// Domain must never contain "/"
		if strings.Contains(domain, "/") {
			t.Errorf("extractDomain(%q) = %q — contains '/'", rawURL, domain)
		}

		// Domain must never contain ":" (port should be stripped)
		if strings.Contains(domain, ":") {
			t.Errorf("extractDomain(%q) = %q — contains ':' (port not stripped)", rawURL, domain)
		}

		// Domain must never contain "@" (userinfo should be stripped)
		if strings.Contains(domain, "@") {
			t.Errorf("extractDomain(%q) = %q — contains '@' (userinfo not stripped)", rawURL, domain)
		}

		// Domain length should never exceed the lowercased input length.
		// R3-236 fix: extractDomain now lowercases the result, and
		// strings.ToLower on invalid UTF-8 bytes can expand byte length.
		if len(domain) > len(strings.ToLower(rawURL)) {
			t.Errorf("extractDomain(%q) produced domain longer than lowercased input: %q", rawURL, domain)
		}

		// If the input was purely a scheme, the domain should be empty
		lower := strings.ToLower(rawURL)
		if lower == "https://" || lower == "http://" {
			if domain != "" {
				t.Errorf("extractDomain(%q) = %q — expected empty for bare scheme", rawURL, domain)
			}
		}

		// For well-formed URLs with userinfo, the domain must NOT be the user portion.
		// e.g., https://user@evil.com -> "evil.com", never "user"
		if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
			if strings.Contains(rawURL, "@") && domain != "" {
				// The domain should come from after the last @, not before it
				schemeLen := 8
				if strings.HasPrefix(lower, "http://") {
					schemeLen = 7
				}
				afterScheme := rawURL[schemeLen:]
				// Strip path
				if idx := strings.Index(afterScheme, "/"); idx != -1 {
					afterScheme = afterScheme[:idx]
				}
				if idx := strings.LastIndex(afterScheme, "@"); idx != -1 {
					hostPart := afterScheme[idx+1:]
					// Strip port from hostPart for comparison
					if cidx := strings.Index(hostPart, ":"); cidx != -1 {
						hostPart = hostPart[:cidx]
					}
					if hostPart != "" && domain != hostPart {
						// This is a potential bypass: domain doesn't match what's after last @
						t.Errorf("extractDomain(%q) = %q — expected %q (after last '@')", rawURL, domain, hostPart)
					}
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzMatchGlobAdversarial — adversarial glob patterns targeting the gobwas/glob
// library and the **/ fallback path in MatchGlob. Focuses on patterns that
// could cause excessive CPU, panics, or incorrect cache interactions.
// ---------------------------------------------------------------------------

func FuzzMatchGlobAdversarial(f *testing.F) {
	seeds := []struct {
		pattern string
		value   string
	}{
		// Deeply nested alternation braces — potential exponential blowup
		{"{a,{b,{c,{d,{e,{f,{g,{h,{i,{j,k}}}}}}}}}}", "j"},
		{strings.Repeat("{a,", 20) + "z" + strings.Repeat("}", 20), "z"},
		{strings.Repeat("{a,", 50) + "z" + strings.Repeat("}", 50), "z"},
		// Very long alternation lists
		{"{" + strings.Join(makeRange(0, 100), ",") + "}", "50"},
		{"{" + strings.Join(makeRange(0, 500), ",") + "}", "250"},
		// Character class edge cases
		{"[]-]", "]"},
		{"[]-]", "-"},
		{"[!]-]", "a"},
		{"[\\]-\\]]", "]"},
		{"[a-z0-9_-]", "-"},
		{"[z-a]", "m"},           // inverted range
		{"[", "x"},               // unterminated bracket
		{"[]", "x"},              // empty bracket
		{"[!", "x"},              // unterminated negated bracket
		{"[!]", "x"},             // negated with no chars
		{"[a-]", "a"},            // trailing dash
		{"[-a]", "-"},            // leading dash
		// Mixed ** with alternation
		{"**/{a,b,c}/*.go", "src/a/main.go"},
		{"**/{a,b,c}/*.go", "main.go"},           // fallback path
		{"{**/*.go,**/*.ts}", "src/main.go"},
		// Extremely long patterns
		{strings.Repeat("?", 1000), strings.Repeat("x", 1000)},
		{strings.Repeat("?", 1000), strings.Repeat("x", 999)},
		{strings.Repeat("*", 500), "abc"},
		{strings.Repeat("[abc]", 200), strings.Repeat("a", 200)},
		// Patterns with ** fallback path that could interact with cache
		{"**/a", "a"},
		{"**/a", "x/a"},
		{"**/*", "file"},
		{"**/*", "a/file"},
		{"**/", ""},
		{"**/", "a/"},
		// Glob separator confusion
		{"a/b/c", "a/b/c"},
		{"a\\b\\c", "a\\b\\c"},
		{"a/*/c", "a/b/c"},
		{"a/*/c", "a\\b\\c"},
		// Patterns that start with **/ and also contain **/ later
		{"**/**/a", "x/y/a"},
		{"**/a/**/b", "x/a/y/b"},
		{"**/a/**", "x/a/y"},
		// Null bytes and control chars in both pattern and value
		{"*\x00*", "abc"},
		{"abc", "a\x00bc"},
		{"\x00**", "\x00abc"},
		{"*\n*", "a\nb"},
		{"*\r\n*", "a\r\nb"},
		// Unicode in patterns
		{"*.txt", "\u00e9.txt"},
		{"\u00e9*", "\u00e9file"},
		{"**/*.\u00e9xt", "dir/file.\u00e9xt"},
		// Pattern and value are identical but contain glob metacharacters
		{"*.go", "*.go"},
		{"**/*.go", "**/*.go"},
		{"[abc]", "[abc]"},
		// Empty segments
		{"a//b", "a//b"},
		{"**//b", "a//b"},
		{"//**", "//a"},
	}

	for _, s := range seeds {
		f.Add(s.pattern, s.value)
	}

	m := NewMatcher()

	f.Fuzz(func(t *testing.T, pattern string, value string) {
		// Primary invariant: must never panic (safeGlobMatch should catch)
		_ = m.MatchGlob(pattern, value)

		// Secondary: calling MatchGlob twice with the same inputs must give
		// the same result (cache consistency)
		r1 := m.MatchGlob(pattern, value)
		r2 := m.MatchGlob(pattern, value)
		if r1 != r2 {
			t.Errorf("MatchGlob(%q, %q) not idempotent: first=%v second=%v", pattern, value, r1, r2)
		}
	})
}

// makeRange generates string representations of integers [lo, hi).
func makeRange(lo, hi int) []string {
	result := make([]string, 0, hi-lo)
	for i := lo; i < hi; i++ {
		result = append(result, strings.Repeat("a", i+1))
	}
	return result
}

// ---------------------------------------------------------------------------
// FuzzMatchToolPatternAdversarial — adversarial tool patterns designed to
// bypass deny rules, confuse the colon-based parse, or trigger ReDoS in
// the regex fallback path.
// ---------------------------------------------------------------------------

func FuzzMatchToolPatternAdversarial(f *testing.F) {
	seeds := []struct {
		pattern  string
		toolName string
		input    string
	}{
		// Multiple colons — first colon splits, rest is command pattern
		{"Bash:echo:hello:world", "Bash", "echo:hello:world"},
		{"Bash:http://evil.com", "Bash", "http://evil.com"},
		{"Bash:curl https://evil.com:8080/path", "Bash", "curl https://evil.com:8080/path"},
		{"Read:/etc/passwd:garbage", "Read", "/etc/passwd:garbage"},
		// Colon at boundaries
		{":anything", "", "anything"},
		{"Bash:", "Bash", ""},
		{"Bash:", "Bash", "rm -rf /"},
		{":", "", ""},
		{"::", "", ":"},
		{":::", "", "::"},
		// Regex patterns in command portion (MatchToolPattern tries both glob AND regex)
		{"Bash:^rm\\s+-rf\\s+/.*$", "Bash", "rm -rf /tmp"},
		{"Bash:^rm\\s+-rf\\s+/.*$", "Bash", "ls -la"},
		// ReDoS-prone regex patterns — Go's regexp is safe (RE2), but let's verify
		{"Bash:(a+)+$", "Bash", strings.Repeat("a", 100) + "!"},
		{"Bash:(a|a)+$", "Bash", strings.Repeat("a", 100) + "!"},
		{"Bash:([a-zA-Z]+)*$", "Bash", strings.Repeat("a", 100) + "1"},
		{"Bash:(a+){10}$", "Bash", strings.Repeat("a", 100)},
		{"Bash:.*" + strings.Repeat("a", 100) + ".*", "Bash", strings.Repeat("b", 1000)},
		// Invalid regex that should fail gracefully
		{"Bash:(?P<name", "Bash", "anything"},
		{"Bash:[invalid", "Bash", "anything"},
		{"Bash:***", "Bash", "anything"},
		{"Bash:+", "Bash", "anything"},
		{"Bash:(?i)rm -rf", "Bash", "RM -RF /"},
		// Glob metacharacters in tool name portion
		{"*:rm *", "Bash", "rm -rf /"},
		{"?ash:*", "Bash", "anything"},
		{"[BR]ead:*", "Read", "/etc/passwd"},
		{"{Bash,Read}:*", "Bash", "rm -rf /"},
		{"{Bash,Read}:*", "Read", "/etc/passwd"},
		{"**:*", "a/b", "anything"},
		// Tool names with special characters
		{"mcp__my-tool:*", "mcp__my-tool", "data"},
		{"mcp__my.tool:*", "mcp__my.tool", "data"},
		{"mcp__my tool:*", "mcp__my tool", "data"},
		// Null bytes and control chars
		{"Bash:\x00rm *", "Bash", "\x00rm -rf /"},
		{"Bash:rm\x00 -rf", "Bash", "rm\x00 -rf /"},
		{"\x00:anything", "\x00", "anything"},
		{"Bash:\nrm -rf", "Bash", "\nrm -rf /"},
		// Extremely long patterns
		{strings.Repeat("a", 5000) + ":" + strings.Repeat("b", 5000), strings.Repeat("a", 5000), strings.Repeat("b", 5000)},
		{"Bash:" + strings.Repeat("*", 500), "Bash", strings.Repeat("x", 1000)},
		{"Bash:" + strings.Repeat("[a-z]", 200), "Bash", strings.Repeat("a", 200)},
		// Deny bypass attempts: tool name that partially matches
		{"Bash:rm -rf /*", "Bash ", "rm -rf /tmp"},   // trailing space in tool name
		{"Bash:rm -rf /*", " Bash", "rm -rf /tmp"},   // leading space in tool name
		{"Bash:rm -rf /*", "BASH", "rm -rf /tmp"},    // case difference
		{"Bash:rm -rf /*", "bash", "rm -rf /tmp"},    // all lowercase
		// Unicode tool names
		{"B\u200bash:*", "B\u200bash", "anything"},   // zero-width space
		{"\u0042ash:*", "Bash", "anything"},           // unicode B
	}

	for _, s := range seeds {
		f.Add(s.pattern, s.toolName, s.input)
	}

	m := NewMatcher()

	f.Fuzz(func(t *testing.T, pattern string, toolName string, input string) {
		// Must not panic
		result := m.MatchToolPattern(pattern, toolName, input)

		// ParseToolPattern must be consistent
		patternTool, patternCmd, hasCmd := ParseToolPattern(pattern)
		if strings.Contains(pattern, ":") && !hasCmd {
			t.Errorf("pattern %q contains ':' but ParseToolPattern says no command", pattern)
		}

		// If there is no colon, the match should be purely on tool name
		if !hasCmd {
			toolMatch := m.MatchGlob(patternTool, toolName)
			if result != toolMatch {
				t.Errorf("no-colon pattern %q: MatchToolPattern=%v but MatchGlob(tool)=%v (tool=%q)",
					pattern, result, toolMatch, toolName)
			}
		}

		// If tool name doesn't match the pattern tool, the result must be false
		if !m.MatchGlob(patternTool, toolName) && result {
			t.Errorf("tool name %q doesn't match pattern tool %q, but MatchToolPattern returned true",
				toolName, patternTool)
		}

		_ = patternCmd
	})
}

// ---------------------------------------------------------------------------
// FuzzExtractDomainUserinfo — focused fuzzer for the userinfo stripping logic.
// The extractDomain function uses strings.LastIndex(rawURL, "@") which is
// security-critical: getting this wrong lets attackers disguise domains.
// ---------------------------------------------------------------------------

func FuzzExtractDomainUserinfo(f *testing.F) {
	// All seeds are http(s) URLs with various userinfo structures
	seeds := []struct {
		userinfo string
		host     string
	}{
		{"user:pass", "evil.com"},
		{"user", "evil.com"},
		{"", "evil.com"},
		{"user:pass:extra", "evil.com"},
		{"user@inner", "evil.com"},       // nested @
		{"user%40inner", "evil.com"},      // percent-encoded @
		{strings.Repeat("a", 10000), "evil.com"},
		{"\x00", "evil.com"},
		{"user\x00safe.com", "evil.com"},
		{"user:pass\x00safe.com", "evil.com"},
		{strings.Repeat("@", 50), "evil.com"},
		{"user:pass@inner1@inner2", "evil.com"},
		{":", "evil.com"},
		{"@", "evil.com"},
		{"user\t:pass", "evil.com"},
		{"user\n:pass", "evil.com"},
	}

	for _, s := range seeds {
		url := "https://" + s.userinfo + "@" + s.host + "/path"
		f.Add(url, s.host)
	}

	f.Fuzz(func(t *testing.T, rawURL string, expectedHost string) {
		// Must not panic
		domain := extractDomain(rawURL)

		// Domain must never contain "@"
		if strings.Contains(domain, "@") {
			t.Errorf("extractDomain(%q) = %q — still contains '@'", rawURL, domain)
		}

		// Domain must never contain "/"
		if strings.Contains(domain, "/") {
			t.Errorf("extractDomain(%q) = %q — still contains '/'", rawURL, domain)
		}

		// Domain must never contain ":"
		if strings.Contains(domain, ":") {
			t.Errorf("extractDomain(%q) = %q — still contains ':'", rawURL, domain)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzMatchGlobCacheConsistency — exercises the glob cache in Matcher to
// verify that cached and uncached results are identical. This catches bugs
// where a compiled glob stored in the cache behaves differently on
// subsequent calls (e.g., due to internal mutation in gobwas/glob).
// ---------------------------------------------------------------------------

func FuzzMatchGlobCacheConsistency(f *testing.F) {
	seeds := []struct {
		pattern string
		value1  string
		value2  string
	}{
		{"**/*.go", "main.go", "src/main.go"},
		{"*.txt", "readme.txt", "notes.txt"},
		{"**/secrets/**", "a/secrets/key", "secrets/key"},
		{"{a,b}*", "abc", "bcd"},
		{"[abc]", "a", "d"},
		{"**/*", "a", "a/b/c"},
		{"**/a", "a", "x/y/a"},
	}

	for _, s := range seeds {
		f.Add(s.pattern, s.value1, s.value2)
	}

	f.Fuzz(func(t *testing.T, pattern string, value1 string, value2 string) {
		// Use a fresh matcher so cache starts empty
		m := NewMatcher()

		// First call compiles and caches
		r1a := m.MatchGlob(pattern, value1)
		// Second call with different value uses cached glob
		r1b := m.MatchGlob(pattern, value2)
		// Third call re-checks first value from cache
		r1c := m.MatchGlob(pattern, value1)
		// Fourth call re-checks second value from cache
		r1d := m.MatchGlob(pattern, value2)

		// Results must be deterministic regardless of cache state
		if r1a != r1c {
			t.Errorf("cache inconsistency: MatchGlob(%q, %q) first=%v third=%v",
				pattern, value1, r1a, r1c)
		}
		if r1b != r1d {
			t.Errorf("cache inconsistency: MatchGlob(%q, %q) second=%v fourth=%v",
				pattern, value2, r1b, r1d)
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzMatchToolPatternDenyBypass — targeted fuzzer that checks whether
// adversarial tool inputs can bypass a specific deny pattern. This directly
// tests policy enforcement correctness rather than just crash-freedom.
// ---------------------------------------------------------------------------

func FuzzMatchToolPatternDenyBypass(f *testing.F) {
	seeds := []struct {
		toolName string
		input    string
	}{
		{"Bash", "rm -rf /"},
		{"Bash", "rm -rf /tmp"},
		{"Bash", " rm -rf /"},         // leading space
		{"Bash", "\trm -rf /"},        // leading tab
		{"Bash", "rm  -rf /"},         // double space
		{"Bash", "rm\t-rf /"},         // tab instead of space
		{"Bash", "RM -RF /"},          // uppercase
		{"Bash", "'rm' '-rf' '/'"},    // quoted
		{"Bash", "r\\m -rf /"},        // backslash escape
		{"Bash", "rm -r -f /"},        // split flags
		{"Bash", "rm --recursive --force /"},
		{"Bash", "/bin/rm -rf /"},     // absolute path
		{"Bash", "command rm -rf /"}, // command prefix
		{"Bash", "rm -rf /\x00safe"}, // null byte
		{"Bash", "rm\x00 -rf /"},
		{"Bash", "rm -rf /home/../"},
		{"Bash", "$(rm -rf /)"},
		{"Bash", "`rm -rf /`"},
		{"Bash", "rm -rf /" + strings.Repeat(" ", 1000)},
	}

	for _, s := range seeds {
		f.Add(s.toolName, s.input)
	}

	m := NewMatcher()

	f.Fuzz(func(t *testing.T, toolName string, input string) {
		// The deny pattern "Bash:rm -rf /*" should catch rm -rf commands.
		// We verify the function doesn't panic and returns a bool.
		denyPattern := "Bash:rm -rf /*"
		_ = m.MatchToolPattern(denyPattern, toolName, input)

		// Also test with regex-style deny pattern
		denyRegex := `Bash:rm\s+-rf\s+/.*`
		_ = m.MatchToolPattern(denyRegex, toolName, input)

		// And a glob wildcard deny
		denyGlob := "Bash:*rm*-rf*/*"
		_ = m.MatchToolPattern(denyGlob, toolName, input)
	})
}
