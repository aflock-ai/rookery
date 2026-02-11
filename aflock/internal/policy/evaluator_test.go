package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// ---------------------------------------------------------------------------
// EvaluatePreToolUse – deny list
// ---------------------------------------------------------------------------

func TestEvaluatePreToolUse_DenyList(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "exact tool name in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
					Deny:  []string{"Task"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "tool with command pattern in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
					Deny:  []string{"Bash:rm *"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "rm -rf /tmp/test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "bash allowed when command does not match deny pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash"},
					Deny:  []string{"Bash:rm *"},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "ls -la"}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "glob deny pattern with wildcard tool name",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Deny: []string{"mcp__*"},
				},
			},
			toolName:       "mcp__github",
			toolInput:      `{}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "deny list takes priority over allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash"},
					Deny:  []string{"Bash"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "echo hi"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "multiple deny patterns - second one matches",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Deny: []string{"Task", "WebFetch"},
				},
			},
			toolName:       "WebFetch",
			toolInput:      `{"url": "https://evil.com"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EvaluatePreToolUse – allow list
// ---------------------------------------------------------------------------

func TestEvaluatePreToolUse_AllowList(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "allowed tool in list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Read", "Write", "Bash"},
				},
			},
			toolName:     "Read",
			toolInput:    `{"file_path": "test.go"}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "tool not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Read", "Write"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "empty allow list allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{},
			},
			toolName:     "AnyTool",
			toolInput:    `{}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "wildcard allow list allows everything",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
				},
			},
			toolName:     "SomeRandomTool",
			toolInput:    `{}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "glob pattern in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"mcp__*", "Read"},
				},
			},
			toolName:     "mcp__github",
			toolInput:    `{}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "glob pattern in allow list non-matching",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"mcp__*"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "echo hi"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "allow list with tool:command pattern still matches tool name only",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash:ls *"},
				},
			},
			// The allow list check only looks at the tool name portion of the pattern
			toolName:     "Bash",
			toolInput:    `{"command": "rm -rf /"}`,
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EvaluatePreToolUse – requireApproval
// ---------------------------------------------------------------------------

func TestEvaluatePreToolUse_RequireApproval(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "tool requires approval via command pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow:           []string{"Bash"},
					RequireApproval: []string{"Bash:git push*"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "git push origin main"}`,
			wantDecision:   aflock.DecisionAsk,
			wantReasonPart: "requires approval",
		},
		{
			name: "tool does not match approval pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow:           []string{"Bash"},
					RequireApproval: []string{"Bash:git push*"},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "git status"}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "tool name only in requireApproval",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					RequireApproval: []string{"Task"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "do something dangerous"}`,
			wantDecision:   aflock.DecisionAsk,
			wantReasonPart: "requires approval",
		},
		{
			name: "deny takes priority over requireApproval",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Deny:            []string{"Task"},
					RequireApproval: []string{"Task"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "requireApproval with glob tool pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					RequireApproval: []string{"mcp__*"},
				},
			},
			toolName:       "mcp__slack_send",
			toolInput:      `{}`,
			wantDecision:   aflock.DecisionAsk,
			wantReasonPart: "requires approval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evaluateFileAccess
// ---------------------------------------------------------------------------

func TestEvaluateFileAccess(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		filePath       string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "file in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"src/**", "tests/**"},
				},
			},
			toolName:     "Read",
			filePath:     "src/main.go",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "file not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"src/**"},
				},
			},
			toolName:       "Read",
			filePath:       "config/secrets.yaml",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "file matches deny pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"**/*"},
					Deny:  []string{"**/.env", "**/secrets/**"},
				},
			},
			toolName:       "Read",
			filePath:       "src/.env",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "write to read-only file denied",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Write"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"package.json", "go.mod"},
				},
			},
			toolName:       "Write",
			filePath:       "go.mod",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "read-only",
		},
		{
			name: "edit to read-only file denied",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Edit"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"*.lock"},
				},
			},
			toolName:       "Edit",
			filePath:       "yarn.lock",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "read-only",
		},
		{
			name: "read from read-only file allowed",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"go.mod"},
				},
			},
			toolName:     "Read",
			filePath:     "go.mod",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "deny takes priority over allow for files",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"**/*"},
					Deny:  []string{"**/private/**"},
				},
			},
			toolName:       "Read",
			filePath:       "data/private/key.pem",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "secrets directory deny with nested path",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"**/secrets/**"},
				},
			},
			toolName:       "Read",
			filePath:       "config/secrets/key.pem",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "nil files policy allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
			},
			toolName:     "Read",
			filePath:     "/etc/passwd",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "empty files policy allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{},
			},
			toolName:     "Read",
			filePath:     "anything.txt",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "Glob tool is a file operation",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Glob"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"**/secret*"},
				},
			},
			toolName:       "Glob",
			filePath:       "secret-keys",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "Grep tool is a file operation",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Grep"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"**/secret*"},
				},
			},
			toolName:       "Grep",
			filePath:       "secret-keys",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "absolute path file deny",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"/etc/**"},
				},
			},
			toolName:       "Read",
			filePath:       "/etc/shadow",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			input := json.RawMessage(`{"file_path": "` + tt.filePath + `"}`)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, input)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evaluateDomainAccess
// ---------------------------------------------------------------------------

func TestEvaluateDomainAccess(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		url            string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "domain in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"api.github.com", "*.anthropic.com"},
				},
			},
			toolName:     "WebFetch",
			url:          "https://api.github.com/repos",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "domain not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"api.github.com"},
				},
			},
			toolName:       "WebFetch",
			url:            "https://evil.com/steal",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "domain in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"*.evil.com"},
				},
			},
			toolName:       "WebFetch",
			url:            "https://api.evil.com/data",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "deny takes priority over allow for domains",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"*.example.com"},
					Deny:  []string{"bad.example.com"},
				},
			},
			toolName:       "WebFetch",
			url:            "https://bad.example.com/data",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "wildcard subdomain in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"*.anthropic.com"},
				},
			},
			toolName:     "WebFetch",
			url:          "https://docs.anthropic.com/api",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "nil domains policy allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
			},
			toolName:     "WebFetch",
			url:          "https://anything.com",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "empty domains policy allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{},
			},
			toolName:     "WebFetch",
			url:          "https://anything.com",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "WebSearch is a network operation",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebSearch"}},
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"evil.com"},
				},
			},
			toolName:       "WebSearch",
			url:            "https://evil.com/search",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "mcp__ prefixed tool is treated as network operation",
			policy: &aflock.Policy{
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"evil.com"},
				},
			},
			toolName:       "mcp__slack",
			url:            "https://evil.com/webhook",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "URL with port",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"localhost"},
				},
			},
			toolName:     "WebFetch",
			url:          "http://localhost:8080/api",
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			input := json.RawMessage(`{"url": "` + tt.url + `"}`)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, input)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EvaluateDataFlow
// ---------------------------------------------------------------------------

func TestEvaluateDataFlow(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		materials      []aflock.MaterialClassification
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
		wantLabel      string
	}{
		{
			name: "read financial data classifies as financial",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv", "Read:**/account*.csv"},
						"public":    {"Bash:*bird*", "Bash:*tweet*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public", Message: "Cannot post financial data to public channels"},
					},
				},
			},
			toolName:     "Read",
			toolInput:    `{"file_path": "/home/user/bank-account.csv"}`,
			materials:    nil,
			wantDecision: aflock.DecisionAllow,
			wantLabel:    "financial",
		},
		{
			name: "bash command to twitter blocked after financial read",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
						"public":    {"Bash:*bird*", "Bash:*tweet*", "Bash:*twitter*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public", Message: "Cannot post financial data to public channels"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "bird tweet 'I spent $500 today'"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/home/user/bank-account.csv"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "Cannot post financial data",
		},
		{
			name: "bash command to imsg allowed after financial read",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
						"public":    {"Bash:*bird*", "Bash:*tweet*"},
						"private":   {"Bash:*imsg*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public", Message: "Cannot post financial data to public channels"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "imsg send --to wife 'Check our balance'"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/home/user/bank-account.csv"},
			},
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "no materials - all operations allowed",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
						"public":    {"Bash:*bird*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public"},
					},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "bird tweet 'Hello world'"}`,
			materials:    nil,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "pii data blocked from public",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"pii":    {"Read:**/users/**", "Read:**/customers/**"},
						"public": {"Bash:*curl*api.public*", "Write:**/public/**"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "pii->public", Message: "PII cannot be sent to public APIs"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "curl -X POST api.public.com/data"}`,
			materials: []aflock.MaterialClassification{
				{Label: "pii", Source: "Read:/data/users/user123.json"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "PII cannot be sent",
		},
		{
			name:      "no dataFlow policy - allow all",
			policy:    &aflock.Policy{},
			toolName:  "Bash",
			toolInput: `{"command": "bird tweet 'anything'"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/bank.csv"},
			},
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "default deny message when no custom message",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"internal": {"Read:**/internal/**"},
						"external": {"Bash:*curl*external*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "internal->external"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "curl external-api.com"}`,
			materials: []aflock.MaterialClassification{
				{Label: "internal", Source: "Read:/data/internal/doc.txt"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "Data flow violation",
		},
		{
			name: "duplicate material label is not re-added",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
					},
				},
			},
			toolName:  "Read",
			toolInput: `{"file_path": "/home/user/bank-other.csv"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/home/user/bank-first.csv"},
			},
			wantDecision: aflock.DecisionAllow,
			wantLabel:    "", // no new material because label already present
		},
		{
			name: "write to file classified as external sink is blocked",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"secret": {"Read:**/.ssh/**"},
						"public": {"Write:**/public/**"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "secret->public", Message: "Cannot expose secrets publicly"},
					},
				},
			},
			toolName:  "Write",
			toolInput: `{"file_path": "/var/www/public/keys.txt"}`,
			materials: []aflock.MaterialClassification{
				{Label: "secret", Source: "Read:/home/user/.ssh/id_rsa"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "Cannot expose secrets publicly",
		},
		{
			name: "Edit to classified sink is blocked",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"secret": {"Read:**/.ssh/**"},
						"public": {"Edit:**/public/**"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "secret->public", Message: "No secrets in public"},
					},
				},
			},
			toolName:  "Edit",
			toolInput: `{"file_path": "/var/www/public/index.html"}`,
			materials: []aflock.MaterialClassification{
				{Label: "secret", Source: "Read:/home/user/.ssh/id_rsa"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "No secrets in public",
		},
		{
			name: "malformed flow rule is skipped",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"a": {"Read:**/a/**"},
						"b": {"Bash:*b*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "not-a-valid-rule"},
						{Deny: "a->b", Message: "blocked"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "run_b"}`,
			materials: []aflock.MaterialClassification{
				{Label: "a", Source: "Read:/data/a/file"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			decision, reason, newMaterial := e.EvaluateDataFlow(tt.toolName, json.RawMessage(tt.toolInput), tt.materials)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
			if tt.wantLabel != "" {
				if newMaterial == nil {
					t.Errorf("expected new material with label %q, got nil", tt.wantLabel)
				} else if newMaterial.Label != tt.wantLabel {
					t.Errorf("got material label %q, want %q", newMaterial.Label, tt.wantLabel)
				}
			}
			if tt.wantLabel == "" && newMaterial != nil {
				t.Errorf("expected no new material, got label %q", newMaterial.Label)
			}
		})
	}
}

func TestEvaluateDataFlow_ExfilPrevention(t *testing.T) {
	policy := &aflock.Policy{
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"financial": {
					"Read:**/bank-*.csv",
					"Read:**/account*.csv",
					"Read:**/financial*.csv",
				},
				"public": {
					"Bash:*bird*",
					"Bash:*tweet*",
					"Bash:*twitter*",
					"Bash:*curl*twitter*",
					"Bash:*curl*x.com*",
					"Bash:*linkedin*",
				},
				"private": {
					"Bash:*imsg*",
				},
			},
			FlowRules: []aflock.DataFlowRule{
				{
					Deny:    "financial->public",
					Message: "BLOCKED: Cannot post financial data to public channels (Twitter/X, LinkedIn). Use private channels instead.",
				},
			},
		},
	}

	e := NewEvaluator(policy)

	// Step 1: Read bank account data - should classify as financial
	readInput := json.RawMessage(`{"file_path": "/Users/test/private-data/bank-account.csv"}`)
	decision, _, newMaterial := e.EvaluateDataFlow("Read", readInput, nil)
	if decision != aflock.DecisionAllow {
		t.Errorf("Expected read to be allowed, got %v", decision)
	}
	if newMaterial == nil || newMaterial.Label != "financial" {
		t.Errorf("Expected financial material classification, got %v", newMaterial)
	}

	materials := []aflock.MaterialClassification{*newMaterial}

	// Step 2: Try to tweet - should be BLOCKED
	tweetInput := json.RawMessage(`{"command": "bird tweet 'My bank balance is $10,111.08'"}`)
	decision, reason, _ := e.EvaluateDataFlow("Bash", tweetInput, materials)
	if decision != aflock.DecisionDeny {
		t.Errorf("Expected tweet to be blocked, got %v (reason: %s)", decision, reason)
	}
	if !strings.Contains(reason, "BLOCKED") {
		t.Errorf("Expected BLOCKED in reason, got: %s", reason)
	}

	// Step 3: Send via iMessage - should be ALLOWED
	imsgInput := json.RawMessage(`{"command": "imsg send --to wife 'Our balance is $10,111.08'"}`)
	decision, reason, _ = e.EvaluateDataFlow("Bash", imsgInput, materials)
	if decision != aflock.DecisionAllow {
		t.Errorf("Expected imsg to be allowed, got %v (reason: %s)", decision, reason)
	}
}

// ---------------------------------------------------------------------------
// CheckLimits
// ---------------------------------------------------------------------------

func TestCheckLimits(t *testing.T) {
	tests := []struct {
		name        string
		policy      *aflock.Policy
		metrics     *aflock.SessionMetrics
		enforcement string
		wantExceed  bool
		wantLimit   string
	}{
		{
			name: "under all limits",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
					MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 5.0,
				Turns:   10,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "exceeds spend limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 5.0, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 10.0,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxSpendUSD",
		},
		{
			name: "exceeds turns limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 15,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxTurns",
		},
		{
			name: "exceeds tokensIn limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTokensIn: &aflock.Limit{Value: 1000, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				TokensIn: 2000,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxTokensIn",
		},
		{
			name: "exceeds tokensOut limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTokensOut: &aflock.Limit{Value: 500, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				TokensOut: 501,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxTokensOut",
		},
		{
			name: "exceeds toolCalls limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxToolCalls: &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				ToolCalls: 101,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxToolCalls",
		},
		{
			name: "within tokensIn limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTokensIn: &aflock.Limit{Value: 1000, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				TokensIn: 999,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "within toolCalls limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxToolCalls: &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				ToolCalls: 50,
			},
			enforcement: "fail-fast",
			wantExceed:  false, // not exceeded: 50 is not > 50
		},
		{
			name: "post-hoc enforcement not checked during fail-fast",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "post-hoc"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 100,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "post-hoc enforcement checked when requested",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "post-hoc"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 100,
			},
			enforcement: "post-hoc",
			wantExceed:  true,
			wantLimit:   "maxTurns",
		},
		{
			name:   "nil limits policy never exceeds",
			policy: &aflock.Policy{},
			metrics: &aflock.SessionMetrics{
				CostUSD:   999.0,
				TokensIn:  999999,
				TokensOut: 999999,
				Turns:     999,
				ToolCalls: 999,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "empty limits policy never exceeds",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 999.0,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "spend is checked before turns - first exceeded wins",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 1.0, Enforcement: "fail-fast"},
					MaxTurns:    &aflock.Limit{Value: 1, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 10.0,
				Turns:   100,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxSpendUSD", // spend is checked before turns
		},
		{
			name: "limit message includes values",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 5.0, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 7.5,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxSpendUSD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy)
			exceeded, limitName, msg := e.CheckLimits(tt.metrics, tt.enforcement)

			if exceeded != tt.wantExceed {
				t.Errorf("got exceeded=%v, want %v (msg: %s)", exceeded, tt.wantExceed, msg)
			}
			if tt.wantExceed && limitName != tt.wantLimit {
				t.Errorf("got limit=%q, want %q", limitName, tt.wantLimit)
			}
			if tt.wantExceed && msg == "" {
				t.Error("expected non-empty message when limit exceeded")
			}
			if !tt.wantExceed && msg != "" {
				t.Errorf("expected empty message when limit not exceeded, got %q", msg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fail-closed: malformed JSON tool input
// ---------------------------------------------------------------------------

func TestFailClosed_MalformedJSON(t *testing.T) {
	t.Run("malformed JSON for file tool returns deny", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
			Files: &aflock.FilesPolicy{
				Allow: []string{"**/*"},
			},
		}
		e := NewEvaluator(policy)
		// Malformed JSON: missing closing brace
		decision, reason := e.EvaluatePreToolUse("Read", json.RawMessage(`{invalid json`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for malformed JSON, got %v (reason: %s)", decision, reason)
		}
		if !strings.Contains(reason, "failed to parse") {
			t.Errorf("reason should mention parse failure, got %q", reason)
		}
	})

	t.Run("malformed JSON for domain tool returns deny", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
			Domains: &aflock.DomainsPolicy{
				Allow: []string{"*"},
			},
		}
		e := NewEvaluator(policy)
		decision, reason := e.EvaluatePreToolUse("WebFetch", json.RawMessage(`not json at all`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for malformed JSON, got %v (reason: %s)", decision, reason)
		}
		if !strings.Contains(reason, "failed to parse") {
			t.Errorf("reason should mention parse failure, got %q", reason)
		}
	})

	t.Run("empty JSON object for file tool with allow list denies", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
			Files: &aflock.FilesPolicy{
				Allow: []string{"src/**"},
			},
		}
		e := NewEvaluator(policy)
		// Empty file_path will not match allow patterns
		decision, _ := e.EvaluatePreToolUse("Read", json.RawMessage(`{}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for empty file path with allow list, got %v", decision)
		}
	})

	t.Run("empty JSON for domain tool with allow list denies", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
			Domains: &aflock.DomainsPolicy{
				Allow: []string{"github.com"},
			},
		}
		e := NewEvaluator(policy)
		// Empty URL will extract to empty domain -> "empty domain" deny
		decision, reason := e.EvaluatePreToolUse("WebFetch", json.RawMessage(`{}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for empty URL, got %v (reason: %s)", decision, reason)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge cases: nil/empty policy sections, no rules
// ---------------------------------------------------------------------------

func TestEdgeCases_NilPolicySections(t *testing.T) {
	t.Run("nil tools policy allows everything", func(t *testing.T) {
		policy := &aflock.Policy{}
		e := NewEvaluator(policy)
		decision, _ := e.EvaluatePreToolUse("AnyTool", json.RawMessage(`{}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with nil tools policy, got %v", decision)
		}
	})

	t.Run("nil tools with file tool still checks files policy", func(t *testing.T) {
		policy := &aflock.Policy{
			Files: &aflock.FilesPolicy{
				Deny: []string{"**/.env"},
			},
		}
		e := NewEvaluator(policy)
		decision, reason := e.EvaluatePreToolUse("Read", json.RawMessage(`{"file_path": ".env"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for .env file, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("nil tools with WebFetch still checks domains policy", func(t *testing.T) {
		policy := &aflock.Policy{
			Domains: &aflock.DomainsPolicy{
				Deny: []string{"evil.com"},
			},
		}
		e := NewEvaluator(policy)
		decision, reason := e.EvaluatePreToolUse("WebFetch", json.RawMessage(`{"url": "https://evil.com/data"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for evil.com, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("non-file non-network tool with nil tools policy", func(t *testing.T) {
		policy := &aflock.Policy{
			Files: &aflock.FilesPolicy{
				Deny: []string{"**/*"},
			},
			Domains: &aflock.DomainsPolicy{
				Deny: []string{"*"},
			},
		}
		e := NewEvaluator(policy)
		// "Task" is not a file operation or network operation
		decision, _ := e.EvaluatePreToolUse("Task", json.RawMessage(`{"prompt": "test"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow for non-file non-network tool, got %v", decision)
		}
	})

	t.Run("completely empty policy allows everything", func(t *testing.T) {
		policy := &aflock.Policy{}
		e := NewEvaluator(policy)

		decision, _ := e.EvaluatePreToolUse("Bash", json.RawMessage(`{"command": "rm -rf /"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with empty policy, got %v", decision)
		}

		decision, _ = e.EvaluatePreToolUse("Read", json.RawMessage(`{"file_path": "/etc/shadow"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with empty policy, got %v", decision)
		}

		decision, _ = e.EvaluatePreToolUse("WebFetch", json.RawMessage(`{"url": "https://evil.com"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with empty policy, got %v", decision)
		}
	})
}

// ---------------------------------------------------------------------------
// extractDomain helper
// ---------------------------------------------------------------------------

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url    string
		domain string
	}{
		{"https://api.github.com/repos", "api.github.com"},
		{"http://example.com:8080/path", "example.com"},
		{"https://sub.domain.com/", "sub.domain.com"},
		{"example.com", "example.com"},
		{"https://localhost:3000", "localhost"},
		{"", ""},
		{"https://", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractDomain(tt.url)
			if got != tt.domain {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.url, got, tt.domain)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isFileOperation / isNetworkOperation helpers
// ---------------------------------------------------------------------------

func TestIsFileOperation(t *testing.T) {
	fileOps := []string{"Read", "Write", "Edit", "Glob", "Grep"}
	for _, tool := range fileOps {
		if !isFileOperation(tool) {
			t.Errorf("expected %q to be a file operation", tool)
		}
	}

	nonFileOps := []string{"Bash", "Task", "WebFetch", "WebSearch", "mcp__github"}
	for _, tool := range nonFileOps {
		if isFileOperation(tool) {
			t.Errorf("expected %q to NOT be a file operation", tool)
		}
	}
}

func TestIsNetworkOperation(t *testing.T) {
	netOps := []string{"WebFetch", "WebSearch", "mcp__slack", "mcp__github_api"}
	for _, tool := range netOps {
		if !isNetworkOperation(tool) {
			t.Errorf("expected %q to be a network operation", tool)
		}
	}

	nonNetOps := []string{"Read", "Write", "Edit", "Bash", "Task", "Glob", "Grep"}
	for _, tool := range nonNetOps {
		if isNetworkOperation(tool) {
			t.Errorf("expected %q to NOT be a network operation", tool)
		}
	}
}

// ---------------------------------------------------------------------------
// extractInputForMatching
// ---------------------------------------------------------------------------

func TestExtractInputForMatching(t *testing.T) {
	e := NewEvaluator(&aflock.Policy{})

	tests := []struct {
		name     string
		toolName string
		input    string
		want     string
	}{
		{"Bash extracts command", "Bash", `{"command": "echo hello"}`, "echo hello"},
		{"Read extracts file_path", "Read", `{"file_path": "/tmp/test.go"}`, "/tmp/test.go"},
		{"Write extracts file_path", "Write", `{"file_path": "/tmp/out.txt"}`, "/tmp/out.txt"},
		{"Edit extracts file_path", "Edit", `{"file_path": "/tmp/fix.go"}`, "/tmp/fix.go"},
		{"Task extracts prompt", "Task", `{"prompt": "summarize this"}`, "summarize this"},
		{"WebFetch extracts url", "WebFetch", `{"url": "https://example.com"}`, "https://example.com"},
		{"unknown tool returns empty", "Unknown", `{"foo": "bar"}`, ""},
		{"malformed JSON returns empty", "Bash", `{bad`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.extractInputForMatching(tt.toolName, json.RawMessage(tt.input))
			if got != tt.want {
				t.Errorf("extractInputForMatching(%q, ...) = %q, want %q", tt.toolName, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isReadOperation / isWriteOperation helpers
// ---------------------------------------------------------------------------

func TestIsReadOperation(t *testing.T) {
	readOps := []string{"Read", "Glob", "Grep", "WebFetch"}
	for _, tool := range readOps {
		if !isReadOperation(tool) {
			t.Errorf("expected %q to be a read operation", tool)
		}
	}

	// mcp__ without "write" is a read
	if !isReadOperation("mcp__slack_read") {
		t.Error("expected mcp__slack_read to be a read operation")
	}

	// mcp__ with "write" is NOT a read
	if isReadOperation("mcp__slack_write") {
		t.Error("expected mcp__slack_write to NOT be a read operation")
	}

	nonReadOps := []string{"Write", "Edit", "Bash", "Task"}
	for _, tool := range nonReadOps {
		if isReadOperation(tool) {
			t.Errorf("expected %q to NOT be a read operation", tool)
		}
	}
}

func TestIsWriteOperation(t *testing.T) {
	writeOps := []string{"Write", "Edit", "Bash"}
	for _, tool := range writeOps {
		if !isWriteOperation(tool) {
			t.Errorf("expected %q to be a write operation", tool)
		}
	}

	// mcp__ with "write" is a write
	if !isWriteOperation("mcp__slack_write") {
		t.Error("expected mcp__slack_write to be a write operation")
	}

	// mcp__ without "write" is NOT a write
	if isWriteOperation("mcp__slack_read") {
		t.Error("expected mcp__slack_read to NOT be a write operation")
	}

	nonWriteOps := []string{"Read", "Glob", "Grep", "WebFetch", "Task"}
	for _, tool := range nonWriteOps {
		if isWriteOperation(tool) {
			t.Errorf("expected %q to NOT be a write operation", tool)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: evaluation order / priority
// ---------------------------------------------------------------------------

func TestEvaluationOrder(t *testing.T) {
	t.Run("deny checked before requireApproval", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{
				Deny:            []string{"Bash:rm *"},
				RequireApproval: []string{"Bash:rm *"},
			},
		}
		e := NewEvaluator(policy)
		decision, reason := e.EvaluatePreToolUse("Bash", json.RawMessage(`{"command": "rm -rf /"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected deny to take priority over requireApproval, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("requireApproval checked before file access", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{
				RequireApproval: []string{"Write"},
			},
			Files: &aflock.FilesPolicy{
				Allow: []string{"**/*"},
			},
		}
		e := NewEvaluator(policy)
		decision, reason := e.EvaluatePreToolUse("Write", json.RawMessage(`{"file_path": "test.txt"}`))
		if decision != aflock.DecisionAsk {
			t.Errorf("expected requireApproval before file access check, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("file access checked before tool allow list", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{
				Allow: []string{"Read"},
			},
			Files: &aflock.FilesPolicy{
				Deny: []string{"**/.secret"},
			},
		}
		e := NewEvaluator(policy)
		decision, reason := e.EvaluatePreToolUse("Read", json.RawMessage(`{"file_path": ".secret"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected file deny to block before allow list passes, got %v (reason: %s)", decision, reason)
		}
		if !strings.Contains(reason, "matches deny pattern") {
			t.Errorf("expected file deny reason, got: %s", reason)
		}
	})
}
