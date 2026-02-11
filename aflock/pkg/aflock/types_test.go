package aflock

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLimitUnmarshalJSON_Number(t *testing.T) {
	var l Limit
	if err := json.Unmarshal([]byte(`42.5`), &l); err != nil {
		t.Fatalf("Unmarshal number: %v", err)
	}
	if l.Value != 42.5 {
		t.Errorf("Value = %f, want 42.5", l.Value)
	}
	if l.Enforcement != "fail-fast" {
		t.Errorf("Enforcement = %q, want %q", l.Enforcement, "fail-fast")
	}
}

func TestLimitUnmarshalJSON_Object(t *testing.T) {
	var l Limit
	if err := json.Unmarshal([]byte(`{"value": 100, "enforcement": "post-hoc"}`), &l); err != nil {
		t.Fatalf("Unmarshal object: %v", err)
	}
	if l.Value != 100 {
		t.Errorf("Value = %f, want 100", l.Value)
	}
	if l.Enforcement != "post-hoc" {
		t.Errorf("Enforcement = %q, want %q", l.Enforcement, "post-hoc")
	}
}

func TestLimitUnmarshalJSON_ObjectDefaultEnforcement(t *testing.T) {
	var l Limit
	if err := json.Unmarshal([]byte(`{"value": 50}`), &l); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if l.Enforcement != "fail-fast" {
		t.Errorf("Enforcement = %q, want %q (default)", l.Enforcement, "fail-fast")
	}
}

func TestLimitUnmarshalJSON_Invalid(t *testing.T) {
	var l Limit
	if err := json.Unmarshal([]byte(`"not a number"`), &l); err == nil {
		t.Error("expected error for string input")
	}
}

func TestLimitUnmarshalJSON_Zero(t *testing.T) {
	var l Limit
	if err := json.Unmarshal([]byte(`0`), &l); err != nil {
		t.Fatalf("Unmarshal zero: %v", err)
	}
	if l.Value != 0 {
		t.Errorf("Value = %f, want 0", l.Value)
	}
}

func TestLimitUnmarshalJSON_InPolicy(t *testing.T) {
	data := `{
		"limits": {
			"maxSpendUSD": 10.0,
			"maxTurns": {"value": 50, "enforcement": "post-hoc"},
			"maxToolCalls": 100
		}
	}`
	var p Policy
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		t.Fatalf("Unmarshal policy: %v", err)
	}
	if p.Limits == nil {
		t.Fatal("Limits should not be nil")
	}
	if p.Limits.MaxSpendUSD == nil || p.Limits.MaxSpendUSD.Value != 10.0 {
		t.Errorf("MaxSpendUSD = %v", p.Limits.MaxSpendUSD)
	}
	if p.Limits.MaxTurns == nil || p.Limits.MaxTurns.Value != 50 || p.Limits.MaxTurns.Enforcement != "post-hoc" {
		t.Errorf("MaxTurns = %v", p.Limits.MaxTurns)
	}
	if p.Limits.MaxToolCalls == nil || p.Limits.MaxToolCalls.Value != 100 {
		t.Errorf("MaxToolCalls = %v", p.Limits.MaxToolCalls)
	}
}

func TestPolicyIsExpired(t *testing.T) {
	// No expiry
	p := &Policy{}
	if p.IsExpired() {
		t.Error("Policy without expires should not be expired")
	}

	// Future expiry
	future := time.Now().Add(24 * time.Hour)
	p = &Policy{Expires: &future}
	if p.IsExpired() {
		t.Error("Policy with future expiry should not be expired")
	}

	// Past expiry
	past := time.Now().Add(-24 * time.Hour)
	p = &Policy{Expires: &past}
	if !p.IsExpired() {
		t.Error("Policy with past expiry should be expired")
	}
}

func TestParseDataFlowRule(t *testing.T) {
	tests := []struct {
		rule       string
		wantSource string
		wantSink   string
		wantOk     bool
	}{
		{"internal->public", "internal", "public", true},
		{"pii -> external", "pii", "external", true},
		{"no-arrow", "", "", false},
		{"a->b->c", "", "", false},
		{"->sink", "", "sink", true},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			source, sink, ok := ParseDataFlowRule(tt.rule)
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v", ok, tt.wantOk)
			}
			if source != tt.wantSource {
				t.Errorf("source = %q, want %q", source, tt.wantSource)
			}
			if sink != tt.wantSink {
				t.Errorf("sink = %q, want %q", sink, tt.wantSink)
			}
		})
	}
}

func TestPolicyMarshalRoundTrip(t *testing.T) {
	expires := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	original := &Policy{
		Version: "1.0",
		Name:    "test-policy",
		Expires: &expires,
		Tools: &ToolsPolicy{
			Allow:           []string{"Read", "Write"},
			Deny:            []string{"Bash:rm -rf *"},
			RequireApproval: []string{"Bash"},
		},
		Files: &FilesPolicy{
			Allow:    []string{"src/**"},
			Deny:     []string{".env", "*.key"},
			ReadOnly: []string{"go.mod", "go.sum"},
		},
		Domains: &DomainsPolicy{
			Allow: []string{"github.com", "*.googleapis.com"},
			Deny:  []string{"evil.com"},
		},
		Limits: &LimitsPolicy{
			MaxSpendUSD: &Limit{Value: 10.0, Enforcement: "fail-fast"},
			MaxTurns:    &Limit{Value: 50, Enforcement: "post-hoc"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var roundTripped Policy
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if roundTripped.Name != original.Name {
		t.Errorf("Name = %q, want %q", roundTripped.Name, original.Name)
	}
	if roundTripped.Version != original.Version {
		t.Errorf("Version = %q, want %q", roundTripped.Version, original.Version)
	}
	if roundTripped.Tools == nil {
		t.Fatal("Tools should not be nil")
	}
	if len(roundTripped.Tools.Allow) != 2 {
		t.Errorf("Tools.Allow len = %d, want 2", len(roundTripped.Tools.Allow))
	}
	if len(roundTripped.Files.Deny) != 2 {
		t.Errorf("Files.Deny len = %d, want 2", len(roundTripped.Files.Deny))
	}
	if roundTripped.Limits.MaxSpendUSD.Value != 10.0 {
		t.Errorf("MaxSpendUSD = %f, want 10.0", roundTripped.Limits.MaxSpendUSD.Value)
	}
}

func TestHookInputUnmarshal(t *testing.T) {
	data := `{
		"session_id": "sess-123",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "ls -la"}
	}`

	var input HookInput
	if err := json.Unmarshal([]byte(data), &input); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if input.SessionID != "sess-123" {
		t.Errorf("SessionID = %q, want %q", input.SessionID, "sess-123")
	}
	if input.HookEventName != HookPreToolUse {
		t.Errorf("HookEventName = %q, want %q", input.HookEventName, HookPreToolUse)
	}
	if input.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want %q", input.ToolName, "Bash")
	}
	if input.ToolInput == nil {
		t.Error("ToolInput should not be nil")
	}

	var bashInput BashToolInput
	if err := json.Unmarshal(input.ToolInput, &bashInput); err != nil {
		t.Fatalf("Unmarshal BashToolInput: %v", err)
	}
	if bashInput.Command != "ls -la" {
		t.Errorf("Command = %q, want %q", bashInput.Command, "ls -la")
	}
}

func TestHookEventConstants(t *testing.T) {
	events := []HookEventName{
		HookSessionStart,
		HookPreToolUse,
		HookPostToolUse,
		HookPermissionRequest,
		HookUserPromptSubmit,
		HookStop,
		HookSubagentStop,
		HookSessionEnd,
		HookNotification,
		HookPreCompact,
	}

	seen := make(map[HookEventName]bool)
	for _, e := range events {
		if seen[e] {
			t.Errorf("duplicate event name: %q", e)
		}
		seen[e] = true
		if e == "" {
			t.Error("event name should not be empty")
		}
	}
}

func TestDecisionConstants(t *testing.T) {
	if DecisionAllow != "allow" {
		t.Errorf("DecisionAllow = %q", DecisionAllow)
	}
	if DecisionDeny != "deny" {
		t.Errorf("DecisionDeny = %q", DecisionDeny)
	}
	if DecisionAsk != "ask" {
		t.Errorf("DecisionAsk = %q", DecisionAsk)
	}
}
