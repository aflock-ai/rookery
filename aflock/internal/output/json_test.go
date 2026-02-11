package output

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

func TestPreToolUseAllow(t *testing.T) {
	out := PreToolUseAllow()
	if out.HookSpecificOutput == nil {
		t.Fatal("HookSpecificOutput should not be nil")
	}
	if out.HookSpecificOutput.HookEventName != aflock.HookPreToolUse {
		t.Errorf("HookEventName = %q, want %q", out.HookSpecificOutput.HookEventName, aflock.HookPreToolUse)
	}
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAllow {
		t.Errorf("PermissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, aflock.DecisionAllow)
	}
}

func TestPreToolUseDeny(t *testing.T) {
	out := PreToolUseDeny("not allowed")
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionDeny {
		t.Errorf("PermissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, aflock.DecisionDeny)
	}
	if out.HookSpecificOutput.PermissionDecisionReason != "not allowed" {
		t.Errorf("Reason = %q, want %q", out.HookSpecificOutput.PermissionDecisionReason, "not allowed")
	}
}

func TestPreToolUseAsk(t *testing.T) {
	out := PreToolUseAsk("needs approval")
	if out.HookSpecificOutput.PermissionDecision != aflock.DecisionAsk {
		t.Errorf("PermissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, aflock.DecisionAsk)
	}
	if out.HookSpecificOutput.PermissionDecisionReason != "needs approval" {
		t.Errorf("Reason = %q", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestPermissionAllow(t *testing.T) {
	out := PermissionAllow()
	if out.HookSpecificOutput.HookEventName != aflock.HookPermissionRequest {
		t.Errorf("HookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.Decision == nil {
		t.Fatal("Decision should not be nil")
	}
	if out.HookSpecificOutput.Decision.Behavior != "allow" {
		t.Errorf("Behavior = %q, want %q", out.HookSpecificOutput.Decision.Behavior, "allow")
	}
}

func TestPermissionDeny(t *testing.T) {
	out := PermissionDeny("blocked", true)
	if out.HookSpecificOutput.Decision.Behavior != "deny" {
		t.Errorf("Behavior = %q, want %q", out.HookSpecificOutput.Decision.Behavior, "deny")
	}
	if out.HookSpecificOutput.Decision.Message != "blocked" {
		t.Errorf("Message = %q", out.HookSpecificOutput.Decision.Message)
	}
	if !out.HookSpecificOutput.Decision.Interrupt {
		t.Error("Interrupt should be true")
	}
}

func TestSessionStartContext(t *testing.T) {
	out := SessionStartContext("policy loaded")
	if out.HookSpecificOutput.HookEventName != aflock.HookSessionStart {
		t.Errorf("HookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.AdditionalContext != "policy loaded" {
		t.Errorf("AdditionalContext = %q", out.HookSpecificOutput.AdditionalContext)
	}
}

func TestPostToolUseContext(t *testing.T) {
	out := PostToolUseContext("action recorded")
	if out.HookSpecificOutput.HookEventName != aflock.HookPostToolUse {
		t.Errorf("HookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.AdditionalContext != "action recorded" {
		t.Errorf("AdditionalContext = %q", out.HookSpecificOutput.AdditionalContext)
	}
}

func TestPostToolUseBlock(t *testing.T) {
	out := PostToolUseBlock("limit exceeded")
	if out.Decision != "block" {
		t.Errorf("Decision = %q, want %q", out.Decision, "block")
	}
	if out.Reason != "limit exceeded" {
		t.Errorf("Reason = %q", out.Reason)
	}
}

func TestStopBlock(t *testing.T) {
	out := StopBlock("attestation missing")
	if out.Decision != "block" {
		t.Errorf("Decision = %q, want %q", out.Decision, "block")
	}
	if out.Reason != "attestation missing" {
		t.Errorf("Reason = %q", out.Reason)
	}
}

func TestStopAllow(t *testing.T) {
	out := StopAllow()
	if out.Decision != "" {
		t.Errorf("Decision = %q, want empty", out.Decision)
	}
}

func TestUserPromptContext(t *testing.T) {
	out := UserPromptContext("context injected")
	if out.HookSpecificOutput.HookEventName != aflock.HookUserPromptSubmit {
		t.Errorf("HookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.AdditionalContext != "context injected" {
		t.Errorf("AdditionalContext = %q", out.HookSpecificOutput.AdditionalContext)
	}
}

func TestUserPromptBlock(t *testing.T) {
	out := UserPromptBlock("prompt rejected")
	if out.Decision != "block" {
		t.Errorf("Decision = %q, want %q", out.Decision, "block")
	}
	if out.HookSpecificOutput.HookEventName != aflock.HookUserPromptSubmit {
		t.Errorf("HookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
}

func TestOutputMarshalJSON(t *testing.T) {
	outputs := []*aflock.HookOutput{
		PreToolUseAllow(),
		PreToolUseDeny("reason"),
		PreToolUseAsk("reason"),
		PermissionAllow(),
		PermissionDeny("msg", false),
		SessionStartContext("ctx"),
		PostToolUseContext("ctx"),
		PostToolUseBlock("reason"),
		StopBlock("reason"),
		StopAllow(),
		UserPromptContext("ctx"),
		UserPromptBlock("reason"),
	}

	for i, out := range outputs {
		data, err := json.Marshal(out)
		if err != nil {
			t.Errorf("output[%d] marshal failed: %v", i, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("output[%d] marshaled to empty", i)
		}

		// Verify round-trip
		var decoded aflock.HookOutput
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("output[%d] unmarshal failed: %v", i, err)
		}
	}
}
