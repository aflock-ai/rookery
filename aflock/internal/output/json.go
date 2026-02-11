// Package output handles formatting hook output for Claude Code.
package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// PreToolUseAllow returns an allow decision for PreToolUse.
func PreToolUseAllow() *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName:      aflock.HookPreToolUse,
			PermissionDecision: aflock.DecisionAllow,
		},
	}
}

// PreToolUseDeny returns a deny decision for PreToolUse.
func PreToolUseDeny(reason string) *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName:            aflock.HookPreToolUse,
			PermissionDecision:       aflock.DecisionDeny,
			PermissionDecisionReason: reason,
		},
	}
}

// PreToolUseAsk returns an ask decision for PreToolUse.
func PreToolUseAsk(reason string) *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName:            aflock.HookPreToolUse,
			PermissionDecision:       aflock.DecisionAsk,
			PermissionDecisionReason: reason,
		},
	}
}

// PermissionAllow returns an allow decision for PermissionRequest.
func PermissionAllow() *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName: aflock.HookPermissionRequest,
			Decision: &aflock.DecisionOutput{
				Behavior: "allow",
			},
		},
	}
}

// PermissionDeny returns a deny decision for PermissionRequest.
func PermissionDeny(message string, interrupt bool) *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName: aflock.HookPermissionRequest,
			Decision: &aflock.DecisionOutput{
				Behavior:  "deny",
				Message:   message,
				Interrupt: interrupt,
			},
		},
	}
}

// SessionStartContext returns context to inject at session start.
func SessionStartContext(context string) *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName:     aflock.HookSessionStart,
			AdditionalContext: context,
		},
	}
}

// PostToolUseContext returns context after tool execution.
func PostToolUseContext(context string) *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName:     aflock.HookPostToolUse,
			AdditionalContext: context,
		},
	}
}

// PostToolUseBlock returns a block decision for PostToolUse.
func PostToolUseBlock(reason string) *aflock.HookOutput {
	return &aflock.HookOutput{
		Decision: "block",
		Reason:   reason,
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName: aflock.HookPostToolUse,
		},
	}
}

// StopBlock returns a block decision for Stop/SubagentStop.
func StopBlock(reason string) *aflock.HookOutput {
	return &aflock.HookOutput{
		Decision: "block",
		Reason:   reason,
	}
}

// StopAllow returns an allow (continue) for Stop/SubagentStop.
func StopAllow() *aflock.HookOutput {
	return &aflock.HookOutput{}
}

// UserPromptContext returns context for UserPromptSubmit.
func UserPromptContext(context string) *aflock.HookOutput {
	return &aflock.HookOutput{
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName:     aflock.HookUserPromptSubmit,
			AdditionalContext: context,
		},
	}
}

// UserPromptBlock returns a block decision for UserPromptSubmit.
func UserPromptBlock(reason string) *aflock.HookOutput {
	return &aflock.HookOutput{
		Decision: "block",
		Reason:   reason,
		HookSpecificOutput: &aflock.HookSpecificOutput{
			HookEventName: aflock.HookUserPromptSubmit,
		},
	}
}

// Write outputs the hook response as JSON to stdout.
func Write(output *aflock.HookOutput) error {
	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	_, err = os.Stdout.Write(data)
	return err
}

// WriteEmpty writes an empty JSON object (successful hook with no output).
func WriteEmpty() error {
	_, err := os.Stdout.WriteString("{}")
	return err
}

// ExitWithError writes to stderr and exits with code 2 (blocking error).
func ExitWithError(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}

// ExitWithWarning writes to stderr and exits with code 1 (non-blocking).
func ExitWithWarning(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
