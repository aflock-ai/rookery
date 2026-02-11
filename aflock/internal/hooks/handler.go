// Package hooks handles Claude Code hook events.
package hooks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/aflock/internal/identity"
	"github.com/aflock-ai/rookery/aflock/internal/output"
	"github.com/aflock-ai/rookery/aflock/internal/policy"
	"github.com/aflock-ai/rookery/aflock/internal/state"
	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// Handler processes Claude Code hook events.
type Handler struct {
	stateManager *state.Manager
}

// NewHandler creates a new hook handler.
func NewHandler() *Handler {
	return &Handler{
		stateManager: state.NewManager(""),
	}
}

// Handle reads input from stdin and dispatches to the appropriate handler.
func (h *Handler) Handle(hookName string) error {
	// Read input from stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	var input aflock.HookInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("parse input: %w", err)
	}

	// Dispatch to appropriate handler
	switch aflock.HookEventName(hookName) {
	case aflock.HookSessionStart:
		return h.handleSessionStart(&input)
	case aflock.HookPreToolUse:
		return h.handlePreToolUse(&input)
	case aflock.HookPostToolUse:
		return h.handlePostToolUse(&input)
	case aflock.HookPermissionRequest:
		return h.handlePermissionRequest(&input)
	case aflock.HookUserPromptSubmit:
		return h.handleUserPromptSubmit(&input)
	case aflock.HookStop:
		return h.handleStop(&input)
	case aflock.HookSubagentStop:
		return h.handleSubagentStop(&input)
	case aflock.HookSessionEnd:
		return h.handleSessionEnd(&input)
	case aflock.HookNotification:
		return h.handleNotification(&input)
	case aflock.HookPreCompact:
		return h.handlePreCompact(&input)
	default:
		return fmt.Errorf("unknown hook: %s", hookName)
	}
}

// handleSessionStart initializes session state and loads policy.
func (h *Handler) handleSessionStart(input *aflock.HookInput) error {
	// Try to load policy from cwd or env
	var pol *aflock.Policy
	var policyPath string
	var err error

	// First try AFLOCK_POLICY env var
	if envPolicy := os.Getenv("AFLOCK_POLICY"); envPolicy != "" {
		pol, policyPath, err = policy.Load(envPolicy)
	} else if input.Cwd != "" {
		// Try to find policy in cwd
		pol, policyPath, err = policy.Load(input.Cwd)
	}

	if err != nil {
		// No policy found - this is OK, we just won't enforce
		return output.WriteEmpty()
	}

	// Discover agent identity
	agentIdentity, err := identity.DiscoverAgentIdentity()
	if err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to discover agent identity: %v", err))
		return nil
	}

	// Validate identity against policy constraints (skip if model is unknown in development)
	if pol.Identity != nil && len(pol.Identity.AllowedModels) > 0 {
		if agentIdentity.Model != "unknown" && !agentIdentity.Matches(pol.Identity.AllowedModels, nil) {
			output.ExitWithError(fmt.Sprintf("[aflock] Agent model '%s' not in allowed models: %v",
				agentIdentity.Model, pol.Identity.AllowedModels))
			return nil
		}
	}

	// Initialize session state
	sessionState := h.stateManager.Initialize(input.SessionID, pol, policyPath)
	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
		return nil
	}

	// Build context to inject
	context := h.buildPolicyContext(pol, agentIdentity)
	return output.Write(output.SessionStartContext(context))
}

// buildPolicyContext creates context string describing the active policy.
func (h *Handler) buildPolicyContext(pol *aflock.Policy, agentIdentity *identity.AgentIdentity) string {
	ctx := fmt.Sprintf("# aflock Policy Active: %s\n\n", pol.Name)

	if agentIdentity != nil {
		ctx += "## Agent Identity\n"
		ctx += fmt.Sprintf("- Model: %s@%s\n", agentIdentity.Model, agentIdentity.ModelVersion)
		if agentIdentity.Binary != nil {
			ctx += fmt.Sprintf("- Binary: %s@%s\n", agentIdentity.Binary.Name, agentIdentity.Binary.Version)
		}
		ctx += fmt.Sprintf("- Identity Hash: %s\n\n", agentIdentity.IdentityHash[:16])
	}

	if pol.Limits != nil {
		ctx += "## Limits\n"
		if pol.Limits.MaxSpendUSD != nil {
			ctx += fmt.Sprintf("- Max spend: $%.2f (%s)\n", pol.Limits.MaxSpendUSD.Value, pol.Limits.MaxSpendUSD.Enforcement)
		}
		if pol.Limits.MaxTokensIn != nil {
			ctx += fmt.Sprintf("- Max tokens in: %.0f (%s)\n", pol.Limits.MaxTokensIn.Value, pol.Limits.MaxTokensIn.Enforcement)
		}
		if pol.Limits.MaxTurns != nil {
			ctx += fmt.Sprintf("- Max turns: %.0f (%s)\n", pol.Limits.MaxTurns.Value, pol.Limits.MaxTurns.Enforcement)
		}
		ctx += "\n"
	}

	if pol.Tools != nil {
		ctx += "## Tool Restrictions\n"
		if len(pol.Tools.Allow) > 0 {
			ctx += fmt.Sprintf("- Allowed: %v\n", pol.Tools.Allow)
		}
		if len(pol.Tools.Deny) > 0 {
			ctx += fmt.Sprintf("- Denied: %v\n", pol.Tools.Deny)
		}
		if len(pol.Tools.RequireApproval) > 0 {
			ctx += fmt.Sprintf("- Require approval: %v\n", pol.Tools.RequireApproval)
		}
		ctx += "\n"
	}

	if pol.Files != nil {
		ctx += "## File Restrictions\n"
		if len(pol.Files.Deny) > 0 {
			ctx += fmt.Sprintf("- Denied patterns: %v\n", pol.Files.Deny)
		}
		if len(pol.Files.ReadOnly) > 0 {
			ctx += fmt.Sprintf("- Read-only: %v\n", pol.Files.ReadOnly)
		}
		ctx += "\n"
	}

	return ctx
}

// handlePreToolUse evaluates policy before tool execution.
func (h *Handler) handlePreToolUse(input *aflock.HookInput) error {
	// Load session state
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to load session state: %v", err))
		return nil
	}

	// If no session state, try to load policy directly (for when SessionStart wasn't run)
	if sessionState == nil || sessionState.Policy == nil {
		pol, policyPath, err := policy.Load(input.Cwd)
		if err != nil {
			// No policy found - allow everything
			return output.Write(output.PreToolUseAllow())
		}
		// Create ephemeral session state
		sessionState = h.stateManager.Initialize(input.SessionID, pol, policyPath)
	}

	pol := sessionState.Policy
	evaluator := policy.NewEvaluator(pol)

	// First evaluate tool/file access
	decision, reason := evaluator.EvaluatePreToolUse(input.ToolName, input.ToolInput)

	// If tool is allowed, also check data flow rules
	if decision == aflock.DecisionAllow {
		flowDecision, flowReason, newMaterial := evaluator.EvaluateDataFlow(
			input.ToolName, input.ToolInput, sessionState.Materials)

		if flowDecision == aflock.DecisionDeny {
			decision = flowDecision
			reason = flowReason
		} else if newMaterial != nil {
			// Track the new material classification
			newMaterial.Timestamp = time.Now()
			sessionState.Materials = append(sessionState.Materials, *newMaterial)
		}
	}

	// Record the action
	h.stateManager.RecordAction(sessionState, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  input.ToolName,
		ToolUseID: input.ToolUseID,
		ToolInput: input.ToolInput,
		Decision:  string(decision),
		Reason:    reason,
	})

	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
	}

	// Return decision
	switch decision {
	case aflock.DecisionDeny:
		// Exit with code 2 to block and provide feedback
		output.ExitWithError(fmt.Sprintf("[aflock] BLOCKED: %s", reason))
		return nil
	case aflock.DecisionAsk:
		return output.Write(output.PreToolUseAsk(reason))
	default:
		return output.Write(output.PreToolUseAllow())
	}
}

// handlePostToolUse records tool execution and updates metrics.
func (h *Handler) handlePostToolUse(input *aflock.HookInput) error {
	// Load session state
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to load session state: %v", err))
		return nil
	}

	if sessionState == nil {
		return output.WriteEmpty()
	}

	// Track file access
	if isFileOperation(input.ToolName) {
		var fileInput aflock.FileToolInput
		if err := json.Unmarshal(input.ToolInput, &fileInput); err == nil {
			h.stateManager.TrackFile(sessionState, input.ToolName, fileInput.FilePath)
		}
	}

	// Save updated state
	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
	}

	// Check fail-fast limits after tool execution
	if sessionState.Policy != nil && sessionState.Policy.Limits != nil {
		evaluator := policy.NewEvaluator(sessionState.Policy)
		exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "fail-fast")
		if exceeded {
			return output.Write(output.PostToolUseBlock(
				fmt.Sprintf("[aflock] Limit exceeded: %s - %s", limitName, msg)))
		}
	}

	return output.WriteEmpty()
}

// handlePermissionRequest auto-approves or denies based on policy.
func (h *Handler) handlePermissionRequest(input *aflock.HookInput) error {
	// Load session state
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		return output.WriteEmpty()
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.WriteEmpty()
	}

	// For now, let the user decide - don't auto-approve
	// Future: could auto-approve based on policy allowlists
	return output.WriteEmpty()
}

// handleUserPromptSubmit validates prompt against policy.
func (h *Handler) handleUserPromptSubmit(input *aflock.HookInput) error {
	// Load session state
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		return output.WriteEmpty()
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.WriteEmpty()
	}

	// Increment turns on each user prompt
	h.stateManager.IncrementTurns(sessionState)
	if err := h.stateManager.Save(sessionState); err != nil {
		output.ExitWithWarning(fmt.Sprintf("Failed to save session state: %v", err))
	}

	return output.WriteEmpty()
}

// handleStop checks if required attestations are complete.
func (h *Handler) handleStop(input *aflock.HookInput) error {
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		// Fail-closed: if we can't load state, we can't verify attestations
		return output.Write(output.StopBlock(
			fmt.Sprintf("[aflock] Cannot stop: failed to load session state: %v", err)))
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.Write(output.StopAllow())
	}

	// Check if required attestations are present
	if len(sessionState.Policy.RequiredAttestations) > 0 {
		attestDir := h.stateManager.AttestationsDir(input.SessionID)
		var missing []string
		for _, required := range sessionState.Policy.RequiredAttestations {
			if !findAttestation(attestDir, required) {
				missing = append(missing, required)
			}
		}
		if len(missing) > 0 {
			return output.Write(output.StopBlock(
				fmt.Sprintf("[aflock] Cannot stop: missing required attestations: %v", missing)))
		}
	}

	return output.Write(output.StopAllow())
}

// handleSubagentStop checks sublayout constraints.
func (h *Handler) handleSubagentStop(input *aflock.HookInput) error {
	// Similar to Stop, but for subagents
	return output.Write(output.StopAllow())
}

// handleSessionEnd finalizes attestations and runs verification.
func (h *Handler) handleSessionEnd(input *aflock.HookInput) error {
	sessionState, err := h.stateManager.Load(input.SessionID)
	if err != nil {
		return output.WriteEmpty()
	}

	if sessionState == nil || sessionState.Policy == nil {
		return output.WriteEmpty()
	}

	// Check post-hoc limits
	if sessionState.Policy.Limits != nil {
		evaluator := policy.NewEvaluator(sessionState.Policy)
		exceeded, limitName, msg := evaluator.CheckLimits(sessionState.Metrics, "post-hoc")
		if exceeded {
			// Log warning but don't block session end
			fmt.Fprintf(os.Stderr, "[aflock] Post-hoc limit exceeded: %s - %s\n", limitName, msg)
		}
	}

	// Log final metrics
	fmt.Fprintf(os.Stderr, "[aflock] Session ended. Metrics: turns=%d, toolCalls=%d\n",
		sessionState.Metrics.Turns, sessionState.Metrics.ToolCalls)

	return output.WriteEmpty()
}

// handleNotification logs notifications.
func (h *Handler) handleNotification(input *aflock.HookInput) error {
	// Just acknowledge
	return output.WriteEmpty()
}

// handlePreCompact records compaction event.
func (h *Handler) handlePreCompact(input *aflock.HookInput) error {
	// Just acknowledge
	return output.WriteEmpty()
}

// findAttestation checks if an attestation file exists for the given name.
// It first checks for exact filename matches (name.json, name.intoto.json),
// then scans all .intoto.json files in the directory and checks if any
// attestation's tool name matches the required name.
func findAttestation(dir, name string) bool {
	// First try exact filename match
	exactPaths := []string{
		filepath.Join(dir, name+".json"),
		filepath.Join(dir, name+".intoto.json"),
	}
	for _, p := range exactPaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}

	// Scan attestation files and check their content for matching tool names.
	// This handles the case where filenames are timestamp-prefixed (e.g., 20260210-143022-ab3def12.intoto.json)
	// but the required attestation is a logical name (e.g., "Bash").
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() || !isAttestationFile(entry.Name()) {
			continue
		}
		if attestationMatchesName(filepath.Join(dir, entry.Name()), name) {
			return true
		}
	}

	return false
}

// isAttestationFile checks if a filename looks like an attestation file.
func isAttestationFile(name string) bool {
	return strings.HasSuffix(name, ".intoto.json") || strings.HasSuffix(name, ".json")
}

// attestationMatchesName checks if an attestation file's content matches the required name.
// It looks at the predicate's toolName field in action attestations.
func attestationMatchesName(path, name string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	// Parse envelope to get payload
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return false
	}

	// Parse statement to get predicate
	var statement struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return false
	}

	// Check if the predicate's toolName matches
	var predicate struct {
		ToolName string `json:"toolName"`
		Action   string `json:"action"`
	}
	if err := json.Unmarshal(statement.Predicate, &predicate); err != nil {
		return false
	}

	return strings.EqualFold(predicate.ToolName, name) || strings.EqualFold(predicate.Action, name)
}

func isFileOperation(toolName string) bool {
	switch toolName {
	case "Read", "Write", "Edit", "Glob", "Grep":
		return true
	default:
		return false
	}
}
