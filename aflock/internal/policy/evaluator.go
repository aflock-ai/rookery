// Package policy provides policy evaluation for hook decisions.
package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// Evaluator evaluates policy rules against hook inputs.
type Evaluator struct {
	policy  *aflock.Policy
	matcher *Matcher
}

// NewEvaluator creates a new policy evaluator.
func NewEvaluator(policy *aflock.Policy) *Evaluator {
	return &Evaluator{
		policy:  policy,
		matcher: NewMatcher(),
	}
}

// EvaluatePreToolUse evaluates whether a tool call should be allowed.
func (e *Evaluator) EvaluatePreToolUse(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	// Extract relevant input for pattern matching
	inputStr := e.extractInputForMatching(toolName, toolInput)

	// 1. Check deny list first
	if e.policy.Tools != nil {
		for _, pattern := range e.policy.Tools.Deny {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				return aflock.DecisionDeny, fmt.Sprintf("Tool '%s' matches deny pattern '%s'", toolName, pattern)
			}
		}
	}

	// 2. Check requireApproval patterns
	if e.policy.Tools != nil {
		for _, pattern := range e.policy.Tools.RequireApproval {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				return aflock.DecisionAsk, fmt.Sprintf("Tool '%s' requires approval (matches '%s')", toolName, pattern)
			}
		}
	}

	// 3. Check file access for file-related tools
	if isFileOperation(toolName) {
		decision, reason := e.evaluateFileAccess(toolName, toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 4. Check domain access for network tools
	if isNetworkOperation(toolName) {
		decision, reason := e.evaluateDomainAccess(toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 5. Check allow list (if specified, tool must be in it)
	if e.policy.Tools != nil && len(e.policy.Tools.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Tools.Allow {
			patternTool, _, _ := ParseToolPattern(pattern)
			if e.matcher.MatchGlob(patternTool, toolName) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("Tool '%s' not in allow list", toolName)
		}
	}

	return aflock.DecisionAllow, ""
}

// extractInputForMatching extracts the relevant string from tool input for pattern matching.
func (e *Evaluator) extractInputForMatching(toolName string, toolInput json.RawMessage) string {
	switch toolName {
	case "Bash":
		var input aflock.BashToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Command
		}
	case "Read", "Write", "Edit":
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.FilePath
		}
	case "Task":
		var input aflock.TaskToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Prompt
		}
	case "WebFetch":
		var input aflock.WebFetchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.URL
		}
	}
	return ""
}

// evaluateFileAccess checks file access against policy.
func (e *Evaluator) evaluateFileAccess(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Files == nil {
		return aflock.DecisionAllow, ""
	}

	var input aflock.FileToolInput
	if err := json.Unmarshal(toolInput, &input); err != nil {
		return aflock.DecisionDeny, fmt.Sprintf("failed to parse file tool input: %v", err)
	}

	filePath := input.FilePath

	// Normalize path for matching
	normalizedPath := filepath.Clean(filePath)

	// Check deny patterns first
	for _, pattern := range e.policy.Files.Deny {
		if e.matcher.MatchGlob(pattern, normalizedPath) || e.matcher.MatchGlob(pattern, filePath) {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' matches deny pattern '%s'", filePath, pattern)
		}
	}

	// Check readOnly for write operations
	if toolName == "Write" || toolName == "Edit" {
		for _, pattern := range e.policy.Files.ReadOnly {
			if e.matcher.MatchGlob(pattern, normalizedPath) || e.matcher.MatchGlob(pattern, filepath.Base(filePath)) {
				return aflock.DecisionDeny, fmt.Sprintf("File '%s' is read-only (matches '%s')", filePath, pattern)
			}
		}
	}

	// Check allow patterns (if specified, file must match)
	if len(e.policy.Files.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Files.Allow {
			if e.matcher.MatchGlob(pattern, normalizedPath) || e.matcher.MatchGlob(pattern, filePath) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' not in allow list", filePath)
		}
	}

	return aflock.DecisionAllow, ""
}

// evaluateDomainAccess checks domain access against policy.
func (e *Evaluator) evaluateDomainAccess(toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Domains == nil {
		return aflock.DecisionAllow, ""
	}

	var input aflock.WebFetchToolInput
	if err := json.Unmarshal(toolInput, &input); err != nil {
		return aflock.DecisionDeny, fmt.Sprintf("failed to parse network tool input: %v", err)
	}

	domain := extractDomain(input.URL)
	if domain == "" {
		return aflock.DecisionDeny, "empty domain in network request"
	}

	// Check deny patterns first
	for _, pattern := range e.policy.Domains.Deny {
		if e.matcher.MatchGlob(pattern, domain) {
			return aflock.DecisionDeny, fmt.Sprintf("Domain '%s' matches deny pattern '%s'", domain, pattern)
		}
	}

	// Check allow patterns (if specified, domain must match)
	if len(e.policy.Domains.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Domains.Allow {
			if e.matcher.MatchGlob(pattern, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return aflock.DecisionDeny, fmt.Sprintf("Domain '%s' not in allow list", domain)
		}
	}

	return aflock.DecisionAllow, ""
}

func isFileOperation(toolName string) bool {
	switch toolName {
	case "Read", "Write", "Edit", "Glob", "Grep":
		return true
	default:
		return false
	}
}

func isNetworkOperation(toolName string) bool {
	switch toolName {
	case "WebFetch", "WebSearch":
		return true
	default:
		// Check for MCP tools that might access network
		return strings.HasPrefix(toolName, "mcp__")
	}
}

func extractDomain(url string) string {
	// Simple domain extraction
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	return url
}

// EvaluateDataFlow checks if an operation violates data flow rules.
// For source operations (reads), it returns materials to track.
// For sink operations (writes), it checks materials against rules.
func (e *Evaluator) EvaluateDataFlow(toolName string, toolInput json.RawMessage, materials []aflock.MaterialClassification) (aflock.PermissionDecision, string, *aflock.MaterialClassification) {
	if e.policy.DataFlow == nil {
		return aflock.DecisionAllow, "", nil
	}

	inputStr := e.extractInputForMatching(toolName, toolInput)
	toolPattern := fmt.Sprintf("%s:%s", toolName, inputStr)

	// Get current material labels
	currentLabels := make([]string, 0, len(materials))
	for _, m := range materials {
		currentLabels = append(currentLabels, m.Label)
	}

	// Check classifications to see what label this tool has
	var matchedLabel string
	for label, patterns := range e.policy.DataFlow.Classify {
		for _, pattern := range patterns {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
				matchedLabel = label
				break
			}
		}
		if matchedLabel != "" {
			break
		}
	}

	// If this is a read operation (not a sink in flow rules), track the material
	if matchedLabel != "" && isReadOperation(toolName) {
		// Check if we already have this label
		if !containsString(currentLabels, matchedLabel) {
			return aflock.DecisionAllow, "", &aflock.MaterialClassification{
				Label:  matchedLabel,
				Source: toolPattern,
			}
		}
	}

	// If this is a write operation, check flow rules
	if matchedLabel != "" && isWriteOperation(toolName) {
		sinkLabel := matchedLabel

		// Check all flow rules
		for _, rule := range e.policy.DataFlow.FlowRules {
			sourceLabel, ruleSinkLabel, ok := aflock.ParseDataFlowRule(rule.Deny)
			if !ok {
				continue
			}
			if ruleSinkLabel != sinkLabel {
				continue
			}
			// Check if we have the source label in our materials
			if containsString(currentLabels, sourceLabel) {
				msg := rule.Message
				if msg == "" {
					msg = fmt.Sprintf("Data flow violation: %s data cannot be written to %s destination (%s)",
						sourceLabel, sinkLabel, toolPattern)
				}
				return aflock.DecisionDeny, msg, nil
			}
		}
	}

	return aflock.DecisionAllow, "", nil
}

func isReadOperation(toolName string) bool {
	switch toolName {
	case "Read", "Glob", "Grep", "WebFetch":
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && !strings.Contains(toolName, "write")
	}
}

func isWriteOperation(toolName string) bool {
	switch toolName {
	case "Write", "Edit", "Bash":
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && strings.Contains(toolName, "write")
	}
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CheckLimits checks if cumulative metrics exceed policy limits.
// Returns (exceeded, limitName, message).
func (e *Evaluator) CheckLimits(metrics *aflock.SessionMetrics, enforcementMode string) (bool, string, string) {
	if e.policy.Limits == nil {
		return false, "", ""
	}

	// Only check limits with matching enforcement mode
	checkLimit := func(limit *aflock.Limit, name string, current float64) (bool, string, string) {
		if limit == nil {
			return false, "", ""
		}
		if limit.Enforcement != enforcementMode {
			return false, "", ""
		}
		if current > limit.Value {
			return true, name, fmt.Sprintf("%s exceeded: %.2f > %.2f", name, current, limit.Value)
		}
		return false, "", ""
	}

	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxSpendUSD, "maxSpendUSD", metrics.CostUSD); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTokensIn, "maxTokensIn", float64(metrics.TokensIn)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTokensOut, "maxTokensOut", float64(metrics.TokensOut)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxTurns, "maxTurns", float64(metrics.Turns)); exceeded {
		return true, name, msg
	}
	if exceeded, name, msg := checkLimit(e.policy.Limits.MaxToolCalls, "maxToolCalls", float64(metrics.ToolCalls)); exceeded {
		return true, name, msg
	}

	return false, "", ""
}
