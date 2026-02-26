// Package policy provides policy evaluation for hook decisions.
package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// Tool name constants to avoid repeated string literals (goconst).
const (
	toolWebSearch    = "WebSearch"
	toolWebFetch     = "WebFetch"
	toolEdit         = "Edit"
	toolRead         = "Read"
	toolWrite        = "Write"
	toolGrep         = "Grep"
	toolGlob         = "Glob"
	toolNotebookEdit = "NotebookEdit"
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
//
//nolint:gocognit,gocyclo // pre-tool-use evaluation checks many conditions
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
	// WebSearch doesn't have a target URL (only a search query), so domain
	// restrictions don't apply — the search engine itself picks which sites
	// to query. Only WebFetch has a user-specified URL to check.
	if isNetworkOperation(toolName) && toolName != toolWebSearch {
		decision, reason := e.evaluateDomainAccess(toolInput)
		if decision != aflock.DecisionAllow {
			return decision, reason
		}
	}

	// 5. Check allow list (if specified, tool must be in it)
	// Security (R3-230): Use MatchToolPattern to check both tool name AND command
	// pattern. Previously only the tool name was checked, so Allow: ["Bash:git *"]
	// would allow ALL Bash commands instead of only git commands.
	if e.policy.Tools != nil && len(e.policy.Tools.Allow) > 0 {
		allowed := false
		for _, pattern := range e.policy.Tools.Allow {
			if e.matcher.MatchToolPattern(pattern, toolName, inputStr) {
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
//
//nolint:gocyclo // input extraction maps tool types to fields
func (e *Evaluator) extractInputForMatching(toolName string, toolInput json.RawMessage) string {
	switch toolName {
	case "Bash":
		var input aflock.BashToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Command
		}
	case toolRead, toolWrite, toolEdit:
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.FilePath
		}
	case toolGrep:
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Pattern
		}
	case toolGlob:
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Pattern
		}
	case toolNotebookEdit:
		var input aflock.NotebookEditToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.NotebookPath
		}
	case "Task":
		var input aflock.TaskToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Prompt
		}
	case toolWebFetch:
		var input aflock.WebFetchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.URL
		}
	case toolWebSearch:
		var input aflock.WebSearchToolInput
		if err := json.Unmarshal(toolInput, &input); err == nil {
			return input.Query
		}
	}
	return ""
}

// extractFilePath extracts the file/directory path from tool input.
// Different tools use different JSON field names for their path:
//   - Read/Write/Edit: "file_path"
//   - Grep/Glob: "path"
//   - NotebookEdit: "notebook_path"
func extractFilePath(toolName string, toolInput json.RawMessage) (string, error) {
	switch toolName {
	case toolGrep:
		var input aflock.GrepToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", err
		}
		return input.Path, nil
	case toolGlob:
		var input aflock.GlobToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", err
		}
		return input.Path, nil
	case toolNotebookEdit:
		var input aflock.NotebookEditToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", err
		}
		return input.NotebookPath, nil
	default:
		var input aflock.FileToolInput
		if err := json.Unmarshal(toolInput, &input); err != nil {
			return "", err
		}
		return input.FilePath, nil
	}
}

// evaluateFileAccess checks file access against policy.
//
//nolint:gocognit,gocyclo // file access evaluation has complex path logic
func (e *Evaluator) evaluateFileAccess(toolName string, toolInput json.RawMessage) (aflock.PermissionDecision, string) {
	if e.policy.Files == nil {
		return aflock.DecisionAllow, ""
	}

	filePath, err := extractFilePath(toolName, toolInput)
	if err != nil {
		return aflock.DecisionDeny, fmt.Sprintf("failed to parse file tool input: %v", err)
	}

	// Normalize path for matching
	normalizedPath := filepath.Clean(filePath)

	// For directory-based tools (Grep, Glob), the path is a directory being searched.
	// We need to also check if files WITHIN the directory would match deny patterns.
	// e.g., if path is "/etc" and deny pattern is "/etc/**", the glob won't match
	// "/etc" directly but should deny since the tool will access files under /etc.
	isDirectoryTool := toolName == toolGrep || toolName == toolGlob

	// Check deny patterns first
	for _, pattern := range e.policy.Files.Deny {
		if e.matcher.MatchGlob(pattern, normalizedPath) || e.matcher.MatchGlob(pattern, filePath) {
			return aflock.DecisionDeny, fmt.Sprintf("File '%s' matches deny pattern '%s'", filePath, pattern)
		}
		// For directory tools, also check if a child path would match.
		// This handles patterns like "/etc/**" when the tool path is "/etc".
		if isDirectoryTool && normalizedPath != "" {
			childPath := normalizedPath + "/check"
			if e.matcher.MatchGlob(pattern, childPath) {
				return aflock.DecisionDeny, fmt.Sprintf("Directory '%s' matches deny pattern '%s' (contains denied files)", filePath, pattern)
			}
		}
	}

	// Check readOnly for write operations
	if toolName == toolWrite || toolName == toolEdit {
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
	case toolRead, toolWrite, toolEdit, toolGlob, toolGrep, toolNotebookEdit:
		return true
	default:
		return false
	}
}

func isNetworkOperation(toolName string) bool {
	switch toolName {
	case toolWebFetch, toolWebSearch:
		return true
	default:
		return false
	}
}

func extractDomain(rawURL string) string {
	// Case-insensitive scheme stripping — URLs like HTTPS://evil.com or Http://evil.com
	// must be handled correctly to prevent domain deny rule bypasses.
	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "https://") {
		rawURL = rawURL[len("https://"):]
	} else if strings.HasPrefix(lower, "http://") {
		rawURL = rawURL[len("http://"):]
	}

	// Security (R3-231): Strip protocol-relative URL prefix.
	// Without this, //evil.com extracts "//evil.com" which won't match
	// deny patterns like "evil.com".
	rawURL = strings.TrimLeft(rawURL, "/")

	// Strip path first
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		rawURL = rawURL[:idx]
	}

	// Security: strip userinfo (user:pass@) before extracting host.
	// Without this, https://user:pass@evil.com extracts "user" instead of
	// "evil.com", allowing domain deny rule bypass (R3-122).
	if idx := strings.LastIndex(rawURL, "@"); idx != -1 {
		rawURL = rawURL[idx+1:]
	}

	// Strip port
	if idx := strings.Index(rawURL, ":"); idx != -1 {
		rawURL = rawURL[:idx]
	}

	// Security (R3-236): Normalize domain to lowercase.
	// DNS is case-insensitive (RFC 4343), so EVIL.COM and evil.com are
	// the same domain. Without this, deny rules for "evil.com" wouldn't
	// block "EVIL.COM".
	rawURL = strings.ToLower(rawURL)

	return rawURL
}

// EvaluateDataFlow checks if an operation violates data flow rules.
// For source operations (reads), it returns materials to track.
// For sink operations (writes), it checks materials against rules.
//
//nolint:gocognit,gocyclo // data flow evaluation checks many tool x label combos
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

	// Check classifications to see what label this tool has.
	// Sort labels for deterministic evaluation — Go map iteration is non-deterministic,
	// so without sorting, the same input could match different labels on different runs.
	classifyLabels := make([]string, 0, len(e.policy.DataFlow.Classify))
	for label := range e.policy.DataFlow.Classify {
		classifyLabels = append(classifyLabels, label)
	}
	sort.Strings(classifyLabels)

	var matchedLabel string
	for _, label := range classifyLabels {
		patterns := e.policy.DataFlow.Classify[label]
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
	if matchedLabel != "" && isWriteOperation(toolName) { //nolint:nestif
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
	case toolRead, toolGlob, toolGrep, toolWebFetch, toolWebSearch:
		return true
	default:
		return strings.HasPrefix(toolName, "mcp__") && !strings.Contains(toolName, "write")
	}
}

func isWriteOperation(toolName string) bool {
	switch toolName {
	case toolWrite, toolEdit, "Bash":
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
