// Package state manages session state for aflock.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// safeSessionIDRegex ensures session IDs contain only safe characters.
// This prevents path traversal via session IDs like "../../etc".
var safeSessionIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

const (
	// DefaultStateDir is the default directory for session state.
	DefaultStateDir = "~/.aflock/sessions"
)

// Manager handles session state persistence.
type Manager struct {
	stateDir string
	mu       sync.Mutex
}

// NewManager creates a new state manager.
func NewManager(stateDir string) *Manager {
	if stateDir == "" {
		stateDir = expandPath(DefaultStateDir)
	}
	return &Manager{stateDir: stateDir}
}

// validateSessionID checks that a session ID is safe for use in file paths.
// It rejects IDs containing path traversal sequences or special characters.
func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID must not be empty")
	}
	// MCP server generates IDs like "mcp-1234567890". Hooks receive UUIDs.
	// Allow alphanumeric, hyphens, and underscores only.
	if !safeSessionIDRegex.MatchString(sessionID) {
		return fmt.Errorf("invalid session ID %q: must contain only alphanumeric characters, hyphens, and underscores", sessionID)
	}
	return nil
}

// SessionDir returns the directory for a specific session.
// It validates the session ID to prevent path traversal attacks.
// If the session ID is invalid, it returns a path using a sanitized version.
func (m *Manager) SessionDir(sessionID string) string {
	// Validate session ID to prevent path traversal.
	// If invalid (e.g., "../../etc"), use only the base name.
	if err := validateSessionID(sessionID); err != nil {
		// Fall back to using the base of the state dir to avoid escaping
		return m.stateDir
	}
	return filepath.Join(m.stateDir, sessionID)
}

// Load loads the session state for a session ID.
func (m *Manager) Load(sessionID string) (*aflock.SessionState, error) {
	if err := validateSessionID(sessionID); err != nil {
		return nil, err
	}
	path := filepath.Join(m.SessionDir(sessionID), "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No existing state
		}
		return nil, fmt.Errorf("read state: %w", err)
	}

	var state aflock.SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}

	return &state, nil
}

// Save persists the session state.
func (m *Manager) Save(state *aflock.SessionState) error {
	if err := validateSessionID(state.SessionID); err != nil {
		return err
	}
	dir := m.SessionDir(state.SessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}

	return nil
}

// Initialize creates a new session state.
func (m *Manager) Initialize(sessionID string, policy *aflock.Policy, policyPath string) *aflock.SessionState {
	return &aflock.SessionState{
		SessionID:  sessionID,
		StartedAt:  time.Now(),
		Policy:     policy,
		PolicyPath: policyPath,
		Metrics: &aflock.SessionMetrics{
			Tools: make(map[string]int),
		},
	}
}

// RecordAction records an action in the session state.
// It is safe for concurrent use.
func (m *Manager) RecordAction(state *aflock.SessionState, record aflock.ActionRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state.Actions = append(state.Actions, record)
	state.Metrics.ToolCalls++
	if state.Metrics.Tools == nil {
		state.Metrics.Tools = make(map[string]int)
	}
	state.Metrics.Tools[record.ToolName]++
}

// AttestationsDir returns the attestations directory for a session.
func (m *Manager) AttestationsDir(sessionID string) string {
	return filepath.Join(m.SessionDir(sessionID), "attestations")
}

// expandPath expands ~ to home directory.
func expandPath(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

// LoadMetrics loads just the metrics from session state.
func (m *Manager) LoadMetrics(sessionID string) (*aflock.SessionMetrics, error) {
	state, err := m.Load(sessionID)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, nil
	}
	return state.Metrics, nil
}

// UpdateMetrics updates cumulative metrics (for PostToolUse).
// It is safe for concurrent use.
func (m *Manager) UpdateMetrics(state *aflock.SessionState, tokensIn, tokensOut int64, costUSD float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state.Metrics.TokensIn += tokensIn
	state.Metrics.TokensOut += tokensOut
	state.Metrics.CostUSD += costUSD
}

// IncrementTurns increments the turn counter.
// It is safe for concurrent use.
func (m *Manager) IncrementTurns(state *aflock.SessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state.Metrics.Turns++
}

// TrackFile records a file access.
// It is safe for concurrent use.
func (m *Manager) TrackFile(state *aflock.SessionState, toolName string, filePath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch toolName {
	case "Read", "Glob", "Grep":
		if !contains(state.Metrics.FilesRead, filePath) {
			state.Metrics.FilesRead = append(state.Metrics.FilesRead, filePath)
		}
	case "Write", "Edit":
		if !contains(state.Metrics.FilesWritten, filePath) {
			state.Metrics.FilesWritten = append(state.Metrics.FilesWritten, filePath)
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
