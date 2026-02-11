// Package state manages session state for aflock.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

const (
	// DefaultStateDir is the default directory for session state.
	DefaultStateDir = "~/.aflock/sessions"
)

// Manager handles session state persistence.
type Manager struct {
	stateDir string
}

// NewManager creates a new state manager.
func NewManager(stateDir string) *Manager {
	if stateDir == "" {
		stateDir = expandPath(DefaultStateDir)
	}
	return &Manager{stateDir: stateDir}
}

// SessionDir returns the directory for a specific session.
func (m *Manager) SessionDir(sessionID string) string {
	return filepath.Join(m.stateDir, sessionID)
}

// Load loads the session state for a session ID.
func (m *Manager) Load(sessionID string) (*aflock.SessionState, error) {
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
	dir := m.SessionDir(state.SessionID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
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
func (m *Manager) RecordAction(state *aflock.SessionState, record aflock.ActionRecord) {
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
func (m *Manager) UpdateMetrics(state *aflock.SessionState, tokensIn, tokensOut int64, costUSD float64) {
	state.Metrics.TokensIn += tokensIn
	state.Metrics.TokensOut += tokensOut
	state.Metrics.CostUSD += costUSD
}

// IncrementTurns increments the turn counter.
func (m *Manager) IncrementTurns(state *aflock.SessionState) {
	state.Metrics.Turns++
}

// TrackFile records a file access.
func (m *Manager) TrackFile(state *aflock.SessionState, toolName string, filePath string) {
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
