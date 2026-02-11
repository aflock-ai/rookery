package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

func TestManagerInitialize(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	policy := &aflock.Policy{
		Name:    "test-policy",
		Version: "1.0",
	}

	state := m.Initialize("test-session", policy, "/path/to/.aflock")

	if state.SessionID != "test-session" {
		t.Errorf("SessionID = %q, want %q", state.SessionID, "test-session")
	}
	if state.Policy != policy {
		t.Error("Policy not set correctly")
	}
	if state.PolicyPath != "/path/to/.aflock" {
		t.Errorf("PolicyPath = %q, want %q", state.PolicyPath, "/path/to/.aflock")
	}
	if state.Metrics == nil {
		t.Error("Metrics should be initialized")
	}
	if state.Metrics.Tools == nil {
		t.Error("Metrics.Tools map should be initialized")
	}
	if state.StartedAt.IsZero() {
		t.Error("StartedAt should be set")
	}
}

func TestManagerSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Create state
	policy := &aflock.Policy{
		Name:    "test-policy",
		Version: "1.0",
	}
	state := m.Initialize("save-load-test", policy, "/test/.aflock")
	state.Metrics.Turns = 5
	state.Metrics.ToolCalls = 10
	state.Metrics.CostUSD = 1.23

	// Save
	if err := m.Save(state); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	statePath := filepath.Join(tmpDir, "save-load-test", "state.json")
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		t.Error("State file not created")
	}

	// Load
	loaded, err := m.Load("save-load-test")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.SessionID != "save-load-test" {
		t.Errorf("Loaded SessionID = %q, want %q", loaded.SessionID, "save-load-test")
	}
	if loaded.Policy.Name != "test-policy" {
		t.Errorf("Loaded Policy.Name = %q, want %q", loaded.Policy.Name, "test-policy")
	}
	if loaded.Metrics.Turns != 5 {
		t.Errorf("Loaded Turns = %d, want 5", loaded.Metrics.Turns)
	}
	if loaded.Metrics.ToolCalls != 10 {
		t.Errorf("Loaded ToolCalls = %d, want 10", loaded.Metrics.ToolCalls)
	}
	if loaded.Metrics.CostUSD != 1.23 {
		t.Errorf("Loaded CostUSD = %f, want 1.23", loaded.Metrics.CostUSD)
	}
}

func TestManagerLoadNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state, err := m.Load("nonexistent-session")
	if err != nil {
		t.Errorf("Load should not error for nonexistent: %v", err)
	}
	if state != nil {
		t.Error("State should be nil for nonexistent session")
	}
}

func TestManagerRecordAction(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := m.Initialize("action-test", nil, "")

	// Record first action
	m.RecordAction(state, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		ToolUseID: "tu_1",
		Decision:  "allow",
	})

	if len(state.Actions) != 1 {
		t.Errorf("Actions count = %d, want 1", len(state.Actions))
	}
	if state.Metrics.ToolCalls != 1 {
		t.Errorf("ToolCalls = %d, want 1", state.Metrics.ToolCalls)
	}
	if state.Metrics.Tools["Read"] != 1 {
		t.Errorf("Tools[Read] = %d, want 1", state.Metrics.Tools["Read"])
	}

	// Record second action with same tool
	m.RecordAction(state, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Read",
		ToolUseID: "tu_2",
		Decision:  "allow",
	})

	if state.Metrics.ToolCalls != 2 {
		t.Errorf("ToolCalls = %d, want 2", state.Metrics.ToolCalls)
	}
	if state.Metrics.Tools["Read"] != 2 {
		t.Errorf("Tools[Read] = %d, want 2", state.Metrics.Tools["Read"])
	}

	// Record action with different tool
	m.RecordAction(state, aflock.ActionRecord{
		Timestamp: time.Now(),
		ToolName:  "Bash",
		ToolUseID: "tu_3",
		Decision:  "allow",
	})

	if state.Metrics.Tools["Bash"] != 1 {
		t.Errorf("Tools[Bash] = %d, want 1", state.Metrics.Tools["Bash"])
	}
}

func TestManagerUpdateMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := m.Initialize("metrics-test", nil, "")

	// Update metrics
	m.UpdateMetrics(state, 1000, 500, 0.05)
	if state.Metrics.TokensIn != 1000 {
		t.Errorf("TokensIn = %d, want 1000", state.Metrics.TokensIn)
	}
	if state.Metrics.TokensOut != 500 {
		t.Errorf("TokensOut = %d, want 500", state.Metrics.TokensOut)
	}
	if state.Metrics.CostUSD != 0.05 {
		t.Errorf("CostUSD = %f, want 0.05", state.Metrics.CostUSD)
	}

	// Update again - should accumulate
	m.UpdateMetrics(state, 500, 250, 0.03)
	if state.Metrics.TokensIn != 1500 {
		t.Errorf("TokensIn = %d, want 1500", state.Metrics.TokensIn)
	}
	if state.Metrics.TokensOut != 750 {
		t.Errorf("TokensOut = %d, want 750", state.Metrics.TokensOut)
	}
	if state.Metrics.CostUSD != 0.08 {
		t.Errorf("CostUSD = %f, want 0.08", state.Metrics.CostUSD)
	}
}

func TestManagerIncrementTurns(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := m.Initialize("turns-test", nil, "")

	if state.Metrics.Turns != 0 {
		t.Errorf("Initial turns = %d, want 0", state.Metrics.Turns)
	}

	m.IncrementTurns(state)
	if state.Metrics.Turns != 1 {
		t.Errorf("Turns = %d, want 1", state.Metrics.Turns)
	}

	m.IncrementTurns(state)
	m.IncrementTurns(state)
	if state.Metrics.Turns != 3 {
		t.Errorf("Turns = %d, want 3", state.Metrics.Turns)
	}
}

func TestManagerTrackFile(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := m.Initialize("track-file-test", nil, "")

	// Track read operations
	m.TrackFile(state, "Read", "src/main.go")
	m.TrackFile(state, "Glob", "src/")
	m.TrackFile(state, "Grep", "internal/")

	if len(state.Metrics.FilesRead) != 3 {
		t.Errorf("FilesRead count = %d, want 3", len(state.Metrics.FilesRead))
	}

	// Track write operations
	m.TrackFile(state, "Write", "output.txt")
	m.TrackFile(state, "Edit", "src/main.go")

	if len(state.Metrics.FilesWritten) != 2 {
		t.Errorf("FilesWritten count = %d, want 2", len(state.Metrics.FilesWritten))
	}

	// Duplicate should not be added
	m.TrackFile(state, "Read", "src/main.go")
	if len(state.Metrics.FilesRead) != 3 {
		t.Errorf("FilesRead count after duplicate = %d, want 3", len(state.Metrics.FilesRead))
	}
}

func TestManagerSessionDir(t *testing.T) {
	m := NewManager("/custom/path")

	dir := m.SessionDir("my-session")
	if dir != "/custom/path/my-session" {
		t.Errorf("SessionDir = %q, want %q", dir, "/custom/path/my-session")
	}
}

func TestManagerAttestationsDir(t *testing.T) {
	m := NewManager("/custom/path")

	dir := m.AttestationsDir("my-session")
	if dir != "/custom/path/my-session/attestations" {
		t.Errorf("AttestationsDir = %q, want %q", dir, "/custom/path/my-session/attestations")
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"~/.aflock", filepath.Join(home, ".aflock")},
		{"~/sessions", filepath.Join(home, "sessions")},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := expandPath(tt.input)
			if got != tt.want {
				t.Errorf("expandPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoadMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Setup - create and save state with metrics
	state := m.Initialize("metrics-load-test", nil, "")
	state.Metrics.Turns = 10
	state.Metrics.CostUSD = 2.5
	m.Save(state)

	// Test loading just metrics
	metrics, err := m.LoadMetrics("metrics-load-test")
	if err != nil {
		t.Fatalf("LoadMetrics failed: %v", err)
	}
	if metrics.Turns != 10 {
		t.Errorf("Turns = %d, want 10", metrics.Turns)
	}
	if metrics.CostUSD != 2.5 {
		t.Errorf("CostUSD = %f, want 2.5", metrics.CostUSD)
	}

	// Test loading nonexistent
	metrics, err = m.LoadMetrics("nonexistent")
	if err != nil {
		t.Errorf("LoadMetrics should not error for nonexistent: %v", err)
	}
	if metrics != nil {
		t.Error("Metrics should be nil for nonexistent session")
	}
}
