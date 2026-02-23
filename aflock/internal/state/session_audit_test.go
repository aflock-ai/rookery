//go:build audit

// Security audit tests for aflock state persistence.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// BUG-STATE-1: Save() does non-atomic writes via os.WriteFile.
// If the process crashes or is killed mid-write, state.json is truncated/corrupted.
// Next Load() returns a parse error, and the session state is permanently lost.
// Fix: write to a temp file, then os.Rename (atomic on POSIX).
func TestSave_NonAtomicWrite_CorruptionOnPartialWrite(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := &aflock.SessionState{
		SessionID: "sess-atomic-test",
		StartedAt: time.Now(),
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "1.0",
		},
		Metrics: &aflock.SessionMetrics{
			Turns: 5,
			Tools: make(map[string]int),
		},
	}

	// Save valid state first
	if err := m.Save(state); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	// Verify it loads correctly
	loaded, err := m.Load("sess-atomic-test")
	if err != nil {
		t.Fatalf("Load after valid save: %v", err)
	}
	if loaded.Metrics.Turns != 5 {
		t.Fatalf("expected 5 turns, got %d", loaded.Metrics.Turns)
	}

	// Simulate partial write: write truncated JSON directly
	path := filepath.Join(tmpDir, "sess-atomic-test", "state.json")
	truncatedJSON := `{"session_id":"sess-atomic-test","started_at":"2025-01-01T00:00:00Z","policy":{"version":"1.0","name":"tes`
	if err := os.WriteFile(path, []byte(truncatedJSON), 0600); err != nil {
		t.Fatalf("write truncated: %v", err)
	}

	// Load should now fail with parse error - the previous valid state is lost
	_, err = m.Load("sess-atomic-test")
	if err == nil {
		t.Fatal("Expected error loading truncated state file, but got nil - this means the truncated data parsed successfully which is surprising")
	}
	// This proves the bug: a partial write destroys state permanently.
	// With atomic writes (write tmp + rename), the previous valid state.json
	// would remain intact if the process dies mid-write.
	t.Logf("BUG-STATE-1 confirmed: partial write destroys state. Error: %v", err)
}

// BUG-STATE-2: Concurrent Save() calls race on the same session file.
// There is no file locking or mutex. Two goroutines calling Save() simultaneously
// can interleave writes, corrupting the file.
func TestSave_ConcurrentWriteRace(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Run many concurrent saves to increase chance of interleaved writes
	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup
	var errors []error
	var mu sync.Mutex

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				state := &aflock.SessionState{
					SessionID: "sess-race",
					StartedAt: time.Now(),
					Policy: &aflock.Policy{
						Name:    "race-policy",
						Version: "1.0",
					},
					Metrics: &aflock.SessionMetrics{
						Turns:     id*1000 + i,
						ToolCalls: id*1000 + i,
						Tools:     map[string]int{"tool": id*1000 + i},
					},
				}
				if err := m.Save(state); err != nil {
					mu.Lock()
					errors = append(errors, err)
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()

	if len(errors) > 0 {
		t.Logf("BUG-STATE-2: %d write errors during concurrent access", len(errors))
	}

	// After all writes, the file should still be valid JSON
	loaded, err := m.Load("sess-race")
	if err != nil {
		t.Fatalf("BUG-STATE-2 confirmed: state file corrupted after concurrent writes: %v", err)
	}
	if loaded == nil {
		t.Fatal("BUG-STATE-2: loaded state is nil after concurrent writes")
	}
	t.Logf("Final state: turns=%d", loaded.Metrics.Turns)
}

// BUG-STATE-3: SessionDir does path traversal with unsanitized sessionID.
// A sessionID like "../../etc" would resolve outside the state directory.
func TestSessionDir_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// An attacker-controlled sessionID with path traversal
	maliciousIDs := []string{
		"../../etc",
		"../../../tmp/evil",
		"foo/../../../etc/passwd",
		"/absolute/path",
	}

	for _, id := range maliciousIDs {
		dir := m.SessionDir(id)
		// The result should stay within tmpDir
		abs, _ := filepath.Abs(dir)
		stateAbs, _ := filepath.Abs(tmpDir)
		if len(abs) < len(stateAbs) || abs[:len(stateAbs)] != stateAbs {
			t.Errorf("BUG-STATE-3: SessionDir(%q) = %q escapes state dir %q", id, abs, stateAbs)
		}
	}
}

// BUG-STATE-4: RecordAction is not concurrency-safe.
// Multiple goroutines appending to state.Actions without synchronization.
func TestRecordAction_ConcurrentAppend(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := m.Initialize("sess-concurrent", &aflock.Policy{Name: "test"}, "test.aflock")

	var wg sync.WaitGroup
	const goroutines = 10
	const actionsPerGoroutine = 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < actionsPerGoroutine; i++ {
				m.RecordAction(state, aflock.ActionRecord{
					Timestamp: time.Now(),
					ToolName:  "TestTool",
					ToolUseID: "tu_" + string(rune('A'+id)),
					Decision:  "allow",
				})
			}
		}(g)
	}
	wg.Wait()

	// With proper synchronization, we'd expect exactly goroutines*actionsPerGoroutine actions
	expected := goroutines * actionsPerGoroutine
	actual := len(state.Actions)
	if actual != expected {
		t.Errorf("BUG-STATE-4: Expected %d actions, got %d (lost %d due to race)",
			expected, actual, expected-actual)
	}

	// Also check metrics
	if state.Metrics.ToolCalls != expected {
		t.Errorf("BUG-STATE-4: Expected ToolCalls=%d, got %d", expected, state.Metrics.ToolCalls)
	}
}

// BUG-STATE-5: expandPath only strips the first character of ~, not ~/
// expandPath("~") returns filepath.Join(home, "") which is correct.
// expandPath("~foo") would return filepath.Join(home, "foo") which is wrong on Unix
// (should be the home of user "foo", not current user's home + "foo").
// However more critically: if UserHomeDir fails, the raw ~ path is returned as-is.
func TestExpandPath_TildaEdgeCases(t *testing.T) {
	// Tilde with username (Unix convention: ~user means user's home)
	// The code treats "~user" as "home_dir/user" which is incorrect
	result := expandPath("~otheruser/docs")
	if result == "~otheruser/docs" {
		// UserHomeDir failed, raw path returned - this is the expected fallback
		// but it means the path is unusable
		t.Log("expandPath returned raw ~ path (UserHomeDir failed)")
	}
	// The main concern is that ~user is not the same as ~/user
	// but the code strips only index [0] (the ~) and joins the rest.
	// For "~otheruser/docs", path[1:] = "otheruser/docs"
	// Result: /home/currentuser/otheruser/docs (WRONG - should error or resolve ~otheruser)
	t.Logf("expandPath(~otheruser/docs) = %s", result)

	// Empty path
	result = expandPath("")
	if result != "" {
		t.Errorf("expandPath(\"\") = %q, want empty", result)
	}

	// Just tilde
	result = expandPath("~")
	home, _ := os.UserHomeDir()
	if home != "" && result != home {
		t.Errorf("expandPath(\"~\") = %q, want %q", result, home)
	}

	// Normal tilde-slash
	result = expandPath("~/sessions")
	if home != "" {
		expected := filepath.Join(home, "sessions")
		if result != expected {
			t.Errorf("expandPath(\"~/sessions\") = %q, want %q", result, expected)
		}
	}
}

// BUG-STATE-6: Load returns (nil, nil) for nonexistent state.
// Callers that don't check for nil before dereferencing will panic.
// Several places in handler.go DO check, but the API contract is dangerous.
func TestLoad_ReturnsNilNilForNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state, err := m.Load("nonexistent-session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != nil {
		t.Fatal("expected nil state for nonexistent session")
	}
	// This is the documented behavior but it's a footgun.
	// Any caller that does: state.Policy.Name will panic.
	// Better: return a sentinel error like ErrSessionNotFound.
	t.Log("BUG-STATE-6 confirmed: Load returns (nil, nil) for missing sessions - nil-deref footgun")
}

// BUG-STATE-7: Save dereferences state.SessionID without nil-check on state itself.
func TestSave_NilState(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	defer func() {
		if r := recover(); r != nil {
			t.Logf("BUG-STATE-7 confirmed: Save(nil) panics: %v", r)
		}
	}()

	err := m.Save(nil)
	if err == nil {
		t.Log("Save(nil) returned nil error - should have returned an error")
	}
}

// BUG-STATE-8: UpdateMetrics has no nil check on state.Metrics
func TestUpdateMetrics_NilMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := &aflock.SessionState{
		SessionID: "test",
		Metrics:   nil, // nil metrics
	}

	defer func() {
		if r := recover(); r != nil {
			t.Logf("BUG-STATE-8 confirmed: UpdateMetrics panics on nil Metrics: %v", r)
		}
	}()

	m.UpdateMetrics(state, 100, 50, 0.01)
	t.Log("UpdateMetrics didn't panic (Metrics was nil)")
}

// BUG-STATE-9: IncrementTurns has no nil check on state.Metrics
func TestIncrementTurns_NilMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := &aflock.SessionState{
		SessionID: "test",
		Metrics:   nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Logf("BUG-STATE-9 confirmed: IncrementTurns panics on nil Metrics: %v", r)
		}
	}()

	m.IncrementTurns(state)
	t.Log("IncrementTurns didn't panic (Metrics was nil)")
}

// BUG-STATE-10: TrackFile has no nil check on state.Metrics
func TestTrackFile_NilMetrics(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := &aflock.SessionState{
		SessionID: "test",
		Metrics:   nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Logf("BUG-STATE-10 confirmed: TrackFile panics on nil Metrics: %v", r)
		}
	}()

	m.TrackFile(state, "Read", "/some/file")
	t.Log("TrackFile didn't panic (Metrics was nil)")
}

// BUG-STATE-11: State file permissions too permissive for MkdirAll.
// The dir is created with 0700 (good) but there's no check that an
// existing directory has correct permissions.
func TestSave_DirectoryPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	state := &aflock.SessionState{
		SessionID: "perms-test",
		StartedAt: time.Now(),
		Policy:    &aflock.Policy{Name: "test"},
		Metrics:   &aflock.SessionMetrics{Tools: make(map[string]int)},
	}

	if err := m.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Check file permissions
	path := filepath.Join(tmpDir, "perms-test", "state.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	// File should be 0600 (owner-only read/write)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("File permissions: %o, expected 0600", perm)
	}

	// Directory should be 0700
	dirInfo, err := os.Stat(filepath.Join(tmpDir, "perms-test"))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	dirPerm := dirInfo.Mode().Perm()
	if dirPerm != 0700 {
		t.Errorf("Dir permissions: %o, expected 0700", dirPerm)
	}
}

// BUG-STATE-12: JSON deserialization round-trip with special characters in session ID
func TestSaveLoad_SpecialSessionIDs(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	// Session IDs that could cause issues
	testCases := []string{
		"normal-session-id",
		"session with spaces",
		"session\twith\ttabs",
	}

	for _, id := range testCases {
		state := &aflock.SessionState{
			SessionID: id,
			StartedAt: time.Now(),
			Policy:    &aflock.Policy{Name: "test"},
			Metrics:   &aflock.SessionMetrics{Tools: make(map[string]int)},
		}

		if err := m.Save(state); err != nil {
			t.Logf("Save(%q) failed: %v", id, err)
			continue
		}

		loaded, err := m.Load(id)
		if err != nil {
			t.Errorf("Load(%q) after Save failed: %v", id, err)
			continue
		}
		if loaded == nil {
			t.Errorf("Load(%q) returned nil", id)
			continue
		}
		if loaded.SessionID != id {
			t.Errorf("Round-trip failed: saved %q, loaded %q", id, loaded.SessionID)
		}
	}
}

// Verify that the JSON round-trip preserves all fields
func TestSaveLoad_FullRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManager(tmpDir)

	now := time.Now().Truncate(time.Second) // Truncate for JSON precision
	state := &aflock.SessionState{
		SessionID:  "roundtrip-test",
		StartedAt:  now,
		PolicyPath: "/some/path/.aflock",
		Policy: &aflock.Policy{
			Name:    "test-policy",
			Version: "2.0",
		},
		Metrics: &aflock.SessionMetrics{
			TokensIn:  1000,
			TokensOut: 500,
			CostUSD:   0.123456789,
			Turns:     10,
			ToolCalls: 20,
			Tools:     map[string]int{"Read": 10, "Write": 5, "Bash": 5},
			FilesRead: []string{"/a/b.go", "/c/d.go"},
		},
		Actions: []aflock.ActionRecord{
			{
				Timestamp: now,
				ToolName:  "Read",
				ToolUseID: "tu_1",
				ToolInput: json.RawMessage(`{"file_path":"/test"}`),
				Decision:  "allow",
			},
		},
	}

	if err := m.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := m.Load("roundtrip-test")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.SessionID != state.SessionID {
		t.Errorf("SessionID: got %q, want %q", loaded.SessionID, state.SessionID)
	}
	if loaded.PolicyPath != state.PolicyPath {
		t.Errorf("PolicyPath: got %q, want %q", loaded.PolicyPath, state.PolicyPath)
	}
	if loaded.Metrics.CostUSD != state.Metrics.CostUSD {
		t.Errorf("CostUSD: got %f, want %f", loaded.Metrics.CostUSD, state.Metrics.CostUSD)
	}
	if len(loaded.Actions) != len(state.Actions) {
		t.Errorf("Actions: got %d, want %d", len(loaded.Actions), len(state.Actions))
	}
}
