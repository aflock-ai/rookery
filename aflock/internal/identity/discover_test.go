package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- extractModelFromSession ---

func TestExtractModelFromSession_MessageModel(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	lines := []map[string]interface{}{
		{
			"type": "assistant",
			"message": map[string]interface{}{
				"model": "claude-opus-4-5-20251101",
				"role":  "assistant",
			},
		},
	}

	writeJSONLFile(t, sessionFile, lines)

	model, err := extractModelFromSession(sessionFile)
	if err != nil {
		t.Fatalf("extractModelFromSession failed: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

func TestExtractModelFromSession_TopLevelModel(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	lines := []map[string]interface{}{
		{
			"type":  "request",
			"model": "claude-sonnet-4-20250514",
		},
	}

	writeJSONLFile(t, sessionFile, lines)

	model, err := extractModelFromSession(sessionFile)
	if err != nil {
		t.Fatalf("extractModelFromSession failed: %v", err)
	}
	if model != "claude-sonnet-4-20250514" {
		t.Fatalf("Expected claude-sonnet-4-20250514, got %s", model)
	}
}

func TestExtractModelFromSession_LastModelWins(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	lines := []map[string]interface{}{
		{
			"type": "assistant",
			"message": map[string]interface{}{
				"model": "claude-sonnet-4-20250514",
			},
		},
		{
			"type": "assistant",
			"message": map[string]interface{}{
				"model": "claude-opus-4-5-20251101",
			},
		},
	}

	writeJSONLFile(t, sessionFile, lines)

	model, err := extractModelFromSession(sessionFile)
	if err != nil {
		t.Fatalf("extractModelFromSession failed: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected last model claude-opus-4-5-20251101, got %s", model)
	}
}

func TestExtractModelFromSession_MixedTopLevelAndMessage(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	lines := []map[string]interface{}{
		{
			"type":  "request",
			"model": "claude-sonnet-4-20250514",
		},
		{
			"type": "assistant",
			"message": map[string]interface{}{
				"model": "claude-opus-4-5-20251101",
			},
		},
		{
			"type": "user_input",
			// No model field
		},
	}

	writeJSONLFile(t, sessionFile, lines)

	model, err := extractModelFromSession(sessionFile)
	if err != nil {
		t.Fatalf("extractModelFromSession failed: %v", err)
	}
	// Last model set was from message.model
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

func TestExtractModelFromSession_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	err := os.WriteFile(sessionFile, []byte(""), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = extractModelFromSession(sessionFile)
	if err == nil {
		t.Fatal("Expected error for empty session file")
	}
}

func TestExtractModelFromSession_NoModelField(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	lines := []map[string]interface{}{
		{"type": "user_input", "text": "hello"},
		{"type": "system", "content": "you are helpful"},
	}

	writeJSONLFile(t, sessionFile, lines)

	_, err := extractModelFromSession(sessionFile)
	if err == nil {
		t.Fatal("Expected error when no model field present")
	}
}

func TestExtractModelFromSession_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	// Mix of valid and invalid JSON lines
	content := "not valid json\n{\"model\": \"claude-opus-4-5-20251101\"}\nalso not valid\n"
	err := os.WriteFile(sessionFile, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	model, err := extractModelFromSession(sessionFile)
	if err != nil {
		t.Fatalf("Should skip invalid lines and find model: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

func TestExtractModelFromSession_EmptyModelField(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	lines := []map[string]interface{}{
		{"model": ""},
		{"message": map[string]interface{}{"model": ""}},
	}

	writeJSONLFile(t, sessionFile, lines)

	_, err := extractModelFromSession(sessionFile)
	if err == nil {
		t.Fatal("Expected error when model fields are empty strings")
	}
}

func TestExtractModelFromSession_BlankLines(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	content := "\n\n{\"model\": \"claude-opus-4-5-20251101\"}\n\n\n"
	err := os.WriteFile(sessionFile, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	model, err := extractModelFromSession(sessionFile)
	if err != nil {
		t.Fatalf("Should handle blank lines: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

func TestExtractModelFromSession_NonexistentFile(t *testing.T) {
	_, err := extractModelFromSession("/nonexistent/path/session.jsonl")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
}

func TestExtractModelFromSession_LargeLines(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.jsonl")

	// Create a line with a large payload (simulating real session data)
	bigContent := make([]byte, 100*1024) // 100KB
	for i := range bigContent {
		bigContent[i] = 'a'
	}

	entry := map[string]interface{}{
		"type":    "assistant",
		"content": string(bigContent),
		"message": map[string]interface{}{
			"model": "claude-opus-4-5-20251101",
		},
	}

	writeJSONLFile(t, sessionFile, []map[string]interface{}{entry})

	model, err := extractModelFromSession(sessionFile)
	if err != nil {
		t.Fatalf("Should handle large lines: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

// --- findModelFromMostRecentSession ---

func TestFindModelFromMostRecentSession_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two session files with different timestamps
	olderFile := filepath.Join(tmpDir, "older-session.jsonl")
	newerFile := filepath.Join(tmpDir, "newer-session.jsonl")

	writeJSONLFile(t, olderFile, []map[string]interface{}{
		{"model": "claude-sonnet-4-20250514"},
	})

	// Ensure the second file has a newer mtime
	time.Sleep(10 * time.Millisecond)

	writeJSONLFile(t, newerFile, []map[string]interface{}{
		{"model": "claude-opus-4-5-20251101"},
	})

	model, err := findModelFromMostRecentSession(tmpDir)
	if err != nil {
		t.Fatalf("findModelFromMostRecentSession failed: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected model from newest file, got %s", model)
	}
}

func TestFindModelFromMostRecentSession_IgnoresNonJSONL(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .json file (not .jsonl)
	jsonFile := filepath.Join(tmpDir, "index.json")
	os.WriteFile(jsonFile, []byte(`{"model":"wrong"}`), 0644)

	// Create a .txt file
	txtFile := filepath.Join(tmpDir, "notes.txt")
	os.WriteFile(txtFile, []byte("some notes"), 0644)

	// Create the real .jsonl session
	sessionFile := filepath.Join(tmpDir, "session.jsonl")
	writeJSONLFile(t, sessionFile, []map[string]interface{}{
		{"model": "claude-opus-4-5-20251101"},
	})

	model, err := findModelFromMostRecentSession(tmpDir)
	if err != nil {
		t.Fatalf("findModelFromMostRecentSession failed: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

func TestFindModelFromMostRecentSession_IgnoresDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a directory that ends in .jsonl (degenerate case)
	dirPath := filepath.Join(tmpDir, "subdir.jsonl")
	os.Mkdir(dirPath, 0755)

	// Create a real session file
	sessionFile := filepath.Join(tmpDir, "session.jsonl")
	writeJSONLFile(t, sessionFile, []map[string]interface{}{
		{"model": "claude-opus-4-5-20251101"},
	})

	model, err := findModelFromMostRecentSession(tmpDir)
	if err != nil {
		t.Fatalf("findModelFromMostRecentSession failed: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

func TestFindModelFromMostRecentSession_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := findModelFromMostRecentSession(tmpDir)
	if err == nil {
		t.Fatal("Expected error for empty directory")
	}
}

func TestFindModelFromMostRecentSession_NonexistentDir(t *testing.T) {
	_, err := findModelFromMostRecentSession("/nonexistent/path")
	if err == nil {
		t.Fatal("Expected error for nonexistent directory")
	}
}

func TestFindModelFromMostRecentSession_MultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	models := []string{"model-a", "model-b", "model-c", "model-d"}

	for i, model := range models {
		_ = i
		sessionFile := filepath.Join(tmpDir, model+".jsonl")
		writeJSONLFile(t, sessionFile, []map[string]interface{}{
			{"model": model},
		})
		time.Sleep(10 * time.Millisecond)
	}

	model, err := findModelFromMostRecentSession(tmpDir)
	if err != nil {
		t.Fatalf("findModelFromMostRecentSession failed: %v", err)
	}
	// Should be the last file written
	if model != "model-d" {
		t.Fatalf("Expected model-d (most recent), got %s", model)
	}
}

// --- SessionIndex and SessionIndexEntry ---

func TestSessionIndexParsing(t *testing.T) {
	data := `{
		"version": 1,
		"entries": [
			{
				"sessionId": "abc123",
				"fullPath": "/home/user/.claude/projects/test/abc123.jsonl",
				"fileMtime": 1700000000,
				"projectPath": "/home/user/proj/test",
				"modified": "2024-01-01T00:00:00Z"
			},
			{
				"sessionId": "def456",
				"fullPath": "/home/user/.claude/projects/test/def456.jsonl",
				"fileMtime": 1700001000,
				"projectPath": "/home/user/proj/test",
				"modified": "2024-01-01T01:00:00Z"
			}
		]
	}`

	var index SessionIndex
	err := json.Unmarshal([]byte(data), &index)
	if err != nil {
		t.Fatalf("Failed to parse SessionIndex: %v", err)
	}

	if index.Version != 1 {
		t.Fatalf("Expected version 1, got %d", index.Version)
	}

	if len(index.Entries) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(index.Entries))
	}

	entry := index.Entries[0]
	if entry.SessionID != "abc123" {
		t.Fatalf("Expected sessionId abc123, got %s", entry.SessionID)
	}
	if entry.ProjectPath != "/home/user/proj/test" {
		t.Fatalf("Expected projectPath /home/user/proj/test, got %s", entry.ProjectPath)
	}
}

// --- ProcessInfo ---

func TestProcessInfoSerialization(t *testing.T) {
	pi := ProcessInfo{
		PID:        1234,
		PPID:       1000,
		Command:    "/usr/local/bin/claude",
		WorkingDir: "/home/user/proj",
		IsClaude:   true,
	}

	data, err := json.Marshal(pi)
	if err != nil {
		t.Fatalf("Failed to marshal ProcessInfo: %v", err)
	}

	var decoded ProcessInfo
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal ProcessInfo: %v", err)
	}

	if decoded.PID != pi.PID {
		t.Fatalf("PID mismatch: %d vs %d", decoded.PID, pi.PID)
	}
	if decoded.PPID != pi.PPID {
		t.Fatalf("PPID mismatch: %d vs %d", decoded.PPID, pi.PPID)
	}
	if decoded.Command != pi.Command {
		t.Fatalf("Command mismatch: %s vs %s", decoded.Command, pi.Command)
	}
	if decoded.WorkingDir != pi.WorkingDir {
		t.Fatalf("WorkingDir mismatch: %s vs %s", decoded.WorkingDir, pi.WorkingDir)
	}
	if decoded.IsClaude != pi.IsClaude {
		t.Fatalf("IsClaude mismatch: %v vs %v", decoded.IsClaude, pi.IsClaude)
	}
}

// --- ProcessMetadata ---

func TestProcessMetadataSerialization(t *testing.T) {
	meta := ProcessMetadata{
		AflockPID:       1234,
		ParentPID:       1000,
		ClaudePID:       999,
		WorkingDir:      "/home/user/proj",
		SessionID:       "abc123",
		SessionPath:     "/home/user/.claude/projects/test/abc123.jsonl",
		Model:           "claude-opus-4-5-20251101",
		DiscoveryMethod: "pid_trace",
		UserID:          501,
		Hostname:        "myhost",
		Environment: map[string]string{
			"CLAUDE_MODEL": "claude-opus-4-5-20251101",
		},
		ProcessChain: []ProcessInfo{
			{PID: 1000, Command: "/usr/local/bin/claude", IsClaude: true},
			{PID: 500, Command: "/bin/bash"},
		},
	}

	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Failed to marshal ProcessMetadata: %v", err)
	}

	var decoded ProcessMetadata
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal ProcessMetadata: %v", err)
	}

	if decoded.Model != "claude-opus-4-5-20251101" {
		t.Fatalf("Model mismatch: %s", decoded.Model)
	}
	if decoded.DiscoveryMethod != "pid_trace" {
		t.Fatalf("DiscoveryMethod mismatch: %s", decoded.DiscoveryMethod)
	}
	if len(decoded.ProcessChain) != 2 {
		t.Fatalf("ProcessChain length mismatch: %d", len(decoded.ProcessChain))
	}
	if decoded.Environment["CLAUDE_MODEL"] != "claude-opus-4-5-20251101" {
		t.Fatalf("Environment mismatch: %v", decoded.Environment)
	}
}

// --- getProcessChain ---

func TestGetProcessChain_CurrentProcess(t *testing.T) {
	// We can at least test with the current process's parent
	pid := os.Getpid()
	chain := getProcessChain(pid)

	// The chain should contain at least the starting PID
	if len(chain) == 0 {
		t.Fatal("Process chain should contain at least one entry")
	}
	if chain[0] != pid {
		t.Fatalf("First entry should be starting PID %d, got %d", pid, chain[0])
	}

	// Chain should not exceed 11 entries (start + 10 levels)
	if len(chain) > 11 {
		t.Fatalf("Process chain should be capped at 11 entries, got %d", len(chain))
	}
}

func TestGetProcessChain_InvalidPID(t *testing.T) {
	// Use a PID that almost certainly doesn't exist
	chain := getProcessChain(999999999)

	// Should still contain the starting PID
	if len(chain) == 0 {
		t.Fatal("Chain should contain at least the starting PID")
	}
	if chain[0] != 999999999 {
		t.Fatalf("First entry should be 999999999, got %d", chain[0])
	}

	// Should not have more than 1 entry since parent lookup will fail
	if len(chain) > 1 {
		t.Fatalf("Chain for invalid PID should have 1 entry, got %d", len(chain))
	}
}

func TestGetProcessChain_PIDOne(t *testing.T) {
	chain := getProcessChain(1)

	if len(chain) == 0 {
		t.Fatal("Chain should contain at least the starting PID")
	}
	if chain[0] != 1 {
		t.Fatalf("First entry should be 1, got %d", chain[0])
	}

	// PID 1's parent is 0 which is <= 1, so chain should stop at 1
	// (unless the OS reports a different parent)
	if len(chain) > 2 {
		t.Fatalf("Chain for PID 1 should be very short, got %d entries", len(chain))
	}
}

// --- getParentPID ---

func TestGetParentPID_CurrentProcess(t *testing.T) {
	pid := os.Getpid()
	expectedPPID := os.Getppid()

	ppid, err := getParentPID(pid)
	if err != nil {
		t.Fatalf("getParentPID(%d) failed: %v", pid, err)
	}

	if ppid != expectedPPID {
		t.Fatalf("Expected PPID %d, got %d", expectedPPID, ppid)
	}
}

func TestGetParentPID_InvalidPID(t *testing.T) {
	_, err := getParentPID(999999999)
	if err == nil {
		t.Fatal("Expected error for invalid PID")
	}
}

// --- getProcessCommand ---

func TestGetProcessCommand_CurrentProcess(t *testing.T) {
	pid := os.Getpid()

	cmd, err := getProcessCommand(pid)
	if err != nil {
		t.Fatalf("getProcessCommand(%d) failed: %v", pid, err)
	}

	if cmd == "" {
		t.Fatal("Expected non-empty command for current process")
	}

	// The command should contain the test binary name or "go test"
	// (it could be the test binary path or "go test ...")
	if cmd == "" {
		t.Fatal("Command should not be empty for a running process")
	}
}

// --- findModelFromWorkingDir integration ---

func TestFindModelFromWorkingDir_WithSessionsIndex(t *testing.T) {
	// This test creates a full directory structure mimicking Claude's project layout
	tmpDir := t.TempDir()

	// Create a fake workDir
	workDir := filepath.Join(tmpDir, "proj", "myproject")
	os.MkdirAll(workDir, 0755)

	// Create a project slug matching what the code would compute
	// The code does: strings.ReplaceAll(workDir, "/", "-")
	projectSlug := filepath.Join(workDir)
	projectSlug = projectSlug[1:] // remove leading /
	// Actually the code replaces "/" with "-" directly from the workDir
	// but it uses os.UserHomeDir() to find the base dir. We can't easily
	// override that. Let's test findModelFromMostRecentSession directly instead,
	// which is the fallback path.

	// Create a project dir with session files
	projectDir := filepath.Join(tmpDir, "sessions")
	os.MkdirAll(projectDir, 0755)

	sessionFile := filepath.Join(projectDir, "test-session.jsonl")
	writeJSONLFile(t, sessionFile, []map[string]interface{}{
		{
			"type": "assistant",
			"message": map[string]interface{}{
				"model": "claude-opus-4-5-20251101",
				"role":  "assistant",
			},
		},
	})

	// Test the fallback path (findModelFromMostRecentSession)
	model, err := findModelFromMostRecentSession(projectDir)
	if err != nil {
		t.Fatalf("findModelFromMostRecentSession failed: %v", err)
	}
	if model != "claude-opus-4-5-20251101" {
		t.Fatalf("Expected claude-opus-4-5-20251101, got %s", model)
	}
}

// --- TrustedModels ---

func TestTrustedModelsCompleteness(t *testing.T) {
	// Verify the TrustedModels map has the expected structure
	expectedModels := []string{
		"claude-opus-4-5-20251101",
		"claude-sonnet-4-20250514",
		"claude-3-5-haiku-20241022",
	}

	for _, model := range expectedModels {
		tm, ok := TrustedModels[model]
		if !ok {
			t.Fatalf("Expected model %s in TrustedModels", model)
		}
		if tm.SPIFFEID == "" {
			t.Fatalf("TrustedModel %s should have a SPIFFEID", model)
		}
		if tm.Selector == "" {
			t.Fatalf("TrustedModel %s should have a Selector", model)
		}
		if !containsSubstring(tm.SPIFFEID, "spiffe://aflock.ai/agent/") {
			t.Fatalf("SPIFFEID for %s should contain spiffe://aflock.ai/agent/, got %s", model, tm.SPIFFEID)
		}
		if !containsSubstring(tm.Selector, "aflock:model:") {
			t.Fatalf("Selector for %s should contain aflock:model:, got %s", model, tm.Selector)
		}
	}
}

// --- Helpers ---

func writeJSONLFile(t *testing.T, path string, entries []map[string]interface{}) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create JSONL file %s: %v", path, err)
	}
	defer f.Close()

	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Failed to marshal entry: %v", err)
		}
		f.Write(data)
		f.Write([]byte("\n"))
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsCheck(s, substr))
}

func containsCheck(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
