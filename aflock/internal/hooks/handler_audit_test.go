//go:build audit

// Security audit tests for aflock hook handler.
package hooks

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// BUG-HOOKS-1: Handle() formats hookName into an error message without sanitization.
// Line 69: fmt.Errorf("unknown hook: %s", hookName)
// A hookName with control characters or format specifiers is safely handled by %s,
// but the error message is returned to the caller who may log or display it.
// More importantly, hookName comes from CLI args and is not validated against
// the known set before dispatch.
func TestHandle_UnknownHookName(t *testing.T) {
	_ = NewHandler() // just verify it doesn't panic

	// Create a minimal stdin input for the handler
	// The Handle function reads from stdin, so we need to redirect
	// This test documents the behavior - can't easily test without stdin redirect

	testCases := []string{
		"UnknownHook",
		"../../etc/passwd",              // Path traversal attempt
		"<script>alert('xss')</script>", // XSS attempt
		"SessionStart\x00EvilPayload",   // Null byte injection
		"PreToolUse; rm -rf /",          // Command injection attempt
	}

	for _, hookName := range testCases {
		// Just verify the error message doesn't panic or expose system info
		t.Logf("Testing hookName: %q", hookName)
		// The actual Handle() call requires stdin setup which is complex for this test
	}

	t.Log("BUG-HOOKS-1: hookName is not validated before error formatting")
	t.Log("While Go's fmt.Errorf with verb s is safe from injection, the unsanitized name")
	t.Log("appears in error messages that may be logged or displayed")
}

// BUG-HOOKS-2: attestationMatchesName reads and parses arbitrary files.
// The function reads any file that ends in .json or .intoto.json and
// attempts to parse it as a DSSE envelope. A malicious file could:
// 1. Be very large (no size limit check)
// 2. Contain deeply nested JSON (stack overflow)
// 3. Have a payload that's a valid base64 string pointing to data
func TestAttestationMatchesName_LargeFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a very large JSON file
	largePath := filepath.Join(tmpDir, "large.json")
	// 10MB file - attestationMatchesName has no size limit
	largeData := make([]byte, 10*1024*1024)
	for i := range largeData {
		largeData[i] = 'a'
	}
	os.WriteFile(largePath, largeData, 0644)

	// Should not crash or take too long
	result := attestationMatchesName(largePath, "build")
	if result {
		t.Error("Unexpected match for garbage data")
	}
	t.Log("BUG-HOOKS-2: attestationMatchesName reads files without size limit")
}

// BUG-HOOKS-3: attestationMatchesName uses base64.StdEncoding.DecodeString.
// DSSE payloads should use standard base64, but if they use URL-safe base64
// or raw (no padding) base64, the decode fails silently and the attestation
// is not matched. This is actually correct fail-closed behavior.
func TestAttestationMatchesName_Base64Variants(t *testing.T) {
	tmpDir := t.TempDir()

	// Standard base64 payload
	payload := `{"predicate":{"toolName":"Build","action":"build"}}`
	stdB64 := base64.StdEncoding.EncodeToString([]byte(payload))
	urlB64 := base64.URLEncoding.EncodeToString([]byte(payload))
	rawB64 := base64.RawStdEncoding.EncodeToString([]byte(payload))

	testCases := []struct {
		name    string
		payload string
	}{
		{"standard", stdB64},
		{"url-safe", urlB64},
		{"raw-no-padding", rawB64},
	}

	for _, tc := range testCases {
		envelope := `{"payload":"` + tc.payload + `"}`
		path := filepath.Join(tmpDir, tc.name+".json")
		os.WriteFile(path, []byte(envelope), 0644)

		result := attestationMatchesName(path, "Build")
		t.Logf("Base64 %s: matched=%v", tc.name, result)
	}
}

// BUG-HOOKS-4: isAttestationFile matches ANY .json file, not just .intoto.json.
// This means findAttestation could match state.json, config.json, etc.
// In the attestation directory this is probably fine, but it's overly broad.
func TestIsAttestationFile_TooPermissive(t *testing.T) {
	testCases := []struct {
		name     string
		expected bool
	}{
		{"build.intoto.json", true},
		{"build.json", true},
		{"state.json", true},   // Not an attestation
		{"config.json", true},  // Not an attestation
		{"package.json", true}, // Not an attestation
		{".json", true},        // Edge case
		{"file.txt", false},
		{"file.jsonl", false},
		{"file", false},
	}

	for _, tc := range testCases {
		result := isAttestationFile(tc.name)
		if result != tc.expected {
			t.Errorf("isAttestationFile(%q) = %v, want %v", tc.name, result, tc.expected)
		}
	}
	t.Log("BUG-HOOKS-4: isAttestationFile matches any .json file, not just attestation files")
}

// BUG-HOOKS-5: handlePreToolUse creates an ephemeral session state when
// sessionState is nil (lines 190-198), but this ephemeral state is never
// saved. The RecordAction call on line 222 modifies ephemeral state,
// and Save on line 231 saves it, but on the NEXT hook call, Load
// will find the saved state and use it. However, the ephemeral state
// was initialized with a fresh session ID but no SessionStart processing.
// This means:
// - Policy context was never injected
// - Agent identity was never verified
// - Session metrics start from zero
// This is a policy bypass if SessionStart hook is skipped.
func TestHandlePreToolUse_SessionStartBypass(t *testing.T) {
	// This documents the bypass scenario:
	// 1. Start Claude Code without running SessionStart hook
	// 2. First PreToolUse creates ephemeral state with policy from cwd
	// 3. Agent identity is never checked against policy.Identity constraints
	// 4. All subsequent tool calls work with the bypassed state
	t.Log("BUG-HOOKS-5: PreToolUse creates ephemeral state bypassing SessionStart")
	t.Log("If SessionStart was intentionally skipped (e.g., by killing the hook process),")
	t.Log("subsequent PreToolUse calls still enforce tool/file policy but skip identity checks")
}

// BUG-HOOKS-6: findAttestation in handler.go has different logic than
// findAttestation in verifier.go. The handler version (lines 406-436) checks
// exact names and then scans file content. The verifier version (lines 355-368)
// checks exact names and then uses filepath.Glob. These inconsistencies
// mean behavior differs between hook enforcement and post-hoc verification.
func TestFindAttestation_HandlerVsVerifier(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a timestamped attestation file with matching content
	payload := `{"predicate":{"toolName":"Build","action":"build"}}`
	stdB64 := base64.StdEncoding.EncodeToString([]byte(payload))
	envelope := `{"payload":"` + stdB64 + `"}`

	os.WriteFile(filepath.Join(tmpDir, "20260101-120000-abc123.intoto.json"), []byte(envelope), 0644)

	// Handler's findAttestation checks content
	handlerResult := findAttestation(tmpDir, "Build")
	t.Logf("Handler findAttestation('Build'): %v", handlerResult)

	// The verifier's findAttestation uses glob Build* - this would NOT match
	// "20260101-120000-abc123.intoto.json" because the filename doesn't start with "Build"
	// But the handler's version DOES match because it checks file content.
	t.Log("BUG-HOOKS-6: Handler and verifier use different attestation lookup logic")
	t.Log("Handler checks file CONTENT for matching toolName/action")
	t.Log("Verifier uses filename glob matching")
}
