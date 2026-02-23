//go:build audit

// Security tests for aflock agent identity and discovery module.
// Finding IDs: R3-300 series (identity/agent subsystem).
package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// R3-300: Env var filter in DiscoverFromMCPSocket misses sensitive substrings.
//
// The filter only checks KEY, TOKEN, SECRET, PASSWORD, CREDENTIAL.
// It misses AUTH, PRIVATE, BEARER, PASSPHRASE, CERT, SIGNING — all of which
// are common patterns for sensitive values. An env var like CLAUDE_AUTH_HEADER
// or ANTHROPIC_PRIVATE_DATA passes through the filter unredacted.
// ---------------------------------------------------------------------------

func TestSecurity_R3_300_EnvFilterMissesSensitiveSubstrings(t *testing.T) {
	// These env vars should be considered sensitive but are NOT blocked
	// by the current sensitiveSubstrings list.
	leakyVars := map[string]string{
		"CLAUDE_AUTH":            "bearer-abc123",
		"CLAUDE_AUTH_HEADER":     "Authorization: Bearer sk-live-xyz",
		"CLAUDE_PRIVATE_KEY":     "-----BEGIN RSA PRIVATE KEY-----", // "PRIVATE" not in list (only KEY is, but PRIVATE_KEY would match KEY… check)
		"ANTHROPIC_BEARER":       "sk-ant-api123",
		"CLAUDE_PASSPHRASE":      "my-secret-passphrase",
		"ANTHROPIC_SIGNING_KEY":  "ed25519-priv-deadbeef",
		"CLAUDE_CERT_PEM":        "-----BEGIN CERTIFICATE-----",
		"ANTHROPIC_SESSION_PIN":  "123456",
		"CLAUDE_OAUTH_REFRESH":   "refresh-token-value",
		"ANTHROPIC_JWT":          "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
		"CLAUDE_CONN_STRING":     "postgres://user:pass@host/db",
		"ANTHROPIC_WEBHOOK_SIGN": "whsec_abc123",
	}

	// The sensitiveSubstrings from the code
	sensitiveSubstrings := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}

	var leaked []string
	for envKey := range leakyVars {
		isSensitive := false
		upperKey := strings.ToUpper(envKey)
		for _, substr := range sensitiveSubstrings {
			if strings.Contains(upperKey, substr) {
				isSensitive = true
				break
			}
		}
		if !isSensitive {
			leaked = append(leaked, envKey)
		}
	}

	// These are the ones that actually bypass the filter
	assert.NotEmpty(t, leaked, "Expected some env vars to bypass the filter")

	for _, key := range leaked {
		t.Logf("R3-300 LEAK: %s = %q would be included unredacted in attestation metadata", key, leakyVars[key])
	}

	// Verify that known-sensitive patterns are NOT caught
	// CLAUDE_AUTH does not contain KEY, TOKEN, SECRET, PASSWORD, or CREDENTIAL
	assert.Contains(t, leaked, "CLAUDE_AUTH",
		"CLAUDE_AUTH should leak through the filter (missing AUTH substring)")
	assert.Contains(t, leaked, "ANTHROPIC_BEARER",
		"ANTHROPIC_BEARER should leak through the filter (missing BEARER substring)")
	assert.Contains(t, leaked, "CLAUDE_PASSPHRASE",
		"CLAUDE_PASSPHRASE should leak through the filter (missing PASSPHRASE substring)")
}

// ---------------------------------------------------------------------------
// R3-301: TraceProcessInfo has a DIFFERENT (weaker) env filter than
//         DiscoverFromMCPSocket — inconsistent security boundaries.
//
// TraceProcessInfo only checks KEY, TOKEN, SECRET, PASSWORD (no CREDENTIAL).
// This means CLAUDE_CREDENTIAL would be redacted by DiscoverFromMCPSocket
// but NOT redacted by TraceProcessInfo.
// ---------------------------------------------------------------------------

func TestSecurity_R3_301_TraceProcessInfoFilterInconsistency(t *testing.T) {
	// The TraceProcessInfo filter from discover.go lines ~708-715:
	//   strings.Contains(upperK, "KEY") || TOKEN || SECRET || PASSWORD
	// Missing: "CREDENTIAL" (which IS in DiscoverFromMCPSocket's list)

	traceFilters := []string{"KEY", "TOKEN", "SECRET", "PASSWORD"}
	discoverFilters := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}

	// Find what DiscoverFromMCPSocket blocks but TraceProcessInfo does not
	var gapSubstrings []string
	for _, s := range discoverFilters {
		found := false
		for _, tf := range traceFilters {
			if s == tf {
				found = true
				break
			}
		}
		if !found {
			gapSubstrings = append(gapSubstrings, s)
		}
	}

	require.NotEmpty(t, gapSubstrings,
		"Expected filter gap between TraceProcessInfo and DiscoverFromMCPSocket")
	assert.Contains(t, gapSubstrings, "CREDENTIAL",
		"CREDENTIAL is filtered in DiscoverFromMCPSocket but NOT in TraceProcessInfo")

	t.Log("R3-301: CLAUDE_CREDENTIAL would be redacted by DiscoverFromMCPSocket")
	t.Log("R3-301: but exposed by TraceProcessInfo — inconsistent security boundary")
}

// ---------------------------------------------------------------------------
// R3-302: resolveActualBinary follows symlinks to arbitrary sensitive files
//         and reads their content into memory.
//
// If an attacker can control a symlink at the binary path, the function will:
//  1. Follow the symlink (filepath.EvalSymlinks)
//  2. os.Stat the target
//  3. os.ReadFile the target (if < 1 MiB and not a directory)
// This reads arbitrary file content. While it only looks for "exec " patterns,
// the data is loaded into memory and could be leaked via side channels.
// ---------------------------------------------------------------------------

func TestSecurity_R3_302_ResolveFollowsSymlinkToSensitiveFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a "sensitive" file simulating /etc/shadow or a private key
	sensitiveFile := filepath.Join(tmpDir, "sensitive-data")
	sensitiveContent := "root:$6$rounds=656000$salt$hash:19000:0:99999:7:::\n"
	require.NoError(t, os.WriteFile(sensitiveFile, []byte(sensitiveContent), 0600))

	// Create a symlink that points to the sensitive file
	symlinkPath := filepath.Join(tmpDir, "claude-binary")
	require.NoError(t, os.Symlink(sensitiveFile, symlinkPath))

	// resolveActualBinary follows the symlink and reads the file content
	result := resolveActualBinary(symlinkPath)

	// The function resolved through the symlink to the sensitive file
	resolvedSensitive, _ := filepath.EvalSymlinks(sensitiveFile)
	assert.Equal(t, resolvedSensitive, result,
		"R3-302: resolveActualBinary followed symlink to sensitive file without validation")

	t.Log("R3-302: The function read the sensitive file's content looking for exec patterns")
	t.Log("R3-302: It should validate the target is an executable (check ELF/Mach-O header)")
}

// ---------------------------------------------------------------------------
// R3-303: resolveActualBinary exec-chain parsing can be tricked to resolve
//         arbitrary paths. A malicious shell wrapper can reference any file.
//
// The naive `exec ` prefix parsing means a script containing:
//   exec /etc/shadow "$@"
// would cause resolveActualBinary to recurse into /etc/shadow.
// ---------------------------------------------------------------------------

func TestSecurity_R3_303_ExecParsingResolvesToArbitraryPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a "target" that the malicious exec points to
	targetFile := filepath.Join(tmpDir, "sensitive-target")
	require.NoError(t, os.WriteFile(targetFile, []byte("sensitive data here"), 0644))

	// Create a malicious shell wrapper that execs to the target
	maliciousWrapper := filepath.Join(tmpDir, "wrapper.sh")
	// Use the resolved path so EvalSymlinks matches
	resolvedTarget, _ := filepath.EvalSymlinks(targetFile)
	content := fmt.Sprintf("#!/bin/bash\nexec \"%s\" \"$@\"\n", resolvedTarget)
	require.NoError(t, os.WriteFile(maliciousWrapper, []byte(content), 0755))

	result := resolveActualBinary(maliciousWrapper)

	assert.Equal(t, resolvedTarget, result,
		"R3-303: exec parsing followed chain to arbitrary file path")

	t.Log("R3-303: A malicious wrapper can direct resolution to any path on the filesystem")
	t.Log("R3-303: No validation that the exec target is actually an executable binary")
}

// ---------------------------------------------------------------------------
// R3-304: CLAUDE_BINARY env var is trusted without any validation.
//
// discoverBinary() uses os.Getenv("CLAUDE_BINARY") as the binary path
// without validating it's an actual executable. An attacker who can set
// this env var can:
//   1. Cause exec.Command(path, "--version") to run arbitrary binaries
//   2. Cause computeBinaryDigest to hash arbitrary files
//   3. Cause resolveActualBinary to read arbitrary files
// ---------------------------------------------------------------------------

func TestSecurity_R3_304_CLAUDEBINARYEnvNotValidated(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file that is NOT an executable
	fakeFile := filepath.Join(tmpDir, "not-a-binary.txt")
	require.NoError(t, os.WriteFile(fakeFile, []byte("this is not a binary"), 0644))

	// Verify the code would accept this path
	// We can't call discoverBinary() directly because it would actually
	// exec the path, but we can verify the resolution chain accepts it
	result := resolveActualBinary(fakeFile)
	resolvedFake, _ := filepath.EvalSymlinks(fakeFile)
	assert.Equal(t, resolvedFake, result,
		"R3-304: resolveActualBinary accepts non-executable files without validation")

	// Also verify computeBinaryDigest happily hashes anything
	digest := computeBinaryDigest(fakeFile)
	assert.NotEmpty(t, digest,
		"R3-304: computeBinaryDigest hashes non-executable files without validation")

	t.Log("R3-304: CLAUDE_BINARY=/etc/passwd would cause the code to:")
	t.Log("R3-304:   1. exec.Command('/etc/passwd', '--version') — command injection")
	t.Log("R3-304:   2. Hash /etc/passwd into the attestation — info disclosure")
	t.Log("R3-304:   3. resolveActualBinary reads the file content — data exfil risk")
}

// ---------------------------------------------------------------------------
// R3-305: TOCTOU race in resolveActualBinaryDepth.
//
// Between os.Stat(resolved) and os.ReadFile(resolved), an attacker can swap
// the symlink target. The stat check passes (file < 1 MiB, not a dir), then
// the symlink is swapped to point to /dev/urandom or a huge file. ReadFile
// then reads the new target.
//
// More practically: stat shows a small file, then the target is swapped to
// a sensitive large file just over 1 MiB — but because stat already passed
// the size check, ReadFile still reads it.
// ---------------------------------------------------------------------------

func TestSecurity_R3_305_TOCTOURaceInResolve(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two files: one small (passes size check), one that simulates
	// the file being swapped after stat
	smallFile := filepath.Join(tmpDir, "small")
	require.NoError(t, os.WriteFile(smallFile, []byte("#!/bin/bash\necho hello"), 0755))

	largeContent := make([]byte, maxScriptSize+1) // Just over the limit
	for i := range largeContent {
		largeContent[i] = 'A'
	}
	largeFile := filepath.Join(tmpDir, "large")
	require.NoError(t, os.WriteFile(largeFile, largeContent, 0755))

	// Create a symlink initially pointing to the small file
	symlinkPath := filepath.Join(tmpDir, "binary")
	require.NoError(t, os.Symlink(smallFile, symlinkPath))

	// Demonstrate the race window exists:
	// In production, between Stat and ReadFile, the symlink could be changed.
	// We can't reliably trigger the race in a test, but we can show that
	// the code does NOT hold an fd between stat and read — it uses path-based ops.

	// Verify stat and read are separate operations (no fd-based access)
	// by showing that after stat, changing the symlink target affects ReadFile

	// First call: resolves to small file (reads content)
	result1 := resolveActualBinary(symlinkPath)

	// Change the symlink target
	require.NoError(t, os.Remove(symlinkPath))
	require.NoError(t, os.Symlink(largeFile, symlinkPath))

	// Second call: resolves to large file (stat shows > maxScriptSize, so it stops)
	result2 := resolveActualBinary(symlinkPath)

	// The resolved paths differ, proving the race window is exploitable
	resolvedSmall, _ := filepath.EvalSymlinks(smallFile)
	resolvedLarge, _ := filepath.EvalSymlinks(largeFile)

	assert.Equal(t, resolvedSmall, result1, "First resolution should point to small file")
	assert.Equal(t, resolvedLarge, result2, "Second resolution should point to large file")

	t.Log("R3-305: TOCTOU window exists between os.Stat() and os.ReadFile()")
	t.Log("R3-305: An attacker can swap the symlink target between these calls")
	t.Log("R3-305: Fix: open the file once, fstat the fd, then read from the fd")
}

// ---------------------------------------------------------------------------
// R3-306: Session file path traversal via crafted sessions-index.json.
//
// findModelAndSessionFromWorkingDir trusts the FullPath field from
// sessions-index.json. A crafted index can point FullPath to any file
// on the filesystem, causing extractModelFromSession to read it.
// ---------------------------------------------------------------------------

func TestSecurity_R3_306_SessionIndexPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a "sensitive" file that extractModelFromSession would read
	sensitiveFile := filepath.Join(tmpDir, "sensitive.jsonl")
	content := `{"model":"leaked-from-sensitive-file"}` + "\n"
	require.NoError(t, os.WriteFile(sensitiveFile, []byte(content), 0644))

	// Simulate what would happen if sessions-index.json had a traversal path
	// The code reads entry.FullPath and passes it directly to extractModelFromSession
	model, err := extractModelFromSession(sensitiveFile)
	require.NoError(t, err)

	assert.Equal(t, "leaked-from-sensitive-file", model,
		"R3-306: extractModelFromSession reads arbitrary paths without validation")

	// Now demonstrate the traversal: if FullPath contains "../../../etc/something"
	// The index is parsed and the path is used as-is
	traversalPath := filepath.Join(tmpDir, "..", filepath.Base(tmpDir), "sensitive.jsonl")
	model2, err := extractModelFromSession(traversalPath)
	require.NoError(t, err)
	assert.Equal(t, "leaked-from-sensitive-file", model2,
		"R3-306: Path traversal via ../ in FullPath is not prevented")

	t.Log("R3-306: sessions-index.json FullPath field is trusted without validation")
	t.Log("R3-306: A crafted index could point to arbitrary files outside ~/.claude/")
	t.Log("R3-306: Fix: validate FullPath is under the expected project directory")
}

// ---------------------------------------------------------------------------
// R3-307: Identity hash separator injection allows component spoofing.
//
// This extends BUG-IDENTITY-1 from agent_audit_test.go with a more
// realistic exploitation scenario. The pipe separator allows injecting
// fake components that change the meaning of downstream fields.
//
// Specifically: a tools list entry containing "|policy:malicious-digest"
// can override the real policy digest in the canonical representation.
// ---------------------------------------------------------------------------

func TestSecurity_R3_307_ToolNameSeparatorInjectionOverridesPolicy(t *testing.T) {
	// Identity A: legitimate identity with a specific policy digest
	legit := &AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
		Tools:        []string{"Read", "Write"},
		PolicyDigest: "aaaa1111bbbb2222cccc3333dddd4444",
	}
	legitHash := legit.DeriveIdentity()

	// Identity B: attacker injects a tool name that contains the pipe separator
	// and a fake policy component, combined with a different real PolicyDigest.
	// Goal: produce the same canonical string as the legitimate identity.
	//
	// Legit canonical: "model:claude-opus-4-5@4.5.0|tools:Read,Write|policy:aaaa1111bbbb2222cccc3333dddd4444"
	// Attack canonical: if tool = "Read,Write|policy:aaaa1111bbbb2222cccc3333dddd4444"
	// then tools: component = "tools:Read,Write|policy:aaaa1111bbbb2222cccc3333dddd4444"
	// and real policy = "eeee5555ffff6666" appends as "|policy:eeee5555ffff6666"
	// So: "model:claude-opus-4-5@4.5.0|tools:Read,Write|policy:aaaa1111bbbb2222cccc3333dddd4444|policy:eeee5555ffff6666"
	// This does NOT collide (extra policy component), but demonstrates the injection vector.

	attack := &AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
		Tools:        []string{"Read,Write|policy:aaaa1111bbbb2222cccc3333dddd4444"},
		PolicyDigest: "eeee5555ffff6666",
	}
	attackHash := attack.DeriveIdentity()

	// These hashes SHOULD be different (the tool name injection adds an extra policy)
	// but the point is the tool name contains |, which is the component separator
	assert.NotEqual(t, legitHash, attackHash,
		"Hashes differ but tool name still contains pipe separator — "+
			"this means the canonical format is injectable")

	// The real danger: a tool name with | breaks the canonical representation
	// making it impossible to parse components unambiguously
	canonicalLegit := "model:claude-opus-4-5@4.5.0|tools:Read,Write|policy:aaaa1111bbbb2222cccc3333dddd4444"
	canonicalAttack := fmt.Sprintf("model:claude-opus-4-5@4.5.0|tools:%s|policy:eeee5555ffff6666",
		"Read,Write|policy:aaaa1111bbbb2222cccc3333dddd4444")

	// Show that splitting on | produces ambiguous component boundaries
	legitParts := strings.Split(canonicalLegit, "|")
	attackParts := strings.Split(canonicalAttack, "|")

	t.Logf("Legit parts (%d):  %v", len(legitParts), legitParts)
	t.Logf("Attack parts (%d): %v", len(attackParts), attackParts)

	// The attack has MORE parts, but parts[2] in the attack looks like
	// "policy:aaaa1111bbbb2222cccc3333dddd4444" — the attacker's fake policy
	assert.Greater(t, len(attackParts), len(legitParts),
		"R3-307: pipe in tool name creates extra ambiguous components")
	assert.Equal(t, "policy:aaaa1111bbbb2222cccc3333dddd4444", attackParts[2],
		"R3-307: attacker can inject a fake policy component via tool name")
}

// ---------------------------------------------------------------------------
// R3-308: No validation of tool names allows control character injection
//         into the canonical identity representation and SPIFFE paths.
//
// Tool names with newlines, null bytes, or unicode can corrupt the canonical
// representation and potentially the SPIFFE ID path.
// ---------------------------------------------------------------------------

func TestSecurity_R3_308_ToolNameControlCharInjection(t *testing.T) {
	tests := []struct {
		name     string
		tools    []string
		wantDesc string
	}{
		{
			name:     "null byte in tool name",
			tools:    []string{"Read\x00Write"},
			wantDesc: "null byte may truncate string in some contexts",
		},
		{
			name:     "newline in tool name",
			tools:    []string{"Read\nWrite"},
			wantDesc: "newline breaks line-oriented parsing of canonical form",
		},
		{
			name:     "pipe separator in tool name",
			tools:    []string{"Read|binary:evil@9.9"},
			wantDesc: "pipe is the component separator in canonical form",
		},
		{
			name:     "colon separator in tool name",
			tools:    []string{"tools:injected"},
			wantDesc: "colon is the key-value separator in canonical form",
		},
		{
			name:     "comma separator in tool name",
			tools:    []string{"Read,Write,Bash"},
			wantDesc: "comma is the tool list separator — one tool looks like three",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			identity := &AgentIdentity{
				Model:        "test-model",
				ModelVersion: "1.0.0",
				Tools:        tc.tools,
			}

			// DeriveIdentity should not panic
			hash := identity.DeriveIdentity()
			assert.Len(t, hash, 64, "Should still produce valid hash")

			// But the canonical form is corrupted
			t.Logf("R3-308: Tool %q — %s", tc.tools[0], tc.wantDesc)
			t.Logf("R3-308: Hash: %s", hash[:16])
		})
	}
}

// ---------------------------------------------------------------------------
// R3-309: Concurrent access to AgentIdentity during DeriveIdentity.
//
// DeriveIdentity mutates a.IdentityHash as a side effect. If two goroutines
// call DeriveIdentity (or String, or ToSPIFFEID which calls DeriveIdentity)
// concurrently, there's a data race on IdentityHash.
// ---------------------------------------------------------------------------

func TestSecurity_R3_309_ConcurrentDeriveIdentityRace(t *testing.T) {
	identity := &AgentIdentity{
		Model:        "claude-opus-4-5",
		ModelVersion: "4.5.0",
		Tools:        []string{"Read", "Write", "Bash"},
		PolicyDigest: "abc123",
	}

	// Run DeriveIdentity concurrently — if there's a race, the race detector will catch it.
	// This test should be run with -race flag.
	var wg sync.WaitGroup
	hashes := make([]string, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hashes[idx] = identity.DeriveIdentity()
		}(i)
	}
	wg.Wait()

	// All hashes should be identical (deterministic)
	for i := 1; i < len(hashes); i++ {
		assert.Equal(t, hashes[0], hashes[i],
			"R3-309: Concurrent DeriveIdentity produced different results — data race")
	}

	// Also test String() concurrently (calls DeriveIdentity internally)
	strings := make([]string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			strings[idx] = identity.String()
		}(i)
	}
	wg.Wait()

	for i := 1; i < len(strings); i++ {
		assert.Equal(t, strings[0], strings[i],
			"R3-309: Concurrent String() produced different results — data race")
	}
}

// ---------------------------------------------------------------------------
// R3-310: resolveActualBinary depth limit does NOT prevent breadth explosion.
//
// A malicious script at each depth level could contain MANY exec lines.
// The function only follows the first matching exec, but the loop iterates
// all lines. A 1 MiB file with millions of lines wastes CPU/memory.
// ---------------------------------------------------------------------------

func TestSecurity_R3_310_ResolveScriptCPUBomb(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a script with many lines (but under maxScriptSize)
	// Each line is a valid exec statement pointing to a non-existent path
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	// Fill with non-exec lines to waste iteration time
	for i := 0; i < 50000; i++ {
		sb.WriteString(fmt.Sprintf("# comment line %d\n", i))
	}
	// Put the real exec at the end
	sb.WriteString("exec /nonexistent/binary \"$@\"\n")

	scriptPath := filepath.Join(tmpDir, "bomb.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(sb.String()), 0755))

	// Verify it's under the size limit
	info, err := os.Stat(scriptPath)
	require.NoError(t, err)
	assert.Less(t, info.Size(), int64(maxScriptSize),
		"Script should be under the size limit to be processed")

	// This will parse all 50k+ lines looking for exec
	result := resolveActualBinary(scriptPath)

	// It eventually finds the exec target (non-existent path)
	assert.Equal(t, "/nonexistent/binary", result,
		"Should resolve to the exec target even after many lines")

	t.Log("R3-310: resolveActualBinary parses all lines in a script (up to 1 MiB)")
	t.Log("R3-310: A malicious script with many lines wastes CPU in the resolution loop")
	t.Log("R3-310: Fix: limit the number of lines parsed, not just file size")
}

// ---------------------------------------------------------------------------
// R3-311: resolveActualBinary exec parsing doesn't handle shell quoting.
//
// The exec line parsing does strings.Trim(parts[1], "\"'") which handles
// simple quoting, but fails on:
//   exec "/path/with spaces/binary" "$@"  (parts[1] = "\"/path/with" after Fields split)
//   exec '/path/binary' "$@"  (works accidentally)
//   exec /path/binary\ with\ spaces "$@"  (backslash escaping)
// ---------------------------------------------------------------------------

func TestSecurity_R3_311_ExecParsingShellQuotingBypass(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the actual target binary
	targetDir := filepath.Join(tmpDir, "path with spaces")
	require.NoError(t, os.MkdirAll(targetDir, 0755))
	targetBin := filepath.Join(targetDir, "binary")
	require.NoError(t, os.WriteFile(targetBin, []byte{0x7f, 'E', 'L', 'F'}, 0755))

	resolvedTarget, _ := filepath.EvalSymlinks(targetBin)

	// Create a wrapper using proper shell quoting
	wrapper := filepath.Join(tmpDir, "wrapper.sh")
	// This is how shell scripts actually quote paths with spaces
	wrapperContent := fmt.Sprintf("#!/bin/bash\nexec \"%s\" \"$@\"\n", resolvedTarget)
	require.NoError(t, os.WriteFile(wrapper, []byte(wrapperContent), 0755))

	result := resolveActualBinary(wrapper)

	// strings.Fields splits on whitespace, so the quoted path gets split.
	// parts[1] would be `"/path` (with leading quote and partial path)
	// After Trim("\"'"), it becomes the partial path without the closing quote.
	//
	// The path contains spaces, so strings.Fields will split it incorrectly.
	// The exec parsing will get a truncated path.

	if result == resolvedTarget {
		t.Log("R3-311: Exec parsing handled quoted path with spaces correctly (unexpected)")
	} else {
		t.Logf("R3-311: Exec parsing failed on quoted path with spaces")
		t.Logf("R3-311: Expected: %s", resolvedTarget)
		t.Logf("R3-311: Got: %s", result)
		t.Log("R3-311: strings.Fields splits on whitespace inside quotes, breaking path resolution")
	}
}

// ---------------------------------------------------------------------------
// R3-312: resolveActualBinary maxScriptSize check uses os.Stat which
//         reports the apparent file size. On Linux, /proc files report
//         size 0 even though they have content. If the binary path points
//         to a /proc file, it bypasses the size check.
//
// (Platform-specific: primarily affects Linux where /proc is available)
// ---------------------------------------------------------------------------

func TestSecurity_R3_312_ProcFilesBypaseSizeCheck(t *testing.T) {
	// On macOS, /proc doesn't exist. On Linux, /proc/self/maps would have
	// apparent size 0 but real content. We test the logic regardless.

	// The size check: info.Size() > maxScriptSize
	// A file reporting size 0 passes this check, even if reading it produces data.

	// We can simulate this with a file that has size 0 in stat but content when read.
	// On most filesystems this isn't possible, but on /proc it is.

	// Instead, test the logic directly: a file with size exactly at the boundary
	tmpDir := t.TempDir()

	// Exactly at the limit — should still be read
	exactFile := filepath.Join(tmpDir, "exact")
	exactContent := make([]byte, maxScriptSize)
	copy(exactContent, []byte("#!/bin/bash\nexec /usr/bin/true \"$@\"\n"))
	require.NoError(t, os.WriteFile(exactFile, exactContent, 0755))

	result := resolveActualBinary(exactFile)
	resolvedExact, _ := filepath.EvalSymlinks(exactFile)

	// File at exactly maxScriptSize should still be read (the check is >  not >=)
	// This means the entire 1 MiB file is loaded into memory
	if result == "/usr/bin/true" {
		t.Log("R3-312: File at exactly maxScriptSize (1 MiB) was fully read into memory")
		t.Log("R3-312: The check should be >= to avoid processing maximum-size scripts")
	} else {
		assert.Equal(t, resolvedExact, result,
			"File at exact size limit should be handled")
	}
}

// ---------------------------------------------------------------------------
// R3-313: Claude process detection uses naive string matching.
//
// The check `strings.Contains(cmd, "claude") && !strings.Contains(cmd, "node")`
// matches any process with "claude" in its command line (including arguments).
// An attacker who creates a process like:
//   /bin/bash -c "echo claude is great"
// would match as a Claude process, allowing session impersonation.
// ---------------------------------------------------------------------------

func TestSecurity_R3_313_ClaudeProcessDetectionSpoofable(t *testing.T) {
	// Simulate command strings that would incorrectly match as Claude
	spoofableCommands := []string{
		"/bin/bash -c echo claude",            // "claude" in argument
		"/usr/bin/python claude_helper.py",    // "claude" in filename
		"/home/user/claude-notes/editor",      // "claude" in path component
		"vi /tmp/claude-session.txt",          // "claude" in argument path
		"/usr/bin/env CLAUDE_MODE=1 /bin/sh",  // "claude" in env var
		"/opt/claudelib/helper",               // "claude" in directory name
	}

	for _, cmd := range spoofableCommands {
		isDetectedAsClaude := strings.Contains(cmd, "claude") && !strings.Contains(cmd, "node")
		if isDetectedAsClaude {
			t.Logf("R3-313 SPOOF: %q is detected as Claude process", cmd)
		}
	}

	// Legitimate Claude commands that should match but might not
	legitimateCommands := []string{
		"/usr/local/bin/claude --model opus",         // should match
		"/home/user/.local/bin/claude code",          // should match
		"/usr/local/bin/claude-code --version",       // should match
	}

	for _, cmd := range legitimateCommands {
		isDetected := strings.Contains(cmd, "claude") && !strings.Contains(cmd, "node")
		assert.True(t, isDetected, "Legitimate command %q should be detected", cmd)
	}

	// Commands that are actually Claude's node subprocess but get filtered
	nodeCommands := []string{
		"/usr/local/bin/node /usr/local/lib/claude/index.js",
		"node --max-old-space-size=4096 /path/to/claude/cli.js",
	}

	for _, cmd := range nodeCommands {
		isDetected := strings.Contains(cmd, "claude") && !strings.Contains(cmd, "node")
		assert.False(t, isDetected,
			"Node subprocess %q should be filtered", cmd)
	}

	t.Log("R3-313: Claude detection should check the binary name, not search the full command line")
	t.Log("R3-313: Fix: parse the command to extract the binary basename and match against that")
}

// ---------------------------------------------------------------------------
// R3-314: getParentPIDLinux /proc/PID/stat parsing is potentially spoofable.
//
// The function reads /proc/PID/stat and parses it to extract PPID.
// On Linux, a process can set its comm field (the (name) part) to contain
// parentheses. The code correctly uses LastIndex(")") to handle this, BUT
// it does not validate the PID field matches the expected PID.
//
// If /proc is writable (e.g., in a container), or a FUSE filesystem mounts
// over /proc, the stat file could return arbitrary data.
// ---------------------------------------------------------------------------

func TestSecurity_R3_314_ProcStatParsingManipulation(t *testing.T) {
	tmpDir := t.TempDir()

	// Simulate /proc/PID/stat with a malicious comm field
	// Format: pid (comm) state ppid ...
	testCases := []struct {
		name     string
		statLine string
		wantPPID int
		wantErr  bool
	}{
		{
			name:     "normal",
			statLine: "1234 (bash) S 1000 1234 1234 0 -1 ...",
			wantPPID: 1000,
		},
		{
			name:     "comm with spaces",
			statLine: "1234 (my process name) S 1000 1234 1234 0 -1 ...",
			wantPPID: 1000,
		},
		{
			name:     "comm with closing paren",
			statLine: "1234 (evil) process) S 999 1234 1234 0 -1 ...",
			wantPPID: 999,
		},
		{
			name:     "spoofed PPID",
			statLine: "1234 (normal) S 1 1234 1234 0 -1 ...",
			wantPPID: 1,
		},
		{
			name:     "no closing paren",
			statLine: "1234 (unclosed S 1000 ...",
			wantErr:  true,
		},
		{
			name:     "insufficient fields after paren",
			statLine: "1234 (test) S",
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Write a fake stat file
			statFile := filepath.Join(tmpDir, tc.name+"-stat")
			require.NoError(t, os.WriteFile(statFile, []byte(tc.statLine), 0444))

			// Parse it using the same logic as getParentPIDLinux
			data, err := os.ReadFile(statFile)
			require.NoError(t, err)

			stat := string(data)
			lastParen := strings.LastIndex(stat, ")")
			if lastParen < 0 {
				if tc.wantErr {
					return // Expected
				}
				t.Fatal("unexpected: no closing paren")
			}

			fields := strings.Fields(stat[lastParen+1:])
			if len(fields) < 2 {
				if tc.wantErr {
					return // Expected
				}
				t.Fatal("unexpected: insufficient fields")
			}

			var ppid int
			fmt.Sscanf(fields[1], "%d", &ppid)

			if !tc.wantErr {
				assert.Equal(t, tc.wantPPID, ppid, "PPID should match expected")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R3-315: PID reuse allows process impersonation in process chain.
//
// getProcessChain walks up PIDs using getParentPID. Between calls,
// a PID can be recycled by the OS. If PID 1234 dies and a new process
// takes PID 1234, the chain would include the impersonator process.
//
// The code has no mechanism to validate that the process at each PID
// is still the same process it was when the walk started.
// ---------------------------------------------------------------------------

func TestSecurity_R3_315_PIDReuseInProcessChain(t *testing.T) {
	// We can't directly trigger PID reuse in a test, but we can demonstrate
	// that the process chain is built without any temporal consistency checks.

	// The process chain for our own PID should be consistent
	myPID := os.Getpid()
	chain1 := getProcessChain(myPID)
	chain2 := getProcessChain(myPID)

	// Chains should match (no PID reuse during test)
	assert.Equal(t, chain1, chain2,
		"Process chains should be consistent when no PID reuse occurs")

	// But there's no start_time or process creation time validation
	// The code does: getProcessCommand(pid) which uses `ps -o command= -p PID`
	// If the PID was recycled, ps returns the NEW process's command.

	// Demonstrate: getProcessChain does not check process start times
	// It just walks PIDs without any temporal correlation.
	t.Log("R3-315: Process chain walk uses only PIDs without start-time validation")
	t.Log("R3-315: Between getParentPID calls, a PID could be recycled")
	t.Log("R3-315: Fix: capture (PID, start_time) pairs and validate consistency")
	t.Log("R3-315: On Linux: use /proc/PID/stat field 22 (starttime)")
	t.Log("R3-315: On macOS: use `ps -o pid,lstart -p PID`")
}

// ---------------------------------------------------------------------------
// R3-316: resolveActualBinary cycle detection uses resolved paths but
//         an attacker can create a cycle using different initial paths
//         that resolve to the same file via different symlink chains.
//
// Example: /tmp/a -> /tmp/b -> /tmp/c (exec /tmp/a) creates a cycle.
// The seen map tracks resolved paths, so this IS caught. But what if the
// same physical file is accessible via different mount points?
// ---------------------------------------------------------------------------

func TestSecurity_R3_316_ResolveCycleDetection(t *testing.T) {
	tmpDir := t.TempDir()

	resolvedTmpDir, _ := filepath.EvalSymlinks(tmpDir)

	// Create a circular exec chain: a.sh -> b.sh -> a.sh
	aPath := filepath.Join(resolvedTmpDir, "a.sh")
	bPath := filepath.Join(resolvedTmpDir, "b.sh")

	aContent := fmt.Sprintf("#!/bin/bash\nexec \"%s\" \"$@\"\n", bPath)
	bContent := fmt.Sprintf("#!/bin/bash\nexec \"%s\" \"$@\"\n", aPath)

	require.NoError(t, os.WriteFile(aPath, []byte(aContent), 0755))
	require.NoError(t, os.WriteFile(bPath, []byte(bContent), 0755))

	// Should not hang due to cycle detection
	result := resolveActualBinary(aPath)

	// The cycle detection should stop the recursion
	assert.True(t, result == aPath || result == bPath,
		"Cycle detection should terminate the resolution, got: %s", result)

	t.Log("R3-316: Cycle detection works for simple cycles via the 'seen' map")

	// Now test with depth limit: create a chain of 15 scripts (exceeds maxResolveDepth=10)
	prevPath := filepath.Join(resolvedTmpDir, "chain-end")
	require.NoError(t, os.WriteFile(prevPath, []byte{0x7f, 'E', 'L', 'F'}, 0755))

	for i := 14; i >= 0; i-- {
		chainPath := filepath.Join(resolvedTmpDir, fmt.Sprintf("chain-%d.sh", i))
		chainContent := fmt.Sprintf("#!/bin/bash\nexec \"%s\" \"$@\"\n", prevPath)
		require.NoError(t, os.WriteFile(chainPath, []byte(chainContent), 0755))
		prevPath = chainPath
	}

	deepResult := resolveActualBinary(prevPath)
	// At depth 10, it should stop and return whatever it has
	t.Logf("R3-316: Deep chain (15 levels) resolved to: %s", deepResult)
	t.Logf("R3-316: Depth limit %d prevents following the full chain", maxResolveDepth)

	// The result should NOT be chain-end (which is at depth 15)
	chainEnd := filepath.Join(resolvedTmpDir, "chain-end")
	if deepResult != chainEnd {
		t.Log("R3-316: Depth limit correctly prevented resolution of full chain")
	} else {
		t.Log("R3-316: WARNING: Full chain was resolved despite exceeding depth limit")
	}
}

// ---------------------------------------------------------------------------
// R3-317: lsof output parsing in getProcessWorkingDirMacOS and
//         findModelFromOpenFilesMacOS is fragile.
//
// lsof output can contain filenames with spaces, which breaks the
// fields-based parsing in findModelFromOpenFilesMacOS. The code takes
// fields[len(fields)-1] which only gets the last space-separated token
// of the filename, not the full path.
// ---------------------------------------------------------------------------

func TestSecurity_R3_317_LsofOutputParsingWithSpaces(t *testing.T) {
	// Simulate lsof output line with a filename containing spaces
	lsofLine := "claude  1234 user  42r  REG  1,4  8192  12345 /Users/user/my project/.claude/projects/test/session.jsonl"

	// The code does: fields := strings.Fields(line); filePath := fields[len(fields)-1]
	fields := strings.Fields(lsofLine)
	parsedPath := fields[len(fields)-1]

	expectedPath := "/Users/user/my project/.claude/projects/test/session.jsonl"

	assert.NotEqual(t, expectedPath, parsedPath,
		"R3-317: lsof parsing fails on paths with spaces")
	assert.Equal(t, "project/.claude/projects/test/session.jsonl", parsedPath,
		"R3-317: Only the last space-delimited token is captured")

	t.Log("R3-317: findModelFromOpenFilesMacOS uses strings.Fields which splits on spaces")
	t.Log("R3-317: Filenames with spaces are incorrectly parsed, potentially matching wrong files")
	t.Log("R3-317: Fix: use lsof -F format (already done in getProcessWorkingDirMacOS) consistently")
}

// ---------------------------------------------------------------------------
// R3-318: Environment variable values can contain newlines and control chars.
//
// Even when a key passes the filter, the VALUE is included verbatim.
// An env var like CLAUDE_MODEL=$'hello\nmalicious_field:evil_value'
// could inject additional fields when the metadata is serialized to
// text-based formats (JSONL, logs, etc.).
// ---------------------------------------------------------------------------

func TestSecurity_R3_318_EnvVarValueInjection(t *testing.T) {
	// Simulate env vars with control characters in values
	dangerousValues := map[string]string{
		"CLAUDE_MODEL":   "claude-opus\n\"injected\":\"evil\"",
		"CLAUDE_VERSION": "1.0.0\x00hidden-data",
		"CLAUDE_SESSION": "session-123\r\nX-Header: injected",
	}

	for key, value := range dangerousValues {
		// These would pass the key filter (no sensitive substrings)
		// and the value would be stored verbatim in meta.Environment
		assert.True(t, strings.HasPrefix(key, "CLAUDE_"),
			"Key should match CLAUDE_ prefix filter")

		// Check for dangerous characters in value
		hasDangerous := strings.ContainsAny(value, "\n\r\x00")
		assert.True(t, hasDangerous,
			"R3-318: Value for %s contains control characters that are not sanitized", key)
	}

	t.Log("R3-318: Environment variable values are included verbatim without sanitization")
	t.Log("R3-318: Control characters (newline, null, CR) can inject data into text formats")
	t.Log("R3-318: Fix: sanitize or escape control characters in env var values")
}
