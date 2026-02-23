//go:build audit

// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package git

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FINDING 1: Remote URL credential stripping only works for url.Parse-able URLs
// Severity: MEDIUM
//
// The attestor strips credentials from remote URLs using url.Parse.
// If url.Parse fails (e.g., for SSH URLs like git@github.com:org/repo.git),
// the code falls back to storing the original URL. But some SSH URLs CAN
// contain embedded credentials that url.Parse can't handle:
//   - ssh://user:password@host/repo.git (url.Parse handles this)
//   - git@host:repo.git (url.Parse fails, stored as-is, but no password)
//   - https://token@github.com/repo.git (url.Parse handles this)
//
// The concern: if a remote URL contains credentials in a format that
// url.Parse partially handles (doesn't error, but doesn't strip), the
// credentials leak into the attestation.
// =============================================================================

func TestAdversarial_RemoteURLCredentialLeakage(t *testing.T) {
	testCases := []struct {
		name           string
		remoteURL      string
		shouldLeak     bool
		leakedContent  string
		description    string
	}{
		{
			name:          "HTTPS with token in username position",
			remoteURL:     "https://ghp_xxsecrettokenxx@github.com/org/repo.git",
			shouldLeak:    false,
			leakedContent: "ghp_xxsecrettokenxx",
			description:   "Token-as-username should be stripped by url.Parse",
		},
		{
			name:          "HTTPS with user:pass",
			remoteURL:     "https://user:supersecret@github.com/org/repo.git",
			shouldLeak:    false,
			leakedContent: "supersecret",
			description:   "user:pass should be stripped by url.Parse",
		},
		{
			name:          "SSH with password (url.Parse-able)",
			remoteURL:     "ssh://deploy:secretkey@github.com/org/repo.git",
			shouldLeak:    false,
			leakedContent: "secretkey",
			description:   "SSH with user:pass should be stripped",
		},
		{
			name:          "git protocol with credentials",
			remoteURL:     "git://user:pass@github.com/org/repo.git",
			shouldLeak:    false,
			leakedContent: "pass",
			description:   "git:// with user:pass should be stripped",
		},
		{
			name:          "HTTPS with token in query param",
			remoteURL:     "https://github.com/org/repo.git?access_token=ghp_secrettoken",
			shouldLeak:    true,
			leakedContent: "ghp_secrettoken",
			description:   "Token in query parameter is NOT stripped - only User is cleared",
		},
		{
			name:          "HTTPS with token in fragment",
			remoteURL:     "https://github.com/org/repo.git#token=secret",
			shouldLeak:    true,
			leakedContent: "secret",
			description:   "Token in fragment is NOT stripped - only User is cleared",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestor := New()
			_, dir, cleanup := createTestRepo(t, true)
			defer cleanup()

			repo, err := gogit.PlainOpen(dir)
			require.NoError(t, err)

			_, err = repo.CreateRemote(&config.RemoteConfig{
				Name: "origin",
				URLs: []string{tc.remoteURL},
			})
			require.NoError(t, err)

			ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
				attestation.WithWorkingDir(dir))
			require.NoError(t, err)
			err = ctx.RunAttestors()
			require.NoError(t, err)

			require.NotEmpty(t, attestor.Remotes)

			for _, remote := range attestor.Remotes {
				if tc.shouldLeak {
					if strings.Contains(remote, tc.leakedContent) {
						t.Errorf("BUG: %s. Credential %q leaked in remote URL: %s",
							tc.description, tc.leakedContent, remote)
					}
				} else {
					assert.NotContains(t, remote, tc.leakedContent,
						"Credential should be stripped: %s", tc.description)
				}
			}
		})
	}
}

// =============================================================================
// FINDING 2: Commit message can contain arbitrary content
// Severity: LOW
//
// The commit message is stored verbatim in the attestation. While this is
// expected behavior, extremely large commit messages or messages with
// special characters could cause issues with downstream JSON serialization
// or storage.
// =============================================================================

func TestAdversarial_ExtremeCommitMessage(t *testing.T) {
	testCases := []struct {
		name    string
		message string
	}{
		{
			name:    "very long commit message",
			message: strings.Repeat("A", 1024*1024), // 1MB commit message
		},
		{
			name:    "commit message with null bytes",
			message: "normal message\x00hidden content",
		},
		{
			name:    "commit message with embedded JSON",
			message: `fix: update {"malicious":"json","overwrite":"true"}`,
		},
		{
			name:    "commit message with unicode",
			message: "fix: \U0001F600\U0001F4A9\U0001F525 emoji commit",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestor := New()
			_, dir, cleanup := createTestRepo(t, true)
			defer cleanup()

			repo, err := gogit.PlainOpen(dir)
			require.NoError(t, err)

			wt, err := repo.Worktree()
			require.NoError(t, err)

			// Create a file and commit with the adversarial message
			filePath := filepath.Join(dir, "adversarial.txt")
			require.NoError(t, os.WriteFile(filePath, []byte("test"), 0644))
			_, err = wt.Add("adversarial.txt")
			require.NoError(t, err)
			_, err = wt.Commit(tc.message, &gogit.CommitOptions{
				Author: &object.Signature{
					Name:  "Test",
					Email: "test@test.com",
					When:  time.Now(),
				},
			})
			require.NoError(t, err)

			ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
				attestation.WithWorkingDir(dir))
			require.NoError(t, err)
			err = ctx.RunAttestors()
			require.NoError(t, err)

			assert.Equal(t, tc.message, attestor.CommitMessage,
				"Commit message stored verbatim - no sanitization or size limit")
		})
	}
}

// =============================================================================
// FINDING 3: Author/committer email not validated
// Severity: LOW
//
// Author and committer emails are stored from the git commit objects.
// These are user-controlled (via git config) and can contain any string.
// They become subjects via Subjects().
// =============================================================================

func TestAdversarial_MaliciousAuthorEmail(t *testing.T) {
	testCases := []struct {
		name  string
		email string
	}{
		{"email with injection", "test@example.com\r\nX-Injected: true"},
		{"not an email", "not-an-email-at-all"},
		{"empty email", ""},
		{"email with null byte", "test@example\x00.com"},
		{"extremely long email", strings.Repeat("a", 10000) + "@example.com"},
		{"email with special chars", "<script>alert('xss')</script>@evil.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestor := New()
			_, dir, cleanup := createTestRepo(t, false)
			defer cleanup()

			repo, err := gogit.PlainOpen(dir)
			require.NoError(t, err)

			// Create initial file
			filePath := filepath.Join(dir, "test.txt")
			require.NoError(t, os.WriteFile(filePath, []byte("test"), 0644))

			wt, err := repo.Worktree()
			require.NoError(t, err)
			_, err = wt.Add("test.txt")
			require.NoError(t, err)

			_, err = wt.Commit("test commit", &gogit.CommitOptions{
				Author: &object.Signature{
					Name:  "Attacker",
					Email: tc.email,
					When:  time.Now(),
				},
			})
			require.NoError(t, err)

			ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
				attestation.WithWorkingDir(dir))
			require.NoError(t, err)
			err = ctx.RunAttestors()
			require.NoError(t, err)

			assert.Equal(t, tc.email, attestor.AuthorEmail,
				"BUG: Author email %q stored without validation. "+
					"This becomes a subject key in Subjects().", tc.email)

			// Verify it appears in subjects
			subjects := attestor.Subjects()
			key := fmt.Sprintf("authoremail:%v", tc.email)
			_, exists := subjects[key]
			assert.True(t, exists,
				"Malicious email becomes an attestation subject without validation")
		})
	}
}

// =============================================================================
// FINDING 4: Subject key format allows collisions
// Severity: MEDIUM
//
// Subject keys use the format "prefix:value" (e.g., "commithash:abc123").
// If the value contains a colon, the key could be ambiguous. For example:
//   "authoremail:evil:password@host.com" could be parsed as prefix "authoremail"
//   with value "evil:password@host.com" or prefix "authoremail:evil" with
//   value "password@host.com" by a naive downstream parser.
//
// More importantly, there's no encoding/escaping of the value in the key.
// =============================================================================

func TestAdversarial_SubjectKeyAmbiguity(t *testing.T) {
	attestor := &Attestor{
		CommitHash:     "abc123",
		AuthorEmail:    "user:password@host.com", // Contains colon
		CommitterEmail: "committeremail:spoofed-prefix@evil.com",
		ParentHashes:   []string{"def456"},
		RefNameShort:   "main",
	}

	subjects := attestor.Subjects()

	// Check for the author email subject - the key contains multiple colons
	emailKey := fmt.Sprintf("authoremail:%v", attestor.AuthorEmail)
	_, exists := subjects[emailKey]
	assert.True(t, exists)

	// The key "authoremail:user:password@host.com" has 3 colon-separated segments
	// A naive split-on-first-colon would work, but it's fragile
	colons := strings.Count(emailKey, ":")
	if colons > 1 {
		t.Logf("Subject key %q has %d colons. Downstream parsers using split-on-colon "+
			"could misinterpret this.", emailKey, colons)
	}

	// Check for the deliberately confusing committer email
	committerKey := fmt.Sprintf("committeremail:%v", attestor.CommitterEmail)
	_, exists = subjects[committerKey]
	assert.True(t, exists,
		"BUG: Subject key %q embeds what looks like another prefix:value pair. "+
			"No escaping or encoding prevents confusion.", committerKey)
}

// =============================================================================
// FINDING 5: CommitHash subject uses SHA1 without collision protection
// Severity: MEDIUM
//
// The commit hash subject uses crypto.SHA1 with GitOID=false. SHA1 is
// known to have practical collision attacks (SHAttered). While git's
// SHA1 implementation includes collision detection (via sha1cd), the
// attestor's digest set uses plain SHA1.
//
// The SHA256 of the commit hash string is also computed, but the primary
// binding is still SHA1.
// =============================================================================

func TestAdversarial_SHA1CommitDigest(t *testing.T) {
	attestor := New()
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	err = ctx.RunAttestors()
	require.NoError(t, err)

	// Check that CommitDigest uses SHA1
	var hasSHA1 bool
	for dv := range attestor.CommitDigest {
		if dv.Hash == crypto.SHA1 {
			hasSHA1 = true
			assert.False(t, dv.GitOID,
				"CommitDigest SHA1 has GitOID=false (raw SHA1, not gitoid)")
		}
	}
	assert.True(t, hasSHA1,
		"CommitDigest uses SHA1. Consider also including SHA256 for collision resistance.")

	// Check Subjects
	subjects := attestor.Subjects()
	commitKey := fmt.Sprintf("commithash:%v", attestor.CommitHash)
	ds, exists := subjects[commitKey]
	require.True(t, exists)

	for dv := range ds {
		if dv.Hash == crypto.SHA1 {
			t.Log("NOTE: Commit hash subject uses SHA1. Git's SHA-1 has known "+
				"collision attacks (SHAttered). Consider adding SHA-256 binding "+
				"via the TreeHash or using gitoid with sha256.")
		}
	}
}

// =============================================================================
// FINDING 6: GitGetStatus uses exec.Command - PATH manipulation
// Severity: MEDIUM
//
// GitGetStatus runs: exec.Command("git", "-C", workDir, "status", "--porcelain")
// If an attacker controls PATH, they can place a malicious "git" binary
// earlier in the PATH, which would be executed instead of the real git.
//
// GitExists(), GitGetBinPath(), and GitGetBinHash() all use exec.LookPath("git")
// which is also subject to PATH manipulation.
//
// The attestor records GitBinPath and GitBinHash, but an attacker who controls
// PATH can make these point to their malicious binary.
// =============================================================================

func TestAdversarial_GitBinPATHManipulation(t *testing.T) {
	// Create a fake git binary
	tmpDir, err := os.MkdirTemp("", "fake-git-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	fakeGit := filepath.Join(tmpDir, "git")
	// Create a minimal script that pretends to be git
	err = os.WriteFile(fakeGit, []byte("#!/bin/sh\necho 'fake git'\n"), 0755)
	require.NoError(t, err)

	// Prepend our fake git to PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir+":"+origPath)

	// Now verify that the attestor would pick up our fake git
	assert.True(t, GitExists(), "GitExists should find our fake git")

	binPath, err := GitGetBinPath()
	require.NoError(t, err)
	assert.Equal(t, fakeGit, binPath,
		"BUG: GitGetBinPath returns attacker-controlled binary path. "+
			"An attacker who controls PATH can substitute a malicious git binary.")
}

// =============================================================================
// FINDING 7: git_bin.go status parsing doesn't handle renamed files
// Severity: LOW
//
// GitGetStatus parses `git status --porcelain` output. For renamed files,
// the format is "R  old -> new". The current parser takes everything after
// the 2-char status code, which would include "old -> new" as the file path.
// This is incorrect for renamed files.
// =============================================================================

func TestAdversarial_GitStatusParsingEdgeCases(t *testing.T) {
	// Test the parsing logic directly with synthetic inputs
	// The parser expects: XY filename (where X and Y are single chars)

	testCases := []struct {
		name     string
		line     string
		wantFile string
		wantStag string
		wantWork string
	}{
		{
			name:     "normal modified file",
			line:     " M file.txt",
			wantFile: "file.txt",
			wantStag: "unmodified",
			wantWork: "modified",
		},
		{
			name:     "file with spaces in name",
			line:     " M path with spaces/file.txt",
			wantFile: "path with spaces/file.txt",
			wantStag: "unmodified",
			wantWork: "modified",
		},
		{
			name:     "renamed file (arrow notation)",
			line:     "R  old.txt -> new.txt",
			wantFile: "old.txt -> new.txt",
			wantStag: "renamed",
			wantWork: "unmodified",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate what GitGetStatus does
			if len(tc.line) < 3 {
				t.Skip("line too short")
			}
			repoStatus := statusCodeString(gogit.StatusCode(tc.line[0]))
			worktreeStatus := statusCodeString(gogit.StatusCode(tc.line[1]))
			filePath := strings.TrimSpace(tc.line[2:])

			assert.Equal(t, tc.wantStag, repoStatus)
			assert.Equal(t, tc.wantWork, worktreeStatus)
			assert.Equal(t, tc.wantFile, filePath)

			if tc.name == "renamed file (arrow notation)" {
				t.Log("NOTE: Renamed files use 'old -> new' format in git status --porcelain. " +
					"The parser treats this entire string as the file path, which is incorrect. " +
					"The porcelain v1 format for renames is 'XY orig -> dest'. " +
					"Consider splitting on ' -> ' for rename status codes.")
			}
		})
	}
}

// =============================================================================
// FINDING 8: git_bin.go - line parsing vulnerable to short lines
// Severity: LOW
//
// GitGetStatus does line[0], line[1], line[2:] without checking len(line) >= 3.
// The check is len(line) == 0 (skip empty), but a line with 1-2 chars
// would cause an index-out-of-bounds panic.
//
// In practice, git status --porcelain always outputs lines >= 3 chars,
// but a malicious "git" binary (see FINDING 6) could output anything.
// =============================================================================

func TestAdversarial_GitStatusShortLinesPanic(t *testing.T) {
	// If we could inject lines into the git status output, short lines would panic.
	// Since we can't easily do that in a test, we document the issue.

	// Simulate the parsing with short lines
	shortLines := []string{"X", "XY", ""}

	for _, line := range shortLines {
		t.Run(fmt.Sprintf("line=%q", line), func(t *testing.T) {
			if len(line) == 0 {
				t.Log("Empty line correctly skipped")
				return
			}
			if len(line) < 3 {
				t.Logf("BUG: Line %q has len=%d (<3). "+
					"GitGetStatus would panic with index out of bounds. "+
					"Code does line[0], line[1], line[2:] without length check.",
					line, len(line))
			}
		})
	}
}

// =============================================================================
// FINDING 9: Redundant error check in GitGetBinHash
// Severity: INFO (code quality)
//
// GitGetBinHash has a duplicate error check:
//   gitBinDigest, err := cryptoutil.CalculateDigestSetFromFile(...)
//   if err != nil { return }  // line 57-59
//   if err != nil { return }  // line 61-63  (dead code)
// =============================================================================

func TestAdversarial_GitGetBinHashDeadCode(t *testing.T) {
	// This is a code quality issue, not a security bug.
	// The second error check in GitGetBinHash is dead code.
	t.Log("INFO: GitGetBinHash in git_bin.go has a redundant error check at lines 61-63. " +
		"This is dead code - the second 'if err != nil' can never be true because " +
		"the first check already returned on error.")
}

// =============================================================================
// FINDING 10: DetectDotGit traverses up the directory tree
// Severity: LOW
//
// The git.PlainOpenWithOptions call uses DetectDotGit: true, which walks
// up the directory tree looking for a .git directory. If the workingDir
// is controlled by an attacker, they could place a malicious .git directory
// higher in the path to capture the attestor.
// =============================================================================

func TestAdversarial_DetectDotGitTraversal(t *testing.T) {
	// Create a directory structure where a .git exists at a parent level
	parentDir, err := os.MkdirTemp("", "parent-repo-*")
	require.NoError(t, err)
	defer os.RemoveAll(parentDir)

	// Init repo in parent
	_, err = gogit.PlainInit(parentDir, false)
	require.NoError(t, err)

	// Create a child directory without its own .git
	childDir := filepath.Join(parentDir, "subdir", "deep", "path")
	require.NoError(t, os.MkdirAll(childDir, 0755))

	// The attestor running in childDir will find parentDir's .git
	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(childDir))
	require.NoError(t, err)
	err = ctx.RunAttestors()
	// Will succeed with no commits (empty repo, no HEAD)
	require.NoError(t, err)

	t.Log("NOTE: DetectDotGit: true walks up the directory tree. " +
		"If workingDir is in a subdirectory, the attestor uses the PARENT repository. " +
		"An attacker who can place a .git directory higher in the path can " +
		"control what repository the attestor sees.")
}

// =============================================================================
// FINDING 11: PGP signature stored but not verified
// Severity: MEDIUM
//
// The commit's PGP signature is stored in attestor.Signature but is never
// verified. It's included in the attestation as informational data only.
// A downstream consumer might incorrectly assume the signature was verified.
// =============================================================================

func TestAdversarial_PGPSignatureNotVerified(t *testing.T) {
	attestor := New()
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	err = ctx.RunAttestors()
	require.NoError(t, err)

	// Unsigned commits have empty signature
	assert.Empty(t, attestor.Signature,
		"Unsigned commit has empty signature field")

	t.Log("NOTE: The 'signature' field in git attestation stores the raw PGP signature " +
		"from the commit but does NOT verify it. Downstream consumers should not treat " +
		"its presence as proof of authenticity.")
}

// =============================================================================
// FINDING 12: Schema() passes **Attestor to jsonschema.Reflect
// Severity: LOW (correctness)
//
// Schema() calls jsonschema.Reflect(&a) where a is *Attestor (receiver).
// This passes **Attestor, which may generate incorrect schema.
// =============================================================================

func TestAdversarial_SchemaDoublePointer(t *testing.T) {
	a := New()
	schema := a.Schema()
	require.NotNil(t, schema)

	t.Logf("Schema type: %s", schema.Type)
	if schema.Definitions != nil {
		for name := range schema.Definitions {
			t.Logf("Schema definition: %s", name)
		}
	}

	t.Log("NOTE: Schema() passes &a (where a is *Attestor receiver) to jsonschema.Reflect. " +
		"This is **Attestor. Should be jsonschema.Reflect(a) for correct schema generation.")
}

// =============================================================================
// FINDING 13: Empty digest set for empty email
// Severity: LOW
//
// When AuthorEmail or CommitterEmail is empty, CalculateDigestSetFromBytes
// is called with []byte("") which produces a valid SHA256 of empty string.
// This creates a subject with a well-known hash (the SHA256 of "").
// All repos with no author email produce the same subject digest.
// =============================================================================

func TestAdversarial_EmptyEmailDigestCollision(t *testing.T) {
	a1 := &Attestor{
		CommitHash:     "abc",
		AuthorEmail:    "",
		CommitterEmail: "",
	}
	a2 := &Attestor{
		CommitHash:     "def",
		AuthorEmail:    "",
		CommitterEmail: "",
	}

	s1 := a1.Subjects()
	s2 := a2.Subjects()

	// authoremail: subjects should have the same digest (SHA256 of "")
	key := "authoremail:"
	ds1, exists1 := s1[key]
	ds2, exists2 := s2[key]

	assert.True(t, exists1 && exists2)

	// Check that the digests are identical (both SHA256 of empty string)
	for dv, hash1 := range ds1 {
		hash2, ok := ds2[dv]
		if ok {
			assert.Equal(t, hash1, hash2,
				"BUG: Empty author emails produce identical subject digests. "+
					"SHA256('') = %s. This could cause policy collisions between "+
					"unrelated repos.", hash1)
		}
	}
}

// =============================================================================
// Helper: verify commit hash format
// =============================================================================

func TestAdversarial_CommitHashFormat(t *testing.T) {
	attestor := New()
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	err = ctx.RunAttestors()
	require.NoError(t, err)

	// Verify commit hash looks like a valid SHA1 hex string
	assert.Len(t, attestor.CommitHash, 40, "SHA1 hash should be 40 hex chars")
	for _, c := range attestor.CommitHash {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"Commit hash char %c is not valid hex", c)
	}
}

// =============================================================================
// Verify BackRefs returns correct format
// =============================================================================

func TestAdversarial_BackRefsDigestSet(t *testing.T) {
	attestor := &Attestor{
		CommitHash: "abc123def456abc123def456abc123def456abc1",
	}

	refs := attestor.BackRefs()
	require.Len(t, refs, 1)

	key := fmt.Sprintf("commithash:%s", attestor.CommitHash)
	ds, exists := refs[key]
	require.True(t, exists)

	// Verify the digest set has SHA1 with the commit hash
	found := false
	for dv, val := range ds {
		if dv.Hash == crypto.SHA1 && !dv.GitOID {
			found = true
			assert.Equal(t, attestor.CommitHash, val)
		}
	}
	assert.True(t, found, "BackRefs should contain SHA1 digest of commit hash")
}

// Helper to get DigestSet for testing
func digestSetForHash(hash string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{
		{Hash: crypto.SHA1, GitOID: false}: hash,
	}
}
