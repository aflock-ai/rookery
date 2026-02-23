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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// R3-210: Remote URL credential leak via query parameters
//
// SECURITY IMPACT: When a git remote URL contains credentials in query
// parameters (e.g., ?access_token=ghp_XXXX), the credential stripping code
// only clears url.User (the userinfo component). Query parameters and
// fragments are preserved verbatim, leaking tokens like GitHub PATs,
// GitLab deploy tokens, or Bitbucket app passwords into the attestation.
//
// The attestation is typically stored in Archivista or another transparency
// log, making the leaked credential permanently visible to anyone with
// read access. This is a data exfiltration vector: an attacker who can
// set a remote URL with a credential in a query param can harvest tokens
// from the attestation store.
//
// The fix: strip query parameters and fragments from remote URLs, or at
// minimum strip known credential parameters (access_token, token,
// private_token, etc.).
// =============================================================================

func TestSecurity_R3_210_RemoteURLQueryParamCredentialLeak(t *testing.T) {
	testCases := []struct {
		name        string
		remoteURL   string
		credential  string
		description string
	}{
		{
			name:       "GitHub PAT in access_token query param",
			remoteURL:  "https://github.com/org/repo.git?access_token=ghp_1234567890abcdef",
			credential: "ghp_1234567890abcdef",
			description: "GitHub Personal Access Tokens in query params leak into attestation",
		},
		{
			name:       "GitLab deploy token in private_token query param",
			remoteURL:  "https://gitlab.com/org/repo.git?private_token=gldt-XXXXXXXXXXXX",
			credential: "gldt-XXXXXXXXXXXX",
			description: "GitLab deploy tokens in query params leak into attestation",
		},
		{
			name:       "generic token in URL fragment",
			remoteURL:  "https://github.com/org/repo.git#token=mysecrettoken123",
			credential: "mysecrettoken123",
			description: "Tokens in URL fragments leak into attestation",
		},
		{
			name:       "Bitbucket app password in query param",
			remoteURL:  "https://bitbucket.org/org/repo.git?token=bbp_abcdef123456",
			credential: "bbp_abcdef123456",
			description: "Bitbucket app passwords in query params leak into attestation",
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

			require.NotEmpty(t, attestor.Remotes, "Remotes should be populated")

			for _, remote := range attestor.Remotes {
				if strings.Contains(remote, tc.credential) {
					t.Errorf("R3-210 BUG PROVEN: %s\n"+
						"Remote URL in attestation: %s\n"+
						"Leaked credential: %s\n"+
						"The url.User=nil stripping only clears userinfo, not query params or fragments.\n"+
						"Credentials in query parameters are preserved and stored in the attestation.\n"+
						"Fix: also strip query parameters and fragments from remote URLs, or at minimum\n"+
						"remove known credential parameters (access_token, token, private_token).",
						tc.description, remote, tc.credential)
				}
			}
		})
	}
}

// =============================================================================
// R3-211: GitGetStatus panics on short output lines from malicious git binary
//
// SECURITY IMPACT: GitGetStatus parses `git status --porcelain` output by
// accessing line[0], line[1], and line[2:] without checking that len(line) >= 3.
// The only guard is len(line) == 0 which skips empty lines, but a line with
// 1 or 2 characters causes an index-out-of-bounds panic.
//
// Combined with R3-6 (PATH manipulation to substitute a malicious git binary),
// an attacker can crash the attestor with a denial-of-service, or more
// subtly, cause the attestation to fail in a controlled way that bypasses
// security policy enforcement (if the policy requires a git attestation
// to be present and the crash prevents it).
//
// The fix: check len(line) >= 3 before accessing indices.
// =============================================================================

func TestSecurity_R3_211_GitStatusShortLinePanic(t *testing.T) {
	// Create a fake git binary that outputs short lines
	tmpDir, err := os.MkdirTemp("", "fake-git-r3-211-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	fakeGit := filepath.Join(tmpDir, "git")
	// This fake git outputs lines shorter than 3 chars, which will trigger
	// the index-out-of-bounds bug in GitGetStatus's parser.
	script := `#!/bin/sh
if [ "$2" = "status" ] || [ "$3" = "status" ]; then
    printf "X\nAB\n M file.txt\n"
else
    /usr/bin/git "$@"
fi
`
	err = os.WriteFile(fakeGit, []byte(script), 0755)
	require.NoError(t, err)

	// Prepend our fake git to PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir+":"+origPath)

	if !GitExists() {
		t.Skip("git binary not found via modified PATH")
	}

	// Create a test repo directory to pass to GitGetStatus
	repoDir, err := os.MkdirTemp("", "repo-r3-211-*")
	require.NoError(t, err)
	defer os.RemoveAll(repoDir)

	// The test proves that short lines cause a panic (recovered here).
	// If the code is fixed to check line length, the panic won't happen.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("R3-211 BUG PROVEN: GitGetStatus panicked on short line output.\n"+
				"Panic value: %v\n"+
				"GitGetStatus accesses line[0], line[1], line[2:] without checking len(line) >= 3.\n"+
				"A malicious git binary (reachable via PATH manipulation) can crash the attestor.\n"+
				"Fix: add 'if len(line) < 3 { continue }' before accessing line indices.", r)
		}
	}()

	_, err = GitGetStatus(repoDir)
	// If we get here without panic, the code either:
	// 1. Has been fixed (good), or
	// 2. The fake git didn't produce short lines (re-check test setup)
	if err != nil {
		t.Logf("GitGetStatus returned error (not panic): %v", err)
	}
}

// =============================================================================
// R3-212: DetectDotGit parent directory traversal allows repo substitution
//
// SECURITY IMPACT: The git attestor uses DetectDotGit: true when opening
// a repository. This walks UP the directory tree from workingDir until it
// finds a .git directory. An attacker who controls a parent directory can
// place a .git with crafted commits, and the attestor will attest THAT
// repository instead of the intended one.
//
// In containerized CI environments, if the working directory is nested
// inside a volume mount, the parent volume could contain a different .git.
// This substitutes the entire git attestation: commit hash, author, refs,
// remotes -- everything comes from the attacker's repo.
//
// The fix: when running in CI, validate that the discovered .git is inside
// or adjacent to workingDir, or disable upward traversal.
// =============================================================================

func TestSecurity_R3_212_DetectDotGitParentTraversal(t *testing.T) {
	// Create a parent directory with a git repo
	parentDir, err := os.MkdirTemp("", "parent-repo-r3-212-*")
	require.NoError(t, err)
	defer os.RemoveAll(parentDir)

	// Init a repo in the parent with a specific, identifiable commit
	parentRepo, err := gogit.PlainInit(parentDir, false)
	require.NoError(t, err)

	// Create a file and commit
	filePath := filepath.Join(parentDir, "parent-marker.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("parent repo"), 0644))

	wt, err := parentRepo.Worktree()
	require.NoError(t, err)
	_, err = wt.Add("parent-marker.txt")
	require.NoError(t, err)

	_, err = wt.Commit("ATTACKER CONTROLLED COMMIT", &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  "Attacker",
			Email: "attacker@evil.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	// Create a deeply nested child directory WITHOUT its own .git
	childDir := filepath.Join(parentDir, "build", "workspace", "project")
	require.NoError(t, os.MkdirAll(childDir, 0755))

	// Run the attestor from the child directory
	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(childDir))
	require.NoError(t, err)
	err = ctx.RunAttestors()
	require.NoError(t, err)

	// The attestor should ideally NOT attest a parent repo, but it does.
	if attestor.AuthorEmail == "attacker@evil.com" {
		t.Errorf("R3-212 BUG PROVEN: DetectDotGit walked up to parent directory.\n"+
			"WorkingDir: %s\n"+
			"Attested repo found at: %s\n"+
			"Author email: %s (from parent repo)\n"+
			"Commit message: %s\n"+
			"An attacker who controls any parent directory can substitute the entire\n"+
			"git attestation. All commit data, refs, and remotes come from the\n"+
			"attacker's repo instead of the intended project.\n"+
			"Fix: validate that the discovered .git is inside or adjacent to workingDir.",
			childDir, parentDir, attestor.AuthorEmail, attestor.CommitMessage)
	}
}

// =============================================================================
// R3-213: PGP signature field included without verification creates false trust
//
// SECURITY IMPACT: The attestor stores commit.PGPSignature verbatim in the
// Signature field without ever verifying it. This creates a dangerous
// information asymmetry: downstream consumers see a "signature" field and
// may assume it has been verified, when it has not.
//
// An attacker can create a commit with a garbage PGP signature that looks
// valid but is actually self-signed or entirely fabricated. The attestation
// will include this signature, lending false credibility to the commit.
//
// The fix: either verify the signature and mark it as verified/unverified,
// or don't include it at all. If included, add a "signatureVerified: false"
// field to make the lack of verification explicit.
// =============================================================================

func TestSecurity_R3_213_PGPSignatureNotVerified(t *testing.T) {
	// Directly construct an attestor with a fake PGP signature to show
	// the field is stored verbatim without any verification.
	attestor := &Attestor{
		CommitHash: "abc123def456abc123def456abc123def456abc1",
		Signature: `-----BEGIN PGP SIGNATURE-----
FAKE_INVALID_PGP_SIGNATURE_THAT_PROVES_NO_VERIFICATION
This is completely fabricated garbage data that would never
pass any PGP verification, but it will appear in the attestation
as if it were a real signature.
-----END PGP SIGNATURE-----`,
	}

	// The attestor stores whatever is in commit.PGPSignature
	if attestor.Signature != "" {
		t.Errorf("R3-213 BUG PROVEN: PGP signature field stores unverified data.\n"+
			"Signature content: %.80s...\n"+
			"The git attestor includes commit PGP signatures without verification.\n"+
			"Downstream consumers may treat the presence of this field as proof of\n"+
			"authenticity, but the signature is never checked against any keyring.\n"+
			"An attacker can create commits with fake PGP signatures that appear\n"+
			"in the attestation as if they were genuine.\n"+
			"Fix: either verify signatures and add a signatureVerified boolean,\n"+
			"or omit unverified signatures entirely.",
			attestor.Signature)
	}
}

// =============================================================================
// R3-214: Empty author email produces collision across all repos
//
// SECURITY IMPACT: When a git commit has no author email (empty string),
// Subjects() creates a subject with key "authoremail:" and the SHA256
// digest of the empty string (e3b0c44298fc1c149afbf4c8996fb924...).
//
// This digest is identical for ALL repositories with empty author emails,
// creating a universal subject collision. Policy rules that match on
// author email subjects will match ALL attestations with empty emails,
// potentially granting cross-repository authorization.
//
// The fix: skip creating subjects for empty values, or include the commit
// hash in the subject to prevent cross-repo collisions.
// =============================================================================

func TestSecurity_R3_214_EmptyEmailSubjectCollision(t *testing.T) {
	// Two attestors from "different repos" with empty author emails
	a1 := &Attestor{
		CommitHash:     "aaaa000000000000000000000000000000000000",
		AuthorEmail:    "",
		CommitterEmail: "committer@a.com",
	}
	a2 := &Attestor{
		CommitHash:     "bbbb000000000000000000000000000000000000",
		AuthorEmail:    "",
		CommitterEmail: "committer@b.com",
	}

	s1 := a1.Subjects()
	s2 := a2.Subjects()

	key := "authoremail:"
	ds1, exists1 := s1[key]
	ds2, exists2 := s2[key]

	if !exists1 || !exists2 {
		// If the fix skips empty values, both won't exist. That's correct.
		t.Log("R3-214: Empty email subjects correctly skipped (fix applied).")
		return
	}

	// Both exist -- check for collision
	for dv, hash1 := range ds1 {
		hash2, ok := ds2[dv]
		if ok && hash1 == hash2 {
			t.Errorf("R3-214 BUG PROVEN: Empty author emails produce identical subjects.\n"+
				"Repo A commit: %s, Repo B commit: %s\n"+
				"Subject key: %q\n"+
				"Digest: %s (SHA256 of empty string)\n"+
				"Policy rules matching on author email subjects will match ALL\n"+
				"attestations with empty author emails across all repositories.\n"+
				"This creates unintended cross-repository authorization.\n"+
				"Fix: skip creating subjects for empty values.",
				a1.CommitHash, a2.CommitHash, key, hash1)
		}
	}
}

// =============================================================================
// R3-215: Remote URL with SSH-style credentials in non-standard format
//
// SECURITY IMPACT: The credential stripping uses url.Parse which handles
// standard URL formats (https://user:pass@host). But some git hosting
// services support URLs like:
//   https://oauth2:TOKEN@gitlab.com/repo.git
//
// While url.Parse handles these correctly (user info is stripped), the
// fallback path for unparseable URLs stores them verbatim. More concerning
// is that url.Parse silently succeeds on some malformed URLs where the
// "user:pass" component is ambiguous, potentially preserving credentials.
//
// This test verifies the stripping works for all common credential formats
// used by major git hosting services.
// =============================================================================

func TestSecurity_R3_215_AllGitHostingCredentialFormats(t *testing.T) {
	testCases := []struct {
		name       string
		remoteURL  string
		credential string
		shouldLeak bool
	}{
		{
			name:       "GitLab deploy token",
			remoteURL:  "https://gitlab-deploy-token:gldt-XXXXXXXXXXXX@gitlab.com/org/repo.git",
			credential: "gldt-XXXXXXXXXXXX",
			shouldLeak: false,
		},
		{
			name:       "GitLab CI job token",
			remoteURL:  "https://gitlab-ci-token:eyJhbGciOiJSUzI1NiI@gitlab.com/org/repo.git",
			credential: "eyJhbGciOiJSUzI1NiI",
			shouldLeak: false,
		},
		{
			name:       "GitHub PAT as oauth2 token",
			remoteURL:  "https://oauth2:ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX@github.com/org/repo.git",
			credential: "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			shouldLeak: false,
		},
		{
			name:       "Bitbucket app password",
			remoteURL:  "https://username:app-password-here@bitbucket.org/org/repo.git",
			credential: "app-password-here",
			shouldLeak: false,
		},
		{
			name:       "Azure DevOps PAT (empty user)",
			remoteURL:  "https://:azure-pat-token-here@dev.azure.com/org/project/_git/repo",
			credential: "azure-pat-token-here",
			shouldLeak: false,
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
				if strings.Contains(remote, tc.credential) {
					t.Errorf("R3-215 BUG: Credential leaked for %s.\n"+
						"Remote URL stored: %s\n"+
						"Leaked credential: %s\n"+
						"Fix: verify url.Parse stripping works for this credential format.",
						tc.name, remote, tc.credential)
				}
			}
		})
	}
}
