// Copyright 2024 The Witness Contributors
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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// These tests pin one invariant: the git attestor must never report "I looked
// and found nothing" when the truth is "I could not look". An unborn HEAD is
// the ONLY benign reason to produce an empty attestation, and it must be
// PROVEN — never inferred from an error string or an exit code.

// requireGitBinary skips when git is absent. Every test here must run with git
// PRESENT: the pre-existing broken-HEAD coverage clears PATH and therefore can
// only ever exercise the git-absent path.
func requireGitBinary(t *testing.T) {
	t.Helper()
	if !GitExists() {
		t.Skip("git binary not on PATH; these tests exercise the git-PRESENT path")
	}
}

func runGitOrFail(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...) //nolint:gosec // G204: test-controlled arguments
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v failed: %s", args, out)
	return strings.TrimSpace(string(out))
}

func gitExitCode(t *testing.T, dir string, args ...string) int {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...) //nolint:gosec // G204: test-controlled arguments
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		require.ErrorAsf(t, err, &exitErr, "git %v failed without an exit status", args)
		return exitErr.ExitCode()
	}
	return 0
}

// initRepoWithBinary creates a real repository with the real git binary,
// exactly as the defect was measured.
func initRepoWithBinary(t *testing.T, withCommit bool) (dir, branchRef, commitSHA string) {
	t.Helper()
	dir = t.TempDir()
	runGitOrFail(t, dir, "init")
	if !withCommit {
		return dir, "", ""
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("contents\n"), 0o600))
	runGitOrFail(t, dir, "add", "file.txt")
	runGitOrFail(t, dir,
		"-c", "user.name=Fail Closed",
		"-c", "user.email=fail-closed@example.com",
		"-c", "commit.gpgsign=false",
		"commit", "-m", "initial commit")

	branchRef = runGitOrFail(t, dir, "symbolic-ref", "HEAD")
	commitSHA = runGitOrFail(t, dir, "rev-parse", "HEAD")
	return dir, branchRef, commitSHA
}

// TestAttestRefusesDanglingHead is the regression test for the silent-success
// path. A repository whose .git/HEAD names a branch that does not exist STILL
// HAS its refs and its objects: the attestor cannot see the commit, but the
// commit is there. Reporting success with every field zero-valued is a lie.
//
// The measurement this encodes: `git rev-parse --verify --quiet HEAD` exits 1
// here, exactly as it does for a genuinely unborn repository. Exit code 1 —
// and, equivalently, go-git's "reference not found" — is therefore NOT proof
// of an unborn HEAD, and must never be treated as such.
func TestAttestRefusesDanglingHead(t *testing.T) {
	requireGitBinary(t)

	dir, branchRef, commitSHA := initRepoWithBinary(t, true)

	// Break only HEAD. Nothing else about the repository changes.
	headPath := filepath.Join(dir, ".git", "HEAD")
	require.NoError(t, os.WriteFile(headPath, []byte("ref: refs/heads/does-not-exist\n"), 0o600))

	// The ambiguous signal: identical to a genuinely unborn repository.
	require.Equal(t, 1, gitExitCode(t, dir, "rev-parse", "--verify", "--quiet", "HEAD"),
		"git reports a dangling HEAD with the same exit code as an unborn HEAD")

	// The discriminator: this repository has refs AND objects, so it is not unborn.
	require.NotEmpty(t, runGitOrFail(t, dir, "for-each-ref"),
		"the dangling-HEAD repository must still have refs")
	require.Equal(t, commitSHA, runGitOrFail(t, dir, "rev-parse", branchRef),
		"the original branch ref must still resolve to the commit")
	require.Equal(t, 0, gitExitCode(t, dir, "cat-file", "-e", commitSHA),
		"the commit object must still be present")

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(dir))
	require.NoError(t, err)

	err = attestor.Attest(ctx)
	require.Error(t, err,
		"a dangling HEAD is 'I could not look', not 'I looked and found nothing'")
	require.Contains(t, err.Error(), "refusing to attest",
		"the refusal must use the file's own refusal phrasing")
	require.Empty(t, attestor.CommitHash, "no commit may be recorded when HEAD is unresolvable")
	require.Empty(t, attestor.Subjects(), "a refused attestation must contribute no subjects")
}

// TestAttestRefusesDanglingHeadWithPackedRefs is the same defect with the refs
// packed instead of loose. Refusal must not depend on where git happens to
// store a ref, so the surviving branch has to be found in packed-refs too.
func TestAttestRefusesDanglingHeadWithPackedRefs(t *testing.T) {
	requireGitBinary(t)

	dir, branchRef, _ := initRepoWithBinary(t, true)
	runGitOrFail(t, dir, "pack-refs", "--all")
	require.NoFileExists(t, filepath.Join(dir, ".git", branchRef),
		"pack-refs should have removed the loose ref")

	headPath := filepath.Join(dir, ".git", "HEAD")
	require.NoError(t, os.WriteFile(headPath, []byte("ref: refs/heads/does-not-exist\n"), 0o600))

	require.Equal(t, 1, gitExitCode(t, dir, "rev-parse", "--verify", "--quiet", "HEAD"))
	require.NotEmpty(t, runGitOrFail(t, dir, "for-each-ref"),
		"the packed branch ref must still be discoverable")

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(dir))
	require.NoError(t, err)

	err = attestor.Attest(ctx)
	require.Error(t, err, "a packed surviving ref is still a surviving ref")
	require.Contains(t, err.Error(), "refusing to attest")
}

// TestAttestRefusesUnresolvableHeadWithNoRefs exercises the OTHER half of the
// discriminator. Deleting every ref makes the repository look unborn by refs
// alone, but the commit object is still sitting in the object store: the
// history exists and this attestor simply cannot reach it. Refs alone are
// therefore not a sufficient test, and the object store has to be consulted.
func TestAttestRefusesUnresolvableHeadWithNoRefs(t *testing.T) {
	requireGitBinary(t)

	dir, _, commitSHA := initRepoWithBinary(t, true)

	require.NoError(t, os.RemoveAll(filepath.Join(dir, ".git", "refs", "heads")))
	require.NoError(t, os.RemoveAll(filepath.Join(dir, ".git", "packed-refs")))
	headPath := filepath.Join(dir, ".git", "HEAD")
	require.NoError(t, os.WriteFile(headPath, []byte("ref: refs/heads/does-not-exist\n"), 0o600))

	// Indistinguishable from an unborn repository by refs alone...
	require.Empty(t, runGitOrFail(t, dir, "for-each-ref"),
		"every ref was removed, so the refs check alone cannot tell this apart from unborn")
	require.Equal(t, 1, gitExitCode(t, dir, "rev-parse", "--verify", "--quiet", "HEAD"))

	// ...but the commit is still there.
	require.Equal(t, 0, gitExitCode(t, dir, "cat-file", "-e", commitSHA),
		"the commit object must still be present")

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(dir))
	require.NoError(t, err)

	err = attestor.Attest(ctx)
	require.Error(t, err,
		"a repository still holding commit objects is not unborn, whatever its refs say")
	require.Contains(t, err.Error(), "refusing to attest")
}

// TestAttestAcceptsProvablyUnbornHead is the other half of the discriminator:
// a repository with no refs and no objects is genuinely unborn, and remains
// the one benign case that produces an empty attestation without an error.
func TestAttestAcceptsProvablyUnbornHead(t *testing.T) {
	requireGitBinary(t)

	dir, _, _ := initRepoWithBinary(t, false)

	// Same ambiguous signal as the dangling-HEAD case above.
	require.Equal(t, 1, gitExitCode(t, dir, "rev-parse", "--verify", "--quiet", "HEAD"),
		"an unborn HEAD also exits 1")

	// The discriminator: no refs, and no objects.
	require.Empty(t, runGitOrFail(t, dir, "for-each-ref"),
		"a genuinely unborn repository has no refs")
	require.Contains(t, runGitOrFail(t, dir, "count-objects", "-v"), "count: 0",
		"a genuinely unborn repository has no loose objects")

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(dir))
	require.NoError(t, err)

	require.NoError(t, attestor.Attest(ctx),
		"a provably unborn repository is the one benign empty attestation")
	require.Empty(t, attestor.CommitHash)
	require.Empty(t, attestor.Subjects(),
		"an unborn repository must contribute no subjects")
}

// TestSubjectsOmitEmptyComponents pins the subject guard. commithash and
// parenthash are already skipped when empty; authoremail, committeremail,
// refnameshort and remote were emitted unconditionally, producing subjects
// literally named "authoremail:" carrying SHA256("") — a digest identical
// across every repository, and therefore a cross-repository policy collision.
func TestSubjectsOmitEmptyComponents(t *testing.T) {
	// The exact shape produced by the old silent-success path: every field
	// zero-valued. Measured on a linked worktree it emitted 5 subjects, 3 of
	// them empty, and no commithash. It must now emit none.
	require.Empty(t, (&Attestor{}).Subjects(),
		"an attestor that observed nothing must contribute no subjects")

	commit := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	attestor := &Attestor{
		CommitHash:     commit,
		AuthorEmail:    "",
		CommitterEmail: "committer@example.com",
		RefNameShort:   "",
		ParentHashes:   []string{""},
		Remotes:        []string{"", "https://example.com/org/repo.git"},
	}

	subjects := attestor.Subjects()
	for name := range subjects {
		require.False(t, strings.HasSuffix(name, ":"),
			"subject %q carries an empty value and therefore a universal digest", name)
	}

	require.NotContains(t, subjects, "authoremail:")
	require.NotContains(t, subjects, "refnameshort:")
	require.NotContains(t, subjects, "remote:")
	require.NotContains(t, subjects, "parenthash:")

	require.Contains(t, subjects, "commithash:"+commit)
	require.Contains(t, subjects, "committeremail:committer@example.com")
	require.Contains(t, subjects, "remote:https://example.com/org/repo.git")
	require.Len(t, subjects, 3, "only the three non-empty components may be emitted")
}
