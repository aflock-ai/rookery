// jade:ring local
// Copyright 2026 TestifySec, Inc.
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

package baseancestry

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

// The fixtures here go through the git binary rather than the go-git fixtures
// the other tests use: the point is the on-disk layout git produces (a
// lowercase extensions.worktreeconfig key, a linked worktree's `.git` file and
// commondir, a config.worktree), which is what go-git v5.19.2 refuses to open.

func requireGitOnPath(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH; these tests exercise git-written repository layouts")
	}
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...) //nolint:gosec // G204: test-controlled arguments
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v failed: %s", args, out)
	return strings.TrimSpace(string(out))
}

func gitRepoWithCommit(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "main")
	require.NoError(t, os.Mkdir(dir, 0o755))
	gitRun(t, dir, "init")
	gitRun(t, dir, "config", "user.email", "t@example.test")
	gitRun(t, dir, "config", "user.name", "t")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hi\n"), 0o644))
	gitRun(t, dir, "add", "f.txt")
	gitRun(t, dir, "-c", "commit.gpgsign=false", "commit", "-m", "c1")
	return dir, gitRun(t, dir, "rev-parse", "HEAD")
}

// Twin of TestOpenRepositoryToleratesWorktreeConfigExtension in
// plugins/attestors/git; see openRepository for why the helper is duplicated.
func TestOpenRepositoryToleratesWorktreeConfigExtension(t *testing.T) {
	requireGitOnPath(t)
	dir, sha := gitRepoWithCommit(t)
	gitRun(t, dir, "config", "extensions.worktreeconfig", "true")

	_, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true})
	require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion,
		"go-git v5.19.2 refuses extensions.worktreeconfig at format version 0; if this passes, upstream fixed the case bug and openRepository's fallback can go")

	repo, err := openRepository(dir)
	require.NoError(t, err, "openRepository must tolerate the worktreeConfig extension")
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())

	cfg, err := repo.Config()
	require.NoError(t, err)
	require.Error(t, repo.Storer.SetConfig(cfg), "the extension-tolerant storer must refuse to write config back")
	require.Equal(t, "true", gitRun(t, dir, "config", "--get", "extensions.worktreeconfig"),
		"opening must never rewrite the repository's config")
}

func TestOpenRepositoryLinkedWorktreeResolvesThroughCommonDir(t *testing.T) {
	requireGitOnPath(t)
	dir, sha := gitRepoWithCommit(t)
	gitRun(t, dir, "remote", "add", "origin", "https://example.test/org/repo.git")
	gitRun(t, dir, "config", "extensions.worktreeconfig", "true")
	wt := filepath.Join(filepath.Dir(dir), "wt")
	gitRun(t, dir, "worktree", "add", wt, "-b", "linked-branch")

	repo, err := openRepository(wt)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())
	require.Equal(t, "linked-branch", head.Name().Short())
	remotes, err := repo.Remotes()
	require.NoError(t, err)
	require.Len(t, remotes, 1, "remotes live in the common dir and must be visible")
	require.Equal(t, "origin", remotes[0].Config().Name)
}

func TestOpenRepositoryStillRefusesUnknownExtensions(t *testing.T) {
	requireGitOnPath(t)
	for _, alsoWorktree := range []bool{false, true} {
		dir, _ := gitRepoWithCommit(t)
		gitRun(t, dir, "config", "extensions.frobnicate", "true")
		if alsoWorktree {
			gitRun(t, dir, "config", "extensions.worktreeconfig", "true")
		}
		_, err := openRepository(dir)
		require.Error(t, err, "an unknown extension must still refuse (worktreeConfig alongside: %v)", alsoWorktree)
		require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion)
		require.Contains(t, err.Error(), "frobnicate")
		require.NotContains(t, err.Error(), "worktreeconfig")
	}
}

// TestAttestWorksInsideRepositoryWithWorktreeConfig closes the loop on the
// attestor itself: Attest must observe HEAD through openRepository rather than
// fail at the open, which is what produced an envelope with no git subject.
func TestAttestWorksInsideRepositoryWithWorktreeConfig(t *testing.T) {
	requireGitOnPath(t)
	dir, sha := gitRepoWithCommit(t)
	gitRun(t, dir, "config", "extensions.worktreeconfig", "true")

	a := attest(t, dir)
	require.Equal(t, sha, a.Head)
}

// linkedOnlyOriginURL: an origin that exists in exactly one linked worktree's
// config.worktree and nowhere in the shared config (the shape the independent
// review of judge#9038 reproduced with real git).
const linkedOnlyOriginURL = "https://example.invalid/linked-only.git"

// worktreeConfigFixture: the linked-only origin, and a single-valued core key
// overriding the shared value.
const worktreeConfigFixture = "[remote \"origin\"]\n\turl = " + linkedOnlyOriginURL + "\n[core]\n\tsparseCheckout = true\n"

func linkedWorktreeWithConfig(t *testing.T, worktreeConfig string) (string, string, string) {
	t.Helper()
	dir, sha := gitRepoWithCommit(t)
	gitRun(t, dir, "config", "core.sparseCheckout", "false")
	gitRun(t, dir, "config", "extensions.worktreeconfig", "true")
	wt := filepath.Join(filepath.Dir(dir), "wt")
	gitRun(t, dir, "worktree", "add", wt, "-b", "linked-branch")
	gitdir := gitRun(t, wt, "rev-parse", "--absolute-git-dir")
	require.NoError(t, os.WriteFile(filepath.Join(gitdir, "config.worktree"), []byte(worktreeConfig), 0o644))
	return dir, wt, sha
}

// Twin of TestOpenRepositoryMergesWorktreeConfig in plugins/attestors/git.
func TestOpenRepositoryMergesWorktreeConfig(t *testing.T) {
	requireGitOnPath(t)
	dir, wt, sha := linkedWorktreeWithConfig(t, worktreeConfigFixture)

	require.Equal(t, linkedOnlyOriginURL, gitRun(t, wt, "remote", "get-url", "origin"))
	require.Equal(t, "true", gitRun(t, wt, "config", "--get", "core.sparseCheckout"))
	require.Empty(t, gitRun(t, dir, "remote"))

	repo, err := openRepository(wt)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())
	remotes, err := repo.Remotes()
	require.NoError(t, err)
	require.Len(t, remotes, 1, "an origin defined only in config.worktree is part of git's effective configuration")
	require.Equal(t, "origin", remotes[0].Config().Name)
	require.Equal(t, []string{linkedOnlyOriginURL}, remotes[0].Config().URLs)
	cfg, err := repo.Config()
	require.NoError(t, err)
	require.Equal(t, "true", cfg.Raw.Section("core").Option("sparseCheckout"))

	main, err := openRepository(dir)
	require.NoError(t, err)
	mainRemotes, err := main.Remotes()
	require.NoError(t, err)
	require.Empty(t, mainRemotes, "the main checkout must not see a remote from another worktree's config.worktree")
	mainCfg, err := main.Config()
	require.NoError(t, err)
	require.Equal(t, "false", mainCfg.Raw.Section("core").Option("sparseCheckout"))
}

// Twin of TestOpenRepositoryRefusesUnknownExtensionInWorktreeConfig.
func TestOpenRepositoryRefusesUnknownExtensionInWorktreeConfig(t *testing.T) {
	requireGitOnPath(t)
	_, wt, _ := linkedWorktreeWithConfig(t, "[extensions]\n\tfrobnicate = true\n")

	_, err := openRepository(wt)
	require.Error(t, err, "an unknown extension in config.worktree must still refuse")
	require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion)
	require.Contains(t, err.Error(), "frobnicate")
	require.NotContains(t, err.Error(), "worktreeconfig")
}

// TestAttestSeesWorktreeOnlyRemote closes the loop on the attestor: the
// origin that exists only in the worktree's config.worktree must be the
// remote Attest records, because that is the repository identity git itself
// reports there.
func TestAttestSeesWorktreeOnlyRemote(t *testing.T) {
	requireGitOnPath(t)
	_, wt, sha := linkedWorktreeWithConfig(t, worktreeConfigFixture)

	a := attest(t, wt)
	require.Equal(t, sha, a.Head)
	require.Equal(t, []string{linkedOnlyOriginURL}, a.Remotes)
}

// Twin of TestOpenRepositoryExpandsTildeLikeGoGit.
func TestOpenRepositoryExpandsTildeLikeGoGit(t *testing.T) {
	requireGitOnPath(t)
	dir, sha := gitRepoWithCommit(t)
	gitRun(t, dir, "config", "extensions.worktreeconfig", "true")
	t.Setenv("HOME", filepath.Dir(dir))

	repo, err := openRepository("~/" + filepath.Base(dir))
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String(), "~ must expand to HOME, not resolve relative to the working directory")
}

// gitExitCode runs git and returns its exit code, for positive controls that
// expect git to answer "no".
func gitExitCode(t *testing.T, dir string, args ...string) int {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...) //nolint:gosec // G204: test-controlled arguments
	_ = cmd.Run()
	return cmd.ProcessState.ExitCode()
}

// Twin of TestOpenRepositoryIgnoresWorktreeConfigWhenExtensionIsFalse.
func TestOpenRepositoryIgnoresWorktreeConfigWhenExtensionIsFalse(t *testing.T) {
	requireGitOnPath(t)
	dir, wt, sha := linkedWorktreeWithConfig(t, worktreeConfigFixture)
	gitRun(t, dir, "config", "extensions.worktreeconfig", "false")

	require.Empty(t, gitRun(t, wt, "remote"))
	require.Equal(t, "false", gitRun(t, wt, "config", "--get", "core.sparseCheckout"))
	_, err := git.PlainOpenWithOptions(wt, &git.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true})
	require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion)

	repo, err := openRepository(wt)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())
	remotes, err := repo.Remotes()
	require.NoError(t, err)
	require.Empty(t, remotes, "config.worktree must not be merged when extensions.worktreeconfig is false")
	cfg, err := repo.Config()
	require.NoError(t, err)
	require.Equal(t, "false", cfg.Raw.Section("core").Option("sparseCheckout"))

	// The attestor records what git reports: no remote.
	a := attest(t, wt)
	require.Equal(t, sha, a.Head)
	require.Empty(t, a.Remotes)
}

// bareKey marks the table row whose extension key is written with no value
// (`worktreeConfig` on a line of its own), which git reads as true; git
// config cannot write that form, so the row appends the text itself.
const bareKey = "<bare key, no value>"

func appendToConfig(t *testing.T, dir, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(text)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// Twin of TestOpenRepositoryWorktreeConfigBooleanValues.
func TestOpenRepositoryWorktreeConfigBooleanValues(t *testing.T) {
	requireGitOnPath(t)
	for _, tc := range []struct {
		value string
		want  string // "merged", "skipped" or "refused"
	}{
		{value: "true", want: "merged"},
		{value: "yes", want: "merged"},
		{value: "on", want: "merged"},
		{value: "1", want: "merged"},
		{value: "TRUE", want: "merged"},
		{value: bareKey, want: "merged"},
		{value: "false", want: "skipped"},
		{value: "no", want: "skipped"},
		{value: "off", want: "skipped"},
		{value: "0", want: "skipped"},
		{value: "", want: "skipped"},
		{value: "maybe", want: "refused"},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			dir, sha := gitRepoWithCommit(t)
			if tc.value == bareKey {
				appendToConfig(t, dir, "[extensions]\n\tworktreeConfig\n")
				require.Equal(t, "true", gitRun(t, dir, "config", "--type=bool", "extensions.worktreeconfig"),
					"positive control: git reads a bare key as true")
			} else {
				gitRun(t, dir, "config", "extensions.worktreeconfig", tc.value)
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "config.worktree"), []byte(worktreeConfigFixture), 0o644))

			repo, err := openRepository(dir)
			if tc.want == "refused" {
				require.Error(t, err)
				require.Contains(t, err.Error(), "extensions.worktreeConfig")
				return
			}
			require.NoError(t, err)
			head, err := repo.Head()
			require.NoError(t, err)
			require.Equal(t, sha, head.Hash().String())
			remotes, err := repo.Remotes()
			require.NoError(t, err)
			if tc.want == "merged" {
				require.Equal(t, linkedOnlyOriginURL, gitRun(t, dir, "remote", "get-url", "origin"), "positive control: git honours config.worktree")
				require.Len(t, remotes, 1)
				require.Equal(t, []string{linkedOnlyOriginURL}, remotes[0].Config().URLs)
				return
			}
			require.NotZero(t, gitExitCode(t, dir, "remote", "get-url", "origin"), "positive control: git ignores config.worktree")
			require.Empty(t, remotes)
		})
	}
}

// Twin of TestOpenRepositoryAcceptsFilePathLikeGoGit.
func TestOpenRepositoryAcceptsFilePathLikeGoGit(t *testing.T) {
	requireGitOnPath(t)
	dir, sha := gitRepoWithCommit(t)
	gitRun(t, dir, "config", "extensions.worktreeconfig", "true")

	repo, err := openRepository(filepath.Join(dir, "f.txt"))
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())
}
