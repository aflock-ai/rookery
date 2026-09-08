// jade:ring local
// Copyright 2026 The Aflock Authors
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
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

// initRepoWithCommit creates a repository with one commit and returns its
// directory and HEAD sha. Everything goes through the git binary so the
// on-disk layout (and the lowercase config keys git writes) is git's, not
// go-git's.
func initRepoWithCommit(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "main")
	require.NoError(t, os.Mkdir(dir, 0o755))
	runGitOrFail(t, dir, "init")
	runGitOrFail(t, dir, "config", "user.email", "t@example.test")
	runGitOrFail(t, dir, "config", "user.name", "t")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hi\n"), 0o644))
	runGitOrFail(t, dir, "add", "f.txt")
	runGitOrFail(t, dir, "-c", "commit.gpgsign=false", "commit", "-m", "c1")
	return dir, runGitOrFail(t, dir, "rev-parse", "HEAD")
}

// TestOpenRepositoryToleratesWorktreeConfigExtension documents the upstream
// go-git bug and pins the fallback. git enables extensions.worktreeConfig
// itself (a sparse checkout in a linked worktree does it), writes the key
// lowercase, and every worktree of that repository then fails to open in
// go-git v5.19.2: verifyExtensions lowercases the keys it reads but its v0
// allowlist is spelled "worktreeConfig", so the allowlisted extension can
// never match. The first assertion is the bug; if it ever fails, upstream
// fixed it and the fallback can be retired.
func TestOpenRepositoryToleratesWorktreeConfigExtension(t *testing.T) {
	requireGitBinary(t)
	dir, sha := initRepoWithCommit(t)
	runGitOrFail(t, dir, "config", "extensions.worktreeconfig", "true")

	_, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true})
	require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion,
		"go-git v5.19.2 refuses extensions.worktreeconfig at format version 0; if this passes, upstream fixed the case bug and OpenRepository's fallback can go")

	repo, err := OpenRepository(dir)
	require.NoError(t, err, "OpenRepository must tolerate the worktreeConfig extension")
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())

	// The tolerance is read-side only. The storer refuses to write config, and
	// the on-disk config still carries the extension git put there.
	cfg, err := repo.Config()
	require.NoError(t, err)
	require.Error(t, repo.Storer.SetConfig(cfg), "the extension-tolerant storer must refuse to write config back")
	require.Equal(t, "true", runGitOrFail(t, dir, "config", "--get", "extensions.worktreeconfig"),
		"opening must never rewrite the repository's config")
}

// TestOpenRepositoryLinkedWorktreeResolvesThroughCommonDir is the shape that
// actually bites: a linked worktree (`.git` is a file naming a gitdir with a
// commondir) of a repository whose config enables worktreeConfig. HEAD's
// branch and the remotes live in the common dir; the fallback must resolve
// both, exactly as PlainOpenWithOptions{EnableDotGitCommonDir: true} does.
func TestOpenRepositoryLinkedWorktreeResolvesThroughCommonDir(t *testing.T) {
	requireGitBinary(t)
	dir, sha := initRepoWithCommit(t)
	runGitOrFail(t, dir, "remote", "add", "origin", "https://example.test/org/repo.git")
	runGitOrFail(t, dir, "config", "extensions.worktreeconfig", "true")
	wt := filepath.Join(filepath.Dir(dir), "wt")
	runGitOrFail(t, dir, "worktree", "add", wt, "-b", "linked-branch")

	repo, err := OpenRepository(wt)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())
	require.Equal(t, "linked-branch", head.Name().Short(),
		"the linked worktree's own branch must resolve through the worktree gitdir")
	remotes, err := repo.Remotes()
	require.NoError(t, err)
	require.Len(t, remotes, 1, "remotes live in the common dir and must be visible")
	require.Equal(t, "origin", remotes[0].Config().Name)
}

// TestOpenRepositoryStillRefusesUnknownExtensions bounds the tolerance to the
// one mis-cased key. An extension go-git does not implement changes what the
// repository means, and opening it anyway would attest a repository we cannot
// read correctly. Both with and without worktreeConfig alongside: the
// fallback path must not turn into a blanket "ignore extensions".
func TestOpenRepositoryStillRefusesUnknownExtensions(t *testing.T) {
	requireGitBinary(t)
	for _, tc := range []struct {
		name          string
		alsoWorktree  bool
		wantSubstring string
	}{
		{name: "unknown extension alone", alsoWorktree: false, wantSubstring: "frobnicate"},
		{name: "unknown extension beside worktreeConfig", alsoWorktree: true, wantSubstring: "frobnicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := initRepoWithCommit(t)
			runGitOrFail(t, dir, "config", "extensions.frobnicate", "true")
			if tc.alsoWorktree {
				runGitOrFail(t, dir, "config", "extensions.worktreeconfig", "true")
			}
			_, err := OpenRepository(dir)
			require.Error(t, err, "an unknown extension must still refuse")
			require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion)
			require.Contains(t, err.Error(), tc.wantSubstring)
			require.NotContains(t, err.Error(), "worktreeconfig",
				"only the unknown extension may be reported once worktreeConfig is tolerated")
		})
	}
}

// linkedOnlyOriginURL is the URL of an origin that exists in exactly one
// linked worktree's config.worktree and nowhere in the shared config: the
// shape the independent review of judge#9038 reproduced with real git
// (`git remote get-url origin` answers in the worktree, the shared repository
// has no remotes) and for which the first fallback returned an empty
// Remotes().
const linkedOnlyOriginURL = "https://example.invalid/linked-only.git"

// worktreeConfigFixture is what git's effective configuration adds for that
// worktree once extensions.worktreeConfig is on: the linked-only origin, and
// a single-valued core setting that overrides the shared config's value.
const worktreeConfigFixture = "[remote \"origin\"]\n\turl = " + linkedOnlyOriginURL + "\n[core]\n\tsparseCheckout = true\n"

// linkedWorktreeWithConfig creates a repository with the extension on and no
// remotes, a linked worktree, and the given config.worktree in that
// worktree's own gitdir. It returns the main checkout, the worktree, and the
// sha.
func linkedWorktreeWithConfig(t *testing.T, worktreeConfig string) (string, string, string) {
	t.Helper()
	dir, sha := initRepoWithCommit(t)
	runGitOrFail(t, dir, "config", "core.sparseCheckout", "false")
	runGitOrFail(t, dir, "config", "extensions.worktreeconfig", "true")
	wt := filepath.Join(filepath.Dir(dir), "wt")
	runGitOrFail(t, dir, "worktree", "add", wt, "-b", "linked-branch")
	gitdir := runGitOrFail(t, wt, "rev-parse", "--absolute-git-dir")
	require.NoError(t, os.WriteFile(filepath.Join(gitdir, "config.worktree"), []byte(worktreeConfig), 0o644))
	return dir, wt, sha
}

// TestOpenRepositoryMergesWorktreeConfig: with the extension on, git reads
// <gitdir>/config.worktree after the shared config as part of the effective
// configuration. The tolerant open must see the same: an origin defined only
// there is the worktree's one remote, a single-valued key defined in both
// takes the worktree's value, and the main checkout (whose gitdir is .git,
// with no config.worktree) sees neither. Without the merge, an attestation
// from the worktree carried no remote at all.
func TestOpenRepositoryMergesWorktreeConfig(t *testing.T) {
	requireGitBinary(t)
	dir, wt, sha := linkedWorktreeWithConfig(t, worktreeConfigFixture)

	// Positive control: git itself resolves both through config.worktree, and
	// the shared repository has no remotes.
	require.Equal(t, linkedOnlyOriginURL, runGitOrFail(t, wt, "remote", "get-url", "origin"))
	require.Equal(t, "true", runGitOrFail(t, wt, "config", "--get", "core.sparseCheckout"))
	require.Empty(t, runGitOrFail(t, dir, "remote"))
	require.Equal(t, "false", runGitOrFail(t, dir, "config", "--get", "core.sparseCheckout"))

	repo, err := OpenRepository(wt)
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
	require.Equal(t, "true", cfg.Raw.Section("core").Option("sparseCheckout"),
		"config.worktree is read after the shared config, so its value wins for a single-valued key")

	// Isolation: the main checkout's gitdir is .git, which has no
	// config.worktree, so the worktree-only settings must not leak into it.
	main, err := OpenRepository(dir)
	require.NoError(t, err)
	mainRemotes, err := main.Remotes()
	require.NoError(t, err)
	require.Empty(t, mainRemotes, "the main checkout must not see a remote from another worktree's config.worktree")
	mainCfg, err := main.Config()
	require.NoError(t, err)
	require.Equal(t, "false", mainCfg.Raw.Section("core").Option("sparseCheckout"))
}

// TestOpenRepositoryRefusesUnknownExtensionInWorktreeConfig: an extension
// declared in config.worktree reaches go-git's validation like one in the
// shared config, so the merge cannot become a side door for extensions the
// tolerant open does not understand.
func TestOpenRepositoryRefusesUnknownExtensionInWorktreeConfig(t *testing.T) {
	requireGitBinary(t)
	_, wt, _ := linkedWorktreeWithConfig(t, "[extensions]\n\tfrobnicate = true\n")

	_, err := OpenRepository(wt)
	require.Error(t, err, "an unknown extension in config.worktree must still refuse")
	require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion)
	require.Contains(t, err.Error(), "frobnicate")
	require.NotContains(t, err.Error(), "worktreeconfig")
}

// TestOpenRepositoryExpandsTildeLikeGoGit: git.PlainOpen expands a leading
// "~/" (its internal path_util.ReplaceTildeWithHome), so a caller that opened
// "~/repo" before the extension was enabled must still open it through the
// fallback. HOME is pointed at the temp dir so "~/main" is the repository.
func TestOpenRepositoryExpandsTildeLikeGoGit(t *testing.T) {
	requireGitBinary(t)
	dir, sha := initRepoWithCommit(t)
	runGitOrFail(t, dir, "config", "extensions.worktreeconfig", "true")
	t.Setenv("HOME", filepath.Dir(dir))

	repo, err := OpenRepository("~/" + filepath.Base(dir))
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String(), "~ must expand to HOME, not resolve relative to the working directory")
}

// TestOpenRepositoryIgnoresWorktreeConfigWhenExtensionIsFalse: go-git rejects
// the extension by NAME whatever its value, so extensions.worktreeconfig=false
// also lands in the fallback - but native git ignores config.worktree when
// the extension is off (the value table below covers every spelling). A stale worktree-only remote left behind in
// config.worktree must therefore NOT become the repository's identity: the
// open succeeds (git accepts the repository) and Remotes() is empty, exactly
// as git reports it.
func TestOpenRepositoryIgnoresWorktreeConfigWhenExtensionIsFalse(t *testing.T) {
	requireGitBinary(t)
	dir, wt, sha := linkedWorktreeWithConfig(t, worktreeConfigFixture)
	runGitOrFail(t, dir, "config", "extensions.worktreeconfig", "false")

	// Positive control: git ignores the stale file once the extension is off.
	require.Empty(t, runGitOrFail(t, wt, "remote"))
	require.Equal(t, "false", runGitOrFail(t, wt, "config", "--get", "core.sparseCheckout"))
	// And go-git still refuses the repository by the extension's name alone,
	// which is why the fallback has to handle the false case at all.
	_, err := git.PlainOpenWithOptions(wt, &git.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true})
	require.ErrorIs(t, err, git.ErrUnsupportedExtensionRepositoryFormatVersion)

	repo, err := OpenRepository(wt)
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
}

// bareKey marks the table row whose extension key is written with no value
// at all (`worktreeConfig` on a line of its own), which git reads as true.
// `git config` cannot write that form - it always emits `key = value` - so
// the row appends the text to .git/config directly.
const bareKey = "<bare key, no value>"

func appendToConfig(t *testing.T, dir, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(text)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// TestOpenRepositoryWorktreeConfigBooleanValues pins git's boolean rules for
// the extension value: true/yes/on/1 (any case) and a bare key merge
// config.worktree; false/no/off/0 and the empty value skip it; anything git
// would die on ("bad boolean config value") refuses here too. git is the
// positive control on every row. The fixture is the main checkout's own
// .git/config.worktree, which git reads the same way.
func TestOpenRepositoryWorktreeConfigBooleanValues(t *testing.T) {
	requireGitBinary(t)
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
			dir, sha := initRepoWithCommit(t)
			if tc.value == bareKey {
				appendToConfig(t, dir, "[extensions]\n\tworktreeConfig\n")
				require.Equal(t, "true", runGitOrFail(t, dir, "config", "--type=bool", "extensions.worktreeconfig"),
					"positive control: git reads a bare key as true")
			} else {
				runGitOrFail(t, dir, "config", "extensions.worktreeconfig", tc.value)
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "config.worktree"), []byte(worktreeConfigFixture), 0o644))

			repo, err := OpenRepository(dir)
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
				require.Equal(t, linkedOnlyOriginURL, runGitOrFail(t, dir, "remote", "get-url", "origin"), "positive control: git honours config.worktree")
				require.Len(t, remotes, 1)
				require.Equal(t, []string{linkedOnlyOriginURL}, remotes[0].Config().URLs)
				return
			}
			require.NotZero(t, gitExitCode(t, dir, "remote", "get-url", "origin"), "positive control: git ignores config.worktree")
			require.Empty(t, remotes)
		})
	}
}

// TestOpenRepositoryAcceptsFilePathLikeGoGit: with DetectDotGit on, go-git
// starts the .git search from an existing file's directory; the fallback
// must too, instead of statting <file>/.git and failing with ENOTDIR.
func TestOpenRepositoryAcceptsFilePathLikeGoGit(t *testing.T) {
	requireGitBinary(t)
	dir, sha := initRepoWithCommit(t)
	runGitOrFail(t, dir, "config", "extensions.worktreeconfig", "true")

	repo, err := OpenRepository(filepath.Join(dir, "f.txt"))
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	require.Equal(t, sha, head.Hash().String())
}
