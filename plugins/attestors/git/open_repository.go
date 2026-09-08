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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/go-git/gcfg"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
)

// A twin of this file lives in plugins/attestors/base-ancestry/open_repository.go
// (package-private there), because that module must not gain a go.mod
// requirement on this one. Keep the two in step.

// worktreeConfigExtension is the one extension OpenRepository tolerates, in
// the mixed-case spelling go-git's own allowlist uses. git writes the key
// lowercase; the removal below matches case-insensitively.
const worktreeConfigExtension = "worktreeConfig"

// errReadOnlyStorer is returned by extensionTolerantStorer.SetConfig: the
// tolerance is read-side only and must never be persisted into .git/config.
var errReadOnlyStorer = errors.New("extension-tolerant storer refuses to write repository config")

// OpenRepository opens the repository containing dir the way the attestors
// always have - git.PlainOpenWithOptions with DetectDotGit (walk up to the
// nearest .git) and EnableDotGitCommonDir (a linked worktree's branch refs
// live in the main repository's common dir, judge#8290) - with one fallback
// for a go-git bug.
//
// go-git v5.19.2 refuses any repository whose config carries
// extensions.worktreeConfig under core.repositoryformatversion 0:
// verifyExtensions (repository_extensions.go:73) lowercases the keys it
// reads, but its v0 allowlist (:52) is spelled "worktreeConfig", so the
// allowlisted extension can never match and PlainOpen fails with
// "core.repositoryformatversion does not support extension: worktreeconfig".
// git writes the key lowercase and enables it by itself for a sparse checkout
// in a linked worktree, so every worktree of a repository that has one sparse
// checkout fails to open, and the attestation is minted with no git subject.
// v5.19.2 is the newest v5; the bug is upstream and unfixed.
//
// The fallback is taken only when the error is exactly that one. It re-opens
// through a storer whose Config() drops the worktreeConfig option before
// go-git validates it. Nothing else is tolerated: any other unknown extension
// still refuses, and the storer refuses to write config back. worktreeConfig
// only gates config.worktree, which go-git never reads, so what the attestor
// observes through the repository is unchanged.
func OpenRepository(dir string) (*git.Repository, error) {
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if err == nil || !errors.Is(err, git.ErrUnsupportedExtensionRepositoryFormatVersion) {
		return repo, err
	}
	return openToleratingWorktreeConfig(dir)
}

// openToleratingWorktreeConfig resolves the dot-git with the same steps
// git.PlainOpenWithOptions takes (repository.go:310-338 and :341-458 in go-git
// v5.19.2 - expand a leading ~, start from an existing file's directory, walk
// up for .git, follow a `gitdir:` file, honour a commondir), reimplemented
// here because go-git's are unexported, and opens it through
// extensionTolerantStorer. The steps are mirrored one by one below; nothing
// beyond what each helper's comment states is claimed.
func openToleratingWorktreeConfig(dir string) (*git.Repository, error) {
	dot, wt, err := dotGitFilesystems(dir)
	if err != nil {
		return nil, err
	}
	common, err := commonDirFilesystem(dot)
	if err != nil {
		return nil, err
	}
	// With a nil common dir every path maps to dot, which is what go-git does
	// for a main checkout under EnableDotGitCommonDir.
	repoFS := dotgit.NewRepositoryFilesystem(dot, common)
	st := &extensionTolerantStorer{
		Storage: filesystem.NewStorage(repoFS, cache.NewObjectLRUDefault()),
		dot:     dot,
	}
	return git.Open(st, wt)
}

// dotGitFilesystems mirrors go-git's dotGitToOSFilesystems with detection on:
// from startDirectory(dir) it walks up until a .git entry is found and
// returns the dot-git filesystem plus the worktree filesystem it sits in. A
// .git directory is chrooted; a .git file names the gitdir of a linked
// worktree.
func dotGitFilesystems(dir string) (billy.Filesystem, billy.Filesystem, error) {
	path, err := startDirectory(dir)
	if err != nil {
		return nil, nil, err
	}
	for {
		wt := osfs.New(path)
		info, statErr := wt.Stat(git.GitDirName)
		switch {
		case statErr == nil && info.IsDir():
			dot, chrootErr := wt.Chroot(git.GitDirName)
			return dot, wt, chrootErr
		case statErr == nil:
			dot, fileErr := dotGitFileFilesystem(path, wt)
			return dot, wt, fileErr
		case !os.IsNotExist(statErr):
			return nil, nil, statErr
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil, nil, git.ErrRepositoryNotExists
		}
		path = parent
	}
}

// startDirectory resolves where the .git search begins, as go-git's
// dotGitToOSFilesystems does with DetectDotGit on: a leading ~ is expanded
// (expandTilde), the path is made absolute, and an existing regular file is
// replaced by its directory. Without the last step a file path stats
// <file>/.git and fails with ENOTDIR where go-git succeeds.
func startDirectory(dir string) (string, error) {
	expanded, err := expandTilde(dir)
	if err != nil {
		return "", err
	}
	path, err := filepath.Abs(expanded)
	if err != nil {
		return "", err
	}
	if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() {
		path = filepath.Dir(path)
	}
	return path, nil
}

// expandTilde mirrors go-git's internal path_util.ReplaceTildeWithHome: a
// leading "~/" becomes the current user's home directory, "~name/" that
// user's, and a bare "~" is left as it is, as upstream leaves it.
func expandTilde(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	firstSlash := strings.Index(path, "/")
	switch {
	case firstSlash == 1:
		home, err := os.UserHomeDir()
		if err != nil {
			return path, err
		}
		return strings.Replace(path, "~", home, 1), nil
	case firstSlash > 1:
		account, err := user.Lookup(path[1:firstSlash])
		if err != nil {
			return path, err
		}
		return strings.Replace(path, path[:firstSlash], account.HomeDir, 1), nil
	}
	return path, nil
}

// dotGitFileFilesystem mirrors go-git's dotGitFileToOSFilesystem: the .git
// entry is a file whose first line is "gitdir: <path>", relative to the
// worktree unless absolute.
func dotGitFileFilesystem(path string, wt billy.Filesystem) (billy.Filesystem, error) {
	f, err := wt.Open(git.GitDirName)
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(f)
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	const prefix = "gitdir: "
	rest, ok := strings.CutPrefix(string(b), prefix)
	if !ok {
		return nil, fmt.Errorf("%s file has no %q prefix", git.GitDirName, prefix)
	}
	gitdir := strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0])
	if filepath.IsAbs(gitdir) {
		return osfs.New(gitdir), nil
	}
	return osfs.New(filepath.Join(path, gitdir)), nil
}

// commonDirFilesystem mirrors go-git's dotGitCommonDirectory: a linked
// worktree's gitdir carries a "commondir" file naming the main repository's
// .git, relative to the gitdir unless absolute. It returns nil when there is
// no such file, and git.ErrRepositoryIncomplete when the named directory is
// missing.
func commonDirFilesystem(dot billy.Filesystem) (billy.Filesystem, error) {
	f, err := dot.Open("commondir")
	if os.IsNotExist(err) {
		return nil, nil //nolint:nilnil // no commondir is the ordinary main-checkout case, as in go-git
	}
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(f)
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	path := strings.TrimSpace(string(b))
	if path == "" {
		return nil, nil //nolint:nilnil // an empty commondir file is treated as absent, as in go-git
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(dot.Root(), path)
	}
	common := osfs.New(path)
	if _, statErr := common.Stat(""); statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, git.ErrRepositoryIncomplete
		}
		return nil, statErr
	}
	return common, nil
}

// worktreeConfigFile is the per-worktree config git reads, from the
// worktree's own gitdir, once extensions.worktreeConfig is on.
const worktreeConfigFile = "config.worktree"

// extensionTolerantStorer is filesystem.Storage with two differences, both
// confined to Config().
//
// First, it reproduces git's effective configuration for the worktree being
// opened. With extensions.worktreeConfig on - checked by VALUE in the shared
// config, see worktreeConfigEnabled, because go-git lands here for "false"
// too and git reads nothing extra then - git reads <gitdir>/config.worktree
// after the shared config: a remote, a core setting or anything else defined
// only there is part of what git reports, and an attestation that ignored it
// would carry an incomplete repository identity (the Codex review of
// judge#9038 named a remote defined only there vanishing from Remotes()).
// dot is the worktree's own gitdir - .git/worktrees/<name> for a linked
// worktree, .git itself for the main checkout, which is why the main
// checkout's own config.worktree, if any, is read the same way and another
// worktree's never is. The shared config is marshalled back to bytes, the
// worktree file appended after it, and the pair re-parsed: git's precedence
// (later wins for a single-valued key, values accumulate for a multi-valued
// one) is exactly what a concatenated parse gives, and go-git's raw
// [extensions] section survives the round-trip, so an extension declared in
// either file still reaches verifyExtensions.
//
// Second, it drops the worktreeConfig option from the merged raw
// [extensions] section before go-git's verifyExtensions sees it. Everything
// else in the section survives, so an extension go-git genuinely does not
// implement still refuses.
//
// It is read-only with respect to config: SetConfig refuses, so neither the
// tolerance nor the merged view can ever be persisted (a Config()->SetConfig()
// round-trip would have written the worktree's settings into the shared
// config and dropped the extension git relies on to read them).
type extensionTolerantStorer struct {
	*filesystem.Storage
	dot billy.Filesystem
}

// Config returns the repository's effective config for this worktree, with
// the worktreeConfig extension removed from its raw form. RemoveOption matches
// by strings.EqualFold, so the lowercase key git writes is removed by go-git's
// mixed-case spelling.
func (s *extensionTolerantStorer) Config() (*config.Config, error) {
	cfg, err := s.Storage.Config()
	if err != nil {
		return nil, err
	}
	enabled, err := worktreeConfigEnabled(s.Filesystem())
	if err != nil {
		return nil, err
	}
	if enabled {
		cfg, err = mergeWorktreeConfig(cfg, s.dot)
		if err != nil {
			return nil, err
		}
	}
	if cfg.Raw != nil && cfg.Raw.HasSection(extensionsSection) {
		cfg.Raw.Section(extensionsSection).RemoveOption(worktreeConfigExtension)
	}
	return cfg, nil
}

// extensionsSection is the config section git reads repository extensions
// from - the shared config only; config.worktree cannot enable one.
const extensionsSection = "extensions"

// worktreeConfigEnabled reports whether the SHARED config turns the extension
// on, so that config.worktree is merged exactly when git would read it.
// go-git refuses the extension by name whatever its value, so the fallback
// sees "false" as well as "true", and git ignores config.worktree for
// "false": merging it then would turn a stale worktree-only remote into the
// repository's identity.
//
// The value is read from the config bytes through gcfg's callback reader,
// the reader go-git's own decoder is built on, because go-git's decoded form
// drops gcfg's "blank" flag and so cannot tell a bare key (true in git) from
// `key =` (false in git). fs is the repository filesystem, on which "config"
// resolves to the shared config for a linked worktree too. The last
// occurrence wins, as in git.
func worktreeConfigEnabled(fs billy.Filesystem) (bool, error) {
	f, err := fs.Open("config")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	present, blank, value := false, false, ""
	readErr := gcfg.ReadWithCallback(f, func(section, subsection, name, v string, isBlank bool) error {
		if subsection == "" && strings.EqualFold(section, extensionsSection) && strings.EqualFold(name, worktreeConfigExtension) {
			present, blank, value = true, isBlank, v
		}
		return nil
	})
	closeErr := f.Close()
	if readErr != nil {
		return false, readErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if !present {
		return false, nil
	}
	if blank {
		return true, nil
	}
	return parseGitBool(value)
}

// parseGitBool applies git's boolean rules for a key that has a value
// (git-config(1)): true, yes, on and 1 are true; false, no, off, 0 and the
// empty string are false; case-insensitive. Any other value is an error, as
// git itself dies on a bad boolean here; the open must refuse, not guess. A
// bare key (no value at all) is handled by the caller, which sees it as true.
func parseGitBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "yes", "on", "1":
		return true, nil
	case "false", "no", "off", "0", "":
		return false, nil
	}
	return false, fmt.Errorf("extensions.worktreeConfig has a value this open cannot honour: %q", value)
}

// mergeWorktreeConfig returns cfg with <dot>/config.worktree applied after
// it, or cfg itself when the worktree has no such file.
func mergeWorktreeConfig(cfg *config.Config, dot billy.Filesystem) (*config.Config, error) {
	extra, err := readWorktreeConfig(dot)
	if err != nil {
		return nil, err
	}
	if extra == nil {
		return cfg, nil
	}
	base, err := cfg.Marshal()
	if err != nil {
		return nil, err
	}
	merged := make([]byte, 0, len(base)+1+len(extra))
	merged = append(merged, base...)
	merged = append(merged, '\n')
	merged = append(merged, extra...)
	return config.ReadConfig(bytes.NewReader(merged))
}

// readWorktreeConfig returns the bytes of <dot>/config.worktree, or nil when
// the file does not exist.
func readWorktreeConfig(dot billy.Filesystem) ([]byte, error) {
	f, err := dot.Open(worktreeConfigFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(f)
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return b, nil
}

// SetConfig refuses: see extensionTolerantStorer.
func (s *extensionTolerantStorer) SetConfig(*config.Config) error {
	return errReadOnlyStorer
}
