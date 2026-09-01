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

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression for judge#8290: resolveCommitSHA opens the repository with only
// DetectDotGit. In a LINKED git worktree (`git worktree add`), `.git` is a
// file pointing at <main>/.git/worktrees/<name>, and HEAD's branch ref lives
// in the main repository's common dir — without EnableDotGitCommonDir the
// open succeeds but revision resolution finds no refs, so
// `cilock policy from-commit HEAD` fails from a linked worktree while
// working from the primary checkout.
func TestResolveCommitSHA_ResolvesInsideLinkedWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH")
	}
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // G204: test-controlled arguments
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v failed: %s", args, out)
		return strings.TrimSpace(string(out))
	}

	base := t.TempDir()
	mainDir := filepath.Join(base, "main")
	require.NoError(t, os.Mkdir(mainDir, 0o755))
	git(mainDir, "init")
	git(mainDir, "config", "user.email", "t@example.test")
	git(mainDir, "config", "user.name", "t")
	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "f.txt"), []byte("hi\n"), 0o644))
	git(mainDir, "add", "f.txt")
	git(mainDir, "-c", "commit.gpgsign=false", "commit", "-m", "c1")
	sha := git(mainDir, "rev-parse", "HEAD")

	linked := filepath.Join(base, "linked")
	git(mainDir, "worktree", "add", linked, "-b", "linked-branch")

	t.Chdir(linked)
	got, err := resolveCommitSHA("HEAD")
	require.NoError(t, err,
		"resolveCommitSHA must resolve HEAD from inside a linked git worktree (judge#8290)")
	assert.Equal(t, sha, got)
}
