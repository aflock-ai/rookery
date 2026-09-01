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

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression for judge#8290 (follow-up to judge#8288). Inside a LINKED git
// worktree (`git worktree add`), `.git` is a file pointing at
// <main>/.git/worktrees/<name>, and the branch refs HEAD resolves through
// live in the main repository's COMMON dir. Opening without
// EnableDotGitCommonDir cannot see those refs, and the attestor once
// produced a signed attestation with ZERO git subjects while reporting
// success — no commithash subject for the pushgate `tested` gate to join
// on, so the push was refused while the tooling looked healthy.
//
// This pins the fixed behavior: attesting from a linked worktree records
// the worktree's HEAD commit and emits the commithash subject.
func TestAttestorRecordsCommitSubjectInsideLinkedWorktree(t *testing.T) {
	requireGitBinary(t)

	base := t.TempDir()
	mainDir := filepath.Join(base, "main")
	require.NoError(t, os.Mkdir(mainDir, 0o755))
	runGitOrFail(t, mainDir, "init")
	runGitOrFail(t, mainDir, "config", "user.email", "t@example.test")
	runGitOrFail(t, mainDir, "config", "user.name", "t")
	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "f.txt"), []byte("hi\n"), 0o644))
	runGitOrFail(t, mainDir, "add", "f.txt")
	runGitOrFail(t, mainDir, "-c", "commit.gpgsign=false", "commit", "-m", "c1")
	sha := runGitOrFail(t, mainDir, "rev-parse", "HEAD")

	linked := filepath.Join(base, "linked")
	runGitOrFail(t, mainDir, "worktree", "add", linked, "-b", "linked-branch")

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor},
		attestation.WithWorkingDir(linked))
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx),
		"the git attestor must attest from a linked worktree")

	assert.Equal(t, sha, attestor.CommitHash,
		"the linked worktree's HEAD commit must be recorded")
	assert.Equal(t, "linked-branch", attestor.RefNameShort,
		"the linked worktree's own branch must be recorded, not the main checkout's")
	require.Contains(t, attestor.Subjects(), "commithash:"+sha,
		"the commithash subject the pushgate tested gate joins on must be present")
}
