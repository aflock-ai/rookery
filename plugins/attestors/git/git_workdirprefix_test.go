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

package git

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// A mint's position in the worktree is a signed fact (testifysec/judge#9856).
//
// The git attestor finds the repository by walking up from the working
// directory, so from a subdirectory it records the whole commit, while the
// material attestor walks only that subdirectory: one mint attested 518 of
// 284,644 files and bound the right commit. workdirprefix is the working
// directory relative to the worktree root, "" at the root, and it is always
// serialized so a collection from an older cilock (no field) stays
// distinguishable from a root mint.

// attestAt runs the attestor and returns the error it reported, which the
// context records per attestor (the workflow turns it into a failed run).
func attestAt(t *testing.T, dir string, a *Attestor) error {
	t.Helper()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	if err := ctx.RunAttestors(); err != nil {
		return err
	}
	for _, c := range ctx.CompletedAttestors() {
		if c.Error != nil {
			return c.Error
		}
	}
	return nil
}

func TestWorkdirPrefixIsEmptyAtTheWorktreeRoot(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	a := New()
	require.NoError(t, attestAt(t, dir, a))
	require.NotEmpty(t, a.CommitHash, "the root mint must still attest the commit")
	require.Equal(t, "", a.WorkdirPrefix)

	raw, err := json.Marshal(a)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	v, present := fields["workdirprefix"]
	require.True(t, present, "a root mint must SAY it is at the root: absent means an older cilock")
	require.Equal(t, "", v)
}

func TestWorkdirPrefixSubdirectoryMintRefusesByDefault(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	sub := filepath.Join(dir, "subdir", "deeper")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	a := New()
	err := attestAt(t, sub, a)
	require.Error(t, err, "a subdirectory mint attests a partial tree and must fail fast")
	require.Contains(t, err.Error(), "subdir/deeper")
	require.Contains(t, err.Error(), "worktree root")
	require.Contains(t, err.Error(), "--attestor-git-allow-subdirectory", "the refusal names the opt-out exactly as cilock parses it")
}

func TestWorkdirPrefixSubdirectoryMintRecordedWhenAllowed(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	sub := filepath.Join(dir, "subdir")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	a := New()
	WithAllowSubdirectory(true)(a)
	require.NoError(t, attestAt(t, sub, a))
	require.Equal(t, "subdir", a.WorkdirPrefix, "the prefix is still signed, so a verifier can refuse it")
}

func TestWorkdirPrefixResolvesSymlinkedPaths(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	// The same worktree reached through a symlink is still the root.
	link := filepath.Join(t.TempDir(), "via-link")
	require.NoError(t, os.Symlink(dir, link))
	a := New()
	require.NoError(t, attestAt(t, link, a))
	require.Equal(t, "", a.WorkdirPrefix)
}
