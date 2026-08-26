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

//go:build linux

package alpsevidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadNULSeparatedPreservesInternalEmptyArguments pins the /proc/cmdline
// read path to the corrected split semantics. The algorithm itself is pinned
// portably in TestSplitNULTerminatedPreservesInternalEmptyArguments; this
// covers the file-backed wrapper the Linux source actually calls.
func TestReadNULSeparatedPreservesInternalEmptyArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmdline")
	require.NoError(t, os.WriteFile(path, []byte("codex\x00--model\x00\x00--sandbox\x00read-only\x00"), 0o600))

	argv, err := readNULSeparated(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"codex", "--model", "", "--sandbox", "read-only"}, argv)

	// An unreadable cmdline reports the FAILURE rather than an empty argv.
	// Collapsing the two is what let a process that exited mid-walk look like
	// one that simply had no arguments; the builder turns this error into a
	// recorded identity gap.
	missing, err := readNULSeparated(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	assert.Nil(t, missing)
}

func TestReadProcessRefusesARecycledSlotAcrossStatBracket(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "42")
	require.NoError(t, os.MkdirAll(proc, 0o750))
	target := filepath.Join(t.TempDir(), "codex")
	require.NoError(t, os.WriteFile(target, []byte("binary"), 0o700))
	require.NoError(t, os.Symlink(target, filepath.Join(proc, "exe")))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "comm"), []byte("codex\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "cmdline"), []byte("codex\x00"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "auxv"), []byte("generation"), 0o600))

	procStat := func(ppid, start string) []byte {
		fields := make([]string, 20)
		for i := range fields {
			fields[i] = "0"
		}
		fields[0], fields[1], fields[19] = "S", ppid, start
		return []byte("42 (codex) " + strings.Join(fields, " "))
	}
	statReads := 0
	src := osProcessSource{root: root, readFile: func(path string) ([]byte, error) {
		if filepath.Base(path) == "stat" {
			statReads++
			if statReads == 1 {
				return procStat("1", "100"), nil
			}
			return procStat("1", "200"), nil
		}
		return os.ReadFile(path) //nolint:gosec // test-owned path
	}}

	_, err := src.ReadProcess(42)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProcessNotFound)
	assert.Contains(t, err.Error(), "changed process slot")
}

// writeProcStat writes a minimal /proc/<pid>/stat fixture with the given comm,
// ppid and start time.
func writeProcStat(t *testing.T, proc, comm, ppid, start string) {
	t.Helper()
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[1], fields[19] = "S", ppid, start
	require.NoError(t, os.WriteFile(filepath.Join(proc, "stat"),
		[]byte(filepath.Base(proc)+" ("+comm+") "+strings.Join(fields, " ")), 0o600))
}

// TestReadProcessWithoutGenerationBracketIsPartialAndPublishesNoIdentity pins
// both halves of the unbracketed-read contract.
//
// All publishable identity fields are readable, but without the generation
// reads on both sides nothing proves they describe one execution — so none of
// them may be published. The read itself is still a PARTIAL observation, not
// an error: the pid resolved and its stat was readable, and aborting the walk
// here reported "could not look at this ancestor" as "this process does not
// exist". The builder records the gaps instead, which is what degrades the
// verdict, and the absent generation is what makes every follow-up read
// refuse (processInstance.validate fails on an empty side).
func TestReadProcessWithoutGenerationBracketIsPartialAndPublishesNoIdentity(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "42")
	require.NoError(t, os.MkdirAll(proc, 0o750))
	target := filepath.Join(t.TempDir(), "codex")
	require.NoError(t, os.WriteFile(target, []byte("binary"), 0o700))
	require.NoError(t, os.Symlink(target, filepath.Join(proc, "exe")))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "comm"), []byte("codex\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "cmdline"), []byte("codex\x00"), 0o600))
	// Deliberately no auxv: no generation bracket is available at all.
	writeProcStat(t, proc, "codex", "1", "100")

	p, err := (osProcessSource{root: root}).ReadProcess(42)
	require.NoError(t, err, "an unbracketed read is a partial observation, not a missing process")

	assert.Empty(t, p.Executable, "an identity field without a generation bracket must not be published")
	assert.Empty(t, p.Comm)
	assert.Nil(t, p.Argv)
	assert.False(t, p.fullyExamined())
	assert.ElementsMatch(t, []identitySource{identityExecutable, identityComm, identityArgv}, p.identityGaps())

	// The empty generation keeps every follow-up read refused, so degrading
	// the error to a partial read weakened nothing downstream.
	require.Error(t, p.instance().validate(p))
}

// TestZombieProcessReadsAsPartialWithExplicitGaps drives the Linux source over
// the exact /proc shape a zombie leaves behind — stat still readable, exe link
// gone, cmdline present but empty, auxv present but EMPTY (the mm is gone) —
// which is the fixture the live zombie tests (process_live_test.go) wait for.
// Before the fix, the empty auxv made ReadProcess return an error, so a zombie
// ancestor read as "process not found" and the live fixtures could never
// observe the partial read they assert.
func TestZombieProcessReadsAsPartialWithExplicitGaps(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "43")
	require.NoError(t, os.MkdirAll(proc, 0o750))
	writeProcStat(t, proc, "codex", "1", "100")
	// No exe link at all, an empty cmdline, and an EMPTY auxv: the kernel
	// keeps the files but the exited process no longer has an address space
	// to answer from.
	require.NoError(t, os.WriteFile(filepath.Join(proc, "comm"), []byte("codex\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "cmdline"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(proc, "auxv"), nil, 0o600))

	p, err := (osProcessSource{root: root}).ReadProcess(43)
	require.NoError(t, err, "the PID still resolves; this is a partial read, not a missing process")

	assert.False(t, p.fullyExamined(),
		"a ProcessInfo assembled from failed identity reads must not claim to have been examined")
	assert.Contains(t, p.identityGaps(), identityExecutable,
		"the sources that could not be read must be named")
	assert.Empty(t, p.Executable)
	assert.Equal(t, 1, p.PPID, "the ancestry link survives so the walk can continue past the zombie")
}
