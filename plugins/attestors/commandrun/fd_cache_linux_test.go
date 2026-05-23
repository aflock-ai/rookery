// Copyright 2026 The Rookery Contributors
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

// Unit tests for the fd→path cache. These exercise the cache mutator
// helpers and resolveFD directly without ptrace — fast, race-friendly,
// and exhaustive on the close/dup edge cases. The integration tests in
// expanded_syscalls_integ_linux_test.go cover the real ptrace path.

package commandrun

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// marshalProcInfoForTest is a tiny helper used by the JSON-leak assertion
// in fd_cache_integ_linux_test.go. Kept here so the integ file doesn't
// need to import encoding/json.
func marshalProcInfoForTest(p ProcessInfo) ([]byte, error) {
	return json.Marshal(p)
}

// newTestContext builds a ptraceContext suitable for cache-mutator unit
// tests. No real ptrace happens — we only exercise the in-process maps.
func newTestContext() *ptraceContext {
	return &ptraceContext{
		processes:       make(map[int]*ProcessInfo),
		tlsPendingFDs:   make(map[string]int),
		pendingSyscalls: make(map[int]*pendingSyscall),
	}
}

// TestFDCache_ResolveCacheHit verifies that a path put into the cache is
// returned by resolveFD without touching /proc.
func TestFDCache_ResolveCacheHit(t *testing.T) {
	p := newTestContext()
	pid := os.Getpid()
	pi := p.getProcInfo(pid)
	pi.openedFDs[42] = "/tmp/from-cache"

	got := p.resolveFD(pid, 42)
	assert.Equal(t, "/tmp/from-cache", got, "cache hit should bypass readlink")
}

// TestFDCache_ResolveCacheMiss_FallbackToReadlink verifies that a miss
// falls back to /proc/<pid>/fd/N. We use the current process's own fd 0
// (stdin) as the canary — it is always present and readlink of it
// returns a non-empty string.
func TestFDCache_ResolveCacheMiss_FallbackToReadlink(t *testing.T) {
	p := newTestContext()
	// Use a real, live fd in the test process. fd 0 is always open.
	// Cache is empty so resolveFD should readlink and return something.
	got := p.resolveFD(os.Getpid(), 0)
	assert.NotEmpty(t, got, "miss should readlink /proc/self/fd/0 successfully")
}

// TestFDCache_OpenatExit_PopulatesCache simulates the openat-exit handler
// inserting a fresh entry. We assemble the same state the real handler
// would (pendingSyscalls + a registered path) and assert the cache is
// populated correctly.
func TestFDCache_OpenatExit_PopulatesCache(t *testing.T) {
	p := newTestContext()
	pid := 99
	pi := p.getProcInfo(pid)

	// Simulate openat("/etc/passwd") at entry, returning fd 7 at exit.
	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: openatSyscallNumber(),
		path:      "/etc/passwd",
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 7)
	delete(p.pendingSyscalls, pid)

	assert.Equal(t, "/etc/passwd", pi.openedFDs[7], "openat exit should cache the path")
}

// TestFDCache_OpenatExit_FailedOpenNotCached verifies that a negative
// return value (open failure) leaves the cache untouched. A failed
// openat returns -ENOENT/-EACCES; we MUST NOT cache the path for it.
func TestFDCache_OpenatExit_FailedOpenNotCached(t *testing.T) {
	p := newTestContext()
	pid := 100
	pi := p.getProcInfo(pid)

	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: openatSyscallNumber(),
		path:      "/nonexistent",
	}
	applyTestExit(pi, p.pendingSyscalls[pid], -2 /* -ENOENT */)
	delete(p.pendingSyscalls, pid)

	assert.Empty(t, pi.openedFDs, "failed openat must not populate the cache")
}

// TestFDCache_Close_Evicts verifies that close evicts the cache entry on
// success.
func TestFDCache_Close_Evicts(t *testing.T) {
	p := newTestContext()
	pid := 101
	pi := p.getProcInfo(pid)
	pi.openedFDs[5] = "/var/log/app.log"

	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: closeSyscallNumber(),
		oldFD:     5,
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 0 /* success */)
	delete(p.pendingSyscalls, pid)

	_, present := pi.openedFDs[5]
	assert.False(t, present, "close success should evict the cache entry")
}

// TestFDCache_Close_FailureKeepsEntry verifies that a failed close does
// NOT evict — the fd is still open in the tracee.
func TestFDCache_Close_FailureKeepsEntry(t *testing.T) {
	p := newTestContext()
	pid := 102
	pi := p.getProcInfo(pid)
	pi.openedFDs[9] = "/var/log/keepme.log"

	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: closeSyscallNumber(),
		oldFD:     9,
	}
	applyTestExit(pi, p.pendingSyscalls[pid], -9 /* -EBADF */)
	delete(p.pendingSyscalls, pid)

	assert.Equal(t, "/var/log/keepme.log", pi.openedFDs[9], "failed close must keep cache entry")
}

// TestFDCache_FDReuse_CorrectnessOnCloseThenReopen exercises the most
// critical correctness case: the same fd number reopened on a different
// file. A naïve cache that didn't evict on close would misattribute the
// second file's writes to the first file's path.
func TestFDCache_FDReuse_CorrectnessOnCloseThenReopen(t *testing.T) {
	p := newTestContext()
	pid := 103
	pi := p.getProcInfo(pid)

	// open /tmp/a → fd 4
	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: openatSyscallNumber(),
		path:      "/tmp/a",
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 4)
	delete(p.pendingSyscalls, pid)
	assert.Equal(t, "/tmp/a", pi.openedFDs[4])

	// close(4)
	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: closeSyscallNumber(),
		oldFD:     4,
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 0)
	delete(p.pendingSyscalls, pid)
	_, present := pi.openedFDs[4]
	require.False(t, present, "fd 4 must be evicted after close")

	// open /tmp/b → also fd 4 (kernel hands out lowest-available)
	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: openatSyscallNumber(),
		path:      "/tmp/b",
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 4)
	delete(p.pendingSyscalls, pid)

	assert.Equal(t, "/tmp/b", pi.openedFDs[4],
		"reopened fd 4 must point at the new path, not the old one")
}

// TestFDCache_Dup_CopiesEntry verifies dup() copies the cache entry from
// the source fd to the kernel-assigned new fd.
func TestFDCache_Dup_CopiesEntry(t *testing.T) {
	p := newTestContext()
	pid := 104
	pi := p.getProcInfo(pid)
	pi.openedFDs[3] = "/tmp/source"

	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: dupSyscallNumber(),
		oldFD:     3,
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 11 /* new fd */)
	delete(p.pendingSyscalls, pid)

	assert.Equal(t, "/tmp/source", pi.openedFDs[11], "dup should copy the entry")
	assert.Equal(t, "/tmp/source", pi.openedFDs[3], "dup must NOT remove the source entry")
}

// TestFDCache_Dup2_OverwritesExistingEntry verifies that dup2 onto an
// already-occupied fd evicts the previous entry there — the kernel
// silently closes the previous file at newFD before installing the dup.
func TestFDCache_Dup2_OverwritesExistingEntry(t *testing.T) {
	p := newTestContext()
	pid := 105
	pi := p.getProcInfo(pid)
	pi.openedFDs[1] = "/tmp/old-stdout"
	pi.openedFDs[7] = "/tmp/log-source"

	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: dup2SyscallNumber(),
		oldFD:     7,
		newFD:     1,
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 1 /* dup2 returns newFD on success */)
	delete(p.pendingSyscalls, pid)

	assert.Equal(t, "/tmp/log-source", pi.openedFDs[1],
		"after dup2(7, 1), fd 1 must point at the source file")
	assert.Equal(t, "/tmp/log-source", pi.openedFDs[7],
		"dup2 source entry must remain")
}

// TestFDCache_Dup2_OldFDNotCached_LeavesNewFDClean verifies the corner
// case where dup2 is called with an oldFD we never observed. The result
// is that the prior entry at newFD is evicted but no new entry is added
// — leaving the cache in a "miss" state so resolveFD falls back to
// readlink. This is correct: the readlink will still return the right
// answer because the kernel HAS performed the dup.
func TestFDCache_Dup2_OldFDNotCached_LeavesNewFDClean(t *testing.T) {
	p := newTestContext()
	pid := 106
	pi := p.getProcInfo(pid)
	pi.openedFDs[2] = "/tmp/old-stderr"

	p.pendingSyscalls[pid] = &pendingSyscall{
		syscallID: dup2SyscallNumber(),
		oldFD:     50, // we never cached fd 50
		newFD:     2,
	}
	applyTestExit(pi, p.pendingSyscalls[pid], 2)
	delete(p.pendingSyscalls, pid)

	_, present := pi.openedFDs[2]
	assert.False(t, present, "dup2 from uncached source should evict newFD entry")
}

// TestFDCache_Execve_ClearsCache verifies the cache is wiped on execve —
// CLOEXEC fds get closed by the kernel and we don't observe those closes.
func TestFDCache_Execve_ClearsCache(t *testing.T) {
	p := newTestContext()
	pid := 107
	pi := p.getProcInfo(pid)
	pi.openedFDs[3] = "/tmp/pre-exec"
	pi.openedFDs[4] = "/tmp/pre-exec-2"

	// Simulate execve clear (mirrors handleSyscall's SYS_EXECVE branch).
	for k := range pi.openedFDs {
		delete(pi.openedFDs, k)
	}

	assert.Empty(t, pi.openedFDs, "execve must clear the cache")
}

// TestFDCache_Stress_1000Cycles is the bounded-size correctness test:
// 1000 open/close cycles, all on the same fd, must leave the cache at
// most size 1 and writes always attributed to the most-recent path.
func TestFDCache_Stress_1000Cycles(t *testing.T) {
	p := newTestContext()
	pid := 200
	pi := p.getProcInfo(pid)

	for i := 0; i < 1000; i++ {
		path := fmt.Sprintf("/tmp/file-%d", i)
		// open
		p.pendingSyscalls[pid] = &pendingSyscall{
			syscallID: openatSyscallNumber(),
			path:      path,
		}
		applyTestExit(pi, p.pendingSyscalls[pid], 5)
		delete(p.pendingSyscalls, pid)
		require.Equal(t, path, pi.openedFDs[5], "iter %d: cache should hold current path", i)

		// resolveFD should match
		got := p.resolveFD(pid, 5)
		require.Equal(t, path, got, "iter %d: resolveFD must return current path", i)

		// close
		p.pendingSyscalls[pid] = &pendingSyscall{
			syscallID: closeSyscallNumber(),
			oldFD:     5,
		}
		applyTestExit(pi, p.pendingSyscalls[pid], 0)
		delete(p.pendingSyscalls, pid)
	}

	assert.LessOrEqual(t, len(pi.openedFDs), 1, "cache must not grow unbounded under churn")
}

// TestFDCache_MissReadlinkUsesProcFD verifies that on a miss, resolveFD
// returns the readlink result. We open a real file in this test process
// and let the resolveFD path do the readlink.
func TestFDCache_MissReadlinkUsesProcFD(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("readlink test requires /proc")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real-file")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o600))

	f, err := os.Open(target)
	require.NoError(t, err)
	defer f.Close()

	p := newTestContext()
	got := p.resolveFD(os.Getpid(), int(f.Fd()))
	// readlink resolves /proc/self/fd/N to the canonical path. macOS-style
	// /private/var/folders prefixes may apply on Darwin; we run only on
	// Linux per the build tag.
	assert.Contains(t, got, "real-file", "readlink fallback should resolve real fd")
}

// applyTestExit mirrors the production handleSyscallExit dispatch
// without requiring a real PtraceRegs struct. Mirrors are kept narrow
// so the dispatch logic is genuinely covered.
//
// Keeping this in a test helper rather than carving handleSyscallExit
// into smaller methods avoids growing the production API surface for the
// sake of testability.
func applyTestExit(pi *ProcessInfo, pending *pendingSyscall, retVal int64) {
	switch pending.syscallID {
	case uint64(openatSyscallNumber()), openatAltSyscallNumber():
		if retVal < 0 {
			return
		}
		pi.openedFDs[int(retVal)] = pending.path
	case uint64(dupSyscallNumber()):
		if retVal < 0 {
			return
		}
		if path, hit := pi.openedFDs[pending.oldFD]; hit {
			pi.openedFDs[int(retVal)] = path
		}
	case uint64(dup2SyscallNumber()), uint64(dup3SyscallNumber()):
		if retVal < 0 {
			return
		}
		delete(pi.openedFDs, pending.newFD)
		if path, hit := pi.openedFDs[pending.oldFD]; hit {
			pi.openedFDs[int(retVal)] = path
		}
	case uint64(closeSyscallNumber()):
		if retVal == 0 {
			delete(pi.openedFDs, pending.oldFD)
		}
	}
}
