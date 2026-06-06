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

package fanotify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// childProcState reads /proc/<pid>/stat and returns the single-char process
// state (R/S/D/Z/T/...). 'D' = TASK_KILLABLE/UNINTERRUPTIBLE sleep — exactly
// the fanotify_get_response() strand we're testing against. comm can contain
// spaces and parens, so split on the LAST ')'.
func childProcState(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "?(" + err.Error() + ")"
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return "?"
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) == 0 {
		return "?"
	}
	return fields[0]
}

// TestHandler_ReleasesOpenerWhenHashBlocks is the regression test for the
// uninterruptible D-state strand that hung the release fan-out.
//
// THE BUG: cilock arms fanotify in PERMISSION mode (FAN_OPEN_PERM). The kernel
// blocks every opener inside open() -> fanotify_get_response() (wait_event_-
// killable, NO timeout) until cilock writes FAN_ALLOW. The pre-fix handler
// wrote that response only AFTER hashing the file, so any hash that blocked
// (a stalled read under cross-container concurrency) stranded the opener
// FOREVER in uninterruptible 'D' state — ignoring SIGTERM/SIGINT and holding
// the inherited stdout pipe, hanging the whole build.
//
// We mark a DEDICATED tmpfs mount (so FAN_MARK_FILESYSTEM scopes to just it —
// marking '/' plus a blocking hash would wedge every process in the test
// container), inject a hash that blocks forever, then have a CHILD process
// (different PID, so PID self-exclusion does not skip it) open a file on that
// mount.
//
//	GREEN (default budget 200ms): the deadline fires, FAN_ALLOW is written,
//	       the child's open() returns and it runs to completion.
//	RED   (CILOCK_TEST_HASH_BUDGET=0 → deadline disabled → the pre-fix
//	       respond-after-blocking-hash): the child blocks forever and the
//	       test fails, reporting the child's kernel state ('D').
//
// Requires Linux + CAP_SYS_ADMIN (real permission-mode fanotify + tmpfs
// mount). Skips otherwise, so it no-ops on dev machines and only really runs
// in CI, a privileged container (colima/docker --privileged), or the buildbox.
func TestHandler_ReleasesOpenerWhenHashBlocks(t *testing.T) {
	// Dedicated tmpfs mount: a FAN_MARK_FILESYSTEM on it covers ONLY this
	// mount's superblock, so a blocking hash strands only opens of OUR file —
	// not every process in the container.
	mnt := t.TempDir()
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, ""); err != nil {
		t.Skipf("need CAP_SYS_ADMIN to mount tmpfs (run in a privileged container): %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(mnt, 0) })

	if err := Probe(mnt); err != nil {
		t.Skipf("fanotify FAN_OPEN_PERM unavailable (need Linux + CAP_SYS_ADMIN): %v", err)
	}
	file := filepath.Join(mnt, "input.bin")
	if err := os.WriteFile(file, []byte("material-content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Scope marks to ONLY the tmpfs: drop the global '/','/usr',... coverage so
	// the strand can't reach processes outside the test.
	origPaths := globalCoveragePaths
	globalCoveragePaths = nil
	t.Cleanup(func() { globalCoveragePaths = origPaths })

	h, err := New(mnt)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Budget toggle. Default 200ms exercises the FIX (deadline fires, opener
	// released). CILOCK_TEST_HASH_BUDGET=0 disables the deadline, reproducing
	// the pre-fix respond-after-blocking-hash → this test goes RED.
	budget := 200 * time.Millisecond
	if v := os.Getenv("CILOCK_TEST_HASH_BUDGET"); v != "" {
		if v == "0" {
			budget = 0
		} else if d, perr := time.ParseDuration(v); perr == nil {
			budget = d
		}
	}
	h.HandlerBudget = budget

	// A hash that blocks forever — the worst case the kernel's missing
	// per-event timeout exposes. Released in cleanup so no goroutine leaks.
	block := make(chan struct{})
	h.hashFn = func(int) ([32]byte, int64, error) {
		<-block
		return [32]byte{}, 0, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = h.Run(ctx); close(runDone) }()
	time.Sleep(200 * time.Millisecond) // let Run reach poll()

	// Child (different PID) opens the marked file -> FAN_OPEN_PERM -> the
	// blocking hash. cat's own libs live on '/' (unmarked here), so only the
	// open of our tmpfs file is gated.
	child := exec.Command("cat", file)
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	childPID := child.Process.Pid
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()

	t.Cleanup(func() {
		close(block)
		_ = child.Process.Kill()
		cancel()
		_ = h.Close()
		<-runDone
	})

	select {
	case waitErr := <-childDone:
		t.Logf("GREEN: opener released, child returned (budget=%v, err=%v)", budget, waitErr)
	case <-time.After(15 * time.Second):
		st := childProcState(childPID)
		t.Fatalf("RED: opener (pid %d) stranded for >15s in kernel state %q — the handler never wrote FAN_ALLOW because the response was gated on a blocking hash. State 'D' is the uninterruptible fanotify_get_response strand that hung the fan-out. (budget=%v)",
			childPID, st, budget)
	}
}
