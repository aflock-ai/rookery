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

//go:build !windows

package commandrun

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
)

// TestRunCmd_DoesNotHangOnLingeringChild is the OS-general regression
// test for the command-run hang bug.
//
// THE BUG: runCmd sets c.Stdout/c.Stderr to io.MultiWriter (so it can
// tee the wrapped command's output into the attestation buffers AND,
// optionally, the terminal). Because those are io.Writers and not
// *os.File, os/exec routes the child's stdout/stderr through INTERNAL
// os.Pipes and spawns copy goroutines; c.Wait() then blocks until those
// pipes hit EOF — which requires EVERY descendant that inherited the
// write end to close it (i.e. exit). A wrapped command that BACKGROUNDS
// a child outliving the foreground process keeps that write end open, so
// c.Wait() — and therefore Attest()/runCmd() — HANGS FOREVER.
//
// On the buildbox this manifests as a traced go-build grandchild
// (stranded by ptrace/eBPF under concurrent cold builds) outliving the
// main process; cilock then never returns and the CI step force-kills at
// the 20-minute timeout. But the root pattern — exec.Cmd + MultiWriter +
// Wait + a backgrounded stdout-inheriting child — is OS-GENERAL, so this
// test reproduces it on darwin with NO bpf, NO ptrace, NO root, NO
// tracing enabled. It drives the DEFAULT (non-tracing) wait path in
// runCmd (the `err = c.Wait()` else branch), which is exactly the path a
// plain `cilock run` takes on macOS.
//
// It exercises the REAL production fix — c.WaitDelay — not merely
// context cancellation: the foreground process exits in milliseconds and
// is NEVER cancelled, so the ONLY thing that can unblock c.Wait() is the
// WaitDelay timer firing after the wrapped process exits and force-
// closing the pipes (exactly what saves the buildbox, where CI does not
// cancel cilock's context — it just hangs to the job timeout). We shorten
// commandWaitDelay to keep the suite fast while exercising that same path.
//
// RED (without the fix — no WaitDelay): Attest never returns; the select
// below trips its deadline and the test fails "HANG".
//
// GREEN (with the fix): WaitDelay force-closes the pipes shortly after
// the foreground process exits; Wait returns exec.ErrWaitDelay, which
// runCmd swallows because the wrapped command itself succeeded; Attest
// returns nil well within the deadline, AND the legitimate output
// ("started\n") is still captured — proving the fix does not truncate
// normal fast output.
//
// Unix-only (//go:build !windows): the repro shells out to `sh` and the
// stray reaper uses pgrep/syscall.Kill; the production reaping fix
// (Setpgid + group SIGKILL) is itself unix-only, so there is nothing to
// regress on Windows beyond the platform-portable WaitDelay, which is
// covered by the package building/compiling there.
func TestRunCmd_DoesNotHangOnLingeringChild(t *testing.T) {
	// Shorten the post-exit I/O wait so the force-close fires in well under
	// the test deadline. This is the SAME code path production uses at 30s;
	// we only change the duration, then restore it.
	prevDelay := commandWaitDelay
	commandWaitDelay = 750 * time.Millisecond
	t.Cleanup(func() { commandWaitDelay = prevDelay })

	// Unique per-run marker so the self-cleaning reaper can find any process
	// strayed by a RED run without ever matching an unrelated process.
	marker := fmt.Sprintf("cilock-cmdrun-hang-%d", time.Now().UnixNano())

	// The foreground `sh` prints one line of real output, then backgrounds a
	// child that inherits stdout and outlives it. The backgrounded child is a
	// TWO-statement script (`sleep 120; : <marker>`): the trailing no-op
	// statement defeats sh's single-command exec-optimization, so the
	// backgrounded sh does NOT replace its own image with `sleep` and stays
	// alive with the marker in its argv (a single `sh -c 'sleep 120' <marker>`
	// would exec away into bare `sleep 120`, discarding the marker — that is
	// the bug the earlier version of this test had). The backgrounded sh (and
	// its sleep child) hold the inherited stdout pipe write-end open, which is
	// exactly what wedges c.Wait().
	bg := fmt.Sprintf("sh -c 'sleep 120; : %s' &", marker)
	cmd := []string{"sh", "-c", "echo started; " + bg}

	// Self-cleaning: reap any process this test spawned, on both success and
	// failure, so it never leaks a long-lived sleep across runs.
	t.Cleanup(func() { killStraysByMarker(marker) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	actx, err := attestation.NewContext(
		"commandrun-hang-test",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(t.TempDir()),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}

	// silent=true keeps the child's stdout out of the test log AND, more
	// importantly, excludes os.Stdout from the MultiWriter so the ONLY thing
	// keeping the internal pipe open is the lingering child — not the test
	// process's own stdout. The capture buffers remain the first writers in
	// the MultiWriter, so output capture is still exercised.
	rc := New(
		WithCommand(cmd),
		WithTracing(false), // default cilock-run path on macOS: no ptrace/bpf/root
		WithSilent(true),
	)

	// Run Attest in a goroutine and race it against a hard deadline that is
	// generously larger than the (shortened) WaitDelay but far smaller than
	// the 120s the lingering child would otherwise hold the pipe. WITHOUT the
	// fix, Attest blocks in c.Wait() for the full 120s and this select trips
	// the timeout branch (RED). WITH the fix WaitDelay fires at ~750ms and
	// Attest returns (GREEN).
	const deadline = 10 * time.Second
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- rc.Attest(actx) }()

	select {
	case attestErr := <-done:
		elapsed := time.Since(start)
		// With the fix the wrapped command exited 0 and the WaitDelay expiry
		// is swallowed by runCmd's `errors.Is(err, exec.ErrWaitDelay)` branch,
		// so Attest must return nil. A non-nil error here is a regression
		// (e.g. ErrWaitDelay leaking out, or a spurious failure on a build
		// that actually succeeded).
		if attestErr != nil {
			t.Errorf("Attest returned non-nil err=%v after %v; runCmd must swallow "+
				"exec.ErrWaitDelay on a wrapped command that exited 0", attestErr, elapsed)
		}
		// Prove the WaitDelay path does not truncate normal output: the real
		// command's single line of stdout must survive the force-close.
		if got := rc.Data().Stdout; !strings.Contains(got, "started") {
			t.Errorf("expected captured stdout to contain %q, got %q", "started", got)
		}
		// Prove WaitDelay actually did the work: the foreground process exits
		// in ms, so a return must come AFTER the delay window (it cannot
		// complete before the pipes are force-closed).
		if elapsed < commandWaitDelay {
			t.Errorf("Attest returned in %v, faster than the WaitDelay window %v — "+
				"the lingering-child pipe should have blocked Wait until force-close",
				elapsed, commandWaitDelay)
		}
		t.Logf("Attest returned in %v (GREEN: no hang), stdout=%q", elapsed, rc.Data().Stdout)

	case <-time.After(deadline):
		// Cancel to try to unwind, then fail. Without the fix, c.Wait() is
		// wedged on the pipe-copy goroutines and only the lingering child
		// finishing (120s) — or this cancel hitting the process group via the
		// fix's Cancel hook — can release it. Reaching here means neither
		// WaitDelay nor reaping was wired: the production hang.
		cancel()
		t.Fatalf("HANG: Attest did not return within %s — runCmd's c.Wait() is "+
			"blocked on the MultiWriter pipe-copy goroutines because the "+
			"backgrounded child still holds the inherited stdout write-end. "+
			"This is the command-run hang bug; the fix is cmd.WaitDelay (+ "+
			"process-group reaping) set in runCmd before c.Start().", deadline)
	}
}

// killStraysByMarker reaps any process this test backgrounded, so a strayed
// child does not leak a long-lived `sleep` across test runs.
//
// The backgrounded child is `sh -c 'sleep 120; : <marker>'`, which forks a
// `sleep 120` and blocks in wait() on it. The marker lands on the sh's argv
// (the `sleep` leaf carries NO marker), so `pgrep -f <marker>` finds the sh —
// but a naive `kill <sh>` would orphan the sleep to init before we could reap
// it by parent pid (a race that previously leaked sleeps). Both the sh and its
// sleep share a single process group, so we look up the sh's PGID and SIGKILL
// the WHOLE GROUP (negative pgid), reaping the sh and its sleep atomically with
// no reparent race. Verified to leave zero residual `sleep 120` across runs.
//
// Best-effort throughout: a missing pgrep or an already-gone process is a
// no-op (the OS reaps the orphan when its sleep finishes regardless).
func killStraysByMarker(marker string) {
	pgrepPath, err := exec.LookPath("pgrep")
	if err != nil {
		return
	}
	out, _ := exec.Command(pgrepPath, "-f", marker).Output()
	for _, field := range strings.Fields(string(out)) {
		pid, convErr := strconv.Atoi(field)
		if convErr != nil || pid <= 1 {
			continue
		}
		// Reap the marker process's whole group atomically. Getpgid gives the
		// pgid shared by the sh and its sleep child; SIGKILL of the negative
		// pgid kills both before the sleep can reparent. ESRCH (already gone)
		// is benign. Fall back to killing the pid itself if Getpgid fails.
		if pgid, pgErr := syscall.Getpgid(pid); pgErr == nil && pgid > 1 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
