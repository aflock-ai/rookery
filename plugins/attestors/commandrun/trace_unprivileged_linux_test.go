// jade:ring local
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

// Unprivileged tracing: the environment most customers and every coding-agent
// sandbox actually run in: a container with no eBPF, no CAP_SYS_ADMIN, and
// no-new-privileges. Measured 2026-09-24 in that shape, `cilock run --trace`
// exited 1 with "attestor command-run failed: no such process" even though
// explicit CILOCK_TRACE_MODE=ptrace traced the same command correctly. These
// tests pin the auto-fallback path end to end, WITHOUT requiring root, because
// the pre-existing ptrace e2e test skipped unless euid==0 and set the mode
// explicitly: which is exactly why the broken path was never exercised.

package commandrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"golang.org/x/sys/unix"
)

// forceEBPFUnavailable makes auto mode take the ptrace fallback on any host,
// so the test does not depend on the runner lacking CAP_BPF.
func forceEBPFUnavailable(t *testing.T) {
	t.Helper()
	prev := ebpfProbe
	ebpfProbe = func() ebpfProbeResult {
		return ebpfProbeResult{bpfSyscallExists: true, mapCreateError: "operation not permitted (forced by test)"}
	}
	t.Cleanup(func() { ebpfProbe = prev })
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test reads a fixed binary
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// autoTracedDeadline bounds one traced command. A traced helper finishes in
// seconds; without a bound, a tracee left in ptrace-stop after the tracer
// returned held c.Wait() until the 30-minute go test timeout
// (TestFailedExecveDoesNotNameTheNextExec/path, #10011's offload ring,
// 2026-09-28). The command context kills the child when this expires, and
// SIGKILL reaches a ptrace-stopped process.
const autoTracedDeadline = 3 * time.Minute

func runAutoTraced(t *testing.T, dir string, argv []string) (*CommandRun, error) {
	t.Helper()
	rc, err, timedOut := runAutoTracedWithin(t, dir, argv, autoTracedDeadline)
	if timedOut {
		t.Fatalf("traced command %q did not finish within %s and was killed (a tracee left in ptrace-stop?): %v", argv, autoTracedDeadline, err)
	}
	return rc, err
}

// runAutoTracedWithin runs argv under auto tracing with a deadline and
// reports whether the deadline killed it.
func runAutoTracedWithin(t *testing.T, dir string, argv []string, d time.Duration) (*CommandRun, error, bool) { //nolint:revive // the timed-out flag reads last
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	actx, err := attestation.NewContext("unprivileged-trace",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	if err != nil {
		t.Fatalf("attestation ctx: %v", err)
	}
	rc := New(WithCommand(argv), WithTracing(true), WithSilent(true))
	err = rc.Attest(actx)
	return rc, err, errors.Is(ctx.Err(), context.DeadlineExceeded)
}

func copyExecutable(t *testing.T, name, dstDir string) string {
	t.Helper()
	src, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("no %s", name)
	}
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(real) //nolint:gosec // test copies a system binary
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dstDir, name)
	if err := os.WriteFile(dst, b, 0o755); err != nil { //nolint:gosec // must be executable
		t.Fatal(err)
	}
	return dst
}

func findProgram(rc *CommandRun, base string) *ProcessInfo {
	for i := range rc.Processes {
		if filepath.Base(rc.Processes[i].Program) == base {
			return &rc.Processes[i]
		}
	}
	return nil
}

// TestRunTraceRefusesAnUntracedRoot: if the child was started WITHOUT ptrace
// (the auto-fallback bug), the tracer must say so plainly instead of surfacing
// a bare ESRCH from PtraceSetOptions on a reaped pid.
func TestRunTraceRefusesAnUntracedRoot(t *testing.T) {
	c := exec.Command("true")
	if err := c.Start(); err != nil {
		t.Skip("cannot start true:", err)
	}
	p := &ptraceContext{
		parentPid:   c.Process.Pid,
		mainProgram: c.Path,
		processes:   make(map[int]*ProcessInfo),
		hash:        defaultHashes(),
	}
	err := p.runTrace()
	if err == nil {
		t.Fatal("runTrace on an untraced child must fail")
	}
	if errors.Is(err, syscall.ESRCH) || !strings.Contains(err.Error(), "not stopped under ptrace") {
		t.Fatalf("runTrace error = %v; want a stated 'not stopped under ptrace' refusal, not ESRCH", err)
	}
}

// TestLostSyscallStopIsCountedNotFatal: a syscall stop whose registers cannot
// be read (the process vanished: here, a reaped pid) is a counted gap, never
// an attestor failure.
func TestLostSyscallStopIsCountedNotFatal(t *testing.T) {
	c := exec.Command("true")
	if err := c.Run(); err != nil {
		t.Skip("cannot run true:", err)
	}
	gone := c.ProcessState.Pid()
	p := &ptraceContext{processes: make(map[int]*ProcessInfo), hash: defaultHashes()}
	p.handleSyscallStop(gone)
	p.handleSyscallStop(gone)
	if p.syscallStopsLost != 2 {
		t.Fatalf("syscallStopsLost = %d, want 2", p.syscallStopsLost)
	}
	if err := unix.Kill(gone, 0); err == nil {
		t.Log("note: pid was recycled; the read still failed because it is not our tracee")
	}
}
