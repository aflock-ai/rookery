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

func runAutoTraced(t *testing.T, dir string, argv []string) (*CommandRun, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
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
	return rc, rc.Attest(actx)
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

// TestAutoFallbackToPtraceTracesTheTree is the customer shape: default
// CILOCK_TRACE_MODE (auto), no eBPF, fanotify off. Before the fix the child
// was never put under ptrace and the attestor failed with ESRCH.
func TestAutoFallbackToPtraceTracesTheTree(t *testing.T) {
	forceEBPFUnavailable(t)
	t.Setenv(EnvVarTraceMode, "")
	t.Setenv(EnvVarFanotify, "off")

	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(input, []byte("unprivileged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Copy the images we exec into the test dir so their bytes are known and
	// DISTINCT: a digest of one program recorded against another is the
	// failure the exec-stop fix exists to prevent.
	sh := copyExecutable(t, "sh", filepath.Join(dir, "bin"))
	// sh, cat and ls run from COPIES in the test dir. When that dir is on a
	// filesystem the kernel owns (tmpfs, ext4), the ptrace backend can claim
	// a mapped-image digest; measured at execve ENTRY, /proc/<pid>/exe is
	// still the shell, so the shell's digest would be signed as cat's.
	catPath := copyExecutable(t, "cat", filepath.Join(dir, "bin"))
	lsPath := copyExecutable(t, "ls", filepath.Join(dir, "bin"))
	script := catPath + " " + input + " >/dev/null; " + lsPath + " >/dev/null"
	rc, err := runAutoTraced(t, dir, []string{sh, "-c", script})
	if err != nil {
		t.Fatalf("auto-mode ptrace fallback must trace, not fail: %v", err)
	}
	if rc.resolvedTraceBackend != traceModePtrace.String() {
		t.Fatalf("backend = %q, want %q", rc.resolvedTraceBackend, traceModePtrace.String())
	}

	for _, want := range []struct {
		base, path string
	}{{filepath.Base(sh), sh}, {"cat", catPath}, {"ls", lsPath}} {
		p := findProgram(rc, want.base)
		if p == nil {
			got := make([]string, 0, len(rc.Processes))
			for i := range rc.Processes {
				got = append(got, rc.Processes[i].Program)
			}
			t.Fatalf("no process for %s; programs=%v", want.base, got)
		}
		if len(p.OpenedFiles) == 0 {
			t.Errorf("%s: no openedfiles recorded", want.base)
		}
		if len(p.ExeDigest) == 0 {
			t.Errorf("%s: no exedigest recorded", want.base)
			continue
		}
		// The recorded image digest must be the digest of THIS program's
		// bytes (resolved through symlinks, as execve does).
		real, rerr := filepath.EvalSymlinks(want.path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		wantHex := fileSHA256(t, real)
		if got := firstHex(p.ExeDigest); got != wantHex {
			t.Errorf("%s: exedigest %s (source %q) is not the digest of %s (%s)",
				want.base, got, p.ExeDigestSource, real, wantHex)
		}
		// comm is read from the tracee: it must name the new image, not the
		// shell that forked it.
		if want.base != filepath.Base(sh) && p.Comm != want.base {
			t.Errorf("%s: comm = %q, want the post-exec name", want.base, p.Comm)
		}
	}
	if _, ok := findProgram(rc, "cat").OpenedFiles[input]; !ok {
		t.Errorf("cat's open of %s was not recorded", input)
	}
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
