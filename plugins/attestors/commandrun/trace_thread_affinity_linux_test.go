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

package commandrun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"golang.org/x/sys/unix"
)

// occupyCallerThread parks a new goroutine, locked, on the OS thread the
// caller is running on. From then on the caller can only run on some other
// thread, unless the caller is itself locked to this one: then the parked
// goroutine can never be scheduled here, and occupation fails. release frees
// the thread.
func occupyCallerThread(attempts int) (release func(), occupied bool) {
	for range attempts {
		want := unix.Gettid()
		ready := make(chan bool)
		done := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if unix.Gettid() != want {
				ready <- false
				return
			}
			ready <- true
			<-done
		}()
		if <-ready {
			return func() { close(done) }, true
		}
	}
	return func() {}, false
}

// A PTRACE_TRACEME child is traced by the THREAD that forked it, and only
// that thread may issue ptrace requests to it. runCmd started the tracee from
// an unlocked goroutine, and runTrace locked whichever thread the goroutine
// happened to be on later. When the scheduler moved the goroutine in between,
// the first request (PtraceSetOptions) failed with ESRCH, runTrace returned
// with the child still held in its exec stop, and c.Wait() blocked forever:
// #10481, "no such process" after the 3-minute bound in merge_group run
// 36434227303. Under load the scheduler does this on its own; this test does
// it on purpose, by parking a locked goroutine on the forking thread.
func TestPtraceTracerStaysOnTheForkingThread(t *testing.T) {
	forceEBPFUnavailable(t)
	t.Setenv(EnvVarTraceMode, "")
	t.Setenv(EnvVarFanotify, "off")
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}

	release, occupied := func() {}, false
	prev := afterTraceeStart
	afterTraceeStart = func() { release, occupied = occupyCallerThread(100) }
	t.Cleanup(func() { afterTraceeStart = prev })

	_, err, timedOut := runAutoTracedWithin(t, t.TempDir(), []string{sh, "-c", "true"}, 15*time.Second)
	release()
	if timedOut {
		t.Fatalf("traced command hung and was killed after 15s (tracer on the wrong thread?): %v", err)
	}
	if err != nil {
		t.Fatalf("traced run failed: %v", err)
	}
	if occupied {
		t.Fatal("another goroutine took the thread that forked the tracee: runCmd's goroutine was not locked to it")
	}
}

// Whatever makes runTrace fail, trace() must not return with the tracee still
// in ptrace-stop: runCmd's c.Wait() comes next and would block forever. The
// failure forced here is the #10481 one, a tracer on the wrong thread: the
// child is started from a goroutine locked to one thread, and trace() is
// called from another.
func TestPtraceTraceErrorKillsTheTracee(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	c := exec.CommandContext(context.Background(), sleep, "30") //nolint:gosec // fixed test binary
	configureProcessReaping(c)
	configureTraceeForMode(c, traceModePtrace)

	// The forking thread must outlive the trace: a tracer thread that exits
	// detaches its tracees, and the child would then run untraced.
	started := make(chan error)
	release := make(chan struct{})
	defer close(release)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		started <- c.Start()
		<-release
	}()
	if err := <-started; err != nil {
		t.Fatalf("start: %v", err)
	}

	actx, err := attestation.NewContext("trace-error", []attestation.Attestor{},
		attestation.WithContext(context.Background()),
		attestation.WithHashes(defaultHashes()))
	if err != nil {
		t.Fatalf("attestation ctx: %v", err)
	}
	rc := New(WithCommand(c.Args), WithTracing(true), WithSilent(true))
	rc.resolvedTraceBackend = traceModePtrace.String()
	_, err = rc.trace(c, actx)
	if err == nil {
		t.Fatal("trace() from a thread that is not the tracee's tracer returned no error")
	}
	if !strings.Contains(err.Error(), "tracer thread") {
		t.Errorf("error does not name the tracer-thread mismatch: %v", err)
	}

	waited := make(chan struct{})
	go func() { _ = c.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		_ = unix.Kill(-c.Process.Pid, unix.SIGKILL)
		<-waited
		t.Fatal("the tracee was still alive 10s after trace() failed: it was left in ptrace-stop")
	}
}

// A trace that fails AFTER its options are installed holds running tracees
// that are not the command's own child. Killing them is not enough: with
// PTRACE_O_TRACEEXIT a killed tracee can stop at PTRACE_EVENT_EXIT until the
// tracer resumes it, and a dead tracee's zombie waits for the TRACER to reap
// it. So after trace() fails, no pid it traced may be stopped or still held
// by the tracer, including a child whose first stop arrived but was never
// recorded.
func TestPtraceTraceErrorAfterSetupLeavesNoTracee(t *testing.T) {
	cases := []struct {
		name string
		// fault reports whether to fail the trace at this wait.
		fault func(reported int, known []int) bool
	}{
		{"once a second tracee is recorded", func(_ int, known []int) bool {
			return len(known) >= 2
		}},
		{"at a new child's first stop, before it is recorded", func(reported int, known []int) bool {
			return !slices.Contains(known, reported)
		}},
		// The hardest shape: a descendant in its OWN session, so the kill of
		// the command's process group misses it, left at a stop the loop
		// consumed and never resumed, so the kernel reports nothing more for
		// it, and never recorded.
		{"at the unrecorded first stop of a descendant in another session", func(reported int, known []int) bool {
			if slices.Contains(known, reported) {
				return false
			}
			root, err1 := unix.Getsid(known[0])
			sid, err2 := unix.Getsid(reported)
			return err1 == nil && err2 == nil && sid != root
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forceEBPFUnavailable(t)
			t.Setenv(EnvVarTraceMode, "")
			t.Setenv(EnvVarFanotify, "off")
			sh, err := exec.LookPath("sh")
			if err != nil {
				t.Skip("no sh")
			}
			sleep, err := exec.LookPath("sleep")
			if err != nil {
				t.Skip("no sleep")
			}
			setsid, err := exec.LookPath("setsid")
			if err != nil {
				t.Skip("no setsid")
			}
			// The command runs a sleep in the background, and a setsid'd
			// shell whose own background sleep is born in the new session.
			script := sleep + " 30 & " + setsid + " " + sh + " -c '" + sleep + " 30 & wait' & " + sleep + " 30; wait"

			var traced []int
			prev := ptraceLoopFault
			ptraceLoopFault = func(reported int, known []int) error {
				if !tc.fault(reported, known) {
					return nil
				}
				traced = append(slices.Clone(known), reported)
				return errForcedTraceFault
			}
			t.Cleanup(func() { ptraceLoopFault = prev })

			_, err, timedOut := runAutoTracedWithin(t, t.TempDir(), []string{sh, "-c", script}, 15*time.Second)
			if timedOut {
				t.Fatalf("a trace that failed after setup hung until the 15s bound: %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), errForcedTraceFault.Error()) {
				t.Fatalf("the forced trace fault did not fail the attestor: %v", err)
			}
			if len(traced) < 2 {
				t.Fatalf("the fault never fired past the root (pids %v)", traced)
			}
			// A zombie the tracer has already reaped belongs to its real
			// parent (the container's init, once the root died), which the
			// tracer cannot reap for. What must not survive is the TRACER's
			// hold: a stop, or any task that still names a tracer.
			for _, pid := range traced[1:] {
				state := procState(pid)
				if state == "t" || state == "T" {
					t.Errorf("tracee %d outlived the failed trace stopped (state %q)", pid, state)
				}
				if tracer := tracerPidOf(pid); tracer > 0 {
					t.Errorf("tracee %d (state %q) is still held by tracer %d after the failed trace", pid, state, tracer)
				}
			}
		})
	}
}

var errForcedTraceFault = errors.New("forced trace fault")

// procState returns the one-letter state of pid from /proc/<pid>/stat, or ""
// when pid does not exist.
func procState(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	// "pid (comm) S ...": the state follows the LAST ')', since comm may hold one.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return "?"
	}
	return s[i+2 : i+3]
}
