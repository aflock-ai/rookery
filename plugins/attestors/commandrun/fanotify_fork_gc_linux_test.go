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
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
)

// THE FORK/FANOTIFY/GC DEADLOCK.
//
// Go starts a child with clone(CLONE_VFORK|CLONE_VM) (syscall/exec_linux.go),
// and the forking thread holds m.locks, so it cannot be preempted until the
// child execs. The child's execve opens the binary and its ELF interpreter,
// and with the fanotify gate armed each open is a FAN_OPEN_PERM event that
// only THIS process's handler goroutines can answer. If a GC stop-the-world
// begins in that window it waits for the forking thread, which waits for the
// exec, which waits for a handler the stop-the-world has frozen. Nothing in
// the process runs again, including go test's own -timeout alarm.
//
// Observed on buildbox docker-runner-40: TestProveTracedStep's `cilock run
// --trace` sat 94+ minutes with its tracee in D state in
// fanotify_get_response, and every other open on that filesystem (the runner's
// .NET worker, `docker exec`) queued behind it.
//
// Because a deadlocked process cannot time itself out, the stress runs in a
// re-executed child and THIS process is the watchdog.
const fanotifyForkGCChildEnv = "COMMANDRUN_FANOTIFY_FORK_GC_CHILD"

func TestFanotifyArmedTracedStartSurvivesGCPressure(t *testing.T) {
	if os.Getenv(fanotifyForkGCChildEnv) == "1" {
		fanotifyForkGCStress(t)
		return
	}
	if err := fanotifyProbe(t.TempDir()); err != nil {
		t.Skipf("fanotify permission events are unavailable here (%v); this deadlock needs CAP_SYS_ADMIN", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFanotifyArmedTracedStartSurvivesGCPressure$", "-test.count=1") //nolint:gosec // this test binary
	c.Env = append(os.Environ(), fanotifyForkGCChildEnv+"=1")
	out, err := c.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("traced runs with fanotify armed under GC pressure did not finish in 150s: the vfork child is "+
			"waiting on a FAN_OPEN_PERM answer the stopped-the-world handler can never give\n%s", tail(out))
	}
	if err != nil {
		t.Fatalf("stress child failed: %v\n%s", err, tail(out))
	}
}

// fanotifyForkGCStress runs many fanotify-armed traced starts while another
// goroutine keeps the collector cycling, so a stop-the-world lands inside a
// vfork window if one can.
func fanotifyForkGCStress(t *testing.T) {
	forceEBPFUnavailable(t)
	t.Setenv(EnvVarTraceMode, "ptrace")
	t.Setenv(EnvVarFanotify, "1") // required: a run without the gate proves nothing

	prev := debug.SetGCPercent(1)
	defer debug.SetGCPercent(prev)
	var stop atomic.Bool
	defer stop.Store(true)
	go func() {
		var keep [][]byte
		for !stop.Load() {
			keep = append(keep, make([]byte, 256<<10))
			if len(keep) > 16 {
				keep = keep[1:]
			}
		}
	}()

	// The binary is copied INTO the marked filesystem: its exec open must be a
	// FAN_OPEN_PERM event, or no fork can ever wait on the handler and the
	// stress proves nothing.
	dir := t.TempDir()
	truePath := copyExecutable(t, "true", dir)
	// Progress goes to stderr so a timed-out parent can tell a run that
	// STOPPED (deadlock) from one that was merely slow.
	began := time.Now()
	// 100 runs: on buildbox (24 cores, kernel 7.0) main deadlocked before run
	// 25, and the fix ran 400 in 115s, so this is ~30s green with a wide
	// margin under the parent's 150s watchdog.
	for i := 0; i < 100; i++ {
		if i%25 == 0 {
			fmt.Fprintf(os.Stderr, "fanotify-fork-gc: run %d at %s\n", i, time.Since(began).Round(time.Millisecond))
		}
		actx, err := attestation.NewContext("fanotify-fork-gc", []attestation.Attestor{},
			attestation.WithWorkingDir(dir), attestation.WithHashes(defaultHashes()))
		if err != nil {
			t.Fatalf("attestation ctx: %v", err)
		}
		rc := New(WithCommand([]string{truePath}), WithTracing(true), WithSilent(true))
		if err := rc.Attest(actx); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if rc.fanotifyOutcome.State != fanotifyActive {
			t.Fatalf("run %d: the fanotify gate was not active (%s); the stress proves nothing", i, rc.fanotifyOutcome.Reason)
		}
	}
}

func tail(b []byte) string {
	if len(b) > 4000 {
		b = b[len(b)-4000:]
	}
	return string(b)
}
