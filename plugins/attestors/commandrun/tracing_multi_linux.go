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

// Multi-tracer-thread event loop for the trace attestor (#167).
//
// Architecture:
//
//   - The initial tracee (the parent process spawned by exec.Cmd with
//     SysProcAttr.Ptrace=true) is owned by goroutine 0.
//
//   - When goroutine N sees PTRACE_EVENT_CLONE/FORK/VFORK for a new
//     child pid, it consults the pidSharder. If the sharder picks
//     goroutine N (sticky on first observation), the new pid stays
//     on goroutine N (no transfer cost). If the sharder picks a
//     different worker, goroutine N detaches the child with a pending
//     SIGSTOP, then spawns a new dedicated goroutine for the child.
//
//   - Each tracer goroutine:
//   - calls runtime.LockOSThread (ptrace requires same-thread Wait4)
//   - owns a SUBSET of pids; Wait4(-1, ...) returns events for any
//     of them
//   - handles syscalls synchronously (preserves TOCTOU for file hashes)
//   - on tracee exit: releases its sharder slot
//
//   - Shared state (`processes` map, `tlsPendingFDs`, etc.) is guarded
//     by ptraceContext-level locks.
//
// Opt-in via the CILOCK_TRACE_MULTI env var. Off by default until
// validated against the production CI matrix.

package commandrun

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/aflock-ai/rookery/attestation/log"
	"golang.org/x/sys/unix"
)

// EnvVarMultiTracer enables the multi-tracer-thread event loop when
// set to a truthy value ("1"/"true"/"yes"). Default off.
const EnvVarMultiTracer = "CILOCK_TRACE_MULTI"

// multiTracerEnabled reports whether multi-tracer mode is opted into.
func multiTracerEnabled() bool {
	v := os.Getenv(EnvVarMultiTracer)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// multiTracerWorkerCount returns the number of tracer goroutines to use.
// Reads CILOCK_TRACE_MULTI_N if set; defaults to GOMAXPROCS capped at 16.
func multiTracerWorkerCount() int {
	if v := os.Getenv("CILOCK_TRACE_MULTI_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	n := runtime.GOMAXPROCS(0)
	if n > 16 {
		n = 16
	}
	if n < 1 {
		n = 1
	}
	return n
}

// multiTracerState lives on ptraceContext during a multi-tracer run.
// It coordinates the worker goroutines, captures the first fatal error,
// and owns the lifecycle WaitGroup.
type multiTracerState struct {
	sharder    *pidSharder
	wg         sync.WaitGroup
	fatalErr   atomic.Pointer[error] // first fatal worker error wins

	// processesMu guards the shared `processes` map on ptraceContext.
	// Workers take RLock for getProcInfo lookups and Lock for inserts.
	processesMu sync.RWMutex

	// tlsPendingFDsMu guards `tlsPendingFDs`.
	tlsPendingFDsMu sync.Mutex

	// exitCodeOnce ensures the parent's exit code is recorded once.
	exitCodeOnce sync.Once
}

// runTraceMulti is the multi-tracer entry point. The initial parent
// process is started just like in the serial path; runTraceMulti then
// dispatches it to worker goroutine 0 and waits for all workers.
func (p *ptraceContext) runTraceMulti() error {
	defer p.retryOpenedFiles()

	// p.multi was set by runTrace before dispatch.
	if p.multi == nil {
		p.multi = &multiTracerState{
			sharder: newPIDSharder(multiTracerWorkerCount()),
		}
	}

	// Spawn the initial worker for the parent. The parent has already
	// been started by exec.Cmd with Ptrace=true; the auto-attach has
	// happened on the PARENT-tracer Go thread (the one in trace()).
	// We can't just spawn a new goroutine and have it ptrace the parent
	// because the kernel sees the original tracer thread as the owner.
	// Detach + reattach.
	if err := unix.PtraceDetach(p.parentPid); err != nil {
		// First-time detach during stop is benign if the parent isn't
		// fully stopped yet; try a soft path. If it really failed, fall
		// back to serial.
		return fmt.Errorf("multi-tracer detach parent: %w (fallback to serial recommended)", err)
	}

	// Send SIGSTOP so the parent doesn't run before the new worker attaches.
	if err := syscall.Kill(p.parentPid, syscall.SIGSTOP); err != nil {
		return fmt.Errorf("multi-tracer kill SIGSTOP parent: %w", err)
	}

	p.multi.wg.Add(1)
	go p.tracerWorker(p.parentPid, true /*isRoot*/)
	p.multi.wg.Wait()

	if errp := p.multi.fatalErr.Load(); errp != nil {
		return *errp
	}
	return nil
}

// tracerWorker owns a single tracee (rootPid) and ALL of its children
// that the sharder routes to this worker. The goroutine pins itself to
// an OS thread for the entire run because ptrace operations are tied
// to the thread that attached.
//
// isRoot=true means this is the initial parent process; we also stash
// its exit code on the ptraceContext when it exits.
func (p *ptraceContext) tracerWorker(rootPid int, isRoot bool) {
	defer p.multi.wg.Done()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Attach to rootPid. The kernel sends us a SIGSTOP via the attach.
	if err := unix.PtraceAttach(rootPid); err != nil {
		p.multi.fatalErr.CompareAndSwap(nil, &err)
		return
	}

	// Drain the attach SIGSTOP.
	var status unix.WaitStatus
	if _, err := unix.Wait4(rootPid, &status, 0, nil); err != nil {
		p.multi.fatalErr.CompareAndSwap(nil, &err)
		return
	}

	if err := unix.PtraceSetOptions(rootPid,
		unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|
			unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		p.multi.fatalErr.CompareAndSwap(nil, &err)
		return
	}

	if isRoot {
		procInfo := p.getProcInfo(rootPid)
		procInfo.Program = p.mainProgram
	}

	if err := unix.PtraceSyscall(rootPid, 0); err != nil {
		p.multi.fatalErr.CompareAndSwap(nil, &err)
		return
	}

	// Track our owned pids so we know when to exit.
	owned := map[int]bool{rootPid: true}

	for {
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			if errors.Is(err, syscall.ECHILD) {
				return // no more children
			}
			p.multi.fatalErr.CompareAndSwap(nil, &err)
			return
		}

		// Exit / signal handling.
		if status.Exited() {
			pInfo := p.getProcInfo(pid)
			pInfo.ExitCode = status.ExitStatus()
			delete(owned, pid)
			p.multi.sharder.Release(pid)
			if isRoot && pid == rootPid {
				p.multi.exitCodeOnce.Do(func() { p.exitCode = status.ExitStatus() })
				return
			}
			if len(owned) == 0 {
				return
			}
			continue
		}
		if status.Signaled() {
			pInfo := p.getProcInfo(pid)
			pInfo.ExitCode = 128 + int(status.Signal())
			delete(owned, pid)
			p.multi.sharder.Release(pid)
			if isRoot && pid == rootPid {
				p.multi.exitCodeOnce.Do(func() { p.exitCode = 128 + int(status.Signal()) })
				return
			}
			if len(owned) == 0 {
				return
			}
			continue
		}

		sig := status.StopSignal()
		injectedSig := int(sig)
		isPtraceTrap := (unix.SIGTRAP | unix.PTRACE_EVENT_STOP) == sig
		if status.Stopped() && isPtraceTrap {
			injectedSig = 0
			if err := p.nextSyscall(pid); err != nil {
				log.Debugf("(multi-tracing) syscall handler error: %v", err)
			}

			// Check for clone/fork/vfork events — these introduce a
			// new pid we may want to hand off.
			cause := status.TrapCause()
			switch cause {
			case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
				newPid, mErr := unix.PtraceGetEventMsg(pid)
				if mErr == nil && newPid > 0 {
					// Sharder decides where the new tracee lives.
					targetWorker := p.multi.sharder.WorkerFor(int(newPid))
					selfWorker := p.multi.sharder.WorkerFor(pid)
					if targetWorker != selfWorker {
						// Detach the new child and hand off to a new
						// worker goroutine.
						p.handOffTracee(int(newPid))
					} else {
						// Stays on us. Kernel auto-attaches; mark it
						// owned and SetOptions.
						owned[int(newPid)] = true
						_ = unix.PtraceSetOptions(int(newPid),
							unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|
								unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_TRACEVFORK|
								unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE)
					}
				}
			}
		}

		if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
			log.Debugf("(multi-tracing) ptrace syscall resume error: %v", err)
		}
	}
}

// handOffTracee detaches a newly-cloned tracee from the current worker
// and spawns a new worker goroutine to attach it. The new child has
// been auto-attached to the calling thread by the kernel via
// PTRACE_O_TRACECLONE; we detach with SIGSTOP queued so it stays
// suspended until the new worker can attach.
func (p *ptraceContext) handOffTracee(newPid int) {
	// Wait for the new child's initial SIGSTOP-after-clone before we
	// detach it. The auto-attach delivers a SIGSTOP that we need to
	// consume so the kernel knows the tracee is in a ptrace-stopped
	// state.
	var status unix.WaitStatus
	_, _ = unix.Wait4(newPid, &status, 0, nil)

	// Detach + queue SIGSTOP so the child stays put.
	if err := unix.PtraceDetach(newPid); err != nil {
		log.Debugf("(multi-tracing) detach %d for handoff: %v", newPid, err)
		return
	}
	if err := syscall.Kill(newPid, syscall.SIGSTOP); err != nil {
		log.Debugf("(multi-tracing) sigstop %d after detach: %v", newPid, err)
		return
	}

	p.multi.wg.Add(1)
	go p.tracerWorker(newPid, false /*isRoot*/)
}

// Multi-tracer-safe accessors are folded into getProcInfo on
// ptraceContext (it checks p.multi != nil and locks accordingly).
// No additional helper needed here.
