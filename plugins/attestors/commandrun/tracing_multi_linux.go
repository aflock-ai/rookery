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

// Multi-tracer-thread event loop V2 (#167).
//
// Architecture: fixed worker pool of N goroutines, each pinned to its
// own OS thread via runtime.LockOSThread. Each worker runs its own
// Wait4 loop and handles MULTIPLE tracees (sticky-assigned by the
// pidSharder). New tracees enter the pool via per-worker channels.
//
// The Wait4/channel interleaving uses WNOHANG polling + runtime.Gosched
// (Option A from the V2 design doc). Brief CPU yield between empty
// polls. Workers with no owned tracees BLOCK on their incoming channel
// to avoid burning idle CPU.
//
// Pid handoff at CLONE/FORK/VFORK:
//
//   discovering worker A:
//     1. Wait4(newPid, ..) — consume the auto-attach SIGSTOP
//     2. target := sharder.WorkerFor(newPid)
//     3. if target == A: keep on A, set options, continue
//        else:
//          PtraceDetach(newPid)         // release kernel attach
//          kill(newPid, SIGSTOP)         // queue stop signal
//          workers[target].incoming <- newPid
//          target worker: attach, setopts, continue
//
// Shared state on ptraceContext (processes map, tlsPendingFDs) is
// guarded by sync.RWMutex / sync.Mutex when multi mode is active.
// Per-process ProcessInfo slices are mutated only by the owning worker
// — no per-process lock needed.
//
// Opt-in via CILOCK_TRACE_MULTI=1. CILOCK_TRACE_MULTI_N overrides
// worker count (default = GOMAXPROCS, capped at 16).
// CILOCK_TRACE_MULTI_STATS=1 prints per-worker stats at trace end.

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
	"time"

	"github.com/aflock-ai/rookery/attestation/log"
	"golang.org/x/sys/unix"
)

// ptraceDetachWithSignal calls ptrace(PTRACE_DETACH, pid, 0, sig)
// directly. The wrapped form in golang.org/x/sys/unix passes sig=0
// (resume cleanly); we need to pass SIGSTOP so the tracee stays
// stopped after detach, eliminating the race window between detach
// and the receiving worker's attach.
func ptraceDetachWithSignal(pid int, sig syscall.Signal) error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PTRACE,
		uintptr(unix.PTRACE_DETACH),
		uintptr(pid),
		0,
		uintptr(sig),
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

const (
	// EnvVarMultiTracer enables the multi-tracer-thread event loop.
	EnvVarMultiTracer = "CILOCK_TRACE_MULTI"
	// EnvVarMultiTracerN overrides the worker count.
	EnvVarMultiTracerN = "CILOCK_TRACE_MULTI_N"
	// EnvVarMultiTracerStats prints per-worker stats at trace end.
	EnvVarMultiTracerStats = "CILOCK_TRACE_MULTI_STATS"

	// incomingCap is the per-worker handoff channel capacity. Sized to
	// absorb fork-bomb spikes without backpressure-blocking the sender.
	incomingCap = 256

	// idleSleepNs throttles WNOHANG polling when channel + Wait4 are
	// both empty. Trades a tiny latency for not pegging a core.
	idleSleepNs = 100 * time.Microsecond
)

func multiTracerEnabled() bool {
	v := os.Getenv(EnvVarMultiTracer)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func multiTracerStatsEnabled() bool {
	v := os.Getenv(EnvVarMultiTracerStats)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func multiTracerWorkerCount() int {
	if v := os.Getenv(EnvVarMultiTracerN); v != "" {
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

// tracerWorkerStats records per-worker counters for diagnostics.
// Atomic-incremented from the worker's own goroutine (no cross-worker
// contention).
type tracerWorkerStats struct {
	events    uint64 // syscall events handled
	handoffIn uint64 // pids attached via channel
	handoffOut uint64 // pids handed to other workers
	keptLocal uint64 // pids kept on this worker (no handoff)
	exits     uint64 // owned tracees that exited
	wnohangEmpty uint64 // Wait4(WNOHANG) returned 0 (poll miss)
	idleSleeps uint64 // entered idleSleepNs
}

// tracerWorker owns a SUBSET of tracees and processes their events on
// a dedicated OS thread.
type tracerWorker struct {
	id       int
	pctx     *ptraceContext
	incoming chan int          // new pids to attach
	owned    map[int]struct{}  // tracees currently owned by this worker
	stats    tracerWorkerStats
}

// multiTracerState lives on ptraceContext during a multi-tracer run.
type multiTracerState struct {
	sharder  *pidSharder
	workers  []*tracerWorker
	wg       sync.WaitGroup
	fatalErr atomic.Pointer[error]

	processesMu     sync.RWMutex
	tlsPendingFDsMu sync.Mutex
	exitCodeOnce    sync.Once
	shutdownOnce    sync.Once

	// shutdown is closed when the trace is over (parent exited or a
	// fatal error occurred). All workers select on it to break out of
	// any blocking channel receive.
	shutdown chan struct{}

	statsEnabled bool
}

// shutdownOnce guards the close of the shutdown channel. Separate
// from exitCodeOnce because workers may signal shutdown for non-exit
// reasons (e.g., fatal error) where exit code isn't applicable.
//
// signalShutdown closes the shutdown channel exactly once. Safe to
// call from any worker.
func (m *multiTracerState) signalShutdown() {
	m.shutdownOnce.Do(func() {
		close(m.shutdown)
	})
}

// runTraceMulti is the V2 entry. p.multi was initialized by runTrace
// before dispatch. The initial parent has been started by exec.Cmd
// with SysProcAttr.Ptrace=true and auto-attached to THIS goroutine's
// OS thread. We detach it and hand it to worker 0 so all tracee
// ownership runs through the worker pool.
func (p *ptraceContext) runTraceMulti() error {
	defer p.retryOpenedFiles()
	defer p.maybePrintStats()

	if p.multi == nil {
		p.multi = &multiTracerState{
			sharder:      newPIDSharder(multiTracerWorkerCount()),
			shutdown:     make(chan struct{}),
			statsEnabled: multiTracerStatsEnabled(),
		}
	} else if p.multi.shutdown == nil {
		p.multi.shutdown = make(chan struct{})
	}

	n := multiTracerWorkerCount()
	p.multi.workers = make([]*tracerWorker, n)
	for i := 0; i < n; i++ {
		w := &tracerWorker{
			id:       i,
			pctx:     p,
			incoming: make(chan int, incomingCap),
			owned:    make(map[int]struct{}, 16),
		}
		p.multi.workers[i] = w
	}

	// Detach the parent atomically with SIGSTOP delivery. This avoids
	// the race window where a sig=0 detach resumes the tracee briefly
	// before a follow-up Kill catches it.
	if err := ptraceDetachWithSignal(p.parentPid, syscall.SIGSTOP); err != nil {
		return fmt.Errorf("multi-tracer: detach-with-SIGSTOP parent: %w", err)
	}

	// Assign root to worker 0 via the sharder so subsequent CLONE
	// children get balanced choices.
	_ = p.multi.sharder.WorkerFor(p.parentPid) // worker 0 (first call)
	p.multi.workers[0].incoming <- p.parentPid

	// Start all workers.
	for _, w := range p.multi.workers {
		p.multi.wg.Add(1)
		go w.run()
	}

	// Mark the parent root in case the worker sets it before our wait.
	p.getProcInfo(p.parentPid).Program = p.mainProgram

	p.multi.wg.Wait()

	if errp := p.multi.fatalErr.Load(); errp != nil {
		return *errp
	}
	return nil
}

// run is the worker's event loop. Pinned to one OS thread for the
// entire lifetime so ptrace operations stay on the attaching thread.
func (w *tracerWorker) run() {
	defer w.pctx.multi.wg.Done()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var status unix.WaitStatus

	for {
		// 0. Drain incoming channel non-blockingly so new handoffs
		// take effect before we (re-)enter Wait4. This is the only
		// place new pids enter `owned`.
		drained := true
		for drained {
			select {
			case pid, ok := <-w.incoming:
				if !ok {
					return
				}
				if err := w.attach(pid); err != nil {
					log.Debugf("(multi w=%d) attach pid %d: %v", w.id, pid, err)
					continue
				}
				w.owned[pid] = struct{}{}
				atomic.AddUint64(&w.stats.handoffIn, 1)
			default:
				drained = false
			}
		}

		// 1. If shutdown was signaled and we have nothing to do, exit.
		select {
		case <-w.pctx.multi.shutdown:
			if len(w.owned) == 0 {
				return
			}
			// Otherwise keep processing — abandoning owned tracees
			// mid-stop could leave them stuck. Process events until
			// owned drains naturally.
		default:
		}

		// 2. If we own nothing, BLOCK on the channel OR shutdown.
		// This is the idle path — no CPU burn.
		if len(w.owned) == 0 {
			select {
			case pid, ok := <-w.incoming:
				if !ok {
					return
				}
				if err := w.attach(pid); err != nil {
					log.Debugf("(multi w=%d) attach pid %d: %v", w.id, pid, err)
					continue
				}
				w.owned[pid] = struct{}{}
				atomic.AddUint64(&w.stats.handoffIn, 1)
				continue
			case <-w.pctx.multi.shutdown:
				return
			}
		}

		// 3. BLOCKING Wait4 for any owned tracee. Cost: a new handoff
		// in the channel waits until our next ptrace stop wakes us
		// (bounded by the next syscall from one of our owned tracees;
		// trace attestor workloads have frequent syscalls so this is
		// sub-millisecond in practice).
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			if errors.Is(err, syscall.ECHILD) {
				// No more children. Clear owned defensively and loop.
				for opid := range w.owned {
					w.pctx.multi.sharder.Release(opid)
					delete(w.owned, opid)
				}
				continue
			}
			if errors.Is(err, syscall.EINTR) {
				// Spurious wake (e.g., from Go runtime signal). Loop.
				continue
			}
			w.pctx.multi.fatalErr.CompareAndSwap(nil, &err)
			w.pctx.multi.signalShutdown()
			return
		}

		// 4. Process the event.
		w.processEvent(pid, status)
	}
}

// attach acquires kernel ownership of pid for this worker. The pid is
// in TASK_STOPPED (job-control stop from ptrace_detach-with-SIGSTOP)
// when handed off, or in T_TRACED for the initial parent.
//
// We pass WUNTRACED so Wait4 reports the existing TASK_STOPPED state
// without requiring a fresh state transition. This avoids a deadlock
// where the attach SIGSTOP races with a tracee already stopped.
func (w *tracerWorker) attach(pid int) error {
	if err := unix.PtraceAttach(pid); err != nil {
		return fmt.Errorf("PtraceAttach(%d): %w", pid, err)
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(pid, &status, unix.WUNTRACED, nil); err != nil {
		return fmt.Errorf("wait attach %d: %w", pid, err)
	}
	if err := unix.PtraceSetOptions(pid,
		unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|
			unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		return fmt.Errorf("PtraceSetOptions(%d): %w", pid, err)
	}
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		return fmt.Errorf("PtraceSyscall(%d): %w", pid, err)
	}
	return nil
}

// processEvent handles one ptrace stop for `pid`. Same semantics as
// the serial runTrace loop, but scoped to this worker.
func (w *tracerWorker) processEvent(pid int, status unix.WaitStatus) {
	atomic.AddUint64(&w.stats.events, 1)
	p := w.pctx

	// Exit / signal handling — pid leaves our ownership.
	if status.Exited() {
		pInfo := p.getProcInfo(pid)
		pInfo.ExitCode = status.ExitStatus()
		delete(w.owned, pid)
		atomic.AddUint64(&w.stats.exits, 1)
		p.multi.sharder.Release(pid)
		if pid == p.parentPid {
			p.multi.exitCodeOnce.Do(func() { p.exitCode = status.ExitStatus() })
			p.multi.signalShutdown()
		}
		return
	}
	if status.Signaled() {
		pInfo := p.getProcInfo(pid)
		pInfo.ExitCode = 128 + int(status.Signal())
		delete(w.owned, pid)
		atomic.AddUint64(&w.stats.exits, 1)
		p.multi.sharder.Release(pid)
		if pid == p.parentPid {
			p.multi.exitCodeOnce.Do(func() { p.exitCode = 128 + int(status.Signal()) })
			p.multi.signalShutdown()
		}
		return
	}

	sig := status.StopSignal()
	injectedSig := int(sig)
	if status.Stopped() {
		isPtraceTrap := (unix.SIGTRAP | unix.PTRACE_EVENT_STOP) == sig
		cause := status.TrapCause()

		if isPtraceTrap {
			// Syscall enter/exit stop — TRACESYSGOOD-flagged SIGTRAP.
			injectedSig = 0
			if err := p.nextSyscall(pid); err != nil {
				log.Debugf("(multi w=%d) syscall handler error: %v", w.id, err)
			}
		} else if cause > 0 {
			// Ptrace event stop (CLONE/FORK/VFORK/EXEC/EXIT). The
			// signal is SIGTRAP without TRACESYSGOOD — suppress
			// injection so we don't deliver SIGTRAP to the tracee.
			injectedSig = 0
			switch cause {
			case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
				newPid, mErr := unix.PtraceGetEventMsg(pid)
				if mErr == nil && newPid > 0 {
					w.routeNewTracee(int(newPid))
				}
			}
		}
		// Otherwise: real signal stop (e.g., SIGCHLD). Inject as-is.
	}

	if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
		log.Debugf("(multi w=%d) ptrace syscall resume %d: %v", w.id, pid, err)
	}
}

// routeNewTracee processes a CLONE/FORK/VFORK event by adding the new
// pid to THIS worker's owned set.
//
// NOTE on transfer: cross-thread pid transfer via DETACH-with-SIGSTOP
// + remote ATTACH was investigated and found to be racy in the Linux
// ptrace API. After PTRACE_DETACH(pid, sig=SIGSTOP), the tracee
// transitions to TASK_STOPPED (job-control stop). The remote tracer's
// PTRACE_ATTACH succeeds but Wait4 either blocks (without WUNTRACED)
// or returns the stale stopped state, and subsequent PTRACE_SYSCALL
// on a job-control-stopped tracee doesn't reliably re-enter ptrace
// trace mode. PTRACE_SEIZE + PTRACE_INTERRUPT was the cleanest
// alternative but adds a DETACH-RESUME window during which syscalls
// from the tracee are MISSED (a correctness regression).
//
// For a single trace tree, this means parallelism is bounded by the
// kernel's per-thread ptrace ownership — the worker pool is in place
// for future multi-trace use cases (e.g., concurrent attestation of
// multiple independent builds), but a single-build trace funnels
// through one worker.
//
// The performance wins for ptrace-based tracing live elsewhere:
//   - seccomp-BPF prefilter (reduces stops ~10-20x at the kernel)
//   - eBPF (future) — in-kernel capture, no userspace round-trip
func (w *tracerWorker) routeNewTracee(newPid int) {
	// Don't explicitly Wait4(newPid) here — the new tracee's first
	// SIGSTOP (from kernel auto-attach via PTRACE_O_TRACECLONE) will
	// be picked up by the main Wait4(-1, ...) loop. Blocking here
	// can deadlock when multiple CLONE events fire close together.
	//
	// We add to `owned` so the main loop knows this pid is ours, and
	// the first stop event we get for newPid will be processed in
	// processEvent — which sets options on first sight (any subsequent
	// state-handling).
	w.owned[newPid] = struct{}{}
	atomic.AddUint64(&w.stats.keptLocal, 1)
}

// maybePrintStats writes the per-worker stats summary to a file (path
// from CILOCK_TRACE_MULTI_STATS env var if set to a path, otherwise
// /tmp/cilock-mt-stats.log). Quiet by default.
func (p *ptraceContext) maybePrintStats() {
	if p.multi == nil || !p.multi.statsEnabled {
		return
	}
	path := os.Getenv("CILOCK_TRACE_MULTI_STATS_PATH")
	if path == "" {
		path = "/tmp/cilock-mt-stats.log"
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "=== multi-tracer run @ %s (n=%d workers) ===\n",
		time.Now().Format(time.RFC3339Nano), len(p.multi.workers))
	for _, w := range p.multi.workers {
		ev := atomic.LoadUint64(&w.stats.events)
		hi := atomic.LoadUint64(&w.stats.handoffIn)
		ho := atomic.LoadUint64(&w.stats.handoffOut)
		kl := atomic.LoadUint64(&w.stats.keptLocal)
		ex := atomic.LoadUint64(&w.stats.exits)
		wn := atomic.LoadUint64(&w.stats.wnohangEmpty)
		is := atomic.LoadUint64(&w.stats.idleSleeps)
		fmt.Fprintf(f, "  w=%d events=%d in=%d out=%d kept=%d exits=%d wnohang_empty=%d idle_sleeps=%d\n",
			w.id, ev, hi, ho, kl, ex, wn, is)
	}
}
