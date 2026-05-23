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

// eBPF tracing path (#167 V1). Runs the wrapped command without
// ptrace and observes its openat-class syscalls via an in-kernel
// kprobe. Each event is hashed in userspace with TOCTOU-stability
// classification.
//
// Mode is selected by selectTraceMode() in trace_mode_linux.go.
// CILOCK_TRACE_MODE=ebpf (or unset / "auto") routes here; ptrace
// mode bypasses this file.
//
// V1 scope:
//   - openat / openat2 capture via eBPF kprobe (this commit)
//   - other syscalls (clone, write, execve, ...) not yet observed
//     in eBPF — see runTrace ptrace path for the canonical handler
//   - userspace TOCTOU stat-comparison hashing
//
// Future:
//   - kretprobe-based stat-at-open capture in the BPF program
//     (currently SizeAtOpen/MtimeNs are zero; we stat in userspace)
//   - PID-tree filtering in BPF map to drop non-tracee events
//   - capture for the other syscalls handleSyscall covers

package commandrun

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

// runEBPFTrace is the eBPF entry point. The child command has already
// been started by exec.Cmd (no SysProcAttr.Ptrace). We watch its
// process tree via BPF events and hash files openat-by-openat.
//
// On entry: c.Process is the running tracee; p.parentPid is its pid.
func (r *CommandRun) runEBPFTrace(c *exec.Cmd, actx *attestation.AttestationContext, pctx *ptraceContext) ([]ProcessInfo, error) {
	consumer, err := ebpf.Open()
	if err != nil {
		return nil, fmt.Errorf("eBPF tracing requested but unavailable: %w", err)
	}
	defer consumer.Close()

	// Watched-pids set starts with the parent. The BPF program emits
	// events for all openat-family syscalls globally — userspace
	// filters by walking parentage. V1 limitation: a tracee that
	// changes its tgid (via setsid into a new pgrp) might escape the
	// filter. This is acceptable for V1.
	watched := newWatchedSet(c.Process.Pid)

	// Channel for events the consumer goroutine emits to the hasher.
	evCh := make(chan *ebpf.OpenatEvent, 4096)

	// Stop signal — closed when the tracee exits.
	stopCh := make(chan struct{})

	// Consumer goroutine: reads BPF ring buffer, filters by watched
	// set, forwards to evCh.
	var consumerWG sync.WaitGroup
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		defer close(evCh)
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			ev, err := consumer.Read()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
				}
				log.Debugf("(ebpf) consumer read: %v", err)
				return
			}
			if !watched.match(ev.PID, ev.TGID, ev.PPID) {
				continue
			}
			select {
			case evCh <- ev:
			case <-stopCh:
				return
			}
		}
	}()

	// Hasher pool: parallel hashing of files referenced by openat events.
	var hashedTotal, suspectTotal, errorTotal atomic.Uint64
	var hasherWG sync.WaitGroup
	const hashWorkers = 4 // matches typical CI core count
	for i := 0; i < hashWorkers; i++ {
		hasherWG.Add(1)
		go func() {
			defer hasherWG.Done()
			for ev := range evCh {
				watched.add(ev.PID, ev.PPID) // track descendants
				res := ebpf.HashOpenatEvent(ev, pctx.hash)
				hashedTotal.Add(1)
				switch res.Status {
				case ebpf.TOCTOUSuspect:
					suspectTotal.Add(1)
				case ebpf.TOCTOUError, ebpf.TOCTOUMissing:
					errorTotal.Add(1)
				}
				recordEBPFOpenat(pctx, ev, res)
			}
		}()
	}

	// Wait for the tracee to exit, then signal stop.
	waitErr := c.Wait()
	close(stopCh)
	_ = consumer.Close()
	consumerWG.Wait()
	hasherWG.Wait()

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			r.ExitCode = exitErr.ExitCode()
			// Per-pid exit code on the parent's ProcessInfo
			pInfo := pctx.getProcInfo(pctx.parentPid)
			pInfo.ExitCode = r.ExitCode
		} else {
			return nil, fmt.Errorf("wait tracee: %w", waitErr)
		}
	} else {
		r.ExitCode = 0
	}
	pctx.exitCode = r.ExitCode

	log.Debugf("(ebpf) trace complete: hashed=%d toctou-suspect=%d errors=%d",
		hashedTotal.Load(), suspectTotal.Load(), errorTotal.Load())

	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), fmt.Errorf("exit status %v", pctx.exitCode)
	}
	return pctx.procInfoArray(), nil
}

// recordEBPFOpenat records one openat event + its hash result into
// the appropriate ProcessInfo. Concurrent-safe: protected by the
// processes-map lock (multi-tracer state) when present, else by the
// per-process lock added for V3.
func recordEBPFOpenat(pctx *ptraceContext, ev *ebpf.OpenatEvent, res ebpf.HashResult) {
	procInfo := pctx.getProcInfo(int(ev.PID))

	procInfo.mu.Lock()
	defer procInfo.mu.Unlock()

	if procInfo.OpenedFiles == nil {
		procInfo.OpenedFiles = make(map[string]cryptoutil.DigestSet)
	}

	// For stable + suspect we store the digest. For missing/error, store nil.
	switch res.Status {
	case ebpf.TOCTOUStable, ebpf.TOCTOUSuspect:
		procInfo.OpenedFiles[res.Path] = res.Digest
	default:
		procInfo.OpenedFiles[res.Path] = nil
	}

	// Surface TOCTOU-suspect entries via SyscallEvents so verifiers
	// can find them at policy-evaluation time without re-scanning
	// every openedFile.
	if res.Status == ebpf.TOCTOUSuspect {
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "openat",
			Detail:    fmt.Sprintf("TOCTOU-suspect: %s (path=%s)", res.Reason, res.Path),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}

	// Populate Comm if we haven't yet seen this pid via execve handler.
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	if procInfo.ParentPID == 0 {
		procInfo.ParentPID = int(ev.PPID)
	}
}

// watchedSet tracks PIDs that belong to our trace tree. A pid is
// watched if it's the parent or any descendant we've observed via
// an event whose PPID is already watched.
//
// V1 limitation: this is approximate. If a child has done exec()
// before we see it, we may briefly miss its PPID link. We accept
// this for V1; a future BPF-side cgroup or pid-tree filter would be
// more precise.
type watchedSet struct {
	mu  sync.RWMutex
	pid map[uint32]bool
}

func newWatchedSet(root int) *watchedSet {
	return &watchedSet{pid: map[uint32]bool{uint32(root): true}}
}

func (w *watchedSet) match(pid, tgid, ppid uint32) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pid[pid] || w.pid[tgid] || w.pid[ppid]
}

func (w *watchedSet) add(pid, ppid uint32) {
	w.mu.RLock()
	if w.pid[pid] {
		w.mu.RUnlock()
		return
	}
	w.mu.RUnlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pid[ppid] {
		w.pid[pid] = true
	}
}

// envInt is a small helper so callers can override hash worker count
// without re-running go build.
//
//nolint:unused // reserved for future tunable
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
		return def
	}
	return n
}
