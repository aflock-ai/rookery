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
	"hash"
	"net"
	"os"
	"os/exec"
	"strings"
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
// r.ebpfConsumer must be non-nil — opened before c.Start() in runCmd
// so kprobes attach before any child syscall fires.
// arm into a helper just hides the goroutine/lifecycle interaction.
//
//nolint:gocognit // event-loop dispatch on a 4-variant union; pulling each
func (r *CommandRun) runEBPFTrace(c *exec.Cmd, actx *attestation.AttestationContext, pctx *ptraceContext) ([]ProcessInfo, error) {
	raw := r.ebpfConsumer
	if raw == nil {
		return nil, fmt.Errorf("internal: eBPF mode selected but consumer was not pre-opened before c.Start()")
	}
	consumer, ok := raw.(*ebpf.Consumer)
	if !ok {
		return nil, fmt.Errorf("internal: ebpfConsumer is %T, want *ebpf.Consumer", raw)
	}
	defer func() {
		_ = consumer.Close()
		r.ebpfConsumer = nil
	}()

	// The BPF filter has already been enabled in preStartTracingSetup
	// with our pid set as root_parent_tgid, so the child's first
	// openat fires the kprobe via ppid match. The kprobe also adds
	// the child's pid to watched_pids in-kernel for follow-up events.
	//
	// Userspace mirrors the watched set so userspace-side filtering
	// remains exact and so the cleanup AddWatchedPID calls keep the
	// in-kernel map in sync as new descendants are observed.
	watched := newWatchedSet(c.Process.Pid)

	// openatCh feeds the hasher pool. Non-openat events (execve, fileOps,
	// security) go straight through recordEBPF<type> which is cheap.
	openatCh := make(chan *ebpf.OpenatEvent, 4096)

	stopCh := make(chan struct{})

	// V1.4 read-tap state. Single-goroutine — no synchronization
	// needed for these maps; pctx.mu still guards the attestation.
	type pidFdKey struct {
		PID uint32
		FD  int32
	}
	openPaths := make(map[pidFdKey]string)
	streamHashes := make(map[pidFdKey]map[cryptoutil.DigestValue]hash.Hash)
	var readTapBytes, readTapClosures atomic.Uint64

	var readTotal, matchedTotal, otherTotal atomic.Uint64

	var consumerWG sync.WaitGroup
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		defer close(openatCh)
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
			readTotal.Add(1)

			// Dispatch on event type.
			switch {
			case ev.Openat != nil:
				if !watched.match(ev.Openat.PID, ev.Openat.TGID, ev.Openat.PPID) {
					continue
				}
				matchedTotal.Add(1)
				// V1.4 read-tap: remember (pid, fd) → path so the
				// later EVT_CLOSE can record the streaming-hash
				// digest against the right path. fd<0 means the
				// kernel returned an error from openat; skip.
				if ev.Openat.FD >= 0 &&
					!ev.Openat.IsWriteOnly() &&
					!ev.Openat.IsPathOnly() {
					openPaths[pidFdKey{PID: ev.Openat.PID, FD: ev.Openat.FD}] = ev.Openat.Path
				}
				select {
				case openatCh <- ev.Openat:
				case <-stopCh:
					return
				}
			case ev.Execve != nil:
				if !watched.match(ev.Execve.PID, ev.Execve.TGID, ev.Execve.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFExecve(pctx, ev.Execve)
			case ev.FileOp != nil:
				if !watched.match(ev.FileOp.PID, ev.FileOp.TGID, ev.FileOp.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFFileOp(pctx, ev.FileOp)
			case ev.Security != nil:
				if !watched.match(ev.Security.PID, ev.Security.TGID, ev.Security.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFSecurity(pctx, ev.Security)
			case ev.Write != nil:
				if !watched.match(ev.Write.PID, ev.Write.TGID, ev.Write.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFWrite(pctx, ev.Write)
			case ev.Net != nil:
				if !watched.match(ev.Net.PID, ev.Net.TGID, ev.Net.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFNet(pctx, ev.Net)
			case ev.ReadChunk != nil:
				if !watched.match(ev.ReadChunk.PID, ev.ReadChunk.TGID, ev.ReadChunk.PPID) {
					continue
				}
				k := pidFdKey{PID: ev.ReadChunk.PID, FD: ev.ReadChunk.FD}
				hs := streamHashes[k]
				if hs == nil {
					hs = make(map[cryptoutil.DigestValue]hash.Hash, len(pctx.hash))
					for _, dv := range pctx.hash {
						hs[dv] = dv.New()
					}
					streamHashes[k] = hs
				}
				for _, h := range hs {
					h.Write(ev.ReadChunk.Data)
				}
				readTapBytes.Add(uint64(ev.ReadChunk.ChunkLen))
			case ev.Close != nil:
				if !watched.match(ev.Close.PID, ev.Close.TGID, ev.Close.PPID) {
					continue
				}
				k := pidFdKey{PID: ev.Close.PID, FD: ev.Close.FD}
				hs, hadData := streamHashes[k]
				path := openPaths[k]
				delete(streamHashes, k)
				delete(openPaths, k)
				if hadData && path != "" {
					finalizeReadTap(pctx, ev.Close.PID, path, hs)
					readTapClosures.Add(1)
				}
			}
		}
	}()

	// Hasher pool: parallel hashing of files referenced by openat events.
	var hashedTotal, suspectTotal, errorTotal atomic.Uint64
	var hasherWG sync.WaitGroup
	const hashWorkers = 4
	for i := 0; i < hashWorkers; i++ {
		hasherWG.Add(1)
		go func() {
			defer hasherWG.Done()
			for ev := range openatCh {
				if watched.addAndReturnNew(ev.PID, ev.PPID) {
					_ = consumer.AddWatchedPID(ev.PID)
				}
				// Skip hashing for opens we know can't have meaningful
				// content at hash-time:
				//   - O_WRONLY: tracee's own writes; racing the writer.
				//   - O_PATH:   no content read at all (symlink resolve).
				// Still record the path in OpenedFiles (without digest) so
				// policy can see the open occurred — but no hash means no
				// false-positive TOCTOU-suspect noise.
				if ev.IsWriteOnly() || ev.IsPathOnly() {
					recordEBPFOpenatNoHash(pctx, ev)
					continue
				}
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

	// Wait for the tracee to exit, then drain the ring buffer before
	// closing. The drain step is critical: cat-class tracees finish
	// in <100ms and the kernel queues openat events into the ring
	// buffer faster than we pull them. If we close immediately on
	// c.Wait() return, we drop every event queued but not yet read.
	//
	// Flush() is the cilium/ebpf-idiomatic shutdown signal: it
	// unblocks the in-flight Read via the underlying poller (without
	// the lock-contention issue SetReadDeadline has), then Read
	// returns ringbuf.ErrFlushed once the buffer is drained. The
	// consumer goroutine exits on that sentinel.
	waitErr := c.Wait()
	// Disable the kernel-side filter first so no new events are
	// generated. The kernel side stops adding to the ring; userspace
	// drains what's left.
	_ = consumer.DisableFilter()
	_ = consumer.Flush()
	consumerWG.Wait()
	close(stopCh) // unblock any inflight evCh send (defensive)
	hasherWG.Wait()
	_ = consumer.Close()

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

	log.Debugf("(ebpf) trace complete: read=%d matched=%d other=%d hashed=%d toctou-suspect=%d errors=%d",
		readTotal.Load(), matchedTotal.Load(), otherTotal.Load(),
		hashedTotal.Load(), suspectTotal.Load(), errorTotal.Load())
	if v := os.Getenv("CILOCK_EBPF_DEBUG"); v == "1" {
		fmt.Fprintf(os.Stderr,
			"cilock-ebpf: parentPid=%d read=%d matched=%d other=%d hashed=%d suspect=%d errors=%d\n",
			pctx.parentPid, readTotal.Load(), matchedTotal.Load(), otherTotal.Load(),
			hashedTotal.Load(), suspectTotal.Load(), errorTotal.Load())
	}

	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), fmt.Errorf("exit status %v", pctx.exitCode)
	}
	return pctx.procInfoArray(), nil
}

// recordEBPFOpenat records one openat event + its hash result into
// the appropriate ProcessInfo. Concurrent-safe via pctx.mu, which
// guards both the processes-map and the ProcessInfo entries within.
func recordEBPFOpenat(pctx *ptraceContext, ev *ebpf.OpenatEvent, res ebpf.HashResult) {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()

	procInfo := pctx.getProcInfo(int(ev.PID))
	// Retry /proc enrichment if any of {Environ, Cmdline, ExeDigest}
	// is still empty. Execve kprobe fires BEFORE kernel completes
	// the exec, so /proc is stale at execve-event-time for short
	// programs. By the time the first openat fires, the dynamic
	// linker has been running for >microseconds — /proc has the
	// post-exec state. Cheap to retry: the inner enrichFromProc
	// short-circuits per field if already populated.
	needsEnrichment := procInfo.Comm == "" ||
		procInfo.Environ == "" ||
		procInfo.Cmdline == "" ||
		procInfo.ExeDigest == nil

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

	if needsEnrichment {
		enrichFromProc(pctx, procInfo)
	}
}

// recordEBPFOpenatNoHash records an openat we deliberately skipped
// hashing (O_WRONLY / O_PATH). The path goes into OpenedFiles with a
// nil digest so policy can still see WHAT was opened, but we don't
// emit a TOCTOU-suspect that would be a false positive (we know the
// race exists by construction — no point flagging it).
func recordEBPFOpenatNoHash(pctx *ptraceContext, ev *ebpf.OpenatEvent) {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()
	procInfo := pctx.getProcInfo(int(ev.PID))
	if procInfo.OpenedFiles == nil {
		procInfo.OpenedFiles = make(map[string]cryptoutil.DigestSet)
	}
	// Only set to nil if we don't already have a digest from a prior
	// (read) open of the same path.
	if _, ok := procInfo.OpenedFiles[ev.Path]; !ok {
		procInfo.OpenedFiles[ev.Path] = nil
	}
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	if procInfo.ParentPID == 0 {
		procInfo.ParentPID = int(ev.PPID)
	}
}

// finalizeReadTap turns a per-(pid, fd) streaming-hash state into a
// DigestSet and records it on the ProcessInfo against the captured
// path. Called from the consumer goroutine on each EVT_CLOSE that
// had any read bytes streamed. The hashes were maintained by the
// dispatcher; here we just Sum + persist.
//
// The streaming digest is authoritative when read-tap is enabled:
// it reflects the exact bytes the tracee actually consumed,
// race-free against the calling thread (kernel-context capture).
// It overwrites any earlier path-hash entry for the same file —
// the path-hash entry can be racey, the streaming hash isn't.
func finalizeReadTap(
	pctx *ptraceContext, pid uint32, path string,
	hashes map[cryptoutil.DigestValue]hash.Hash,
) {
	if len(hashes) == 0 || path == "" {
		return
	}
	ds := make(cryptoutil.DigestSet, len(hashes))
	for dv, h := range hashes {
		if dv.GitOID {
			ds[dv] = string(h.Sum(nil))
			continue
		}
		ds[dv] = string(cryptoutil.HexEncode(h.Sum(nil)))
	}

	pctx.mu.Lock()
	defer pctx.mu.Unlock()
	procInfo := pctx.getProcInfo(int(pid))
	if procInfo.OpenedFiles == nil {
		procInfo.OpenedFiles = make(map[string]cryptoutil.DigestSet)
	}
	// Read-tap digest is authoritative — overwrite path-hash (which
	// may have come from the racey async hasher pool).
	procInfo.OpenedFiles[path] = ds
}

// recordEBPFExecve handles an EVT_EXECVE event from the BPF kprobe.
// Same semantics as the ptrace SYS_EXECVE handler: stat+digest the
// new program, snapshot /proc/<pid>/{cmdline,environ,status,exe}.
// Userspace reads /proc as quickly as it can after the BPF event
// fires; very-short-lived processes may still have exited.
func recordEBPFExecve(pctx *ptraceContext, ev *ebpf.ExecveEvent) {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()

	procInfo := pctx.getProcInfo(int(ev.PID))
	procInfo.ParentPID = int(ev.PPID)
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}

	// Hash the file the syscall caller named.
	//nolint:nestif // four-level nest mirrors a deliberate fallback chain
	// (digest cache → ProgramDigest → ExeDigest). Unrolling would scatter
	// related decisions across helpers and obscure the intent.
	if ev.Filename != "" {
		procInfo.Program = ev.Filename
		if d, ok := pctx.cachedDigest(ev.Filename); ok {
			if procInfo.ProgramDigest == nil {
				procInfo.ProgramDigest = d
			}
			// Fallback for ExeDigest: argv[0] hash. For 99% of execvees
			// argv[0] resolves to the same binary that /proc/<pid>/exe
			// would symlink to. enrichFromProc below will overwrite
			// with the /proc-resolved digest when the process is still
			// alive — but for sub-millisecond processes (Go's
			// compile/asm subprocs) /proc may already be gone, and
			// argv[0] is the only ExeDigest we'll get.
			if procInfo.ExeDigest == nil {
				procInfo.ExeDigest = d
			}
		}
	}

	// /proc enrichment for the actually-loaded binary + environ + cmdline.
	// Best-effort; the fallback above keeps ExeDigest populated when /proc
	// is gone.
	enrichFromProc(pctx, procInfo)
}

// recordEBPFFileOp handles EVT_UNLINKAT, EVT_RENAMEAT, EVT_FCHMODAT.
// Mirrors the ptrace handlers in tracing_linux.go.
func recordEBPFFileOp(pctx *ptraceContext, ev *ebpf.FileOpEvent) {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()

	procInfo := pctx.getProcInfo(int(ev.PID))
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	if procInfo.FileOps == nil {
		procInfo.FileOps = &FileActivity{}
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	switch ev.Op {
	case ebpf.EVT_UNLINKAT:
		procInfo.FileOps.Deletes = append(procInfo.FileOps.Deletes, FileDelete{
			Path:      ev.Path,
			Timestamp: ts,
		})
	case ebpf.EVT_RENAMEAT:
		procInfo.FileOps.Renames = append(procInfo.FileOps.Renames, FileRename{
			OldPath:   ev.Path,
			NewPath:   ev.Path2,
			Timestamp: ts,
		})
	case ebpf.EVT_FCHMODAT:
		mode := ev.Mode
		procInfo.FileOps.PermChanges = append(procInfo.FileOps.PermChanges, FilePermChange{
			Path:      ev.Path,
			Mode:      mode,
			SetExec:   mode&0o111 != 0,
			Timestamp: ts,
		})
	}
}

// recordEBPFSecurity handles EVT_SECURITY events for the long-tail
// syscalls the ptrace path captures as syscallEvents[]. Formats the
// human-readable Detail string per syscall_nr; numbers come from the
// CILOCK_SYS_*_X64/ARM64 macros in openat_kprobe.bpf.c.
func recordEBPFSecurity(pctx *ptraceContext, ev *ebpf.SecurityEvent) {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()

	procInfo := pctx.getProcInfo(int(ev.PID))
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	se := classifyEBPFSecurityEvent(ev)
	if se.Syscall == "" {
		return // filtered out (uninteresting prctl, mprotect without PROT_EXEC, etc.)
	}
	se.Timestamp = ts
	procInfo.SyscallEvents = append(procInfo.SyscallEvents, se)
}

// classifyEBPFSecurityEvent decodes a SecurityEvent into the
// SyscallEvent fields cilock's predicate uses. Returns SyscallEvent
// with empty Syscall when the event isn't worth surfacing (matches
// ptrace's filtering, e.g. only mprotect with PROT_EXEC, only certain
// prctl options).
//
//nolint:gocyclo // per-syscall classifier, one short case per syscall — splitting hides the parity with the ptrace path.
func classifyEBPFSecurityEvent(ev *ebpf.SecurityEvent) SyscallEvent {
	// IDs must match CILOCK_SEC_* in openat_kprobe.bpf.c.
	const (
		secPtrace      = 100
		secMemfdCreate = 101
		secMount       = 102
		secMprotect    = 103
		secPrctl       = 104
		secSetsid      = 105
		secSetns       = 106
		secInitModule  = 107
		secFinitModule = 108
		secClone       = 109
		secClone3      = 110
		secDup2        = 111
		secDup3        = 112
	)
	nr := ev.SyscallNr
	switch nr {
	case secPtrace:
		return SyscallEvent{
			Syscall: "ptrace",
			Detail:  fmt.Sprintf("ptrace request=%d target_pid=%d — anti-debugging or process injection", ev.Args[0], ev.Args[1]),
			Args:    []int{int(ev.Args[0]), int(ev.Args[1])},
		}
	case secMemfdCreate:
		return SyscallEvent{
			Syscall: "memfd_create",
			Detail:  fmt.Sprintf("anonymous memory file (flags: %d) — used for fileless code execution", ev.Args[1]),
		}
	case secMount:
		return SyscallEvent{
			Syscall: "mount",
			Detail:  "mount syscall observed — potential container escape",
		}
	case secMprotect:
		prot := ev.Args[2]
		if prot&0x04 == 0 { // PROT_EXEC = 0x04
			return SyscallEvent{}
		}
		return SyscallEvent{
			Syscall: "mprotect",
			Detail:  fmt.Sprintf("made memory executable (addr=%#x len=%d prot=%d) — fileless payload indicator", ev.Args[0], ev.Args[1], prot),
			Args:    []int{int(ev.Args[0]), int(ev.Args[1]), int(prot)},
		}
	case secPrctl:
		option := ev.Args[0]
		switch option {
		case 15:
			return SyscallEvent{
				Syscall: "prctl",
				Detail:  fmt.Sprintf("PR_SET_NAME (arg=%#x) — hiding process identity", ev.Args[1]),
				Args:    []int{int(option), int(ev.Args[1])},
			}
		case 4:
			return SyscallEvent{
				Syscall: "prctl",
				Detail:  fmt.Sprintf("PR_SET_DUMPABLE=%d — may prevent forensic core dumps", ev.Args[1]),
				Args:    []int{int(option), int(ev.Args[1])},
			}
		case 38:
			return SyscallEvent{
				Syscall: "prctl",
				Detail:  fmt.Sprintf("PR_SET_NO_NEW_PRIVS=%d — seccomp setup", ev.Args[1]),
				Args:    []int{int(option), int(ev.Args[1])},
			}
		}
		return SyscallEvent{}
	case secSetsid:
		return SyscallEvent{
			Syscall: "setsid",
			Detail:  "created new session — daemonizing to detach from install process tree",
		}
	case secSetns:
		return SyscallEvent{
			Syscall: "setns",
			Detail:  fmt.Sprintf("joined namespace (fd=%d type=%d) — container escape or sandbox evasion", ev.Args[0], ev.Args[1]),
			Args:    []int{int(ev.Args[0]), int(ev.Args[1])},
		}
	case secInitModule, secFinitModule:
		return SyscallEvent{
			Syscall: "init_module",
			Detail:  "attempted to load kernel module — rootkit installation",
		}
	case secClone, secClone3:
		flags := ev.Args[0]
		// CLONE_NEW* flags. Definitions from <sched.h>:
		// CLONE_NEWNS=0x20000, CLONE_NEWUTS=0x4000000, CLONE_NEWIPC=0x8000000,
		// CLONE_NEWUSER=0x10000000, CLONE_NEWPID=0x20000000, CLONE_NEWNET=0x40000000.
		var names []string
		if flags&0x20000 != 0 {
			names = append(names, "CLONE_NEWNS")
		}
		if flags&0x20000000 != 0 {
			names = append(names, "CLONE_NEWPID")
		}
		if flags&0x40000000 != 0 {
			names = append(names, "CLONE_NEWNET")
		}
		if flags&0x10000000 != 0 {
			names = append(names, "CLONE_NEWUSER")
		}
		if len(names) == 0 {
			return SyscallEvent{}
		}
		return SyscallEvent{
			Syscall: "clone",
			Detail:  fmt.Sprintf("clone with namespace flags: %s — potential container escape or sandbox evasion", strings.Join(names, "|")),
			Args:    []int{int(flags)},
		}
	case secDup2, secDup3:
		oldFD := int(ev.Args[0])
		newFD := int(ev.Args[1])
		if newFD > 2 {
			return SyscallEvent{}
		}
		// Without the ptrace fd-table inspection we can't tell socket
		// from pipe here. Surface unconditionally with a hint and let
		// policy interpret.
		target := []string{"stdin", "stdout", "stderr"}[newFD]
		return SyscallEvent{
			Syscall: "dup2",
			Detail:  fmt.Sprintf("redirected fd %d to %s — possible reverse-shell pattern (verify fd source)", oldFD, target),
			Args:    []int{oldFD, newFD},
		}
	}
	return SyscallEvent{}
}

// recordEBPFWrite handles EVT_WRITE events. Mirrors the SYS_WRITE/
// SYS_PWRITE64 ptrace handler: resolve fd → path via /proc, skip
// stdio + pipes + sockets, record (path, bytes) to fileOps.writes.
func recordEBPFWrite(pctx *ptraceContext, ev *ebpf.WriteEvent) {
	if ev.FD <= 2 || ev.Bytes == 0 {
		return // stdio writes are noise; zero-byte writes are no-ops
	}
	path := resolveProcFD(int(ev.PID), int(ev.FD))
	if path == "" {
		return
	}
	if strings.HasPrefix(path, "pipe:") ||
		strings.HasPrefix(path, "socket:") ||
		strings.HasPrefix(path, "anon_inode:") {
		return
	}

	pctx.mu.Lock()
	defer pctx.mu.Unlock()
	procInfo := pctx.getProcInfo(int(ev.PID))
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	if procInfo.FileOps == nil {
		procInfo.FileOps = &FileActivity{}
	}
	procInfo.FileOps.Writes = append(procInfo.FileOps.Writes, FileWrite{
		Path:      path,
		Bytes:     int(ev.Bytes), //nolint:gosec // G115: write() count is bounded by SSIZE_MAX
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// resolveProcFD reads /proc/<pid>/fd/<fd> symlink to resolve the fd
// to a filesystem path. Returns "" if /proc is gone or the fd is
// closed.
func resolveProcFD(pid, fd int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return ""
	}
	return target
}

// recordEBPFNet handles EVT_SOCKET, EVT_CONNECT, EVT_BIND. Mirrors
// the ptrace SYS_SOCKET/CONNECT/BIND handlers.
func recordEBPFNet(pctx *ptraceContext, ev *ebpf.NetEvent) {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()
	procInfo := pctx.getProcInfo(int(ev.PID))
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	if procInfo.Network == nil {
		procInfo.Network = &NetworkActivity{}
	}

	switch ev.Op {
	case ebpf.EVT_SOCKET:
		procInfo.Network.Sockets = append(procInfo.Network.Sockets, SocketInfo{
			Family:   socketFamilyName(int(ev.Family)),
			Type:     socketTypeName(int(ev.Type)),
			Protocol: int(ev.Protocol),
			FD:       int(ev.FD),
		})
	case ebpf.EVT_CONNECT, ebpf.EVT_BIND:
		conn := parseSockaddrEBPF(ev.Family, ev.Addr[:], opName(ev.Op))
		conn.FD = int(ev.FD)
		conn.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		procInfo.Network.Connections = append(procInfo.Network.Connections, *conn)
		// DNS heuristic: any connect to port 53.
		if ev.Op == ebpf.EVT_CONNECT && conn.Port == 53 {
			procInfo.Network.DNSLookups = append(procInfo.Network.DNSLookups, DNSLookup{
				ServerAddress: conn.Address,
				ServerPort:    conn.Port,
			})
		}
	}
}

func opName(op uint32) string {
	switch op {
	case ebpf.EVT_CONNECT:
		return "connect"
	case ebpf.EVT_BIND:
		return "bind"
	}
	return "unknown"
}

// parseSockaddrEBPF parses 32 bytes of raw sockaddr into a
// NetworkConnection. Returns a connection with zero Address/Port
// when the family is unsupported (e.g., AF_NETLINK), still appending
// to the predicate so the syscall is observable.
func parseSockaddrEBPF(family uint32, raw []byte, syscall string) *NetworkConnection {
	conn := &NetworkConnection{Syscall: syscall}
	switch family {
	case 2: // AF_INET — sockaddr_in: family(2) + port(2 big-endian) + addr(4) + pad
		if len(raw) >= 8 {
			conn.Family = afInet
			conn.Port = int(uint16(raw[2])<<8 | uint16(raw[3]))
			conn.Address = net.IP(raw[4:8]).String()
		}
	case 10: // AF_INET6 — sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope(4)
		if len(raw) >= 28 {
			conn.Family = afInet6
			conn.Port = int(uint16(raw[2])<<8 | uint16(raw[3]))
			conn.Address = net.IP(raw[8:24]).String()
		}
	case 1: // AF_UNIX — sockaddr_un: family(2) + path(...)
		conn.Family = afUnix
		end := 2
		for end < len(raw) && raw[end] != 0 {
			end++
		}
		conn.Address = string(raw[2:end])
	}
	return conn
}

// enrichFromProc reads /proc/<pid>/{exe, cmdline, environ, status}
// for the just-seen pid and populates ProcessInfo fields that match
// what the ptrace path captures from the SYS_EXECVE handler. Best-
// effort: process may have exited or have restricted /proc access;
// each read is independent and failures are silent.
//
// Must be called with pctx.mu held (it mutates procInfo).
// short-circuits; the linear shape matches the ptrace handler so the
// two stay obviously equivalent.
//
//nolint:gocognit // /proc reads are sequential best-effort with per-field
func enrichFromProc(pctx *ptraceContext, procInfo *ProcessInfo) {
	pid := procInfo.ProcessID
	if pid == 0 {
		return
	}

	procDir := fmt.Sprintf("/proc/%d", pid)

	// /proc/<pid>/status: spec_store_bypass mitigation + ppid sanity.
	if data, err := os.ReadFile(procDir + "/status"); err == nil { //nolint:gosec // G304: reading /proc by traced pid, mirroring ptrace path
		procInfo.SpecBypassIsVuln = getSpecBypassIsVulnFromStatus(data)
		if procInfo.ParentPID == 0 {
			if ppid, err := getPPIDFromStatus(data); err == nil {
				procInfo.ParentPID = ppid
			}
		}
	}

	// /proc/<pid>/comm: kernel-side comm is authoritative (matches
	// the BPF event but covers /proc reads if BPF comm is empty).
	if procInfo.Comm == "" {
		if data, err := os.ReadFile(procDir + "/comm"); err == nil { //nolint:gosec // G304: see above
			procInfo.Comm = cleanString(string(data))
		}
	}

	// /proc/<pid>/cmdline: argv joined by NULs.
	if procInfo.Cmdline == "" {
		if data, err := os.ReadFile(procDir + "/cmdline"); err == nil { //nolint:gosec // G304: see above
			procInfo.Cmdline = cleanString(string(data))
		}
	}

	// /proc/<pid>/environ: sensitive — pass through the attestation
	// context's environment capturer (which honors --env-* flags).
	if procInfo.Environ == "" && pctx.environmentCapturer != nil {
		if data, err := os.ReadFile(procDir + "/environ"); err == nil { //nolint:gosec // G304: see above
			allVars := strings.Split(string(data), "\x00")
			captured := pctx.environmentCapturer.Capture(allVars)
			env := make([]string, 0, len(captured))
			for k, v := range captured {
				env = append(env, fmt.Sprintf("%s=%s", k, v))
			}
			procInfo.Environ = strings.Join(env, " ")
		}
	}

	// /proc/<pid>/exe is a symlink to the current binary. Resolve +
	// hash via the trace's digest cache for the same per-trace
	// dedup that the ptrace path gets.
	exePath := procDir + "/exe"
	if procInfo.ExeDigest == nil {
		if d, ok := pctx.cachedDigest(exePath); ok {
			procInfo.ExeDigest = d
		}
		// Resolve the symlink so Program can be set to the actual
		// path, mirroring ptrace's argv[0] field.
		if resolved, err := os.Readlink(exePath); err == nil {
			procInfo.Program = resolved
			if procInfo.ProgramDigest == nil {
				if d, ok := pctx.cachedDigest(resolved); ok {
					procInfo.ProgramDigest = d
				}
			}
		}
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
	return &watchedSet{pid: map[uint32]bool{uint32(root): true}} //nolint:gosec // G115: pid fits in u32 by Linux convention
}

func (w *watchedSet) match(pid, tgid, ppid uint32) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pid[pid] || w.pid[tgid] || w.pid[ppid]
}

// addAndReturnNew adds (pid, ppid) to the watched set and returns
// true if pid was newly added. Callers use the return value to push
// only NEW pids into the BPF watched_pids map, avoiding repeated map
// updates for already-watched pids.
func (w *watchedSet) addAndReturnNew(pid, ppid uint32) bool {
	w.mu.RLock()
	if w.pid[pid] {
		w.mu.RUnlock()
		return false
	}
	w.mu.RUnlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pid[pid] {
		return false
	}
	if w.pid[ppid] {
		w.pid[pid] = true
		return true
	}
	return false
}

// openEBPFConsumer opens the consumer (which attaches kprobes
// globally). Exposed as a separate function so preStartTracingSetup
// in tracing_linux.go can call into the ebpf submodule without
// importing it directly.
func openEBPFConsumer() (*ebpf.Consumer, error) {
	return ebpf.Open()
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
