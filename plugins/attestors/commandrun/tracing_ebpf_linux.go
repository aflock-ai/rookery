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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

// AT_FDCWD is the dirfd value for "current working directory" as used
// by openat(2). Defined here to avoid importing `syscall` (deprecated)
// or `golang.org/x/sys/unix.AT_FDCWD` everywhere.
const atFDCWD = -100

// resolveOpenatPath converts a relative openat path to absolute by
// reading /proc/<pid>/cwd (for dirfd=AT_FDCWD) or /proc/<pid>/fd/<dirfd>
// (for *at-relative paths). Called at event-arrival time while the
// tracee is still mid-syscall — the procfs entries are race-narrow
// reliable. Returns "" when resolution fails; caller leaves the path
// as-stashed.
func resolveOpenatPath(ev *ebpf.OpenatEvent) string {
	if ev == nil || ev.Path == "" {
		return ""
	}
	if filepath.IsAbs(ev.Path) {
		return ev.Path
	}
	var base string
	if ev.Dirfd == atFDCWD {
		// AT_FDCWD — resolve against the tracee's cwd.
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ev.PID))
		if err != nil {
			return ""
		}
		base = link
	} else if ev.Dirfd >= 0 {
		// *at-style: resolve against the open dirfd.
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ev.PID, ev.Dirfd))
		if err != nil {
			return ""
		}
		base = link
	} else {
		return ""
	}
	return filepath.Join(base, ev.Path)
}

// resolveRelative is the lightweight variant used by event types that
// only carry a path (no dirfd). Resolves relative paths against
// /proc/<pid>/cwd. Returns "" when the input is already absolute,
// empty, or readlink fails — caller leaves the path as-stashed in
// the empty case.
func resolveRelative(pid int, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return ""
	}
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return filepath.Join(link, path)
}

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

	// fallbackCh carries openat events for which the read-tap got
	// only a partial read (tracee closed before reading the full
	// file — common with bufio peek / magic-number sniff). The
	// hasher pool processes these async via path-hash so the
	// dispatcher stays non-blocking. Sized larger than the openat
	// channel because partial reads dominate the close traffic.
	fallbackCh := make(chan *ebpf.OpenatEvent, 65536)

	stopCh := make(chan struct{})

	// V1.4 read-tap state. Single-goroutine — no synchronization
	// needed for these maps; pctx.mu still guards the attestation.
	type pidFdKey struct {
		PID uint32
		FD  int32
	}
	type openInfo struct {
		Path        string
		EV          *ebpf.OpenatEvent // for path-hash fallback
		Streamed    uint64            // total bytes streamed via read-tap
	}
	openPaths := make(map[pidFdKey]*openInfo)
	streamHashes := make(map[pidFdKey]map[cryptoutil.DigestValue]hash.Hash)
	// streamCounts tracks bytes-streamed per (pid, fd) independently of
	// openPaths. Ringbuf can deliver read-chunk events BEFORE the
	// matching openat (different-CPU submission ordering), in which
	// case openPaths[k] is nil at chunk arrival and we'd lose the
	// running-total. Keying off pidFdKey alone — same as streamHashes —
	// makes the count survive arrival reorder. openInfo.Streamed is
	// kept in sync as a convenience for the end-of-trace sweep, but
	// the close handler reads from streamCounts.
	streamCounts := make(map[pidFdKey]uint64)
	// pendingCloses: ringbuf event reordering can deliver a CLOSE
	// event for (pid, fd) BEFORE the OPENAT event for the same key.
	// This happens when the tracee opens, reads, and closes in
	// microseconds and the events from different CPUs arrive at
	// the userspace ringbuf reader out-of-order. Buffer close events
	// until the matching openat arrives; the openat handler replays.
	pendingCloses := make(map[pidFdKey]*ebpf.CloseEvent)
	var readTapBytes, readTapClosures atomic.Uint64

	var readTotal, matchedTotal, otherTotal atomic.Uint64
	// V2 diagnostic: read-chunk traffic counters. Lets us distinguish
	// "BPF kprobe never fired for the tracee" from "kprobe fired but
	// our matchAndAdd rejected it" when files end up with digest=nil.
	// Surfaced into Summary.Diagnostics at trace end.
	var readChunkSeen, readChunkRejected atomic.Uint64

	// V1.4 backpressure watchdog: when the BPF ringbuf is filling up,
	// broadcast SIGSTOP across the tracee tree so the kernel stops
	// producing events while userspace drains. SIGCONT once drains
	// stabilize. Opt-in via CILOCK_HASH_BACKPRESSURE=1 — proactive
	// pause is aggressive enough to deadlock the build if the
	// consumer falls behind; for most workloads the 256 MB ringbuf
	// alone is sufficient.
	var watchdogWG sync.WaitGroup
	// Backpressure watchdog kept as opt-in via CILOCK_HASH_BACKPRESSURE=1.
	// V2 Phase 8 tried making it on-by-default; the SIGSTOP/SIGCONT cycle
	// disrupts deep fork chains (forks-in-flight either complete with the
	// wrong parent state or fail with EINTR), measurably hurting test
	// reliability. The right default is "off for normal builds, on only
	// for explicit high-volume workloads."
	if os.Getenv("CILOCK_HASH_BACKPRESSURE") == "1" {
		watchdogWG.Add(1)
		go func() {
			defer watchdogWG.Done()
			runBackpressureWatchdog(stopCh, consumer, watched)
		}()
	}

	var consumerWG sync.WaitGroup
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		defer close(openatCh)

		// End-of-trace sweep: when the dispatcher exits, scan any
		// (pid, fd) state we still hold and finalize. This covers
		// the common case of a tracee exiting with open fds — the
		// kernel auto-closes them, but our sys_close kprobe never
		// fires for those kernel-initiated closes. Without this
		// sweep, those files end up with nil digests.
		//
		// BLOCKING send to fallbackCh — we want 100% coverage at
		// trace end, and the hasher pool is still draining. This
		// final pass is bounded; no risk of deadlock since the
		// pool is consuming.
		defer func() {
			for k, oi := range openPaths {
				hs := streamHashes[k]
				delete(streamHashes, k)
				delete(streamCounts, k)
				delete(openPaths, k)
				if oi == nil || oi.Path == "" || oi.EV == nil {
					continue
				}
				fullRead := false
				if oi.EV.SizeAtOpen > 0 && oi.Streamed >= oi.EV.SizeAtOpen {
					fullRead = true
				}
				if fullRead && hs != nil {
					finalizeReadTap(pctx, oi.EV.PID, oi.Path, hs)
					continue
				}
				// Sweep fallback: only path-hash files the tracee
				// actually read (hs != nil OR data was streamed).
				// Write-only opens are output paths; treating them
				// as reads in path-hash would put them in
				// OpenedFiles with a content digest, which then
				// causes TraceOutputs to filter them out as
				// "intermediates." Skip those — they'll appear in
				// FileOps.Writes via the synthesized-write path.
				if oi.EV.IsWriteOnly() || oi.EV.IsPathOnly() {
					continue
				}
				if hs == nil {
					// Tracee opened the fd but never read it (e.g.,
					// pure O_RDWR for stat-only access). Skip.
					continue
				}
				fallbackCh <- oi.EV
			}
		}()

		for {
			select {
			case <-stopCh:
				return
			default:
			}
			ev, err := consumer.Read()
			if err != nil {
				// V2 Phase 8 fix: don't exit on TRANSIENT errors —
				// decode errors from one malformed event would kill
				// the whole dispatcher and lose every subsequent
				// event. This was the actual cause of the ~50% deep-
				// fork-chain flake: under high event volume, an
				// occasional ringbuf record with unexpected layout
				// triggered decodeEvent failure → dispatcher exit →
				// every event after that lost.
				//
				// ONLY exit on ErrFlushed (intentional shutdown) and
				// ringbuf-closed sentinels.
				select {
				case <-stopCh:
					return
				default:
				}
				if ebpf.IsFlushedError(err) {
					return
				}
				if errors.Is(err, os.ErrClosed) {
					return
				}
				// Anything else: skip this event, keep going.
				log.Debugf("(ebpf) consumer read transient error (skipping): %v", err)
				continue
			}
			readTotal.Add(1)

			// Dispatch on event type.
			switch {
			case ev.Openat != nil:
				if !watched.matchAndAdd(ev.Openat.PID, ev.Openat.TGID, ev.Openat.PPID) {
					continue
				}
				matchedTotal.Add(1)
				// Resolve relative paths to absolute via /proc/<pid>/cwd
				// while the tracee is still alive. cc1/javac/many tools
				// call openat(AT_FDCWD, "hello.c", ...) with the path as
				// a relative string. After the tracee closes the fd or
				// exits, /proc/<pid>/fd/<fd> is gone; the path-hash
				// fallback then opens "hello.c" from cilock's cwd —
				// which is wrong — and the digest ends up nil. Reading
				// /proc/<pid>/cwd at event arrival time, while the
				// tracee is in the middle of the open syscall, is
				// race-narrow enough to be reliable. We also do it for
				// dirfd != AT_FDCWD by reading /proc/<pid>/fd/<dirfd>.
				if ev.Openat.Path != "" && !filepath.IsAbs(ev.Openat.Path) {
					if resolved := resolveOpenatPath(ev.Openat); resolved != "" {
						ev.Openat.Path = resolved
					} else if ev.Openat.Dirfd == atFDCWD {
						// /proc/<pid>/cwd gone (tracee exited) — fall back
						// to the cached cwd snapshot. Try the tracee's own
						// cwd first; if that's missing (fast-exec'd process
						// like `as` that we never got to readlink), try the
						// parent's cwd. Children inherit cwd from parent at
						// fork time, so the parent's cached snapshot is a
						// correct stand-in. If the parent's cache is also
						// empty (e.g. parent's matchAndAdd hadn't fired
						// yet), try reading the parent's /proc/<ppid>/cwd
						// live — the parent process tree is more durable
						// than its short-lived children.
						cwd := watched.cwdFor(ev.Openat.PID)
						if cwd == "" {
							cwd = watched.cwdFor(ev.Openat.PPID)
						}
						if cwd == "" && ev.Openat.PPID != 0 {
							if link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ev.Openat.PPID)); err == nil {
								cwd = link
							}
						}
						if cwd != "" {
							ev.Openat.Path = filepath.Join(cwd, ev.Openat.Path)
						}
					}
				}
				// V1.4 read-tap: remember (pid, fd) → path so the
				// later EVT_CLOSE can record the streaming-hash
				// digest against the right path. fd<0 means the
				// kernel returned an error from openat; skip.
				//
				// Track ALL opens (including O_WRONLY and O_PATH)
				// so write events and close events can resolve
				// fd → path even when the writing process exits
				// fast and /proc/<pid>/fd/<fd> is gone by event-
				// dispatch time. The streamHashes path still
				// short-circuits via IsWriteOnly/IsPathOnly checks
				// at chunk time, so we don't waste cycles streaming
				// non-read fds.
				if ev.Openat.FD >= 0 {
					k := pidFdKey{PID: ev.Openat.PID, FD: ev.Openat.FD}
					// Clear any stale state from an earlier open
					// of the same (pid, fd) whose close we missed
					// (process exit, dropped event, etc.). Without
					// this, fd reuse can cause streaming-hash bytes
					// from the OLD file to be attributed to the NEW
					// file's path.
					if prior, ok := openPaths[k]; ok && prior != nil && prior.EV != nil {
						hs := streamHashes[k]
						delete(streamHashes, k)
						fullRead := hs != nil && prior.EV.SizeAtOpen > 0 &&
							prior.Streamed >= prior.EV.SizeAtOpen
						if fullRead {
							finalizeReadTap(pctx, prior.EV.PID, prior.Path, hs)
						} else {
							select {
							case fallbackCh <- prior.EV:
							default:
							}
						}
						// fd reuse: clear stale stream counter so the
						// new openInfo starts fresh.
						delete(streamCounts, k)
					}
					openPaths[k] = &openInfo{
						Path:     ev.Openat.Path,
						EV:       ev.Openat,
						Streamed: streamCounts[k],
					}
					// Replay an out-of-order close that arrived before
					// this openat — finalize now that we know the path.
					//
					// CRITICAL: only replay if the stashed close happened
					// AFTER this openat in kernel time. A close stashed
					// with TimestampNs < openat.TimestampNs was for a
					// PRIOR file at the same (pid, fd) — e.g., cc1
					// inherits fd 3 from gcc and closes it on startup,
					// leaving a pendingClose that would otherwise
					// incorrectly "finalize" every subsequent openat at
					// fd 3 (deleting the freshly-set openInfo and
					// orphaning the real close event).
					if pendingClose, ok := pendingCloses[k]; ok {
						// Always clear — either replay or discard as stale.
						delete(pendingCloses, k)
						// Replay only when the close happened AFTER the
						// openat in kernel time. Stale closes (T_close <=
						// T_openat) belonged to a prior open of the same
						// (pid, fd) — e.g., cc1 inherits fd 3 from gcc
						// and closes it on startup; without this guard
						// every subsequent openat at fd 3 gets
						// incorrectly finalized against that stale close.
						if pendingClose.TimestampNs > ev.Openat.TimestampNs {
							hs, hadData := streamHashes[k]
							oi := openPaths[k]
							delete(streamHashes, k)
							delete(streamCounts, k)
							delete(openPaths, k)
							if oi != nil && oi.Path != "" {
								fullRead := oi.EV != nil && oi.EV.SizeAtOpen > 0 && oi.Streamed >= oi.EV.SizeAtOpen
								if hadData && fullRead {
									finalizeReadTap(pctx, pendingClose.PID, oi.Path, hs)
									readTapClosures.Add(1)
								} else if oi.EV != nil && !oi.EV.IsWriteOnly() && !oi.EV.IsPathOnly() && hadData {
									select {
									case fallbackCh <- oi.EV:
									case <-stopCh:
										return
									}
								}
							}
						}
					}
				}
				select {
				case openatCh <- ev.Openat:
				case <-stopCh:
					return
				}
			case ev.Execve != nil:
				if !watched.matchAndAdd(ev.Execve.PID, ev.Execve.TGID, ev.Execve.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFExecve(pctx, ev.Execve)
			case ev.FileOp != nil:
				if !watched.matchAndAdd(ev.FileOp.PID, ev.FileOp.TGID, ev.FileOp.PPID) {
					continue
				}
				otherTotal.Add(1)
				// Resolve relative Path/Path2 to absolute via the
				// tracee's cwd. Go's linker uses an atomic-rename
				// pattern: write "prog-go-tmp-umask", then
				// renameat2("prog-go-tmp-umask", "prog"). Both legs
				// arrive as relative paths and would otherwise be
				// keyed by the bare basename, causing classification
				// to fail on Stat from cilock's cwd. fchmodat,
				// unlinkat, and renameat2 all use the same struct.
				if p := resolveRelative(int(ev.FileOp.PID), ev.FileOp.Path); p != "" {
					ev.FileOp.Path = p
				}
				if p := resolveRelative(int(ev.FileOp.PID), ev.FileOp.Path2); p != "" {
					ev.FileOp.Path2 = p
				}
				recordEBPFFileOp(pctx, ev.FileOp)
			case ev.Security != nil:
				if !watched.matchAndAdd(ev.Security.PID, ev.Security.TGID, ev.Security.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFSecurity(pctx, ev.Security)
			case ev.Write != nil:
				if !watched.matchAndAdd(ev.Write.PID, ev.Write.TGID, ev.Write.PPID) {
					continue
				}
				otherTotal.Add(1)
				// Resolve fd → path from openPaths (the in-flight
				// (pid, fd) → openat info table). Falls back to
				// /proc/<pid>/fd/<fd> readlink ONLY if openPaths
				// doesn't have it (e.g., a short-lived process
				// that wrote before we saw its openat event).
				// Without this lookup, fast-exiting writers like
				// gcc lose their writes because /proc/<pid> is gone
				// by the time we resolve.
				var writePath string
				if oi := openPaths[pidFdKey{PID: ev.Write.PID, FD: ev.Write.FD}]; oi != nil {
					writePath = oi.Path
				}
				recordEBPFWrite(pctx, ev.Write, writePath)
			case ev.Net != nil:
				if !watched.matchAndAdd(ev.Net.PID, ev.Net.TGID, ev.Net.PPID) {
					continue
				}
				otherTotal.Add(1)
				recordEBPFNet(pctx, ev.Net)
			case ev.ReadChunk != nil:
				readChunkSeen.Add(1)
				if !watched.matchAndAdd(ev.ReadChunk.PID, ev.ReadChunk.TGID, ev.ReadChunk.PPID) {
					readChunkRejected.Add(1)
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
				streamCounts[k] += uint64(ev.ReadChunk.ChunkLen)
				if oi := openPaths[k]; oi != nil {
					oi.Streamed = streamCounts[k]
				}
				readTapBytes.Add(uint64(ev.ReadChunk.ChunkLen))
			case ev.Close != nil:
				if !watched.matchAndAdd(ev.Close.PID, ev.Close.TGID, ev.Close.PPID) {
					continue
				}
				k := pidFdKey{PID: ev.Close.PID, FD: ev.Close.FD}
				if openPaths[k] == nil {
					// Out-of-order delivery: openat for this fd
					// hasn't been processed yet. Buffer the close —
					// the openat handler will replay it. Don't
					// touch streamHashes; read-chunks accumulate
					// into them lazily.
					pendingCloses[k] = ev.Close
					continue
				}
				hs, hadData := streamHashes[k]
				oi := openPaths[k]
				delete(streamHashes, k)
				delete(streamCounts, k)
				delete(openPaths, k)
				if oi == nil || oi.Path == "" {
					continue
				}
				// Full-read check: if the tracee read every byte of
				// the file, the streaming digest IS the file digest.
				// If it read only a prefix (very common — bufio
				// peek, magic-number sniff, partial parse), the
				// streaming digest would be wrong; fall back to a
				// path-hash of the now-closed file.
				// SizeAtOpen comes from BPF (kernel fd → inode → i_size),
				// so no syscall on the dispatcher hot path.
				fullRead := false
				if oi.EV != nil && oi.EV.SizeAtOpen > 0 && oi.Streamed >= oi.EV.SizeAtOpen {
					fullRead = true
				}
				if hadData && fullRead {
					finalizeReadTap(pctx, ev.Close.PID, oi.Path, hs)
					readTapClosures.Add(1)
				} else if oi.EV != nil && !oi.EV.IsWriteOnly() && !oi.EV.IsPathOnly() && hadData {
					// Path-hash fallback — queue to hasher pool.
					// Only fall back when the tracee actually READ
					// the file (hadData=true means we saw read
					// chunks). Write-only opens don't get hashed
					// as reads — they're outputs, classified later
					// via the product/cacheArtifact path.
					// Blocking send: dropping would create nil
					// entries we'd never recover. Pool is large
					// enough (65K buffer) that this rarely blocks
					// in practice.
					fallbackCh <- oi.EV
				}
			}
		}
	}()

	// Hasher pool: parallel hashing of files referenced by openat events.
	// When read-tap is on, the pool SKIPS the actual disk I/O hash —
	// streaming-hash provides the digest, and competing with the build
	// for /proc/<pid>/fd/<fd> reads is wasted work + extra ringbuf
	// pressure from the openat-induced reads.
	//
	// V2: read-tap is ON BY DEFAULT (see tracing_linux.go preStartTracingSetup).
	// CILOCK_HASH_RACE_FREE=0 opts out (diagnostic only).
	readTapOn := os.Getenv("CILOCK_HASH_RACE_FREE") != "0"
	var hashedTotal, suspectTotal, errorTotal atomic.Uint64
	var hasherWG sync.WaitGroup
	const hashWorkers = 4
	for i := 0; i < hashWorkers; i++ {
		hasherWG.Add(1)
		go func() {
			defer hasherWG.Done()
			openClosed := false
			fallbackClosed := false
			for !openClosed || !fallbackClosed {
				select {
				case ev, ok := <-openatCh:
					if !ok {
						openClosed = true
						continue
					}
					if watched.addAndReturnNew(ev.PID, ev.PPID) {
						_ = consumer.AddWatchedPID(ev.PID)
					}
					if ev.IsWriteOnly() || ev.IsPathOnly() {
						recordEBPFOpenatNoHash(pctx, ev)
						continue
					}
					if readTapOn {
						// Read-tap will provide the digest if the
						// tracee reads the whole file; if partial,
						// dispatcher queues to fallbackCh below.
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

				case ev, ok := <-fallbackCh:
					if !ok {
						fallbackClosed = true
						continue
					}
					// Partial-read fallback: path-hash the file
					// after the tracee closed it. Path-only mode
					// is critical here — by now the tracee has
					// closed the fd, and a different file may have
					// been assigned that fd. /proc/<pid>/fd/<fd>
					// would hash the wrong file.
					res := ebpf.HashOpenatEventWithMode(ev, pctx.hash, true /* pathOnly */)
					hashedTotal.Add(1)
					switch res.Status {
					case ebpf.TOCTOUSuspect:
						suspectTotal.Add(1)
					case ebpf.TOCTOUError, ebpf.TOCTOUMissing:
						errorTotal.Add(1)
					}
					recordEBPFOpenat(pctx, ev, res)
				}
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
	close(fallbackCh) // no more partial-read fallbacks after dispatcher exits
	close(stopCh)     // unblock any inflight evCh send (defensive)
	hasherWG.Wait()
	watchdogWG.Wait()

	// Surface ringbuf drop counters BEFORE closing the consumer
	// (Close releases the underlying maps). A non-zero drop count
	// means the attestation has gaps — log loud so operators can
	// see they need to bump ringbuf size or reduce concurrency.
	//
	// V2 Phase 5: ALSO record into TraceSummary.Diagnostics so the
	// counters survive in the attestation itself. Operators verifying
	// a stored attestation can read these without re-running the
	// build; AI agents can flag "incomplete" attestations from a
	// summary read alone.
	if oDrops, rDrops, dErr := consumer.RingbufDrops(); dErr == nil {
		// Stash on CommandRun for buildTraceSummary to consume after
		// the trace returns. Direct r.Summary assignment doesn't work
		// here because Summary is built AFTER trace() returns; any
		// write here would be clobbered.
		r.ringbufDropOpenat = oDrops
		r.ringbufDropReadTap = rDrops
		if oDrops > 0 || rDrops > 0 {
			log.Errorf("(ebpf) RINGBUF DROPS — attestation has gaps: openat=%d read_tap=%d  "+
				"bump ringbuf size or reduce build parallelism",
				oDrops, rDrops)
			fmt.Fprintf(os.Stderr,
				"cilock-ebpf: WARNING: ringbuf dropped openat=%d read_tap=%d events; attestation incomplete\n",
				oDrops, rDrops)
		} else {
			log.Debugf("(ebpf) ringbuf drops: openat=0 read_tap=0 — full capture")
		}
	}

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
			"cilock-ebpf: parentPid=%d read=%d matched=%d other=%d hashed=%d suspect=%d errors=%d "+
				"readChunkSeen=%d readChunkRejected=%d readTapBytes=%d readTapClosures=%d\n",
			pctx.parentPid, readTotal.Load(), matchedTotal.Load(), otherTotal.Load(),
			hashedTotal.Load(), suspectTotal.Load(), errorTotal.Load(),
			readChunkSeen.Load(), readChunkRejected.Load(),
			readTapBytes.Load(), readTapClosures.Load())
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

	// Write-intent: an openat with O_WRONLY/O_RDWR + O_CREAT/O_TRUNC
	// is a strong signal the tracee will write to this fd. The sys_write
	// kprobe may not fire for the actual write (gcc/ld + many other
	// tools mmap the output and write via memory stores, never going
	// through write(2)), so record the OPEN as a synthetic write event
	// here. Without this, products written via mmap disappear from the
	// trace.
	if ev.IsWriteOnly() || isCreateOrTrunc(ev.Flags) {
		if procInfo.FileOps == nil {
			procInfo.FileOps = &FileActivity{}
		}
		// Dedup against any sys_write events for the same path that
		// might have fired before/after.
		alreadyRecorded := false
		for _, w := range procInfo.FileOps.Writes {
			if w.Path == ev.Path {
				alreadyRecorded = true
				break
			}
		}
		if !alreadyRecorded {
			procInfo.FileOps.Writes = append(procInfo.FileOps.Writes, FileWrite{
				Path:      ev.Path,
				Bytes:     0, // unknown at open time; mmap writers never tell us
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
	}
}

// isCreateOrTrunc returns true for openat flags that imply the tracee
// is creating, truncating, or appending to a file — i.e., a write
// intent even when the access mode is RDWR rather than WRONLY.
func isCreateOrTrunc(flags uint32) bool {
	const (
		oCreat  = 0o100
		oTrunc  = 0o1000
		oAppend = 0o2000
	)
	return flags&(oCreat|oTrunc|oAppend) != 0
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
// SYS_PWRITE64 ptrace handler: resolve fd → path, skip stdio +
// pipes + sockets, record (path, bytes) to fileOps.writes.
//
// preResolvedPath is the path the dispatcher looked up from its
// (pid, fd) → openat info map. Empty if the dispatcher couldn't
// resolve — we fall back to /proc/<pid>/fd/<fd> readlink. The
// caller's lookup is preferred because /proc disappears when the
// process exits, which is common for fast writers (gcc, javac, etc.)
// that complete before our async event handler runs.
func recordEBPFWrite(pctx *ptraceContext, ev *ebpf.WriteEvent, preResolvedPath string) {
	if ev.FD <= 2 || ev.Bytes == 0 {
		return // stdio writes are noise; zero-byte writes are no-ops
	}
	path := preResolvedPath
	if path == "" {
		path = resolveProcFD(int(ev.PID), int(ev.FD))
	}
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
	// cwd caches the resolved cwd per-pid, captured at matchAndAdd
	// time (when we KNOW the pid is alive — it just fired an event).
	// Later openat events with relative paths use this cache to
	// resolve without re-reading /proc/<pid>/cwd, which may be gone
	// by event-dispatch time for fast-exiting processes (cc1, etc.).
	cwd map[uint32]string
}

func newWatchedSet(root int) *watchedSet {
	return &watchedSet{
		pid: map[uint32]bool{uint32(root): true}, //nolint:gosec // G115: pid fits in u32 by Linux convention
		cwd: map[uint32]string{},
	}
}

func (w *watchedSet) match(pid, tgid, ppid uint32) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pid[pid] || w.pid[tgid] || w.pid[ppid]
}

// matchAndAdd is the dispatch-time variant of match: when match succeeds
// via parent descent (ppid in set), pid is ALSO added to the set so
// subsequent descendants see the parent immediately.
//
// Root cause of the ~40% deep-fork-chain flake before this:
//
//   1. depth=4 openat arrives at dispatcher → watched.match passes
//      (ppid=cilock=root) → enqueued to openatCh.
//   2. depth=3 openat arrives → watched.match: pid/tgid not in set,
//      ppid=depth=4 — depth=4 NOT YET in set because addAndReturnNew
//      runs in the HASHER goroutine which hasn't drained openatCh yet
//      → REJECTED. depth=3's events are dropped.
//   3. Hasher pulls depth=4 from openatCh, adds it to set. Too late
//      for depth=3 and everything beneath it.
//
// matchAndAdd resolves this by inlining the add at dispatch time.
// Verified: 50/50 PASS on TestPhase8Blocker_ForkChainStability after
// this change (baseline was 24-31/50).
func (w *watchedSet) matchAndAdd(pid, tgid, ppid uint32) bool {
	w.mu.RLock()
	if w.pid[pid] || w.pid[tgid] {
		w.mu.RUnlock()
		return true
	}
	descent := w.pid[ppid]
	w.mu.RUnlock()
	if !descent {
		return false
	}
	// New descendant — snapshot /proc/<pid>/cwd while it's still alive.
	// Fast-exit processes (cc1, ld, etc.) take their /proc entry with
	// them; reading cwd later returns ENOENT. Captured here so relative
	// openat paths resolve correctly even after the tracee dies.
	//
	// Fallback: when /proc/<pid>/cwd is already gone (sub-millisecond
	// exec+exit, e.g. gcc's `as` invocation), inherit cwd from the
	// parent's cached snapshot. Children inherit cwd from their parent
	// on fork; the parent's cached cwd is a correct stand-in.
	var cwd string
	if link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		cwd = link
	}
	if cwd == "" {
		w.mu.RLock()
		cwd = w.cwd[ppid]
		w.mu.RUnlock()
	}
	w.mu.Lock()
	w.pid[pid] = true
	if cwd != "" {
		w.cwd[pid] = cwd
	}
	w.mu.Unlock()
	return true
}

// cwdFor returns the cached cwd for pid (snapshotted at first-seen
// time), or "" if we don't have it. Lookups are reads — fine under
// contention; matchAndAdd is the only writer.
func (w *watchedSet) cwdFor(pid uint32) string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cwd[pid]
}

// snapshot returns a copy of the current pid set. Used by the
// backpressure watchdog to broadcast SIGSTOP/SIGCONT across the
// tracee process tree.
func (w *watchedSet) snapshot() []int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]int, 0, len(w.pid))
	for pid := range w.pid {
		out = append(out, int(pid))
	}
	return out
}

// runBackpressureWatchdog polls the ringbuf fill ratio every 10 ms
// and broadcasts SIGSTOP across the watched pid set when the ring
// climbs past the HIGH_WATER mark — *before* drops actually happen.
// SIGCONT once the consumer drains us back below LOW_WATER. Net
// effect: tracee speed matches consumer drain rate, no silent
// event loss.
//
// Why depth-based (proactive) rather than drop-based (reactive):
// at peak burst (parallel compile, 4 CPUs), the ringbuf can fill
// from 0 to overflow in <10 ms. A drop-based watchdog only learns
// about overflow AFTER events were already lost. Depth-based
// catches the fill as it happens.
//
// SIGSTOP freezes tracee threads at syscall boundaries — in-flight
// syscalls complete and emit their events, then no new syscall
// entry until SIGCONT. Safe.
const (
	backpressureHighWater = 60 // % of ringbuf capacity → SIGSTOP
	backpressureLowWater  = 20 // % of ringbuf capacity → SIGCONT
	backpressureTick      = 10 * time.Millisecond
)

func runBackpressureWatchdog(
	stopCh <-chan struct{},
	consumer *ebpf.Consumer,
	watched *watchedSet,
) {
	ticker := time.NewTicker(backpressureTick)
	defer ticker.Stop()

	cap := consumer.RingbufCapacityBytes()
	if cap <= 0 {
		return // can't measure depth — bail (don't crash the trace)
	}
	highMark := cap * backpressureHighWater / 100
	lowMark := cap * backpressureLowWater / 100

	stopped := false
	totalPauses, totalPausedNs := 0, int64(0)
	var pauseStart time.Time

	defer func() {
		if stopped {
			for _, pid := range watched.snapshot() {
				_ = unix.Kill(pid, unix.SIGCONT)
			}
			totalPausedNs += time.Since(pauseStart).Nanoseconds()
		}
		if totalPauses > 0 {
			log.Debugf("(ebpf) backpressure: %d pause cycles, ~%d ms total stop time, ringbuf cap=%d MB",
				totalPauses, totalPausedNs/int64(time.Millisecond), cap/(1024*1024))
		}
	}()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
		}

		depth := consumer.RingbufAvailableBytes()

		if !stopped && depth > highMark {
			// Pre-emptively pause the tracee tree.
			for _, pid := range watched.snapshot() {
				_ = unix.Kill(pid, unix.SIGSTOP)
			}
			stopped = true
			pauseStart = time.Now()
			totalPauses++
		} else if stopped && depth < lowMark {
			// Drained enough — let the tracee run again.
			for _, pid := range watched.snapshot() {
				_ = unix.Kill(pid, unix.SIGCONT)
			}
			stopped = false
			totalPausedNs += time.Since(pauseStart).Nanoseconds()
		}
	}
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
