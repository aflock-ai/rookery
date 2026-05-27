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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// resolveCwdRelative resolves a relative path against the tracee's
// cwd, with a four-tier fallback chain:
//  1. The tracee's own cached cwd (set at matchAndAdd time).
//  2. The parent's cached cwd (children inherit cwd from parent at
//     fork — the parent's snapshot is a correct stand-in).
//  3. /proc/<ppid>/cwd live readlink (parent process is more
//     durable than its short-lived child like `as`).
//  4. rootCwd — cilock's own cwd snapshotted at trace start. Tracees
//     inherit this from cilock at fork-exec; correct unless they
//     explicitly chdir. Last resort when a fast-fork-and-exit
//     cascade tore down /proc entries for the entire ancestor
//     chain before our readlinks landed.
//
// Returns the resolved absolute path, or path unchanged if already
// absolute or all four tiers fail.
func resolveCwdRelative(watched *watchedSet, pid, ppid uint32, path, rootCwd string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	cwd := watched.cwdFor(pid)
	if cwd == "" {
		cwd = watched.cwdFor(ppid)
	}
	if cwd == "" && ppid != 0 {
		if link, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ppid)); err == nil {
			cwd = link
		}
	}
	if cwd == "" {
		cwd = rootCwd
	}
	if cwd == "" {
		return path
	}
	return filepath.Join(cwd, path)
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
	// Capture the TRACEE's working directory as the root cwd fallback.
	// All descendants of the root tracee inherit this cwd unless they
	// chdir; used as the LAST tier of openat path resolution when
	// /proc/<pid>/cwd is gone for both the tracee AND its parent
	// (fast-fork-and-exit cascade — `as`-class one-shot processes
	// can outpace our matchAndAdd readlinks for the whole ancestor
	// chain). c.Dir is set by commandrun.go to the AttestationContext
	// WorkingDir, which is the directory the user wants traced.
	rootCwd := c.Dir
	if rootCwd == "" {
		// c.Dir empty means inherit cilock's own cwd.
		if link, err := os.Readlink("/proc/self/cwd"); err == nil {
			rootCwd = link
		}
	}

	// Userspace mirrors the watched set so userspace-side filtering
	// remains exact and so the cleanup AddWatchedPID calls keep the
	// in-kernel map in sync as new descendants are observed.
	watched := newWatchedSet(c.Process.Pid)

	// Two-stage pipeline between the BPF ringbuf consumer and the
	// hasher pool: the consumer enqueues events to captureCh; the
	// capture pool opens /proc/<pid>/fd/<fd> in parallel (the time-
	// critical step that must happen before the tracee exits); the
	// hasher pool then computes the digest from the captured file.
	//
	// Why two pools, not one: os.Open on /proc/<pid>/fd/<fd> is fast
	// (microseconds) but must happen as soon as possible after the
	// tracee's openat — otherwise the fd is gone. Hashing is slow
	// (milliseconds, bandwidth-bound). Mixing them in one pool means
	// either (a) too few workers → openat-time backlog → tracee exits
	// before capture, or (b) too many workers → contention everywhere.
	// Splitting them lets each pool size for its own bottleneck.
	//
	// Why not inline capture in the dispatcher: tried, dropped 9M
	// openat events on defconfig. The single ringbuf consumer can't
	// drain at the kernel's emit rate while doing os.Open per event.
	//
	// captureCh and openatCh are deeply buffered (1M each) so neither
	// pool's slow moments can backpressure the dispatcher.
	type pendingHash struct {
		ev   *ebpf.OpenatEvent
		file *os.File // captured /proc/<pid>/fd/<fd>; nil = capture skipped (write-only/path-only) or failed
		stat os.FileInfo
	}
	// captureCh items carry zero held resources (just the event), so
	// it's safe to buffer deeply — absorbs dispatcher burst without
	// blocking the ringbuf consumer.
	captureCh := make(chan *pendingHash, 1024*1024)
	// openatCh items each hold ONE open file descriptor (the captured
	// /proc/<pid>/fd/<fd>). Bounded conservatively so the queue alone
	// can't push the process past its fd ulimit when the hasher pool
	// runs slower than the capturer pool. 512 + ~32 in-flight capturers
	// + baseline cilock fds (~150) leaves headroom under the typical
	// 1024 soft limit. Capturers block on send when full; consumer
	// stays unblocked because captureCh has its own 1M buffer.
	openatCh := make(chan *pendingHash, 512)

	// V2: there is no per-close "fallback" channel. The hasher pool
	// runs HashOpenatEvent at openat-time for every read-capable
	// open — that result is the race-tight baseline and stays in
	// OpenedFiles forever. Read-tap may later upgrade to a stricter
	// kernel-context streaming hash when it completes the full file,
	// but if it doesn't, the baseline is what stands. No
	// post-close path-hash fallback — that would be a TOCTOU lie.

	stopCh := make(chan struct{})

	// Per-(pid, fd) → path map so write/security/close events can resolve
	// fd → path even when the process exits before dispatch. A reopen of
	// the same key overwrites the prior entry.
	type pidFdKey struct {
		PID uint32
		FD  int32
	}
	type openInfo struct {
		Path string
		EV   *ebpf.OpenatEvent
	}
	openPaths := make(map[pidFdKey]*openInfo)
	var readTapBytes, readTapClosures atomic.Uint64
	// Write-tap counters: bytes the BPF kretprobe captured from sys_write.
	// Symmetric to readTapBytes — surfaced as diagnostic in the trace summary.
	var writeTapBytes, writeChunkSeen atomic.Uint64
	// ABLATION lever (deletable): CILOCK_EBPF_WRITETAP=off drops write
	// chunks in the dispatcher so products come ONLY from fanotify
	// close-write + survivor-walk + exists-at-exit. Tests whether the
	// write-tap is redundant (like the read-tap proved to be). The BPF
	// still emits the chunks; we just ignore them, and finalizeWriteTap
	// then no-ops on the empty hash.
	// Write-tap content is permanently OFF (hardcoded default): ablation
	// proved products are captured identically by fanotify FAN_CLOSE_WRITE +
	// survivor-walk + exists-at-exit (digest-verified on GHA Hugo). Write
	// chunks are dropped in the dispatch loop below.
	//
	// openat-time content hashing is skipped WHEN FANOTIFY IS ACTIVE —
	// fanotify (open-perm, hash-once) is the authoritative content source,
	// and the eBPF openat-hash was shown to add only non-regular/transient
	// NOISE (dirs, devices, /tmp cgo intermediates) with zero unique real
	// materials. It is retained ONLY as the no-fanotify fallback so non-GHA
	// runs without fanotify still capture material content.
	openatHashDisabled := r.fanotifySession != nil

	var readTotal, matchedTotal, otherTotal atomic.Uint64
	// V2 diagnostic: read-chunk traffic counters. Lets us distinguish
	// "BPF kprobe never fired for the tracee" from "kprobe fired but
	// our matchAndAdd rejected it" when files end up with digest=nil.
	// Surfaced into Summary.Diagnostics at trace end.
	var readChunkSeen, readChunkRejected atomic.Uint64
	// V2 Phase 8 stage 2 diagnostic: count how often the kernel-side
	// fd_table carried the path inline on the close event vs how
	// often we had to fall back to the userspace openPaths cache.
	// A high inlinePath ratio confirms stage 2 is doing its job and
	// the openPaths userspace map can be safely removed.
	var closeWithInlinePath, closeWithoutInlinePath atomic.Uint64
	// Phase 5 diagnostics: count of fds where read-tap captured only
	// a prefix of the file — the openat-time path-hash is the
	// authoritative digest for those (read-tap upgrade declined).
	// fallbackHashFailures counts openat-time path-hash failures
	// (file missing at hash time, permission denied, etc.) — those
	// entries land in OpenedFiles with a nil digest, which is the
	// honest stance: a hole in the attestation.
	var partialFallbacks, fallbackFailures atomic.Uint64
	// cacheReadsSkipped counts read opens the hasher released WITHOUT
	// hashing because the path classified as build-internal cache/temp
	// (pctx.cacheMatcher). Surfaced as a diagnostic so the reduction in
	// hash attempts (and the corresponding absence of cache-file gaps)
	// is transparent rather than a silent behavior change.
	var cacheReadsSkipped atomic.Uint64
	// Per-bucket counters for hash-failure outcomes. Surfaces the
	// difference between "we caught it elsewhere" (silentByDigest)
	// and "we already recorded this gap" (silentByDedup) so the
	// fallbackFailures total can be honestly explained, not handwaved.
	var hashSilentByDigest, hashSilentByDedup atomic.Uint64

	// V2 Phase 6/8: two-ringbuf architecture. The BPF program emits
	// classification-critical events (openat, execve, fileOps, etc.)
	// to the `events` ringbuf, and high-volume read-tap chunks to a
	// separate `read_tap_events` ringbuf. Each ringbuf is drained by
	// its OWN goroutine into evCh; the dispatcher reads only from
	// evCh, so it sees a single merged event stream while neither
	// reader can starve the other.
	//
	// Buffer size: must absorb the burst from BOTH readers when the
	// dispatcher hits a slow event (e.g. recordEBPFOpenat doing
	// /proc enrichment). JVM-class workloads emit 100k+ read-tap
	// events in a few seconds — under-sized evCh makes readers block,
	// which makes the BPF ringbuf fill, which causes drops. 1M slots
	// × 8B pointer = 8MB channel + ~280B/event × peak-in-flight ≈
	// 280MB worst case (most events are short-lived, peak in-flight
	// is much smaller).
	evCh := make(chan *ebpf.Event, 1024*1024)

	var readerWG sync.WaitGroup
	// Main events reader: openat / execve / fileOps / security /
	// write / network / close. NEVER allowed to starve.
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			ev, err := consumer.Read()
			if err != nil {
				if ebpf.IsFlushedError(err) || errors.Is(err, os.ErrClosed) {
					return
				}
				select {
				case <-stopCh:
					return
				default:
				}
				log.Debugf("(ebpf) events-ringbuf read transient error (skipping): %v", err)
				continue
			}
			select {
			case evCh <- ev:
			case <-stopCh:
				return
			}
		}
	}()
	// (The read-tap reader was removed — the read-tap is gone; fanotify is
	// the authoritative content source. Only the main events reader feeds
	// evCh now.)
	// Closer goroutine: once the reader exits (Flush or stopCh),
	// close evCh so the dispatcher's for-range terminates.
	go func() {
		readerWG.Wait()
		close(evCh)
	}()

	var consumerWG sync.WaitGroup
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		defer close(captureCh)

		for ev := range evCh {
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
						ev.Openat.Path = resolveCwdRelative(watched,
							ev.Openat.PID, ev.Openat.PPID, ev.Openat.Path, rootCwd)
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
					// Remember (pid, fd) → path so later write/security/
					// close events can resolve fd → path even when the
					// process exits fast and /proc/<pid>/fd/<fd> is gone by
					// dispatch time. A reopen of the same (pid, fd) simply
					// overwrites the prior entry.
					k := pidFdKey{PID: ev.Openat.PID, FD: ev.Openat.FD}
					openPaths[k] = &openInfo{Path: ev.Openat.Path, EV: ev.Openat}
				}
				// Hand off to the parallel capture pool. Consumer stays
				// microsecond-per-event; capturers do os.Open in
				// parallel before the tracee can exit.
				ph := &pendingHash{ev: ev.Openat}
				select {
				case captureCh <- ph:
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
				// Resolve any fd-bearing syscalls' paths from the
				// in-flight openPaths table so SyscallEvent.Path /
				// Detail can carry the human-meaningful target.
				secEv := ev.Security
				resolvedPaths := resolveSecurityFds(secEv, func(fd int32) string {
					if fd < 0 {
						return ""
					}
					oi, ok := openPaths[pidFdKey{PID: secEv.PID, FD: fd}]
					if !ok || oi == nil {
						return ""
					}
					return oi.Path
				})
				recordEBPFSecurity(pctx, secEv, resolvedPaths)
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
			}
		}
	}()

	// Capture pool: pulls events from captureCh and opens
	// /proc/<pid>/fd/<fd> in parallel before the tracee can close
	// the fd. The captured *os.File holds the inode alive; the
	// hasher pool can then read at its own pace even if the tracee
	// has unlinked the file or exited.
	//
	// Sized generously (NumCPU*8) because each capturer is I/O-
	// bound on a fast kernel path — most of its wall time is the
	// open syscall and a Stat. Higher parallelism shrinks the
	// queue-latency window between BPF emit and our open.
	captureWorkers := runtime.NumCPU() * 8
	if captureWorkers < 16 {
		captureWorkers = 16
	}
	var captureWG sync.WaitGroup
	var captureAttempts, captureSucceeded atomic.Uint64
	for i := 0; i < captureWorkers; i++ {
		captureWG.Add(1)
		go func() {
			defer captureWG.Done()
			for ph := range captureCh {
				ev := ph.ev
				// Only capture for read-capable opens with a valid
				// fd. Failed openats (fd<0), write-only, and O_PATH
				// pass through with file=nil — the hasher handles
				// those without needing a held fd.
				if ev.FD >= 0 && !ev.IsWriteOnly() && !ev.IsPathOnly() {
					captureAttempts.Add(1)
					if f, err := ebpf.CaptureFileForLaterHash(ev.PID, ev.FD); err == nil && f != nil {
						ph.file = f
						if st, ferr := f.Stat(); ferr == nil {
							ph.stat = st
						}
						captureSucceeded.Add(1)
					}
				}
				select {
				case openatCh <- ph:
				case <-stopCh:
					if ph.file != nil {
						_ = ph.file.Close()
					}
					return
				}
			}
		}()
	}
	// Close openatCh once the capture pool drains (after captureCh
	// is closed by the consumer's defer).
	go func() {
		captureWG.Wait()
		close(openatCh)
	}()

	// Hasher pool: parallel hashing of files referenced by openat
	// events. V2 attestation-correctness pivot: every openat (except
	// write-only / O_PATH) gets an immediate race-tight path-hash
	// via /proc/<pid>/fd/<fd>. Read-tap may later upgrade to a
	// kernel-context streaming hash via finalizeReadTap; if it
	// doesn't, the openat-time path-hash is the authoritative
	// digest. No post-close fallback — TOCTOU is a lie.
	var hashedTotal, suspectTotal, errorTotal atomic.Uint64
	var hasherWG sync.WaitGroup
	// Hasher pool size. CPU-bound + I/O-bound mix; more workers
	// than NumCPU helps because most workers spend time blocked
	// in open/read.
	hashWorkers := runtime.NumCPU() * 2
	if hashWorkers < 4 {
		hashWorkers = 4
	}
	if v := os.Getenv("CILOCK_HASH_WORKERS"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &hashWorkers); n == 1 && err == nil && hashWorkers > 0 {
			// override accepted
		}
	}
	for i := 0; i < hashWorkers; i++ {
		hasherWG.Add(1)
		go func() {
			defer hasherWG.Done()
			for ph := range openatCh {
				ev := ph.ev
				if watched.addAndReturnNew(ev.PID, ev.PPID) {
					_ = consumer.AddWatchedPID(ev.PID)
				}
				// Filter: fd<0 = openat syscall failed in the tracee
				// (ENOENT, EACCES, etc.). Nothing was opened; recording
				// it as a nil-digest entry would be a lie.
				if ev.FD < 0 {
					if ph.file != nil {
						_ = ph.file.Close()
					}
					continue
				}
				if ev.IsWriteOnly() || ev.IsPathOnly() {
					recordEBPFOpenatNoHash(pctx, ev)
					if ph.file != nil {
						_ = ph.file.Close()
					}
					continue
				}
				// Build-internal cache/temp reads (Go module cache,
				// GOCACHE, /tmp scratch) are content-addressed storage
				// pinned by lockfiles, not meaningful materials. Skip
				// hashing them: on a cold build they are the bulk of
				// opens, and they churn (created/renamed in ms) so the
				// path-hash fallback racemost often FAILS — those
				// failures otherwise inflate fallbackHashFailures /
				// hashFailureSilentDrops and break --require-zero-drops.
				// We do NOT record an open for them (no nil-digest gap).
				if pctx.cacheMatcher != nil && pctx.cacheMatcher.Matches(ev.Path) {
					cacheReadsSkipped.Add(1)
					if ph.file != nil {
						_ = ph.file.Close()
					}
					continue
				}
				// fanotify is the authoritative content source: don't hash
				// here, just record the open so fanotify reconciliation can
				// attach the kernel-synchronous digest. Only REGULAR,
				// still-present files are materials — non-regular files
				// (dirs/devices) and already-gone transient intermediates
				// (gcc/cgo /tmp/cc*.s) are neither materials nor gaps, so we
				// suppress them outright (an lstat is far cheaper than a
				// content hash). This keeps the gap list to real files only.
				if openatHashDisabled {
					// fanotify (open-perm, hash-once) is the authoritative
					// content source. Record the open's PATH (without an eBPF
					// content hash) so fanotify reconciliation attaches the
					// kernel-synchronous digest — fanotify-only digests are
					// not in the material tree on their own; they need a
					// recorded open to merge into. Only REGULAR, still-present
					// files are materials: lstat ev.Path authoritatively (the
					// captured ph.stat can be a stale fd-reuse stat), and drop
					// non-regular (dirs/devices) + already-gone transients so
					// they're neither materials nor false gaps.
					if s, e := os.Lstat(ev.Path); e != nil || !s.Mode().IsRegular() {
						if ph.file != nil {
							_ = ph.file.Close()
						}
						continue
					}
					recordEBPFOpenat(pctx, ev, ebpf.HashResult{
						Path:   ev.Path,
						Status: ebpf.TOCTOUError,
						Reason: "fanotify-authoritative: eBPF openat content hash skipped",
					})
					if ph.file != nil {
						_ = ph.file.Close()
					}
					continue
				}
				// Per-trace digest cache: most files in a build are
				// opened many times. Cache by (path, size, mtime);
				// hit means the same bytes are on disk → same digest.
				if cached, ok := pctx.lookupCachedDigest(ev.Path); ok {
					hashedTotal.Add(1)
					recordEBPFOpenat(pctx, ev, ebpf.HashResult{
						Path:   ev.Path,
						Digest: cached,
						Status: ebpf.TOCTOUStable,
					})
					if ph.file != nil {
						_ = ph.file.Close()
					}
					continue
				}
				// Race-tight capture branch: if the dispatcher
				// successfully held the inode via /proc/<pid>/fd/<fd>,
				// hash from THAT — works even when the tracee has
				// unlinked the file or exited. This is the path that
				// catches gcc's /tmp/cc*.s temp files (created, used,
				// unlinked within milliseconds).
				var res ebpf.HashResult
				if ph.file != nil {
					res = ebpf.HashCapturedFile(ev.Path, ph.file, ph.stat, pctx.hash)
				} else {
					// Capture failed — fall back to the original
					// stat-then-open path. Only happens when /proc
					// was already gone at capture time (extremely
					// fast-exit).
					res = ebpf.HashOpenatEvent(ev, pctx.hash)
				}
				hashedTotal.Add(1)
				switch res.Status {
				case ebpf.TOCTOUStable:
					if res.Digest != nil {
						pctx.cacheDigest(ev.Path, res.Digest)
					}
				case ebpf.TOCTOUSuspect:
					suspectTotal.Add(1)
				case ebpf.TOCTOUError, ebpf.TOCTOUMissing:
					errorTotal.Add(1)
					if strings.Contains(res.Reason, "is a directory") {
						continue
					}
					fallbackFailures.Add(1)
				}
				switch recordEBPFOpenat(pctx, ev, res) {
				case recordOutcomeSilentByDigest:
					hashSilentByDigest.Add(1)
				case recordOutcomeSilentByDedup:
					hashSilentByDedup.Add(1)
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
	close(stopCh) // unblock any inflight evCh send (defensive)
	hasherWG.Wait()

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
		r.partialReadFallbacks = partialFallbacks.Load()
		r.fallbackHashFailures = fallbackFailures.Load()
		r.hashSilentByDigest = hashSilentByDigest.Load()
		r.hashSilentByDedup = hashSilentByDedup.Load()
		r.cacheReadsSkipped = cacheReadsSkipped.Load()
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

	log.Debugf("(ebpf) trace complete: read=%d matched=%d other=%d hashed=%d toctou-suspect=%d errors=%d capture-attempts=%d capture-succeeded=%d",
		readTotal.Load(), matchedTotal.Load(), otherTotal.Load(),
		hashedTotal.Load(), suspectTotal.Load(), errorTotal.Load(),
		captureAttempts.Load(), captureSucceeded.Load())
	if v := os.Getenv("CILOCK_DIAGNOSE"); v == "1" {
		fmt.Fprintf(os.Stderr,
			"cilock-ebpf: parentPid=%d read=%d matched=%d other=%d hashed=%d suspect=%d errors=%d "+
				"readChunkSeen=%d readChunkRejected=%d readTapBytes=%d readTapClosures=%d "+
				"writeChunkSeen=%d writeTapBytes=%d "+
				"closeInlinePath=%d closeFallbackPath=%d\n",
			pctx.parentPid, readTotal.Load(), matchedTotal.Load(), otherTotal.Load(),
			hashedTotal.Load(), suspectTotal.Load(), errorTotal.Load(),
			readChunkSeen.Load(), readChunkRejected.Load(),
			readTapBytes.Load(), readTapClosures.Load(),
			writeChunkSeen.Load(), writeTapBytes.Load(),
			closeWithInlinePath.Load(), closeWithoutInlinePath.Load())
	}

	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), fmt.Errorf("exit status %v", pctx.exitCode)
	}
	return pctx.procInfoArray(), nil
}

// digestSetsEqual returns true when two DigestSets carry the same
// (algorithm, digest) pairs. Used to detect mid-build file mutation:
// the same path opened twice in the same process producing different
// digests signals an adversarial or build-script-driven content
// change between the opens.
func digestSetsEqual(a, b cryptoutil.DigestSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		if vb, ok := b[k]; !ok || vb != va {
			return false
		}
	}
	return true
}

// RecordOutcome reports how recordEBPFOpenat dispositioned a hash
// result, so the caller can tally per-bucket counters without
// re-implementing the dispatch logic.
type recordOutcome int

const (
	recordOutcomeNone           recordOutcome = iota // success path (Stable/Suspect)
	recordOutcomeSilentByDigest                      // failure: OpenedFiles already had a digest
	recordOutcomeSilentByDedup                       // failure: UnhashedOpens already had an entry
	recordOutcomeUnhashedAdded                       // failure: new UnhashedOpens entry
)

// recordEBPFOpenat records one openat event + its hash result into
// the appropriate ProcessInfo. Concurrent-safe via pctx.mu, which
// guards both the processes-map and the ProcessInfo entries within.
func recordEBPFOpenat(pctx *ptraceContext, ev *ebpf.OpenatEvent, res ebpf.HashResult) recordOutcome {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()
	outcome := recordOutcomeNone

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

	// Digest write rules:
	//   - TOCTOUStable: we have a verified digest. Store it on first
	//     observation. On subsequent observations, if the digest
	//     matches the stored one, no-op. If it DIFFERS, the file was
	//     mutated between the two opens — keep the FIRST digest (the
	//     bytes the tracee saw earlier are what we attest) and surface
	//     a SyscallEvent so verifiers can find the divergence.
	//     Silently overwriting would lose the signal that the file
	//     changed during the build, which is exactly the adversarial
	//     case attestation must catch.
	//   - TOCTOUSuspect: stat mismatched during hash but we have bytes;
	//     store the suspect digest ONLY if no prior stable digest
	//     exists. A transient suspect read shouldn't clobber a clean
	//     read from the same file moments earlier.
	//   - TOCTOUMissing / TOCTOUError: hash FAILED, no digest. We do
	//     NOT add or update an OpenedFiles entry — the attestation
	//     records only files we have content for. Without this rule,
	//     transient races (gcc unlinking temp files mid-build, fd
	//     reuse between fast-exiting processes) would leave nil-digest
	//     entries — exploitable holes where a file appears "captured"
	//     but its content isn't attested. Verifiers wouldn't be able
	//     to tell the difference between "file was opened with no
	//     known content" and "file was opened with KNOWN content"
	//     without explicit out-of-band metadata. Better to omit the
	//     entry entirely; the rest of the attestation (file events,
	//     fork tree, etc.) still reflects that something happened.
	switch res.Status {
	case ebpf.TOCTOUStable:
		if existing, ok := procInfo.OpenedFiles[res.Path]; ok && existing != nil {
			if !digestSetsEqual(existing, res.Digest) {
				// MID-BUILD MUTATION: same path produced two different
				// stable digests in the same process. Surface to the
				// verifier via SyscallEvents; keep the first digest.
				procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
					Syscall:   "openat",
					Detail:    fmt.Sprintf("TOCTOU-mutation: same path, different digest on second open (path=%s)", res.Path),
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				})
			}
			// Either equal (no-op) or different (kept first). Do not overwrite.
			break
		}
		procInfo.OpenedFiles[res.Path] = res.Digest
	case ebpf.TOCTOUSuspect:
		if existing := procInfo.OpenedFiles[res.Path]; existing == nil {
			procInfo.OpenedFiles[res.Path] = res.Digest
		}
	default:
		// TOCTOUMissing / TOCTOUError: record into UnhashedOpens with
		// the failure reason. If the SAME path elsewhere produced a
		// stable digest in OpenedFiles, the OpenedFiles entry wins —
		// don't also pollute UnhashedOpens with a duplicate of a
		// path we successfully captured.
		if _, hashed := procInfo.OpenedFiles[res.Path]; hashed {
			outcome = recordOutcomeSilentByDigest
			break
		}
		// Non-regular files (directories, char/block devices, pipes,
		// sockets, symlinks) are not content gaps — there's nothing to
		// hash and they aren't materials. Every build opens /dev/null,
		// locale dirs, /proc subdirs, etc.; recording them as "unhashed
		// opens" is a false gap that pollutes the verifier view and trips
		// --require-zero-drops. Drop them (not a real gap). If a future
		// policy needs "what directories/devices did the build touch," add
		// a dedicated field; today suppression is the right call.
		if res.NonRegular || strings.HasPrefix(res.Reason, "directory open") {
			outcome = recordOutcomeSilentByDedup // bookkeeping: not a real gap
			break
		}
		// Avoid recording the same (path, reason) twice — gcc opens
		// /tmp/cc.s many times from many processes; one UnhashedOpen
		// per path per process is enough signal.
		alreadyRecorded := false
		for _, u := range procInfo.UnhashedOpens {
			if u.Path == res.Path {
				alreadyRecorded = true
				break
			}
		}
		if alreadyRecorded {
			outcome = recordOutcomeSilentByDedup
		} else {
			procInfo.UnhashedOpens = append(procInfo.UnhashedOpens, UnhashedOpen{
				Path:   res.Path,
				Reason: res.Reason,
			})
			outcome = recordOutcomeUnhashedAdded
		}
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
	return outcome
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
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	if procInfo.ParentPID == 0 {
		procInfo.ParentPID = int(ev.PPID)
	}
	// V2 attestation correctness: write-only / O_PATH opens DO NOT
	// belong in OpenedFiles (which carries "files read for content").
	// They're outputs tracked in FileOps.Writes below — and the
	// product attestor will hash the final on-disk state. Putting
	// them in OpenedFiles with nil digest creates phantom "holes"
	// that look like attestation gaps but aren't — they're outputs.

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
// fdResolvedPaths holds path lookups for syscalls that carry file
// descriptors in their args. Index is positional in ev.Args; value
// is the resolved path (empty when openPaths had no entry).
type fdResolvedPaths struct {
	// Primary is the "main" file the syscall acts on (the mmap target,
	// the read source for sendfile/copy_file_range/splice).
	Primary string
	// Secondary is the destination side for two-fd transfers
	// (sendfile in→out, copy_file_range src→dst, splice in→out).
	Secondary string
}

// resolveSecurityFds looks up the file paths the security event's fd
// args reference. The lookup closure is supplied by the dispatcher
// (which holds openPaths in scope); done at dispatch time because
// the fd may be closed by the time recordEBPFSecurity runs.
func resolveSecurityFds(
	ev *ebpf.SecurityEvent,
	lookup func(fd int32) string,
) fdResolvedPaths {
	if ev == nil || lookup == nil {
		return fdResolvedPaths{}
	}
	const (
		secCopyFileRange = 113
		secSplice        = 114
		secSendfile      = 115
		secMmap          = 116
	)
	switch ev.SyscallNr {
	case secMmap:
		// Args layout: a0=prot, a1=flags, a2=fd
		if len(ev.Args) >= 3 {
			return fdResolvedPaths{Primary: lookup(int32(ev.Args[2]))}
		}
	case secCopyFileRange:
		// Args: a0=fd_in, a1=fd_out
		if len(ev.Args) >= 2 {
			return fdResolvedPaths{
				Primary:   lookup(int32(ev.Args[0])),
				Secondary: lookup(int32(ev.Args[1])),
			}
		}
	case secSplice:
		// Args: a0=fd_in, a2=fd_out
		if len(ev.Args) >= 3 {
			return fdResolvedPaths{
				Primary:   lookup(int32(ev.Args[0])),
				Secondary: lookup(int32(ev.Args[2])),
			}
		}
	case secSendfile:
		// Args: a0=out_fd, a1=in_fd (kernel API order)
		if len(ev.Args) >= 2 {
			return fdResolvedPaths{
				Primary:   lookup(int32(ev.Args[1])), // source (in_fd)
				Secondary: lookup(int32(ev.Args[0])), // destination (out_fd)
			}
		}
	}
	return fdResolvedPaths{}
}

func recordEBPFSecurity(pctx *ptraceContext, ev *ebpf.SecurityEvent, paths fdResolvedPaths) {
	pctx.mu.Lock()
	defer pctx.mu.Unlock()

	procInfo := pctx.getProcInfo(int(ev.PID))
	if procInfo.Comm == "" {
		procInfo.Comm = ev.Comm
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	se := classifyEBPFSecurityEvent(ev, paths)
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
func classifyEBPFSecurityEvent(ev *ebpf.SecurityEvent, paths fdResolvedPaths) SyscallEvent {
	// IDs must match CILOCK_SEC_* in openat_kprobe.bpf.c.
	const (
		secPtrace        = 100
		secMemfdCreate   = 101
		secMount         = 102
		secMprotect      = 103
		secPrctl         = 104
		secSetsid        = 105
		secSetns         = 106
		secInitModule    = 107
		secFinitModule   = 108
		secClone         = 109
		secClone3        = 110
		secDup2          = 111
		secDup3          = 112
		secCopyFileRange = 113
		secSplice        = 114
		secSendfile      = 115
		secMmap          = 116
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
	case secCopyFileRange:
		// copy_file_range(fd_in, off_in, fd_out, off_out, len, flags).
		// Zero-copy intra-FS copy — bytes move kernel-side without
		// firing our read kprobe. Read-tap can't see them. Surface so
		// the verifier knows: any output file produced via this call
		// has its CONTENT digest derived from the openat-time hash
		// or read-tap on OTHER reads, NOT from the bytes moved here.
		// Args[0..3] are fd_in, off_in, fd_out, off_out; len + flags
		// are beyond the 4-arg SecurityEvent capture window.
		// Zero-copy intra-FS copy. Bytes-not-captured is a property of
		// the syscall itself (documented once in commandrun docs); no
		// need to spell it out per event. Args + Path identify what
		// the kernel moved; verifier reasons from the syscall name.
		return SyscallEvent{
			Syscall:    "copy_file_range",
			Args:       []int{int(ev.Args[0]), int(ev.Args[2])},
			Path:       paths.Primary,
			TargetPath: paths.Secondary,
		}
	case secSplice:
		return SyscallEvent{
			Syscall:    "splice",
			Args:       []int{int(ev.Args[0]), int(ev.Args[2])},
			Path:       paths.Primary,
			TargetPath: paths.Secondary,
		}
	case secSendfile:
		// sendfile(out_fd, in_fd, offset, count). Source is in_fd.
		return SyscallEvent{
			Syscall:    "sendfile",
			Args:       []int{int(ev.Args[1]), int(ev.Args[0]), int(ev.Args[3])},
			Path:       paths.Primary,
			TargetPath: paths.Secondary,
		}
	case secMmap:
		// File-backed mmap with PROT_READ. Args layout: a0=prot,
		// a1=flags, a2=fd. The fact that mmap-reads bypass read-tap
		// is a property of mmap itself, documented in the schema —
		// not repeated per event.
		return SyscallEvent{
			Syscall: "mmap",
			Args:    []int{int(ev.Args[2]), int(ev.Args[0]), int(ev.Args[1])},
			Path:    paths.Primary,
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
	case ebpf.EVT_DNS_QUERY:
		// udp_sendmsg to port 53/5353. Authoritative DNS signal —
		// catches both connected and unconnected UDP sends, where the
		// connect-based heuristic above misses unconnected sendto/
		// sendmsg patterns (which is how glibc's resolver actually
		// queries).
		conn := parseSockaddrEBPF(ev.Family, ev.Addr[:], "dns_query")
		procInfo.Network.DNSLookups = append(procInfo.Network.DNSLookups, DNSLookup{
			ServerAddress: conn.Address,
			ServerPort:    conn.Port,
		})
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "dns_query",
			Detail:    fmt.Sprintf("UDP DNS to %s:%d — query payload not parsed (QNAME capture is V2 phase 6 follow-on)", conn.Address, conn.Port),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})
	case ebpf.EVT_CONNECT_RET:
		// Return code lives in the family field (see emit_connect_ret).
		// Treat 0 as success, negative as errno.
		rc := int32(ev.Family)
		procInfo.SyscallEvents = append(procInfo.SyscallEvents, SyscallEvent{
			Syscall:   "connect_result",
			Detail:    fmt.Sprintf("connect returned %d (%s)", rc, connectResultLabel(rc)),
			Args:      []int{int(rc)},
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

// connectResultLabel turns a connect(2) return code into a short
// human-readable verdict for SyscallEvent.Detail.
func connectResultLabel(rc int32) string {
	switch {
	case rc == 0:
		return "success"
	case rc == -115:
		return "EINPROGRESS (non-blocking)"
	case rc < 0:
		return fmt.Sprintf("failed (errno=%d)", -rc)
	}
	return "unknown"
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
//  1. depth=4 openat arrives at dispatcher → watched.match passes
//     (ppid=cilock=root) → enqueued to openatCh.
//  2. depth=3 openat arrives → watched.match: pid/tgid not in set,
//     ppid=depth=4 — depth=4 NOT YET in set because addAndReturnNew
//     runs in the HASHER goroutine which hasn't drained openatCh yet
//     → REJECTED. depth=3's events are dropped.
//  3. Hasher pulls depth=4 from openatCh, adds it to set. Too late
//     for depth=3 and everything beneath it.
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
