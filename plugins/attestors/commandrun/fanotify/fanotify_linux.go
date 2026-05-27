// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

// Package fanotify implements a zero-drop file-content capture path
// using Linux's fanotify FAN_OPEN_PERM permission events. Unlike BPF
// ringbufs (which silently drop under load), fanotify synchronously
// blocks the tracee on each open() until userspace responds — natural
// backpressure built into the kernel since 2.6.36.
//
// Production patterns used here: ClamAV's clamonacc, fapolicyd, and
// commercial EDR agents all use FAN_OPEN_PERM to intercept opens,
// inspect the file, and grant/deny access. We use the same primitive
// but for attestation: read every byte, compute SHA-256, allow.
//
// Limitations (documented honestly):
//   - mmap reads (page faults) bypass fanotify; BPF read-tap is still
//     needed for those.
//   - zero-copy syscalls (splice/sendfile/copy_file_range) don't fire
//     fanotify; same gap as today.
//   - O_PATH opens don't trigger FAN_OPEN_PERM.
//   - 5-second handler timeout — if userspace is too slow, kernel
//     defaults to FAN_ALLOW; we count these as "degraded" and surface.
//   - 10 consecutive timeouts evicts the group; we re-init if seen.
package fanotify

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Stats is the snapshot type returned by GetStats. The Handler
// stores atomic counters internally (statsAtomic) so workers can
// increment concurrently; GetStats reads them with atomic.Load.
type Stats struct {
	EventsReceived    uint64
	EventsHashed      uint64
	HashErrors        uint64
	HandlerTimeouts   uint64 // events where reading took > budget
	HandlerLatencyP99 time.Duration
	BytesHashed       uint64
	MarkFailures      uint64
	UnknownFamily     uint64 // events without a usable fd
	QueueOverflows    uint64 // FAN_Q_OVERFLOW events — kernel dropped
	// DigestsCapHit counts paths where the handler hashed the file
	// but DID NOT store the digest because the per-trace cap was
	// reached. The tracee was still allowed to proceed; the
	// attestation lacks the path's entry. Non-zero = resource cap
	// degraded the attestation.
	DigestsCapHit uint64
	// CacheSkips counts events the handler released WITHOUT hashing
	// because the path classified as build-internal cache/temp (via
	// SkipHash). These are content-addressed storage (Go module cache,
	// GOCACHE, /tmp scratch) pinned by lockfiles — hashing them adds
	// no provenance and is the dominant synchronous cost + backpressure
	// source on cold builds, so we skip them on purpose.
	CacheSkips uint64
	// IgnoreMarksAdded counts inode FAN_MARK_IGNORE marks added by the
	// "hash once" experiment (EnvVarIgnoreOnce). After first hashing an
	// inode we tell the kernel to stop sending FAN_OPEN_PERM for it
	// (re-armed on modify), collapsing repeat-open storms in-kernel.
	IgnoreMarksAdded uint64
	// IgnoreMarkErrors counts failures to add an ignore mark (does not
	// affect correctness — the file was still hashed; we just keep
	// getting events for it).
	IgnoreMarkErrors uint64
}

// statsAtomic holds the live counters mutated by worker goroutines.
// Snapshot via toStats() (Atomic.Load). All adds use atomic.AddUint64.
type statsAtomic struct {
	EventsReceived   atomic.Uint64
	EventsHashed     atomic.Uint64
	HashErrors       atomic.Uint64
	HandlerTimeouts  atomic.Uint64
	BytesHashed      atomic.Uint64
	MarkFailures     atomic.Uint64
	UnknownFamily    atomic.Uint64
	QueueOverflows   atomic.Uint64
	DigestsCapHit    atomic.Uint64
	CacheSkips       atomic.Uint64
	IgnoreMarksAdded atomic.Uint64
	IgnoreMarkErrors atomic.Uint64
}

func (s *statsAtomic) toStats() Stats {
	return Stats{
		EventsReceived:   s.EventsReceived.Load(),
		EventsHashed:     s.EventsHashed.Load(),
		HashErrors:       s.HashErrors.Load(),
		HandlerTimeouts:  s.HandlerTimeouts.Load(),
		BytesHashed:      s.BytesHashed.Load(),
		MarkFailures:     s.MarkFailures.Load(),
		UnknownFamily:    s.UnknownFamily.Load(),
		QueueOverflows:   s.QueueOverflows.Load(),
		DigestsCapHit:    s.DigestsCapHit.Load(),
		CacheSkips:       s.CacheSkips.Load(),
		IgnoreMarksAdded: s.IgnoreMarksAdded.Load(),
		IgnoreMarkErrors: s.IgnoreMarkErrors.Load(),
	}
}

// Handler runs the fanotify capture loop. Construct with New, start
// with Run, query digests via Digests, close via Close.
//
// Goroutine model:
//   - One reader goroutine pulls events from the fanotify fd.
//   - For each event we hash the file ON THE SAME GOROUTINE before
//     responding. fanotify serializes per-event so the tracee waits
//     until we respond — parallelizing without care risks reordering
//     responses, which the kernel does NOT allow (response fd must
//     match event fd; out-of-order is fine but each response must be
//     written before the kernel times out).
//   - For now: synchronous-per-event. If throughput becomes an issue
//     we can pool workers later.
type Handler struct {
	fd       int
	closed   atomic.Bool
	stats    statsAtomic
	digestMu sync.Mutex
	digests  map[string][32]byte
	// closeWriteDigests holds the FINAL content hash of files the tracee
	// closed after writing (FAN_CLOSE_WRITE). Unlike `digests` (open-time,
	// = inputs/reads), these are PRODUCTS — the kernel hashes the file at
	// close, so the digest is the finished output, captured zero-drop
	// (modulo queue overflow, which is counted) and independent of the
	// lossy eBPF write-tap. Scoped to workspaceRoot to bound overhead.
	closeWriteDigests map[string][32]byte
	// workspaceRoot bounds FAN_CLOSE_WRITE hashing to the build workspace:
	// products live there, and hashing every closed file across the whole
	// marked filesystem (every /tmp/go-build/*.a) would be ruinous. Reads
	// stay filesystem-wide; only product capture is scoped.
	workspaceRoot string
	// Per-event handler budget. Default 2s leaves margin under the
	// kernel's 5s default timeout; configurable for stress tests.
	HandlerBudget time.Duration
	// MaxDigests caps the digests map size to bound memory under
	// adversarial / pathological workloads (tracee opens 1M files).
	// Once reached, we still hash + respond FAN_ALLOW (tracee runs)
	// but stop storing new path → digest entries; the cap-hit
	// counter surfaces the degradation. Zero = unbounded (default
	// 200_000, set in New).
	MaxDigests int
	// SkipHash, when non-nil, is consulted per event with the kernel-
	// resolved path. Returning true releases the tracee (FAN_ALLOW for
	// permission events) WITHOUT hashing the file. Used to skip
	// build-internal cache/temp paths (Go module cache, GOCACHE, /tmp),
	// which are the bulk of opens on a cold build and are content-
	// addressed by lockfiles — hashing them is wasted work and the
	// dominant backpressure source. Set before Run; read-only after.
	SkipHash func(path string) bool

	// ignoreOnce enables the "hash each inode once" EXPERIMENT
	// (EnvVarIgnoreOnce). After first hashing an inode's open we add an
	// inode FAN_MARK_IGNORE for FAN_OPEN_PERM so the kernel stops
	// notifying us about repeat opens of that inode — collapsing the
	// repeat-open storm of a cold build at the source. We deliberately
	// do NOT set FAN_MARK_IGNORED_SURV_MODIFY, so a modify RE-ARMS
	// notification (a rewritten material gets re-hashed — correctness).
	ignoreOnce bool
	// ignoredInodes dedupes the FanotifyMark syscall: once an inode is
	// ignored we don't re-issue the mark. Guarded by digestMu.
	ignoredInodes map[uint64]struct{}
}

// New opens a fanotify fd and registers a mark on the given mount
// (or path-based fallback). Returns Handler ready to Run, or an
// error describing why fanotify isn't available (the caller should
// fall back to BPF-only).
//
// CAP_SYS_ADMIN is required; without it FanotifyInit returns EPERM
// and the caller must cope.
//
// markPath is the primary path (typically the build workingdir).
// Additional paths whose filesystems the build is likely to read
// from — system libs, the Go/Rust/Python toolchains under
// /opt/hostedtoolcache on GHA, the user's $HOME, /usr, /lib — are
// marked automatically. Without these extra marks fanotify only
// sees opens on the workingdir's filesystem (tmpfs in our typical
// smoke), and any /opt/hostedtoolcache read counts as an unhashed
// open. Smoke run 26421741975 hit this on hello-go: 10 unhashed
// opens, all in /opt/hostedtoolcache/go/.../bin/go and friends.
//
// FAN_MARK_FILESYSTEM dedupes per-filesystem — marking 5 paths
// that all live on / is a single in-kernel filesystem-mark.
func New(markPath string) (*Handler, error) {
	if markPath == "" {
		return nil, errors.New("fanotify: empty markPath")
	}
	// FAN_CLASS_CONTENT enables permission events; FAN_NONBLOCK lets
	// us poll(). We don't use FAN_REPORT_FID — keeping the simpler
	// fd-based path matching ClamAV's pattern.
	//
	// Note: FAN_UNLIMITED_QUEUE was trialed (drops the 16384-event cap)
	// and removed — the cap never overflowed in practice (0 FAN_Q_OVERFLOW
	// across local + GHA Azure cold builds), because the blocking
	// permission handler throttles the queue. Re-add the flag here under
	// CAP_SYS_ADMIN if a high-core-count workload ever shows overflows.
	const fanFlags = unix.FAN_CLASS_CONTENT | unix.FAN_NONBLOCK | unix.FAN_CLOEXEC
	const eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	fd, err := unix.FanotifyInit(fanFlags, eventFlags)
	if err != nil {
		return nil, fmt.Errorf("FanotifyInit: %w", err)
	}
	// FAN_OPEN_PERM (permission, blocks the tracee → zero-drop reads) for
	// materials; FAN_CLOSE_WRITE (notification) for products — the kernel
	// hashes the final content when a written file is closed, so product
	// digests no longer depend on the lossy eBPF write-tap.
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_CLOSE_WRITE)

	// Coverage paths. The first one must succeed (it's the build's
	// own workspace — if we can't watch that, the whole layer is
	// useless). Subsequent paths are best-effort; a missing path
	// (e.g., /opt/hostedtoolcache on non-GHA) is fine to skip.
	primary := []string{markPath}
	extra := []string{
		"/",
		"/usr",
		"/opt",
		"/home",
		"/tmp",
	}

	if err := markFilesystemOrMount(fd, mask, primary[0]); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fanotify primary mark on %q: %w", primary[0], err)
	}
	for _, p := range extra {
		if p == markPath {
			continue
		}
		var st unix.Stat_t
		if statErr := unix.Stat(p, &st); statErr != nil {
			continue // path doesn't exist on this system
		}
		_ = markFilesystemOrMount(fd, mask, p) // best-effort
	}

	h := &Handler{
		fd:                fd,
		digests:           make(map[string][32]byte),
		closeWriteDigests: make(map[string][32]byte),
		workspaceRoot:     markPath,
		HandlerBudget:     2 * time.Second,
		MaxDigests:        defaultMaxDigestsFromEnv(),
		ignoreOnce:        ignoreOnceEnabled(),
		ignoredInodes:     make(map[uint64]struct{}),
	}
	return h, nil
}

// EnvVarIgnoreOnce controls "hash each inode once" — after hashing an
// inode's open, FAN_MARK_IGNORE its FAN_OPEN_PERM (re-armed on modify) so
// the kernel stops re-notifying. DEFAULT ON (validated on GHA Azure: −71%
// synchronous hashes / −16% wall on a cold Hugo build; −79%/−30% on a
// synthetic build, correctness-safe). Set to "0"/"off"/"false" to disable.
const EnvVarIgnoreOnce = "CILOCK_FANO_IGNORE_ONCE"

// ignoreOnceEnabled returns whether the hash-once optimization is active.
// DEFAULT ON: only an explicit off-switch disables it.
func ignoreOnceEnabled() bool {
	switch os.Getenv(EnvVarIgnoreOnce) {
	case "0", "off", "false", "no":
		return false
	default:
		return true
	}
}

// DefaultMaxDigests is the compiled-in cap on the digests map size,
// applied when CILOCK_FANOTIFY_MAX_DIGESTS is unset or unparseable.
// Operators tune via the env var; exposed for the override-audit
// regression test.
const DefaultMaxDigests = 200_000

// EnvVarFanotifyMaxDigests is the env-var name operators set to
// override the fanotify digests-map cap. Advanced knob — there is
// no CLI flag because tuning it is uncommon and the env-var surface
// keeps `cilock run --help` from drowning in resource-tuning flags.
const EnvVarFanotifyMaxDigests = "CILOCK_FANOTIFY_MAX_DIGESTS"

// defaultMaxDigestsFromEnv returns the effective MaxDigests for a
// new Handler. Resolves CILOCK_FANOTIFY_MAX_DIGESTS if set to a
// positive integer; otherwise falls back to DefaultMaxDigests.
// A non-positive or unparseable value is logged and ignored — the
// fail-safe is the default, not a silent zero (which would mean
// "unbounded" and could OOM on adversarial workloads).
func defaultMaxDigestsFromEnv() int {
	v := os.Getenv(EnvVarFanotifyMaxDigests)
	if v == "" {
		return DefaultMaxDigests
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		// Don't import the project log package here — fanotify is
		// already loaded very early; just write to stderr. Operators
		// running with a typo'd env var get one visible warning
		// instead of a silent fall-through.
		fmt.Fprintf(os.Stderr,
			"cilock: ignoring invalid %s=%q (want positive integer); using default %d\n",
			EnvVarFanotifyMaxDigests, v, DefaultMaxDigests)
		return DefaultMaxDigests
	}
	return n
}

// markFilesystemOrMount tries FAN_MARK_FILESYSTEM first (covers the
// whole filesystem the path lives on — single in-kernel mark covers
// every file regardless of where the build wanders), falls back to
// FAN_MARK_MOUNT if FILESYSTEM isn't accepted on this kernel/FS
// combination (e.g. virtiofs, some overlayfs configurations).
func markFilesystemOrMount(fd int, mask uint64, path string) error {
	fsFlags := uint(unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM)
	if err := unix.FanotifyMark(fd, fsFlags, mask, unix.AT_FDCWD, path); err == nil {
		return nil
	}
	mntFlags := uint(unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT)
	if err := unix.FanotifyMark(fd, mntFlags, mask, unix.AT_FDCWD, path); err != nil {
		return fmt.Errorf("FanotifyMark on %q: %w", path, err)
	}
	return nil
}

// Probe returns nil if fanotify with FAN_OPEN_PERM is available for
// the given path. Use this for capture-mode auto-detect without
// allocating a long-running Handler.
func Probe(markPath string) error {
	const fanFlags = unix.FAN_CLASS_CONTENT | unix.FAN_NONBLOCK | unix.FAN_CLOEXEC
	const eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	fd, err := unix.FanotifyInit(fanFlags, eventFlags)
	if err != nil {
		return fmt.Errorf("FanotifyInit: %w (CAP_SYS_ADMIN required)", err)
	}
	defer func() { _ = unix.Close(fd) }()
	// Try the mark to ensure the mount supports it. FILESYSTEM is
	// the desired mode; if that fails, try MOUNT.
	mask := uint64(unix.FAN_OPEN_PERM)
	if err := unix.FanotifyMark(fd, uint(unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM), mask, unix.AT_FDCWD, markPath); err != nil {
		if err2 := unix.FanotifyMark(fd, uint(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT), mask, unix.AT_FDCWD, markPath); err2 != nil {
			return fmt.Errorf("FanotifyMark FILESYSTEM=%v MOUNT=%v", err, err2)
		}
	}
	return nil
}

// Run is the handler loop. It returns when ctx is cancelled or the
// fanotify fd is closed. Blocking call — caller spawns in a goroutine.
//
// Architecture: one reader goroutine pulls events from the fanotify
// fd and feeds N worker goroutines via an unbuffered channel. Each
// worker hashes the file and writes its FAN_ALLOW response. The
// kernel only requires that EACH response includes the matching
// event fd — out-of-order responses are valid. Parallelism caps at
// runtime.NumCPU (min 2, max 16) to bound contention on the
// response write (sequential under a mutex) and the digests map.
//
// Per-event flow:
//  1. Reader: poll → read events → parse → forward each via chan.
//  2. Worker: read user's path via /proc/self/fd readlink → fstat
//     to filter non-regular files → SHA-256 the fd → write
//     FAN_ALLOW response → close the event fd.
func (h *Handler) Run(ctx context.Context) error {
	const workerChanBuffer = 1024
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > 16 {
		workerCount = 16
	}
	work := make(chan unix.FanotifyEventMetadata, workerChanBuffer)

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range work {
				h.handleOne(&m)
			}
		}()
	}
	defer func() {
		close(work)
		wg.Wait()
	}()

	buf := make([]byte, 4096)
	pollFds := []unix.PollFd{{Fd: int32(h.fd), Events: unix.POLLIN}}
	for {
		if h.closed.Load() {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// Poll with a short timeout so ctx cancellation is responsive.
		_, err := unix.Poll(pollFds, 200)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if h.closed.Load() {
				return nil
			}
			return fmt.Errorf("fanotify poll: %w", err)
		}
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := unix.Read(h.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if h.closed.Load() || errors.Is(err, unix.EBADF) {
				return nil
			}
			return fmt.Errorf("fanotify read: %w", err)
		}
		// Parse + dispatch events to worker pool. Reader stays fast;
		// workers do the hashing in parallel.
		h.processBatchToWorkers(buf[:n], work)
	}
}

// processBatchToWorkers parses one read()'s worth of events and
// forwards each to the worker pool. Same parsing as processBatch
// but writes to a channel instead of handling inline.
func (h *Handler) processBatchToWorkers(data []byte, work chan<- unix.FanotifyEventMetadata) {
	const metadataSize = 24
	for len(data) >= metadataSize {
		var meta unix.FanotifyEventMetadata
		meta.Event_len = binary.LittleEndian.Uint32(data[0:])
		meta.Vers = data[4]
		meta.Reserved = data[5]
		meta.Metadata_len = binary.LittleEndian.Uint16(data[6:])
		meta.Mask = binary.LittleEndian.Uint64(data[8:])
		meta.Fd = int32(binary.LittleEndian.Uint32(data[16:]))
		meta.Pid = int32(binary.LittleEndian.Uint32(data[20:]))

		if meta.Event_len < metadataSize || int(meta.Event_len) > len(data) {
			break
		}
		work <- meta
		data = data[meta.Event_len:]
	}
}

// handleOne processes a single fanotify event and writes the
// response. Thread-safe via atomic counters + digestMu — N workers
// can call concurrently from the Run loop.
//
// Always responds FAN_ALLOW even on hash failure — we're here for
// attestation, not access control. Closing the event fd is REQUIRED;
// without it we leak fds and the kernel eventually stalls.
func (h *Handler) handleOne(meta *unix.FanotifyEventMetadata) {
	h.stats.EventsReceived.Add(1)

	start := time.Now()
	defer func() {
		if elapsed := time.Since(start); elapsed > h.HandlerBudget {
			h.stats.HandlerTimeouts.Add(1)
		}
	}()

	// FAN_Q_OVERFLOW: the kernel dropped events because our handler
	// fell behind. Count these explicitly — they're the canonical
	// signal that fanotify lost data. The kernel emits this synthetic
	// event with Fd == FAN_NOFD (a fanotify-specific sentinel = -1).
	if meta.Mask&unix.FAN_Q_OVERFLOW != 0 {
		h.stats.QueueOverflows.Add(1)
		// No fd to close, no response to write.
		return
	}

	// fd<0 means kernel had no fd to give us (rare; OOM, anonymous
	// inode). Allow anyway — we can't hash but the tracee shouldn't
	// be blocked.
	if meta.Fd < 0 {
		h.stats.UnknownFamily.Add(1)
		h.respond(meta.Fd, true)
		return
	}
	defer func() { _ = unix.Close(int(meta.Fd)) }()

	isOpenPerm := meta.Mask&unix.FAN_OPEN_PERM != 0
	isCloseWrite := meta.Mask&unix.FAN_CLOSE_WRITE != 0

	// respondIfPerm writes the kernel response only for permission
	// events. FAN_CLOSE_WRITE is a notification — responding to it is
	// wrong (the kernel isn't waiting). Centralizing this keeps every
	// early-return path correct for both event classes.
	respondIfPerm := func() {
		if isOpenPerm {
			h.respond(meta.Fd, true)
		}
	}

	if !isOpenPerm && !isCloseWrite {
		// An event we didn't ask for. Only release the tracee if it's a
		// permission class event; notifications need no response.
		respondIfPerm()
		return
	}

	// Resolve path via /proc/self/fd/<fd> readlink — works because
	// we OWN this fd (kernel handed it to us). The path is the
	// canonical kernel-resolved path the tracee actually opened/closed.
	procPath := fmt.Sprintf("/proc/self/fd/%d", meta.Fd)
	realPath, lerr := os.Readlink(procPath)
	if lerr != nil {
		h.stats.HashErrors.Add(1)
		respondIfPerm()
		return
	}

	// Cache/temp paths are build-internal, content-addressed storage
	// (Go module cache, GOCACHE, /tmp scratch). They are neither
	// products nor meaningful materials — their provenance comes from
	// lockfiles (go.sum) + the build attestor, not per-file hashes.
	// Skipping them here removes the dominant synchronous-hash load on
	// cold builds, cutting handler latency (→ fewer timeouts / queue
	// overflows) and overall overhead. Release the tracee immediately.
	if h.SkipHash != nil && h.SkipHash(realPath) {
		h.stats.CacheSkips.Add(1)
		// EXPERIMENT (deletable): under "hash once", also tell the kernel
		// to stop notifying us about this cache inode entirely — the cache
		// storm (GOCACHE/module cache, the bulk of opens) then collapses at
		// the kernel boundary instead of crossing it cheaply each time.
		// Safe: cache files aren't attested, and a modify re-arms the mark.
		if h.ignoreOnce && isOpenPerm {
			var st syscall.Stat_t
			if syscall.Fstat(int(meta.Fd), &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG {
				h.maybeIgnoreInode(uint64(st.Ino), realPath)
			}
		}
		respondIfPerm()
		return
	}

	// Product capture (close-write) is scoped to the build workspace —
	// hashing every closed file across the whole marked filesystem (every
	// /tmp/go-build/*.a) would be ruinous, and products live in the
	// workspace. Reads (open-perm) stay filesystem-wide so materials are
	// captured wherever they're read from.
	if isCloseWrite && !isOpenPerm && !h.underWorkspace(realPath) {
		return // notification, out of scope — no response, nothing to hash
	}

	// Skip non-regular files — pipes/sockets/devices shouldn't be
	// hashed (would drain the tracee's content), and we'd just be
	// wasting cycles.
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(meta.Fd), &stat); err == nil {
		if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
			respondIfPerm()
			return
		}
	}

	digest, nBytes, err := hashFD(int(meta.Fd))
	if err != nil {
		h.stats.HashErrors.Add(1)
		respondIfPerm()
		return
	}
	h.stats.EventsHashed.Add(1)
	h.stats.BytesHashed.Add(uint64(nBytes))

	h.digestMu.Lock()
	if isCloseWrite {
		// FINAL written content → product. Authoritative (content at
		// close), overrides any earlier open-time entry for this path.
		if h.MaxDigests <= 0 || len(h.closeWriteDigests) < h.MaxDigests {
			h.closeWriteDigests[realPath] = digest
		} else if _, existing := h.closeWriteDigests[realPath]; existing {
			h.closeWriteDigests[realPath] = digest
		} else {
			h.stats.DigestsCapHit.Add(1)
		}
	}
	if isOpenPerm {
		// Open-time content → read/material.
		if h.MaxDigests > 0 && len(h.digests) >= h.MaxDigests {
			if _, existing := h.digests[realPath]; !existing {
				h.stats.DigestsCapHit.Add(1)
				h.digestMu.Unlock()
				h.respond(meta.Fd, true)
				return
			}
		}
		h.digests[realPath] = digest
	}
	h.digestMu.Unlock()

	// EXPERIMENT (deletable): "hash once" — now that this inode's content
	// is captured, stop the kernel notifying us about repeat opens of it.
	if h.ignoreOnce && isOpenPerm {
		h.maybeIgnoreInode(uint64(stat.Ino), realPath)
	}

	respondIfPerm()
}

// maybeIgnoreInode adds an inode FAN_MARK_IGNORE for FAN_OPEN_PERM so the
// kernel stops sending us open-permission events for an inode we've already
// hashed — the in-kernel collapse of a cold build's repeat-open storm.
//
// We deliberately do NOT pass FAN_MARK_IGNORE_SURV (survive-modify): a
// write to the file CLEARS the ignore mask, so the next open re-notifies
// and we re-hash. That preserves attestation correctness for materials
// rewritten mid-build — "ignore forever" would silently freeze a stale
// digest. Dedup via ignoredInodes keeps this to one syscall per inode.
//
// EXPERIMENT (deletable along with EnvVarIgnoreOnce / the call site).
func (h *Handler) maybeIgnoreInode(ino uint64, path string) {
	if ino == 0 {
		return // fstat failed earlier; can't safely dedup by inode
	}
	h.digestMu.Lock()
	if _, done := h.ignoredInodes[ino]; done {
		h.digestMu.Unlock()
		return
	}
	h.ignoredInodes[ino] = struct{}{}
	h.digestMu.Unlock()

	flags := uint(unix.FAN_MARK_ADD | unix.FAN_MARK_IGNORE)
	if err := unix.FanotifyMark(h.fd, flags, unix.FAN_OPEN_PERM, unix.AT_FDCWD, path); err != nil {
		h.stats.IgnoreMarkErrors.Add(1)
		// Roll back so a later event for the same inode can retry.
		h.digestMu.Lock()
		delete(h.ignoredInodes, ino)
		h.digestMu.Unlock()
		return
	}
	h.stats.IgnoreMarksAdded.Add(1)
}

// underWorkspace reports whether path is at or beneath the build
// workspace root. Used to scope FAN_CLOSE_WRITE product hashing.
func (h *Handler) underWorkspace(path string) bool {
	if h.workspaceRoot == "" {
		return true
	}
	if path == h.workspaceRoot {
		return true
	}
	root := h.workspaceRoot
	if !strings.HasSuffix(root, "/") {
		root += "/"
	}
	return strings.HasPrefix(path, root)
}

// hashFD streams SHA-256 over the file descriptor's content. The fd
// is at offset 0 (kernel always provides a fresh fd for fanotify
// events). We seek explicitly to be defensive against future kernel
// changes.
func hashFD(fd int) ([32]byte, int64, error) {
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		var zero [32]byte
		return zero, 0, fmt.Errorf("seek: %w", err)
	}
	h := sha256.New()
	buf := make([]byte, 64*1024)
	var total int64
	for {
		n, err := unix.Read(fd, buf)
		if n > 0 {
			h.Write(buf[:n])
			total += int64(n)
		}
		if err == nil && n == 0 {
			break
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			var zero [32]byte
			return zero, total, err
		}
		if n < len(buf) {
			break
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, total, nil
}

// respond writes the FAN_ALLOW / FAN_DENY decision back to the
// fanotify fd. Must be called for every received event or the
// kernel will time out (5s) and default to FAN_ALLOW with a
// degraded counter.
func (h *Handler) respond(eventFd int32, allow bool) {
	resp := unix.FanotifyResponse{Fd: eventFd}
	if allow {
		resp.Response = unix.FAN_ALLOW
	} else {
		resp.Response = unix.FAN_DENY
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], uint32(resp.Fd))
	binary.LittleEndian.PutUint32(buf[4:], resp.Response)
	// Write to the fanotify fd; ignore short writes (kernel writes
	// the whole struct or fails).
	_, _ = unix.Write(h.fd, buf)
}

// Digests returns a snapshot of paths → SHA-256 digests captured so
// far. Safe to call concurrently with Run; the map is copied.
func (h *Handler) Digests() map[string][32]byte {
	h.digestMu.Lock()
	defer h.digestMu.Unlock()
	out := make(map[string][32]byte, len(h.digests))
	for k, v := range h.digests {
		out[k] = v
	}
	return out
}

// CloseWriteDigests returns a snapshot of paths → SHA-256 of their FINAL
// written content, captured at FAN_CLOSE_WRITE. These are PRODUCTS (outputs
// the tracee wrote and closed), distinct from Digests() (open-time reads).
func (h *Handler) CloseWriteDigests() map[string][32]byte {
	h.digestMu.Lock()
	defer h.digestMu.Unlock()
	out := make(map[string][32]byte, len(h.closeWriteDigests))
	for k, v := range h.closeWriteDigests {
		out[k] = v
	}
	return out
}

// GetStats returns a snapshot of operational counters.
func (h *Handler) GetStats() Stats {
	return h.stats.toStats()
}

// Close drops the fanotify mark and closes the fd. Subsequent
// reads return EBADF and Run returns nil.
func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	return unix.Close(h.fd)
}
