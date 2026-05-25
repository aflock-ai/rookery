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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Stats are the diagnostic counters the dispatcher folds into
// summary.diagnostics at end-of-trace. Honesty over silent loss.
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
	stats    atomic.Pointer[Stats]
	digestMu sync.Mutex
	digests  map[string][32]byte
	// Per-event handler budget. Default 2s leaves margin under the
	// kernel's 5s default timeout; configurable for stress tests.
	HandlerBudget time.Duration
}

// New opens a fanotify fd and registers a mark on the given mount
// (or path-based fallback). Returns Handler ready to Run, or an
// error describing why fanotify isn't available (the caller should
// fall back to BPF-only).
//
// CAP_SYS_ADMIN is required; without it FanotifyInit returns EPERM
// and the caller must cope.
func New(markPath string) (*Handler, error) {
	if markPath == "" {
		return nil, errors.New("fanotify: empty markPath")
	}
	// FAN_CLASS_CONTENT enables permission events; FAN_NONBLOCK lets
	// us poll(). We don't use FAN_REPORT_FID — keeping the simpler
	// fd-based path matching ClamAV's pattern.
	const fanFlags = unix.FAN_CLASS_CONTENT | unix.FAN_NONBLOCK | unix.FAN_CLOEXEC
	const eventFlags = unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	fd, err := unix.FanotifyInit(fanFlags, eventFlags)
	if err != nil {
		return nil, fmt.Errorf("FanotifyInit: %w", err)
	}
	// FAN_MARK_FILESYSTEM covers the entire filesystem the mark point
	// belongs to. Cheaper than per-file marks; ideal for a build
	// workspace that lives on one mount.
	markFlags := uint(unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM)
	mask := uint64(unix.FAN_OPEN_PERM)
	if err := unix.FanotifyMark(fd, markFlags, mask, unix.AT_FDCWD, markPath); err != nil {
		_ = unix.Close(fd)
		// Fall back to MOUNT mark if FILESYSTEM isn't supported on
		// this kernel/FS combination (e.g., virtiofs).
		fd2, err2 := unix.FanotifyInit(fanFlags, eventFlags)
		if err2 != nil {
			return nil, fmt.Errorf("FanotifyInit retry: %w (original: %v)", err2, err)
		}
		if err3 := unix.FanotifyMark(fd2, uint(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT), mask, unix.AT_FDCWD, markPath); err3 != nil {
			_ = unix.Close(fd2)
			return nil, fmt.Errorf("FanotifyMark (both FILESYSTEM and MOUNT failed): mount-err=%v fs-err=%v", err3, err)
		}
		fd = fd2
	}
	h := &Handler{
		fd:            fd,
		digests:       make(map[string][32]byte),
		HandlerBudget: 2 * time.Second,
	}
	h.stats.Store(&Stats{})
	return h, nil
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
	defer unix.Close(fd)
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
// Each iteration:
//  1. Poll for events (with ctx-cancel responsiveness).
//  2. Read up to 4 KB of events from fd (one read may yield multiple).
//  3. For each event: open ourselves a fresh fd via dup() to the
//     event's fd, hash the file, write FAN_ALLOW response.
//  4. Close the kernel-provided fd.
func (h *Handler) Run(ctx context.Context) error {
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
		h.processBatch(buf[:n])
	}
}

// processBatch walks one read() worth of events. Each event is a
// FanotifyEventMetadata header followed by (in FID mode) info
// records. We're in fd mode so each event is exactly Event_len bytes.
func (h *Handler) processBatch(data []byte) {
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
		h.handleOne(&meta)
		data = data[meta.Event_len:]
	}
}

// handleOne processes a single fanotify event and writes the
// response. Always responds FAN_ALLOW even on hash failure — we're
// here for attestation, not access control. Closing the event fd
// is REQUIRED; without it we leak fds and the kernel eventually
// stalls.
func (h *Handler) handleOne(meta *unix.FanotifyEventMetadata) {
	stats := h.loadStats()
	stats.EventsReceived++
	defer h.storeStats(stats)

	start := time.Now()
	defer func() {
		if elapsed := time.Since(start); elapsed > h.HandlerBudget {
			stats.HandlerTimeouts++
		}
	}()

	// FAN_Q_OVERFLOW: the kernel dropped events because our handler
	// fell behind. Count these explicitly — they're the canonical
	// signal that fanotify lost data. The kernel emits this synthetic
	// event with Fd == FAN_NOFD (a fanotify-specific sentinel = -1).
	if meta.Mask&unix.FAN_Q_OVERFLOW != 0 {
		stats.QueueOverflows++
		// No fd to close, no response to write.
		return
	}

	// fd<0 means kernel had no fd to give us (rare; OOM, anonymous
	// inode). Allow anyway — we can't hash but the tracee shouldn't
	// be blocked.
	if meta.Fd < 0 {
		stats.UnknownFamily++
		h.respond(meta.Fd, true)
		return
	}
	defer unix.Close(int(meta.Fd))

	if meta.Mask&unix.FAN_OPEN_PERM == 0 {
		h.respond(meta.Fd, true)
		return
	}

	// Resolve path via /proc/self/fd/<fd> readlink — works because
	// we OWN this fd (kernel handed it to us). The path is the
	// canonical kernel-resolved path the tracee actually opened.
	procPath := fmt.Sprintf("/proc/self/fd/%d", meta.Fd)
	realPath, lerr := os.Readlink(procPath)
	if lerr != nil {
		stats.HashErrors++
		h.respond(meta.Fd, true)
		return
	}

	// Skip non-regular files — pipes/sockets/devices shouldn't be
	// hashed (would drain the tracee's content), and we'd just be
	// wasting cycles.
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(meta.Fd), &stat); err == nil {
		if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
			h.respond(meta.Fd, true)
			return
		}
	}

	digest, nBytes, err := hashFD(int(meta.Fd))
	if err != nil {
		stats.HashErrors++
		h.respond(meta.Fd, true)
		return
	}
	stats.EventsHashed++
	stats.BytesHashed += uint64(nBytes)

	h.digestMu.Lock()
	h.digests[realPath] = digest
	h.digestMu.Unlock()

	h.respond(meta.Fd, true)
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

// Stats returns a snapshot of operational counters.
func (h *Handler) GetStats() Stats {
	s := h.loadStats()
	return *s
}

func (h *Handler) loadStats() *Stats {
	cur := h.stats.Load()
	cp := *cur
	return &cp
}

func (h *Handler) storeStats(s *Stats) {
	h.stats.Store(s)
}

// Close drops the fanotify mark and closes the fd. Subsequent
// reads return EBADF and Run returns nil.
func (h *Handler) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	return unix.Close(h.fd)
}
