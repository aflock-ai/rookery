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

// Package ebpf is cilock's eBPF-based tracing capture path (#167).
//
// V1: kprobe on openat-family syscalls + ring buffer of (pid, path,
// stat_at_open) events. Userspace re-stats the path on consumption
// and classifies the hash as TOCTOU-stable or TOCTOU-suspect based
// on whether stat changed between BPF-capture and userspace-stat.
//
// Requires: CAP_BPF + CAP_PERFMON (Linux 5.8+). The selector in
// trace_mode_linux.go gates entry to this path on availability.

package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	// Must match the C struct openat_event layout exactly. Sizes:
	//   u64 timestamp_ns       (8 bytes, offset 0)
	//   u32 pid                (4, 8)
	//   u32 tgid               (4, 12)
	//   u32 ppid               (4, 16)
	//   s32 dirfd              (4, 20)
	//   u32 path_len           (4, 24)
	//   u32 _pad               (4, 28 — alignment)
	//   u64 size_at_open       (8, 32)
	//   u64 mtime_ns           (8, 40)
	//   char comm[16]          (16, 48)
	//   char path[4096]        (4096, 64)
	// Total: 4160 bytes
	openatEventSize = 4160
	maxPath         = 4096
	taskCommLen     = 16
)

// OpenatEvent is the Go-side decoding of the BPF openat event.
type OpenatEvent struct {
	TimestampNs uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
	Dirfd       int32
	PathLen     uint32
	SizeAtOpen  uint64
	MtimeNs     uint64
	Comm        string
	Path        string
}

//go:embed bpf/openat_kprobe.bpf.o
var bpfObjBytes []byte

// Consumer owns a loaded BPF program + attached kprobe + ringbuf reader.
type Consumer struct {
	coll           *ebpf.Collection
	links          []link.Link
	reader         *ringbuf.Reader
	watchedPids    *ebpf.Map // BPF_MAP_TYPE_HASH: pid -> 1
	filterFlag     *ebpf.Map // BPF_MAP_TYPE_ARRAY[1]: byte
	rootParentTgid *ebpf.Map // BPF_MAP_TYPE_ARRAY[1]: u32
}

// Open loads the embedded BPF object, attaches kprobes for the
// current architecture's openat-family syscalls, and prepares a
// ringbuf reader. Caller must call Close() when done.
func Open() (*Consumer, error) {
	// Without this the BPF program loader fails with "Operation not
	// permitted" even when CAP_BPF is granted — the memlock rlimit
	// defaults to a tiny value on most distros.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjBytes))
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	// Pre-set KernelVersion on every kprobe program so cilium/ebpf
	// skips its built-in detection path, which reads /proc/self/mem.
	// /proc/self/mem requires CAP_SYS_PTRACE on hardened kernels
	// (notably GitHub-hosted Actions runners), so without this hop
	// users with only CAP_BPF + CAP_PERFMON fail at NewCollection
	// with "detecting kernel version: opening mem: ...permission
	// denied". uname(2) is unprivileged on every Linux that runs BPF.
	kver, kverErr := unameKernelVersionCode()
	if kverErr == nil {
		for _, ps := range spec.Programs {
			if ps.Type == ebpf.Kprobe {
				ps.KernelVersion = kver
			}
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("instantiate BPF: %w", err)
	}

	c := &Consumer{coll: coll}

	// Pick the right kprobe symbols for this arch.
	progNames, kprobeSyms := archKprobeNames()
	for i, progName := range progNames {
		prog, ok := coll.Programs[progName]
		if !ok {
			// Program not in this build (e.g., compiled for different arch).
			continue
		}
		l, err := link.Kprobe(kprobeSyms[i], prog, nil)
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("attach %s -> %s: %w", kprobeSyms[i], progName, err)
		}
		c.links = append(c.links, l)
	}
	if len(c.links) == 0 {
		_ = c.Close()
		return nil, fmt.Errorf("no kprobes attached for arch=%s", runtime.GOARCH)
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("events map not found in BPF object")
	}
	r, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	c.reader = r

	watched, ok := coll.Maps["watched_pids"]
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("watched_pids map not found in BPF object")
	}
	c.watchedPids = watched

	flag, ok := coll.Maps["filter_enabled"]
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("filter_enabled map not found in BPF object")
	}
	c.filterFlag = flag

	root, ok := coll.Maps["root_parent_tgid"]
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("root_parent_tgid map not found in BPF object")
	}
	c.rootParentTgid = root

	return c, nil
}

// SetRootParentTgid tells the kprobe which parent tgid to expect.
// When a process whose ppid matches this value fires an openat, the
// kprobe emits the event AND adds the process's pid to the watched
// set. This is the bootstrap signal — call it BEFORE exec.Cmd.Start()
// with os.Getpid() (the cilock process's own tgid) so that the
// to-be-spawned tracee matches the moment its dynamic linker fires.
func (c *Consumer) SetRootParentTgid(tgid uint32) error {
	if c == nil || c.rootParentTgid == nil {
		return fmt.Errorf("consumer not initialized")
	}
	zero := uint32(0)
	return c.rootParentTgid.Update(&zero, &tgid, ebpf.UpdateAny)
}

// AddWatchedPID adds a pid to the in-kernel watched set. The kprobe
// drops events whose pid, tgid, AND ppid are all absent from this
// set, so adding the tracee's root pid enables capture for it and
// (via the ppid check) its immediate children. Userspace should
// continue to call AddWatchedPID as it observes new descendants.
//
// Safe to call concurrently.
func (c *Consumer) AddWatchedPID(pid uint32) error {
	if c == nil || c.watchedPids == nil {
		return fmt.Errorf("consumer not initialized")
	}
	one := uint8(1)
	if err := c.watchedPids.Update(&pid, &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("add watched pid %d: %w", pid, err)
	}
	return nil
}

// RemoveWatchedPID drops a pid from the in-kernel watched set, e.g.
// when a child exits. Missing keys are not an error.
func (c *Consumer) RemoveWatchedPID(pid uint32) error {
	if c == nil || c.watchedPids == nil {
		return nil
	}
	_ = c.watchedPids.Delete(&pid)
	return nil
}

// EnableFilter flips the filter-enabled flag so the kprobe starts
// emitting events. Call AFTER seeding the watched set with the root
// tracee pid — between consumer load and this call, the program
// drops every event, eliminating any startup race.
func (c *Consumer) EnableFilter() error {
	if c == nil || c.filterFlag == nil {
		return fmt.Errorf("consumer not initialized")
	}
	zero := uint32(0)
	one := uint8(1)
	return c.filterFlag.Update(&zero, &one, ebpf.UpdateAny)
}

// DisableFilter flips the filter off (kprobe drops every event).
// Used during shutdown to stop new events from entering the ring
// buffer while we drain.
func (c *Consumer) DisableFilter() error {
	if c == nil || c.filterFlag == nil {
		return nil
	}
	zero := uint32(0)
	off := uint8(0)
	return c.filterFlag.Update(&zero, &off, ebpf.UpdateAny)
}

// unameKernelVersionCode returns the running kernel version encoded
// as KERNEL_VERSION(major, minor, patch) = (major<<16) | (minor<<8) | patch.
// Uses uname(2), which is unprivileged. Returns 0 (and an error) if
// the release string can't be parsed — the caller should leave
// KernelVersion unset and let cilium/ebpf fall back to its own
// detection in that case.
//
// The exact value only matters for kernels < 5.0 (which actually
// validate prog_load's kern_version field for kprobe-type programs).
// On modern kernels the value is ignored, so any non-zero non-magic
// value works. We still parse properly for correctness.
func unameKernelVersionCode() (uint32, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return 0, fmt.Errorf("uname: %w", err)
	}
	rel := unix.ByteSliceToString(u.Release[:])
	// Release looks like "6.8.0-100-generic" or "5.15.17-1-lts".
	// Strip the post-patch suffix at the first '-'.
	base := rel
	if i := strings.IndexByte(base, '-'); i >= 0 {
		base = base[:i]
	}
	parts := strings.SplitN(base, ".", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("kernel release %q has no dotted version", rel)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("parse major from %q: %w", rel, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("parse minor from %q: %w", rel, err)
	}
	patch := 0
	if len(parts) == 3 {
		// patch may be "0" or "0+something"; take the leading digits.
		p := parts[2]
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		if end > 0 {
			patch, _ = strconv.Atoi(p[:end])
		}
	}
	// Clamp each field to 8 bits except major which gets 16. Standard
	// KERNEL_VERSION encoding.
	if major < 0 || major > 0xFFFF {
		major = 0
	}
	if minor < 0 || minor > 0xFF {
		minor = 0
	}
	if patch < 0 || patch > 0xFF {
		patch = 0
	}
	return uint32(major)<<16 | uint32(minor)<<8 | uint32(patch), nil
}

// archKprobeNames returns (BPF program names, kernel symbols) to
// attach on the current architecture. Program names match the SEC()
// labels in openat_kprobe.bpf.c.
func archKprobeNames() ([]string, []string) {
	switch runtime.GOARCH {
	case "amd64":
		return []string{"kprobe_openat_x64", "kprobe_openat2_x64"},
			[]string{"__x64_sys_openat", "__x64_sys_openat2"}
	case "arm64":
		return []string{"kprobe_openat_arm64", "kprobe_openat2_arm64"},
			[]string{"__arm64_sys_openat", "__arm64_sys_openat2"}
	default:
		return nil, nil
	}
}

// Read blocks until the next event is available, then decodes and
// returns it. Returns io.EOF-equivalent when the consumer is closed.
//
// If SetReadDeadline was set, returns os.ErrDeadlineExceeded once no
// new event arrives by the deadline. This is how the caller signals
// "drain pending events then stop" — set a small deadline (a few
// hundred ms) after the tracee exits.
func (c *Consumer) Read() (*OpenatEvent, error) {
	rec, err := c.reader.Read()
	if err != nil {
		return nil, err
	}
	return decodeOpenatEvent(rec.RawSample)
}

// SetReadDeadline applies a deadline to the underlying ringbuf reader.
// A zero time clears the deadline.
//
// WARNING: cilium/ebpf's Reader.SetDeadline acquires the same mutex
// Read holds during its blocking poll. Calling SetDeadline while
// Read is blocked deadlocks. Prefer Flush() for shutdown — it
// unblocks Read via the poller without taking the read mutex.
func (c *Consumer) SetReadDeadline(t time.Time) error {
	if c == nil || c.reader == nil {
		return nil
	}
	c.reader.SetDeadline(t)
	return nil
}

// Flush unblocks any in-flight Read so it returns pending records
// followed by ringbuf.ErrFlushed. Use this during shutdown: after
// c.Wait() returns, call Flush() so the consumer goroutine drains
// queued events and then exits cleanly.
func (c *Consumer) Flush() error {
	if c == nil || c.reader == nil {
		return nil
	}
	return c.reader.Flush()
}

// IsFlushedError reports whether err is the sentinel returned by
// Read() after Flush() completes the drain.
func IsFlushedError(err error) bool {
	return errors.Is(err, ringbuf.ErrFlushed)
}

// Close detaches kprobes and frees BPF resources. Safe to call
// multiple times.
func (c *Consumer) Close() error {
	if c == nil {
		return nil
	}
	for _, l := range c.links {
		_ = l.Close()
	}
	c.links = nil
	if c.reader != nil {
		_ = c.reader.Close()
		c.reader = nil
	}
	if c.coll != nil {
		c.coll.Close()
		c.coll = nil
	}
	return nil
}

// decodeOpenatEvent parses the raw ring-buffer bytes per the layout
// documented in openat_kprobe.bpf.c.
func decodeOpenatEvent(raw []byte) (*OpenatEvent, error) {
	if len(raw) < openatEventSize {
		return nil, fmt.Errorf("event too short: %d < %d", len(raw), openatEventSize)
	}
	ev := &OpenatEvent{
		TimestampNs: binary.LittleEndian.Uint64(raw[0:]),
		PID:         binary.LittleEndian.Uint32(raw[8:]),
		TGID:        binary.LittleEndian.Uint32(raw[12:]),
		PPID:        binary.LittleEndian.Uint32(raw[16:]),
		Dirfd:       int32(binary.LittleEndian.Uint32(raw[20:])),
		PathLen:     binary.LittleEndian.Uint32(raw[24:]),
		// 28: 4 bytes alignment padding
		SizeAtOpen: binary.LittleEndian.Uint64(raw[32:]),
		MtimeNs:    binary.LittleEndian.Uint64(raw[40:]),
		Comm:       cstring(raw[48 : 48+taskCommLen]),
		Path:       cstring(raw[64 : 64+maxPath]),
	}
	return ev, nil
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
