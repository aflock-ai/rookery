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
	"os"
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

// Event type discriminator — must match enum cilock_event_type in
// openat_kprobe.bpf.c. EVT_OPENAT==1 lets us tell legacy raw-openat
// events (which have no leading event_type and start with timestamp)
// from the new tagged events: an openat_event's first 4 bytes are
// the low bits of timestamp_ns, which can never equal 0 in practice
// for a running system, so it'll never collide with a small enum tag.
const (
	EVT_OPENAT     = 1
	EVT_EXECVE     = 2
	EVT_UNLINKAT   = 3
	EVT_RENAMEAT   = 4
	EVT_FCHMODAT   = 5
	EVT_SECURITY   = 6
	EVT_WRITE      = 7
	EVT_SOCKET      = 8
	EVT_CONNECT     = 9
	EVT_BIND        = 10
	EVT_READ_CHUNK  = 11 // V1.4 read-tap: chunk of bytes the kernel returned
	EVT_CLOSE       = 12 // V1.4 read-tap: finalize streaming hash for fd
	EVT_CONNECT_RET = 13 // connect() return code (success/failure) via kretprobe
	EVT_DNS_QUERY   = 14 // UDP send to port 53/5353 — DNS query destination
)

// Event sizes — must match the C structs in openat_kprobe.bpf.c. All
// events share the cilock_evt_hdr (32 bytes); offsets follow.
const (
	cilockHdrSize = 32

	// openat_event: hdr(32) + dirfd(4) + path_len(4) + flags(4) + pad(4)
	//             + size_at_open(8) + mtime_ns(8) + comm(16) + path(4096) = 4176
	openatEventSize = cilockHdrSize + 4 + 4 + 4 + 4 + 8 + 8 + taskCommLen + maxPath

	// execve_event: hdr(32) + comm(16) + filename(4096) = 4144
	execveEventSize = cilockHdrSize + taskCommLen + maxPath

	// file_mutation_event: hdr(32) + mode(4) + flags(4) + pad(8)
	//                    + comm(16) + path(4096) + path2(4096) = 8256
	fileMutationEventSize = cilockHdrSize + 4 + 4 + 8 + taskCommLen + maxPath + maxPath

	// security_event: hdr(32) + comm(16) + syscall_nr(4) + pad(4)
	//               + args[4*8] = 88
	securityEventSize = cilockHdrSize + taskCommLen + 4 + 4 + 32

	// write_event: hdr(32) + comm(16) + fd(4) + pad(4) + bytes(8) = 64
	writeEventSize = cilockHdrSize + taskCommLen + 4 + 4 + 8

	// net_event: hdr(32) + comm(16) + fd(4) + family(4) + type(4)
	//          + protocol(4) + addr(32) = 96
	netEventSize = cilockHdrSize + taskCommLen + 4 + 4 + 4 + 4 + 32

	// read_chunk_event: hdr(32) + comm(16) + fd(4) + seq(4)
	//                 + chunk_len(4) + pad(4) + data(16384) = 16448
	readChunkBytes     = 16384
	readChunkEventSize = cilockHdrSize + taskCommLen + 4 + 4 + 4 + 4 + readChunkBytes

	// close_event: hdr(32) + comm(16) + fd(4) + path_len(4)
	//            + size_at_open(8) + path(256) = 320
	// V2 Phase 8 stage 2: carries the path INLINE so userspace
	// dispatcher doesn't need a parallel openPaths cache.
	closeEventSize = cilockHdrSize + taskCommLen + 4 + 4 + 8 + closePathLen
	closePathLen   = 256

	maxPath     = 4096
	taskCommLen = 16
)

// Event is the union type for all BPF events. Exactly one of the
// embedded pointers is non-nil; the userspace dispatcher walks them
// in order. Type discrimination is via the leading event_type field
// in the ring-buffer record.
type Event struct {
	Type      uint32          // EVT_OPENAT / EVT_EXECVE / ...
	Openat    *OpenatEvent    // EVT_OPENAT
	Execve    *ExecveEvent    // EVT_EXECVE
	FileOp    *FileOpEvent    // EVT_UNLINKAT / EVT_RENAMEAT / EVT_FCHMODAT
	Security  *SecurityEvent  // EVT_SECURITY
	Write     *WriteEvent     // EVT_WRITE
	Net       *NetEvent       // EVT_SOCKET / EVT_CONNECT / EVT_BIND
	ReadChunk *ReadChunkEvent // EVT_READ_CHUNK
	Close     *CloseEvent     // EVT_CLOSE
}

// ReadChunkEvent carries a slice of bytes the kernel returned to the
// tracee on one read syscall. Userspace feeds Data[:ChunkLen] into
// the streaming SHA-256 keyed by (PID, FD).
type ReadChunkEvent struct {
	EventHeader
	Comm     string
	FD       int32
	Seq      uint32
	ChunkLen uint32
	Data     []byte // ChunkLen valid bytes; len(Data) == int(ChunkLen)
}

// CloseEvent signals userspace to finalize the streaming hash for
// (PID, FD).
//
// V2 Phase 8 stage 2: the close event carries the resolved path +
// size_at_open INLINE, populated from the kernel-side fd_table.
// Path is empty when the close fires on an fd we never saw opened
// (inherited fd, LRU-evicted entry); the dispatcher then falls back
// to its in-flight state if any.
type CloseEvent struct {
	EventHeader
	Comm        string
	FD          int32
	Path        string // resolved absolute path from BPF; "" if no fd_table entry
	SizeAtOpen  uint64
}

// WriteEvent carries (fd, bytes) from a write/pwrite kprobe.
// Userspace resolves fd → path via /proc/<pid>/fd/<fd>.
type WriteEvent struct {
	EventHeader
	Comm  string
	FD    int32
	Bytes uint64
}

// NetEvent covers socket/connect/bind. Family/type/protocol fields
// are populated for EVT_SOCKET; Addr is populated for connect/bind
// (32 bytes raw — userspace parses sockaddr_in/in6/un by Family).
type NetEvent struct {
	EventHeader
	Op       uint32 // EVT_SOCKET | EVT_CONNECT | EVT_BIND
	Comm     string
	FD       int32
	Family   uint32
	Type     uint32
	Protocol int32
	Addr     [32]byte
}

// EventHeader is the common 24-byte preamble on every BPF event.
type EventHeader struct {
	EventType   uint32
	TimestampNs uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
}

// OpenatEvent is the Go-side decoding of the BPF openat event.
type OpenatEvent struct {
	TimestampNs uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
	Dirfd       int32
	FD          int32  // kernel-returned fd (>=0 ok, <0 errno) — V1.3
	PathLen     uint32
	Flags       uint32 // openat() flags: O_RDONLY/O_WRONLY/O_CREAT/...
	SizeAtOpen  uint64
	MtimeNs     uint64
	Comm        string
	Path        string
}

// O_* flag constants matching <fcntl.h>. Mode bits in the openat flags
// argument; userspace uses these to decide whether to hash the file.
const (
	O_RDONLY = 0o0
	O_WRONLY = 0o1
	O_RDWR   = 0o2
	O_ACCMODE = 0o3
	O_CREAT  = 0o100
	O_TRUNC  = 0o1000
	O_APPEND = 0o2000
	O_PATH   = 0o10000000 // 010000000 — symlink-only / metadata-only open
)

// IsWriteOnly returns true if the openat was opened with O_WRONLY (no
// read intent). These are the tracee's own writes; hashing them races
// with the tracee's writes and produces meaningless TOCTOU-suspect
// noise. Skip them.
func (ev *OpenatEvent) IsWriteOnly() bool {
	return (ev.Flags & O_ACCMODE) == O_WRONLY
}

// IsPathOnly returns true if the open was O_PATH (no content read at all).
// O_PATH opens don't actually read the file content — they're just for
// symlink resolution / fd-as-handle. Skip hashing.
func (ev *OpenatEvent) IsPathOnly() bool {
	return (ev.Flags & O_PATH) != 0
}

// ExecveEvent corresponds to one observed SYS_EXECVE entry. Filename
// is argv[0] (the file the caller named); userspace pairs this with
// /proc/<pid>/exe to capture both the named path and the actually-
// loaded binary.
type ExecveEvent struct {
	EventHeader
	Comm     string
	Filename string
}

// FileOpEvent covers SYS_UNLINKAT, SYS_RENAMEAT2, SYS_FCHMODAT. The
// Op field carries the discriminator (EVT_UNLINKAT / RENAMEAT /
// FCHMODAT); other fields are populated per-op.
//   unlinkat:   Path = pathname, Flags = AT_REMOVEDIR
//   renameat2:  Path = oldpath,  Path2 = newpath, Flags = renameat2 flags
//   fchmodat:   Path = pathname, Mode = new mode bits
type FileOpEvent struct {
	EventHeader
	Op    uint32 // EVT_UNLINKAT | EVT_RENAMEAT | EVT_FCHMODAT
	Mode  uint32
	Flags uint32
	Comm  string
	Path  string
	Path2 string
}

// SecurityEvent covers the long-tail security-relevant syscalls that
// the ptrace path records under syscallEvents[]: ptrace, mount,
// memfd_create, mprotect, prctl, setsid, setns, init_module,
// clone/clone3, dup2/3. Userspace formats the Detail string from
// SyscallNr+Args.
type SecurityEvent struct {
	EventHeader
	Comm      string
	SyscallNr uint32
	Args      [4]uint64
}

//go:embed bpf/openat_kprobe.bpf.o
var bpfObjBytes []byte

// Consumer owns a loaded BPF program + attached kprobe + ringbuf readers.
//
// Two ringbufs:
//   - reader (the `events` ringbuf): classification-critical events.
//     openat / execve / fileOps / security / write / network / close.
//     Caller drains via Read(); single-consumer guarantee.
//   - readTapReader (the `read_tap_events` ringbuf): V1.4 read-tap
//     chunk records. High-volume; isolated so it can't evict
//     classification events under load.
//
// Caller drains both in parallel goroutines (each ringbuf has its
// own Read method) and multiplexes Events into a single dispatcher.
type Consumer struct {
	coll              *ebpf.Collection
	links             []link.Link
	reader            *ringbuf.Reader
	readRec           ringbuf.Record // reused across Read() calls (single consumer)
	readTapReader     *ringbuf.Reader
	readTapRec        ringbuf.Record // reused across ReadReadTap() calls
	watchedPids       *ebpf.Map      // BPF_MAP_TYPE_HASH: pid -> 1
	filterFlag        *ebpf.Map      // BPF_MAP_TYPE_ARRAY[1]: byte
	rootParentTgid    *ebpf.Map      // BPF_MAP_TYPE_ARRAY[1]: u32
	readTapFlag       *ebpf.Map      // BPF_MAP_TYPE_ARRAY[1]: byte (V1.4 read-tap)
	ringbufDrops      *ebpf.Map      // BPF_MAP_TYPE_PERCPU_ARRAY[2]: u64 drop counters
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

	// Pick the right kprobe symbols for this arch. Attach is
	// best-effort: kernel modules / CONFIG_*=n disables / older
	// kernels may lack some syscalls (e.g., clone3 < 5.3). We require
	// AT LEAST one openat-family kprobe — without that the tracer is
	// useless. Everything else is optional.
	// V2 Phase 8 stage 4: try fentry/security_file_open. When this
	// attaches, every emit_filter-passing open gets the canonical
	// absolute path stashed in d_path_stash; the openat kretprobe
	// picks it up and replaces the raw user-passed pathname. This
	// eliminates userspace cwd resolution entirely for openats. If
	// fentry isn't supported (older kernel, no BTF, bpf_d_path not
	// allowlisted on this kernel's security_file_open), the openat
	// path falls back to bpf_probe_read_user_str + 4-tier cwd
	// resolution as before — no functional regression.
	if sfoProg, ok := coll.Programs["fentry_security_file_open"]; ok {
		l, err := link.AttachTracing(link.TracingOptions{Program: sfoProg})
		if err == nil {
			c.links = append(c.links, l)
		} else {
			fmt.Fprintf(os.Stderr,
				"cilock-ebpf: fentry/security_file_open attach failed (%v) — falling back to userspace cwd resolution\n",
				err)
		}
	}

	// V2 Phase 8 stage 3: try fentry/wake_up_new_task first. fentry
	// has BTF-typed trusted-pointer args, so the child task_struct
	// can be passed directly to bpf_task_storage_get and the
	// watched-bit is set at FORK TIME (no lazy promotion on the
	// child's first syscall). If fentry attach succeeds, we skip
	// the kprobe attach below to avoid double-firing. If fentry
	// fails (older kernel without fentry support, missing BTF),
	// we fall back to the kprobe.
	fentryAttached := false
	if fentryProg, ok := coll.Programs["fentry_wake_up_new_task"]; ok {
		l, err := link.AttachTracing(link.TracingOptions{Program: fentryProg})
		if err == nil {
			c.links = append(c.links, l)
			fentryAttached = true
		} else {
			fmt.Fprintf(os.Stderr,
				"cilock-ebpf: fentry/wake_up_new_task attach failed (%v) — falling back to kprobe\n",
				err)
		}
	}

	progNames, kprobeSyms := archKprobeNames()
	attachFailed := 0
	openatAttached := 0
	for i, progName := range progNames {
		// Skip kprobe_wake_up_new_task when the fentry version already
		// attached — both firing would double-set the watched-bit and
		// double-emit any propagation side effects.
		if fentryAttached && progName == "kprobe_wake_up_new_task" {
			continue
		}
		prog, ok := coll.Programs[progName]
		if !ok {
			continue // program not in this build
		}
		// kretprobe_* programs attach as kretprobes; everything else
		// is a kprobe on entry.
		var l link.Link
		var err error
		if strings.HasPrefix(progName, "kretprobe_") {
			l, err = link.Kretprobe(kprobeSyms[i], prog, nil)
		} else {
			l, err = link.Kprobe(kprobeSyms[i], prog, nil)
		}
		if err != nil {
			attachFailed++
			continue // non-essential syscall absent on this kernel
		}
		c.links = append(c.links, l)
		if strings.Contains(kprobeSyms[i], "_openat") {
			openatAttached++
		}
	}
	// Attach the sched_process_fork raw tracepoint. This adds child
	// pids to watched_pids the moment they're forked from a watched
	// parent, closing the race where a fast-exiting child's first
	// openat fired before userspace could add its pid to the watched
	// set. V2 switched from `tracepoint/sched/sched_process_fork`
	// (hand-rolled args struct, offsets went stale on 5.x+ kernels)
	// to `raw_tracepoint/sched_process_fork` which reads tgid/pid
	// directly from the kernel task_struct via BPF_CORE_READ.
	if forkProg, ok := coll.Programs["raw_tp_sched_process_fork"]; ok {
		tpLink, tpErr := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sched_process_fork",
			Program: forkProg,
		})
		if tpErr == nil {
			c.links = append(c.links, tpLink)
		} else {
			// Surface loud: without this the fork-chain watch
			// propagation falls back to the clone-kretprobe + the
			// ancestor-walk in emit_filter, which has measurable
			// flake on deep fork trees (~20% of ForkChain tests).
			// Operators should see this in logs.
			fmt.Fprintf(os.Stderr,
				"cilock-ebpf: WARNING: raw_tracepoint/sched_process_fork attach failed: %v\n"+
					"  fork-chain watched-ness propagation will degrade; deep build chains may miss events\n",
				tpErr)
		}
	}

	// tp_btf/sched_switch — Tetragon-style early-tag of the next-to-run
	// task. Closes the residual cargo→rustc race where a freshly-forked
	// child's first openat outpaces wake_up_new_task's watched-bit
	// propagation. Fires at the LAST moment before the next task
	// runs; any prior map updates targeting it are visible at that
	// point.
	//
	// BPF-LSM isn't available on most cloud kernels (Ubuntu GHA has
	// CONFIG_BPF_LSM=y but bpf isn't in the active LSM list); this
	// is the closest substitute we can deploy on GHA-class targets.
	if switchProg, ok := coll.Programs["tp_btf_sched_switch"]; ok {
		switchLink, sErr := link.AttachTracing(link.TracingOptions{Program: switchProg})
		if sErr == nil {
			c.links = append(c.links, switchLink)
		} else {
			// Non-fatal: existing fork hooks still propagate; the
			// race window just isn't closed for the rare cases.
			fmt.Fprintf(os.Stderr,
				"cilock-ebpf: tp_btf/sched_switch attach failed (%v); deep-fork-race window remains open for some workloads\n",
				sErr)
		}
	}

	if openatAttached == 0 {
		_ = c.Close()
		return nil, fmt.Errorf("no openat-family kprobes attached for arch=%s (attempted %d, failed %d)",
			runtime.GOARCH, len(progNames), attachFailed)
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

	// read_tap_events ringbuf: only present when the BPF object
	// includes V1.4 read-tap. Older builds may not export it.
	if rtMap, ok := coll.Maps["read_tap_events"]; ok {
		rt, err := ringbuf.NewReader(rtMap)
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("read_tap_events ringbuf reader: %w", err)
		}
		c.readTapReader = rt
	}

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

	// V1.4 read-tap toggle map. Optional — older .bpf.o without
	// read-tap programs won't expose this map, in which case
	// EnableReadTap returns an error and the caller falls back.
	if rt, ok := coll.Maps["read_tap_enabled"]; ok {
		c.readTapFlag = rt
	}
	if drops, ok := coll.Maps["ringbuf_drops"]; ok {
		c.ringbufDrops = drops
	}

	return c, nil
}

// RingbufAvailableBytes returns the number of bytes waiting to be
// drained from the kernel ringbuf. The watchdog uses this for
// proactive backpressure — pause the tracee when usage climbs
// before drops actually happen.
func (c *Consumer) RingbufAvailableBytes() int {
	if c == nil || c.reader == nil {
		return 0
	}
	return c.reader.AvailableBytes()
}

// RingbufCapacityBytes returns the kernel-side ringbuf capacity.
// Used together with RingbufAvailableBytes to compute fill ratio.
func (c *Consumer) RingbufCapacityBytes() int {
	if c == nil || c.reader == nil {
		return 0
	}
	return c.reader.BufferSize()
}

// RingbufDrops returns (openat_drops, read_tap_drops) summed across
// all CPUs since program load. Non-zero values mean the ring buffer
// filled and events were lost — userspace can use this to surface
// "your attestation is incomplete" warnings to the operator.
func (c *Consumer) RingbufDrops() (openatDrops, readTapDrops uint64, err error) {
	if c == nil || c.ringbufDrops == nil {
		return 0, 0, nil
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, 0, fmt.Errorf("possible cpu: %w", err)
	}
	per := make([]uint64, ncpu)
	var k uint32 = 0
	if err := c.ringbufDrops.Lookup(&k, &per); err != nil {
		return 0, 0, fmt.Errorf("lookup drops[openat]: %w", err)
	}
	for _, v := range per {
		openatDrops += v
	}
	k = 1
	if err := c.ringbufDrops.Lookup(&k, &per); err != nil {
		return 0, 0, fmt.Errorf("lookup drops[readtap]: %w", err)
	}
	for _, v := range per {
		readTapDrops += v
	}
	return openatDrops, readTapDrops, nil
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

// EnableReadTap turns on the V1.4 read-tap. With it enabled, the
// read/pread64 kprobes copy up to 16 KB from the user buffer per
// syscall and emit EVT_READ_CHUNK / EVT_CLOSE events the caller
// streams into a per-(pid, fd) SHA-256. See bpf source for the
// threat model — tamper-proof vs the calling thread and external
// procs, NOT vs sibling threads sharing the address space.
func (c *Consumer) EnableReadTap() error {
	if c == nil || c.readTapFlag == nil {
		return fmt.Errorf("read-tap not available (BPF object too old?)")
	}
	zero := uint32(0)
	on := uint8(1)
	return c.readTapFlag.Update(&zero, &on, ebpf.UpdateAny)
}

// DisableReadTap turns the read-tap off. Existing in-flight stash
// entries get cleared by the kretprobe on syscall exit; no draining
// needed on the caller side.
func (c *Consumer) DisableReadTap() error {
	if c == nil || c.readTapFlag == nil {
		return nil
	}
	zero := uint32(0)
	off := uint8(0)
	return c.readTapFlag.Update(&zero, &off, ebpf.UpdateAny)
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
//
// Returns the union of:
//   - openat-family (existing V1)
//   - execve (#82 V1.1 — populates exedigest + environ + cmdline)
//   - unlinkat, renameat2, fchmodat (fileOps mutations)
//   - security-relevant syscalls (ptrace, mount, mprotect, memfd_create,
//     prctl, setsid, setns, init_module/finit_module, clone/clone3,
//     dup2/3) → all routed to syscallEvents[]
//
// Each kprobe attach is best-effort: if a kernel symbol isn't present
// on this kernel (kernel modules, CONFIG_*=n disables, etc.), we skip
// that one and continue. We log at debug level.
func archKprobeNames() ([]string, []string) {
	switch runtime.GOARCH {
	case "amd64":
		return []string{
				// openat family — kprobe stashes args, kretprobe emits w/ fd
				"kprobe_openat_x64", "kretprobe_openat_x64",
				"kprobe_openat2_x64", "kretprobe_openat2_x64",
				// execve
				"kprobe_execve_x64",
				// file mutations
				"kprobe_unlinkat_x64", "kprobe_renameat2_x64", "kprobe_renameat_x64", "kprobe_fchmodat_x64",
				// write
				"kprobe_write_x64", "kprobe_pwrite_x64",
				// network
				"kprobe_socket_x64", "kprobe_connect_x64", "kprobe_bind_x64",
				"kretprobe_connect_x64",
				"kprobe_udp_sendmsg",
				// security syscalls
				"kprobe_ptrace_x64", "kprobe_memfd_create_x64",
				"kprobe_mount_x64", "kprobe_mprotect_x64",
				"kprobe_prctl_x64", "kprobe_setsid_x64", "kprobe_setns_x64",
				"kprobe_init_module_x64", "kprobe_finit_module_x64",
				"kprobe_clone_x64", "kprobe_clone3_x64",
				"kprobe_dup2_x64", "kprobe_dup3_x64",
				"kprobe_copy_file_range_x64", "kprobe_splice_x64",
				"kprobe_sendfile_x64", "kprobe_sendfile64_x64",
				"kprobe_mmap_x64",
				// V2 Phase 8 primary fork hook (Tetragon pattern):
				// kprobe/wake_up_new_task fires when child task_struct
				// is fully set up but before the child runs. Hereditary
				// insertion. Verified to fire for every fork via trace_pipe.
				// NOTE: empirically does NOT fix the deep-fork-chain
				// flake on its own. The remaining race is a userspace
				// dispatcher / ringbuf-event-loss issue documented in
				// memory/ebpf-canonical-patterns.md (TASK_STORAGE + fentry
				// migration). Keeping wake_up_new_task attached anyway —
				// it's the canonical fork hook + costs nothing when
				// attached but unhelpful.
				"kprobe_wake_up_new_task",
				// V2 fork-watch belt (defense-in-depth):
				"kretprobe_clone_x64", "kretprobe_clone3_x64",
				"kretprobe_vfork_x64", "kretprobe_fork_x64",
				// V1.4 read-tap (gated by read_tap_enabled map; cheap when off)
				"kprobe_read_x64", "kretprobe_read_x64",
				"kprobe_pread64_x64", "kretprobe_pread64_x64",
				"kprobe_close_x64",
			},
			[]string{
				"__x64_sys_openat", "__x64_sys_openat",
				"__x64_sys_openat2", "__x64_sys_openat2",
				"__x64_sys_execve",
				"__x64_sys_unlinkat", "__x64_sys_renameat2", "__x64_sys_renameat", "__x64_sys_fchmodat",
				"__x64_sys_write", "__x64_sys_pwrite64",
				"__x64_sys_socket", "__x64_sys_connect", "__x64_sys_bind",
				"__x64_sys_connect",
				"udp_sendmsg",
				"__x64_sys_ptrace", "__x64_sys_memfd_create",
				"__x64_sys_mount", "__x64_sys_mprotect",
				"__x64_sys_prctl", "__x64_sys_setsid", "__x64_sys_setns",
				"__x64_sys_init_module", "__x64_sys_finit_module",
				"__x64_sys_clone", "__x64_sys_clone3",
				"__x64_sys_dup2", "__x64_sys_dup3",
				"__x64_sys_copy_file_range", "__x64_sys_splice",
				"__x64_sys_sendfile", "__x64_sys_sendfile64",
				"__x64_sys_mmap",
				"wake_up_new_task",
				"__x64_sys_clone", "__x64_sys_clone3",
				"__x64_sys_vfork", "__x64_sys_fork",
				"__x64_sys_read", "__x64_sys_read",
				"__x64_sys_pread64", "__x64_sys_pread64",
				"__x64_sys_close",
			}
	case "arm64":
		return []string{
				"kprobe_openat_arm64", "kretprobe_openat_arm64",
				"kprobe_openat2_arm64", "kretprobe_openat2_arm64",
				"kprobe_execve_arm64",
				"kprobe_unlinkat_arm64", "kprobe_renameat2_arm64", "kprobe_renameat_arm64", "kprobe_fchmodat_arm64",
				"kprobe_write_arm64", "kprobe_pwrite_arm64",
				"kprobe_socket_arm64", "kprobe_connect_arm64", "kprobe_bind_arm64",
				"kretprobe_connect_arm64",
				"kprobe_udp_sendmsg",
				"kprobe_ptrace_arm64", "kprobe_memfd_create_arm64",
				"kprobe_mount_arm64", "kprobe_mprotect_arm64",
				"kprobe_prctl_arm64", "kprobe_setsid_arm64", "kprobe_setns_arm64",
				"kprobe_init_module_arm64", "kprobe_finit_module_arm64",
				"kprobe_clone_arm64", "kprobe_clone3_arm64",
				"kprobe_dup3_arm64",
				"kprobe_copy_file_range_arm64", "kprobe_splice_arm64",
				"kprobe_sendfile_arm64", "kprobe_sendfile64_arm64",
				"kprobe_mmap_arm64",
				// V2 Phase 8 primary fork hook (kernel-internal, arch-neutral).
				"kprobe_wake_up_new_task",
				// V2 fork-watch belt:
				"kretprobe_clone_arm64", "kretprobe_clone3_arm64",
				"kprobe_read_arm64", "kretprobe_read_arm64",
				"kprobe_pread64_arm64", "kretprobe_pread64_arm64",
				"kprobe_close_arm64",
			},
			[]string{
				"__arm64_sys_openat", "__arm64_sys_openat",
				"__arm64_sys_openat2", "__arm64_sys_openat2",
				"__arm64_sys_execve",
				"__arm64_sys_unlinkat", "__arm64_sys_renameat2", "__arm64_sys_renameat", "__arm64_sys_fchmodat",
				"__arm64_sys_write", "__arm64_sys_pwrite64",
				"__arm64_sys_socket", "__arm64_sys_connect", "__arm64_sys_bind",
				"__arm64_sys_connect",
				"udp_sendmsg",
				"__arm64_sys_ptrace", "__arm64_sys_memfd_create",
				"__arm64_sys_mount", "__arm64_sys_mprotect",
				"__arm64_sys_prctl", "__arm64_sys_setsid", "__arm64_sys_setns",
				"__arm64_sys_init_module", "__arm64_sys_finit_module",
				"__arm64_sys_clone", "__arm64_sys_clone3",
				"__arm64_sys_dup3",
				"__arm64_sys_copy_file_range", "__arm64_sys_splice",
				"__arm64_sys_sendfile", "__arm64_sys_sendfile64",
				"__arm64_sys_mmap",
				"wake_up_new_task",
				"__arm64_sys_clone", "__arm64_sys_clone3",
				"__arm64_sys_read", "__arm64_sys_read",
				"__arm64_sys_pread64", "__arm64_sys_pread64",
				"__arm64_sys_close",
			}
	default:
		return nil, nil
	}
}

// Read blocks until the next event is available, then decodes it
// based on its event_type discriminator. Returns os.ErrDeadlineExceeded
// after a SetReadDeadline window expires; returns ringbuf.ErrFlushed
// after Flush() completes the drain (use IsFlushedError to detect).
//
// Exactly one of (*Event).Openat, .Execve, .FileOp, .Security is
// non-nil on a successful return.
func (c *Consumer) Read() (*Event, error) {
	// Reuse the same Record struct + RawSample backing buffer across
	// calls — cilium/ebpf's ReadInto fills the existing slice rather
	// than allocating fresh. Single-consumer guarantee (one dispatcher
	// goroutine) makes this safe; the caller MUST consume the returned
	// Event before the next Read() because ReadChunkEvent.Data points
	// into the reused buffer.
	if err := c.reader.ReadInto(&c.readRec); err != nil {
		return nil, err
	}
	return decodeEvent(c.readRec.RawSample)
}

// ReadReadTap blocks until the next read-tap chunk event is
// available on the read_tap_events ringbuf, then decodes it.
// Returns the same errors as Read() (os.ErrDeadlineExceeded after a
// SetReadDeadline; ringbuf.ErrFlushed after Flush()).
//
// Single-consumer guarantee per ringbuf: callers must drain
// read_tap_events from a SEPARATE goroutine than the one draining
// `events` via Read(). The returned Event.ReadChunk.Data points into
// readTapRec's reusable backing buffer; consume before the next call.
//
// Returns (nil, ErrReadTapUnavailable) if the BPF object didn't
// export read_tap_events (e.g. older builds without V1.4).
func (c *Consumer) ReadReadTap() (*Event, error) {
	if c.readTapReader == nil {
		return nil, ErrReadTapUnavailable
	}
	if err := c.readTapReader.ReadInto(&c.readTapRec); err != nil {
		return nil, err
	}
	return decodeEvent(c.readTapRec.RawSample)
}

// HasReadTap reports whether the BPF object exposed the
// read_tap_events ringbuf. Callers gate their second consumer
// goroutine on this.
func (c *Consumer) HasReadTap() bool {
	return c != nil && c.readTapReader != nil
}

// ErrReadTapUnavailable is returned by ReadReadTap when the BPF
// object did not include the read_tap_events ringbuf map. Callers
// should not spawn the second consumer goroutine in this case.
var ErrReadTapUnavailable = fmt.Errorf("read_tap_events ringbuf not present in BPF object")

// decodeEvent dispatches a raw ring-buffer record on its leading
// event_type field (first 4 bytes, little-endian).
func decodeEvent(raw []byte) (*Event, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("event too short: %d bytes", len(raw))
	}
	evtType := binary.LittleEndian.Uint32(raw[0:])
	switch evtType {
	case EVT_OPENAT:
		o, err := decodeOpenatEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, Openat: o}, nil
	case EVT_EXECVE:
		e, err := decodeExecveEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, Execve: e}, nil
	case EVT_UNLINKAT, EVT_RENAMEAT, EVT_FCHMODAT:
		f, err := decodeFileOpEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, FileOp: f}, nil
	case EVT_SECURITY:
		s, err := decodeSecurityEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, Security: s}, nil
	case EVT_WRITE:
		w, err := decodeWriteEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, Write: w}, nil
	case EVT_SOCKET, EVT_CONNECT, EVT_BIND, EVT_CONNECT_RET, EVT_DNS_QUERY:
		n, err := decodeNetEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, Net: n}, nil
	case EVT_READ_CHUNK:
		rc, err := decodeReadChunkEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, ReadChunk: rc}, nil
	case EVT_CLOSE:
		cl, err := decodeCloseEvent(raw)
		if err != nil {
			return nil, err
		}
		return &Event{Type: evtType, Close: cl}, nil
	default:
		return nil, fmt.Errorf("unknown event_type=%d (raw len=%d)", evtType, len(raw))
	}
}

func decodeEventHeader(raw []byte) EventHeader {
	return EventHeader{
		EventType:   binary.LittleEndian.Uint32(raw[0:]),
		TimestampNs: binary.LittleEndian.Uint64(raw[8:]),
		PID:         binary.LittleEndian.Uint32(raw[16:]),
		TGID:        binary.LittleEndian.Uint32(raw[20:]),
		PPID:        binary.LittleEndian.Uint32(raw[24:]),
	}
}

func decodeExecveEvent(raw []byte) (*ExecveEvent, error) {
	if len(raw) < execveEventSize {
		return nil, fmt.Errorf("execve event too short: %d < %d", len(raw), execveEventSize)
	}
	h := decodeEventHeader(raw)
	// hdr is 32 bytes (24 declared + 8 trailing pad to next 8-byte alignment? actually 32 due to _pad1)
	const commOff = 32
	const fileOff = commOff + taskCommLen
	ev := &ExecveEvent{
		EventHeader: h,
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		Filename:    readCStr(raw[fileOff : fileOff+maxPath]),
	}
	return ev, nil
}

func decodeFileOpEvent(raw []byte) (*FileOpEvent, error) {
	if len(raw) < fileMutationEventSize {
		return nil, fmt.Errorf("file_op event too short: %d < %d", len(raw), fileMutationEventSize)
	}
	h := decodeEventHeader(raw)
	// header is 32, then mode(4) + flags(4) + pad(8) + comm(16) + path(4096) + path2(4096)
	const modeOff = 32
	const flagsOff = 36
	const commOff = 48
	const pathOff = commOff + taskCommLen // 64
	const path2Off = pathOff + maxPath    // 4160
	ev := &FileOpEvent{
		EventHeader: h,
		Op:          h.EventType,
		Mode:        binary.LittleEndian.Uint32(raw[modeOff:]),
		Flags:       binary.LittleEndian.Uint32(raw[flagsOff:]),
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		Path:        readCStr(raw[pathOff : pathOff+maxPath]),
		Path2:       readCStr(raw[path2Off : path2Off+maxPath]),
	}
	return ev, nil
}

func decodeSecurityEvent(raw []byte) (*SecurityEvent, error) {
	if len(raw) < securityEventSize {
		return nil, fmt.Errorf("security event too short: %d < %d", len(raw), securityEventSize)
	}
	h := decodeEventHeader(raw)
	const commOff = 32
	const syscallOff = commOff + taskCommLen // 48
	const argsOff = syscallOff + 8           // 56 (4 syscall_nr + 4 pad)
	ev := &SecurityEvent{
		EventHeader: h,
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		SyscallNr:   binary.LittleEndian.Uint32(raw[syscallOff:]),
	}
	for i := 0; i < 4; i++ {
		ev.Args[i] = binary.LittleEndian.Uint64(raw[argsOff+i*8:])
	}
	return ev, nil
}

func decodeWriteEvent(raw []byte) (*WriteEvent, error) {
	if len(raw) < writeEventSize {
		return nil, fmt.Errorf("write event too short: %d < %d", len(raw), writeEventSize)
	}
	h := decodeEventHeader(raw)
	const commOff = cilockHdrSize          // 32
	const fdOff = commOff + taskCommLen    // 48
	const bytesOff = fdOff + 4 + 4         // 56 (fd + pad)
	return &WriteEvent{
		EventHeader: h,
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		FD:          int32(binary.LittleEndian.Uint32(raw[fdOff:])),
		Bytes:       binary.LittleEndian.Uint64(raw[bytesOff:]),
	}, nil
}

func decodeNetEvent(raw []byte) (*NetEvent, error) {
	if len(raw) < netEventSize {
		return nil, fmt.Errorf("net event too short: %d < %d", len(raw), netEventSize)
	}
	h := decodeEventHeader(raw)
	const commOff = cilockHdrSize
	const fdOff = commOff + taskCommLen
	const familyOff = fdOff + 4
	const typeOff = familyOff + 4
	const protoOff = typeOff + 4
	const addrOff = protoOff + 4
	ev := &NetEvent{
		EventHeader: h,
		Op:          h.EventType,
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		FD:          int32(binary.LittleEndian.Uint32(raw[fdOff:])),
		Family:      binary.LittleEndian.Uint32(raw[familyOff:]),
		Type:        binary.LittleEndian.Uint32(raw[typeOff:]),
		Protocol:    int32(binary.LittleEndian.Uint32(raw[protoOff:])),
	}
	copy(ev.Addr[:], raw[addrOff:addrOff+32])
	return ev, nil
}

func decodeReadChunkEvent(raw []byte) (*ReadChunkEvent, error) {
	if len(raw) < readChunkEventSize {
		return nil, fmt.Errorf("read_chunk event too short: %d < %d", len(raw), readChunkEventSize)
	}
	h := decodeEventHeader(raw)
	const commOff = cilockHdrSize       // 32
	const fdOff = commOff + taskCommLen // 48
	const seqOff = fdOff + 4            // 52
	const lenOff = seqOff + 4           // 56
	const dataOff = lenOff + 4 + 4      // 64 (chunk_len + pad)
	chunkLen := binary.LittleEndian.Uint32(raw[lenOff:])
	if chunkLen > readChunkBytes {
		return nil, fmt.Errorf("read_chunk len %d > max %d", chunkLen, readChunkBytes)
	}
	// Copy Data so it survives the next ringbuf.ReadInto which
	// reuses the underlying buffer. The pool-of-bytes pattern below
	// avoids GC pressure: pull from a sync.Pool, fill, return when
	// the dispatcher's done with it (caller's responsibility).
	ev := &ReadChunkEvent{
		EventHeader: h,
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		FD:          int32(binary.LittleEndian.Uint32(raw[fdOff:])),
		Seq:         binary.LittleEndian.Uint32(raw[seqOff:]),
		ChunkLen:    chunkLen,
	}
	ev.Data = make([]byte, chunkLen)
	copy(ev.Data, raw[dataOff:dataOff+int(chunkLen)])
	return ev, nil
}

func decodeCloseEvent(raw []byte) (*CloseEvent, error) {
	if len(raw) < closeEventSize {
		return nil, fmt.Errorf("close event too short: %d < %d", len(raw), closeEventSize)
	}
	h := decodeEventHeader(raw)
	const commOff = cilockHdrSize
	const fdOff = commOff + taskCommLen
	const pathLenOff = fdOff + 4
	const sizeAtOpenOff = pathLenOff + 4
	const pathOff = sizeAtOpenOff + 8
	pathLen := binary.LittleEndian.Uint32(raw[pathLenOff:])
	if pathLen > closePathLen {
		pathLen = closePathLen
	}
	var path string
	if pathLen > 0 {
		// path field is NUL-terminated by bpf_probe_read_kernel — use
		// readCStr which strips at the first NUL.
		path = readCStr(raw[pathOff : pathOff+int(pathLen)])
	}
	return &CloseEvent{
		EventHeader: h,
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		FD:          int32(binary.LittleEndian.Uint32(raw[fdOff:])),
		Path:        path,
		SizeAtOpen:  binary.LittleEndian.Uint64(raw[sizeAtOpenOff:]),
	}, nil
}

// readCStr returns the bytes up to (but not including) the first NUL.
func readCStr(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
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
// queued events and then exits cleanly. Flushes BOTH ringbufs.
func (c *Consumer) Flush() error {
	if c == nil {
		return nil
	}
	var firstErr error
	if c.reader != nil {
		if err := c.reader.Flush(); err != nil {
			firstErr = err
		}
	}
	if c.readTapReader != nil {
		if err := c.readTapReader.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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
	if c.readTapReader != nil {
		_ = c.readTapReader.Close()
		c.readTapReader = nil
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
	h := decodeEventHeader(raw)
	// After hdr (32 bytes): dirfd(4) fd(4) path_len(4) flags(4)
	// size_at_open(8) mtime_ns(8) comm(16) path(4096).
	const dirfdOff = cilockHdrSize        // 32
	const fdOff = dirfdOff + 4            // 36
	const pathLenOff = fdOff + 4          // 40
	const flagsOff = pathLenOff + 4       // 44
	const sizeOff = flagsOff + 4          // 48
	const mtimeOff = sizeOff + 8          // 56
	const commOff = mtimeOff + 8          // 64
	const pathOff = commOff + taskCommLen // 80
	ev := &OpenatEvent{
		TimestampNs: h.TimestampNs,
		PID:         h.PID,
		TGID:        h.TGID,
		PPID:        h.PPID,
		Dirfd:       int32(binary.LittleEndian.Uint32(raw[dirfdOff:])),
		FD:          int32(binary.LittleEndian.Uint32(raw[fdOff:])),
		PathLen:     binary.LittleEndian.Uint32(raw[pathLenOff:]),
		Flags:       binary.LittleEndian.Uint32(raw[flagsOff:]),
		SizeAtOpen:  binary.LittleEndian.Uint64(raw[sizeOff:]),
		MtimeNs:     binary.LittleEndian.Uint64(raw[mtimeOff:]),
		Comm:        readCStr(raw[commOff : commOff+taskCommLen]),
		Path:        readCStr(raw[pathOff : pathOff+maxPath]),
	}
	return ev, nil
}

