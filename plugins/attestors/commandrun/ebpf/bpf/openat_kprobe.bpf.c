// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Rookery Contributors
//
// eBPF kprobes for cilock's tracing path (#167). Captures the syscalls
// that the ptrace path observes in tracing_linux.go so the two modes
// produce equivalent command-run/v0.1 attestations.
//
// All events share one ring buffer. The first field of every event is
// an event_type discriminator the userspace consumer dispatches on.
// Per-event struct layout is fixed — alignment + padding must match
// the Go-side decoders in openat_consumer.go.
//
// V1: openat-family only (TOCTOU-detecting file capture)
// V1.1 (this file): + execve, unlinkat, renameat2, fchmodat,
//                   + security-relevant syscalls (memfd, mount, ptrace,
//                     mprotect, prctl, setsid, setns, init_module,
//                     dup2/3, clone/clone3) for syscallEvents.
//
// Each kprobe pre-flight-filters via the watched_pids set + the
// root_parent_tgid bootstrap signal (see emit_filter() below). Events
// for processes outside the tracee tree are dropped before any path
// copy or ring-buffer write — keeping in-kernel work bounded.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH 4096
#define TASK_COMM_LEN 16

// Event type discriminator. MUST match openat_consumer.go.
enum cilock_event_type {
    EVT_OPENAT      = 1,
    EVT_EXECVE      = 2,
    EVT_UNLINKAT    = 3,
    EVT_RENAMEAT    = 4,
    EVT_FCHMODAT    = 5,
    EVT_SECURITY    = 6, // catch-all for ptrace/mount/memfd_create/etc.
    EVT_WRITE       = 7, // write/pwrite — userspace resolves fd→path
    EVT_SOCKET      = 8, // socket() family/type/protocol
    EVT_CONNECT     = 9, // connect()
    EVT_BIND        = 10, // bind()
    EVT_READ_CHUNK  = 11, // chunk of bytes copy_to_user'd by vfs_read (V1.4 read-tap)
    EVT_CLOSE       = 12, // close/filp_close — finalize per-fd streaming hash
};

// Common header at the start of every event. event_type is read first
// by userspace to dispatch to the right decoder.
//
// Layout (24 bytes):
//   u32 event_type   (4 bytes, offset 0)
//   u32 _hdr_pad     (4, 4)
//   u64 timestamp_ns (8, 8)
//   u32 pid          (4, 16)
//   u32 tgid         (4, 20)
//   u32 ppid         (4, 24)
//   u32 _hdr_pad2    (4, 28)   -- forces 8-byte alignment for subsequent fields
struct cilock_evt_hdr {
    __u32 event_type;
    __u32 _pad0;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 _pad1;
};

// openat event. Header layout matches every other event for uniform
// userspace dispatch on event_type.
// Total: 32 (hdr) + 4 (dirfd) + 4 (fd) + 4 (path_len) + 4 (flags)
//      + 8 (size_at_open) + 8 (mtime_ns) + 16 (comm) + 4096 (path) = 4176
//
// `flags` captures the openat() flags arg (O_RDONLY/O_WRONLY/O_CREAT/...).
// `fd` is the kernel-returned file descriptor (>=0 on success, -errno
// on failure). V1.3: emitted from a kretprobe so userspace can read
// via /proc/<pid>/fd/<fd> while the tracee's fd is still open — that
// gives the same open-file-description the tracee will read from,
// without race on the path.
struct openat_event {
    struct cilock_evt_hdr hdr;
    __s32 dirfd;
    __s32 fd;
    __u32 path_len;
    __u32 flags;
    __u64 size_at_open;
    __u64 mtime_ns;
    char  comm[TASK_COMM_LEN];
    char  path[MAX_PATH];
};

// Kprobe→kretprobe stash. Reuses the openat_event layout so the
// kretprobe just patches in the fd and submits — no large memcpy
// (which BPF rejects).
//
// Sized at 1024 — concurrent in-flight openat()s by any single trace
// tree are bounded by the number of runnable tasks, well under 1024
// even for hyper-forking CI workloads.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct openat_event);
} openat_stash_map SEC(".maps");

// Per-CPU scratch for assembling the openat_event before HASH-map
// update. The event struct is ~4KB which exceeds BPF's 512-byte stack
// limit; per-CPU array keeps it off-stack like the event scratch.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct openat_event);
} openat_stash_scratch SEC(".maps");

// execve event. argv[0] is what the syscall caller passed as the
// program path; userspace hashes that + /proc/<pid>/exe (current
// binary symlink). Both are best-effort — see enrichFromProc in Go.
// Total: 24 + 16 + 4096 = 4136 bytes
struct execve_event {
    struct cilock_evt_hdr hdr;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH];
};

// File mutation: unlinkat, renameat2, fchmodat all share this layout.
// hdr.event_type discriminates. For fchmodat, mode = new mode bits;
// for renameat2, path2 = the new name. Unused fields are zeroed.
// Total: 24 + 16 + 16 + 4096 + 4096 = 8248 bytes
struct file_mutation_event {
    struct cilock_evt_hdr hdr;
    __u32 mode;       // fchmodat: new permission bits; others: 0
    __u32 flags;      // renameat2 flags; unlinkat AT_REMOVEDIR flag
    __u64 _pad;
    char  comm[TASK_COMM_LEN];
    char  path[MAX_PATH];
    char  path2[MAX_PATH]; // renameat2: newpath; others: empty
};

// Generic security-event payload. Userspace formats the human-readable
// detail string from (syscall_id, args[]). The args slot meaning is
// syscall-specific — userspace knows it.
// Total: 24 + 16 + 16 + 32 = 88 bytes (fixed, no path)
struct security_event {
    struct cilock_evt_hdr hdr;
    char  comm[TASK_COMM_LEN];
    __u32 syscall_nr;      // SYS_PTRACE, SYS_MOUNT, SYS_MPROTECT, etc.
    __u32 _pad;
    __u64 args[4];         // syscall args 0..3
};

// Read-chunk event. Carries up to READ_CHUNK_BYTES of file bytes the
// kernel copied to the tracee on a single vfs_read return. Userspace
// feeds these into a per-(pid, fd) streaming SHA-256. The kernel side
// of the race is closed: we get the bytes the tracee actually saw.
//
// Reads larger than READ_CHUNK_BYTES are split into multiple events
// (sequence in `seq`). Single-threaded fd ordering preserves order.
//
// Total = 32 (hdr) + 16 (comm) + 4 (fd) + 4 (seq) + 4 (chunk) + 4 (pad)
//       + 16384 = 16448 bytes
#define READ_CHUNK_BYTES 16384
struct read_chunk_event {
    struct cilock_evt_hdr hdr;
    char  comm[TASK_COMM_LEN];
    __s32 fd;
    __u32 seq;       // chunk index within this read syscall
    __u32 chunk_len; // bytes of `data` that are valid (≤ READ_CHUNK_BYTES)
    __u32 _pad;
    __u8  data[READ_CHUNK_BYTES];
};

// Close event. Signals userspace to finalize the per-(pid, fd) hash
// and record it.
//
// V2 Phase 8 stage 2: carries the resolved path + size_at_open
// INLINE, populated from the kernel-side fd_table (set by the
// matching openat kretprobe). Userspace no longer needs to maintain
// a (pid, fd) → openInfo map — the close event is self-describing.
// Eliminates the entire openPaths/pendingCloses dance + the close-
// before-openat reorder window + the fd-reuse staleness bugs that
// the timestamp-gated pendingClose patch worked around.
//
// `path_len` is the strictly-positive byte length of `path[]`.
// When 0, no fd_table entry existed (close on a non-tracked fd —
// e.g. fd inherited from before tracing began, or already evicted
// by LRU). Userspace falls back to its in-flight state if any.
//
// Total = 32 (hdr) + 16 (comm) + 4 (fd) + 4 (path_len) + 8 (size_at_open) + 256 (path) = 320 bytes
#define CLOSE_PATH_LEN 256
struct close_event {
    struct cilock_evt_hdr hdr;
    char  comm[TASK_COMM_LEN];
    __s32 fd;
    __u32 path_len;
    __u64 size_at_open;
    char  path[CLOSE_PATH_LEN];
};

// Kprobe→kretprobe handoff for read syscalls: stash (fd, user_buf,
// count) on entry so the kretprobe can copy bytes from the user
// buffer + tag with fd. Keyed by pid_tgid like the openat stash.
//
// Threat model: the calling thread is blocked in kernel context
// during the kretprobe — it can't race the user buffer. A sibling
// thread sharing the address space CAN race. Documented; not fixable
// without a kernel hook on the inlined copy_to_user primitives, all
// of which were unhookable on Linux 6.8 as of 2026-05-23.
struct read_stash {
    __u64 user_buf;
    __u64 count;
    __s32 fd;
    __u32 _pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct read_stash);
} read_stash_map SEC(".maps");

// Per-CPU scratch for read_chunk_event (~16KB, way over BPF stack).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct read_chunk_event);
} read_chunk_scratch SEC(".maps");

// Filter to control read-tap independently of the openat filter.
// 0 = off (default; current openat-only behavior). 1 = on. Userspace
// sets this to 1 only in CILOCK_HASH_RACE_FREE mode.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} read_tap_enabled SEC(".maps");

// Write event. Userspace resolves fd → path via /proc/<pid>/fd/<fd>.
// Total: 24 + 16 + 16 = 56 bytes (no path; cheap; high-frequency)
struct write_event {
    struct cilock_evt_hdr hdr;
    char  comm[TASK_COMM_LEN];
    __s32 fd;
    __u32 _pad;
    __u64 bytes;
};

// Socket/connect/bind event. Sockaddr captured as raw bytes (max
// commonly used: 28 bytes for sockaddr_in6). Userspace parses
// AF_INET / AF_INET6 / AF_UNIX based on family field.
// Total: 24 + 16 + 8 + 8 + 32 = 88 bytes
struct net_event {
    struct cilock_evt_hdr hdr;
    char  comm[TASK_COMM_LEN];
    __s32 fd;              // socket(): returned fd; connect/bind: fd
    __u32 family;          // AF_INET / AF_INET6 / AF_UNIX (socket only)
    __u32 type;            // SOCK_STREAM / SOCK_DGRAM (socket only)
    __s32 protocol;        // socket only (0 default, 6 TCP, 17 UDP)
    char  addr[32];        // sockaddr_in/in6/un (connect/bind)
};

// `events` ringbuf — classification-critical events (openat,
// execve, fileOps, security syscalls). 256 MB. This stream is
// small per-event and low-rate, so 256 MB is plenty even on
// parallel kernel builds; defconfig measured peak fill <30 MB.
//
// CRITICAL: this ringbuf must stay drainable at all times — drops
// here mean we lose openat/execve events, which means missing
// files in OpenedFiles. To guarantee that, the high-volume
// read-tap chunk events live in their OWN ringbuf below.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024);
} events SEC(".maps");

// `read_tap_events` ringbuf — V1.4 read-tap chunk events ONLY.
// 1 GB. Read-tap emits one event per read() syscall (16 KB chunks),
// so heavy workloads (kernel compile) emit ~10M events / hundreds
// of MB. Splitting these into their own ringbuf means:
//   - classification events in `events` can never be evicted by
//     read-tap volume
//   - userspace can choose to enable/disable read-tap based on
//     workload character without affecting `events` sizing
//   - either ringbuf can be drained by its own goroutine
//     (userspace dispatcher reads both in parallel)
//
// memlock rlimit is removed at consumer Open() via cilium/ebpf's
// rlimit.RemoveMemlock helper — 1 GB allocation succeeds on any
// host with CAP_BPF and reasonable free RAM.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024 * 1024);
} read_tap_events SEC(".maps");

// Drop counters — every bpf_ringbuf_output that returns < 0 is
// counted here. Userspace can read this to surface drop rates.
// Index 0 = openat-class drops (small), Index 1 = read_chunk
// drops (large 16KB records). Separating them tells us whether
// to bump ringbuf size or split the producer/consumer.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

#define DROP_BUCKET_OPENAT 0
#define DROP_BUCKET_READTAP 1

static __always_inline void
bump_drop(__u32 bucket)
{
    __u64 *cnt = bpf_map_lookup_elem(&ringbuf_drops, &bucket);
    if (cnt) (*cnt)++;
}

// Per-CPU scratch storage for the largest event (file_mutation_event,
// ~8KB). MAX_PATH exceeds BPF's 512-byte stack limit; scratch keeps
// the event off-stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_mutation_event);
} scratch SEC(".maps");

// Watched-PID map (see header doc-comment).
//
// V2 Phase 8 (canonical-pattern migration, stage 1): the kernel-side
// authoritative watched-bit moves to task_storage below. watched_pids
// remains as the bootstrap channel — userspace registers the root tgid
// here at startup; emit_filter populates task_storage on the first
// match so subsequent lookups are constant-time and auto-GC on task
// exit (no LRU sizing concerns).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

// task_state — per-task storage carrying the canonical watched-bit.
// Auto-GC'd when the task exits (kernel releases the storage). This
// is the fast path for all hot syscalls (read/openat/close) — a
// task_storage_get is constant-time and doesn't touch the global
// watched_pids hash. Populated on fork (wake_up_new_task) and on
// emit_filter's first descent match.
struct task_state {
    __u8 watched;
    __u8 _pad[7];
};
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_state);
} task_storage SEC(".maps");

// task_is_watched returns 1 if the current task is in the watched set.
// Fast path: task_storage lookup is constant-time. Slow path
// (bootstrap before task_storage is populated for this task): fall
// back to watched_pids and cache the result.
static __always_inline int
task_is_watched(__u32 pid, __u32 tgid)
{
    struct task_struct *t = bpf_get_current_task_btf();
    if (t) {
        struct task_state *ts = bpf_task_storage_get(&task_storage, t, NULL, 0);
        if (ts && ts->watched) return 1;
    }
    // Bootstrap: not yet in task_storage but may be in watched_pids
    // (root tgid registered by userspace).
    if (bpf_map_lookup_elem(&watched_pids, &pid)) goto cache;
    if (bpf_map_lookup_elem(&watched_pids, &tgid)) goto cache;
    return 0;
cache:
    if (t) {
        struct task_state init = {.watched = 1};
        bpf_task_storage_get(&task_storage, t, &init,
            BPF_LOCAL_STORAGE_GET_F_CREATE);
    }
    return 1;
}

// task_set_watched marks the current task as watched in task_storage.
// Used on descent matches in emit_filter.
static __always_inline void
task_set_watched(void)
{
    struct task_struct *t = bpf_get_current_task_btf();
    if (!t) return;
    struct task_state init = {.watched = 1};
    bpf_task_storage_get(&task_storage, t, &init,
        BPF_LOCAL_STORAGE_GET_F_CREATE);
}

// ───── fd_table — per-(task, fd) open metadata (V2 Phase 8 stage 2) ────
//
// Keyed by (task_struct pointer, fd). Populated by the openat
// kretprobe; consumed (and deleted) by the close kprobe. Carries
// the resolved path + size_at_open inline so the close event is
// self-describing and userspace doesn't need to maintain a parallel
// (pid, fd) → openInfo map.
//
// Why a global LRU_HASH instead of task_storage-with-inner-map: the
// inner-map pattern requires either (a) a fixed-size per-task array
// indexed by fd (MAX_FDS × sizeof(fd_entry) = wasteful for sparse
// fds) or (b) HASH_OF_MAPS with one inner map per task (high alloc
// churn on fork-heavy workloads). LRU_HASH with composite key is
// simpler and the LRU policy handles cleanup if a task exits without
// our close kprobe firing (e.g., abrupt termination, sandbox kill).
//
// 65536 entries × 280B ≈ 18MB max ringbuf-side. Plenty of headroom
// for kernel-compile-class workloads (max ~10K concurrent open fds).
struct fd_key {
    __u64 task;    // task_struct pointer (stable for task's lifetime)
    __s32 fd;
    __u32 _pad;
};
struct fd_entry {
    __u64 size_at_open;
    __u32 path_len;
    __u32 _pad;
    char  path[CLOSE_PATH_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_key);
    __type(value, struct fd_entry);
} fd_table SEC(".maps");

// fd_table_set inserts an entry for the current task's fd. Path
// argument MUST already be NUL-terminated by the caller (we copy
// the strlen-bounded path verbatim).
static __always_inline void
fd_table_set(__s32 fd, const char *path, __u32 path_len, __u64 size_at_open)
{
    if (fd < 0) return;
    if (path_len == 0 || path_len > CLOSE_PATH_LEN) return;
    struct task_struct *t = bpf_get_current_task_btf();
    if (!t) return;
    struct fd_key k = { .task = (__u64)t, .fd = fd };
    struct fd_entry e = {};
    e.size_at_open = size_at_open;
    e.path_len = path_len;
    // bpf_probe_read_kernel_str would handle null-termination, but
    // path here lives in the kernel-side openat_stash already bounded
    // by stash_openat_args. Direct memcpy is safe + verifier-friendly.
    bpf_probe_read_kernel(e.path, CLOSE_PATH_LEN, path);
    bpf_map_update_elem(&fd_table, &k, &e, BPF_ANY);
}

// fd_table_take fetches and DELETES an fd_table entry. Caller copies
// out path + size_at_open before issuing the close event.
static __always_inline struct fd_entry *
fd_table_take(__s32 fd)
{
    if (fd < 0) return NULL;
    struct task_struct *t = bpf_get_current_task_btf();
    if (!t) return NULL;
    struct fd_key k = { .task = (__u64)t, .fd = fd };
    struct fd_entry *e = bpf_map_lookup_elem(&fd_table, &k);
    if (!e) return NULL;
    // The lookup returns a pointer into the map; deletion invalidates
    // it. We MUST NOT delete here — emit_close copies fields out first,
    // then deletes via fd_table_drop().
    return e;
}

static __always_inline void
fd_table_drop(__s32 fd)
{
    if (fd < 0) return;
    struct task_struct *t = bpf_get_current_task_btf();
    if (!t) return;
    struct fd_key k = { .task = (__u64)t, .fd = fd };
    bpf_map_delete_elem(&fd_table, &k);
}

// V2 Phase 8 stage 4: d_path_stash carries the canonical absolute
// path from fentry/security_file_open to the matching openat
// kretprobe. Keyed by (task, file*). LRU-bounded to handle the
// rare case where security_file_open fires but the matching
// openat kretprobe never does (failed open, etc.).
struct dpath_key {
    __u64 task;
    __u64 file;
};
struct dpath_value {
    __u32 path_len;
    __u32 _pad;
    char  path[CLOSE_PATH_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct dpath_key);
    __type(value, struct dpath_value);
} d_path_stash SEC(".maps");

// Per-CPU scratch for bpf_d_path output (~256 bytes — bigger than
// the BPF stack limit on most kernels).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dpath_value);
} dpath_scratch SEC(".maps");


// Filter enabled toggle.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} filter_enabled SEC(".maps");

// root_parent_tgid bootstrap signal.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} root_parent_tgid SEC(".maps");

// emit_filter returns 1 if this caller should be observed. Mirror of
// the openat filter logic — checked at every kprobe entry. Writes
// (cur_pid, cur_tgid, cur_ppid) into the out-params so the caller can
// reuse them without re-querying.
//
// Also adds cur_pid to watched_pids on the descent paths so that
// future syscalls from this process hit the fast (pid-in-map) branch.
static __always_inline int
emit_filter(__u32 *out_pid, __u32 *out_tgid, __u32 *out_ppid)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&filter_enabled, &zero);
    if (!enabled || *enabled == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 cur_pid  = (__u32)(pid_tgid & 0xffffffff);
    __u32 cur_tgid = (__u32)(pid_tgid >> 32);

    __u32 cur_ppid = 0;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    if (t) {
        struct task_struct *parent = BPF_CORE_READ(t, real_parent);
        if (parent)
            cur_ppid = BPF_CORE_READ(parent, tgid);
    }

    // Fast path: task_storage lookup. Populated on fork by
    // wake_up_new_task and by descent matches below; subsequent
    // syscalls from this task hit this branch and return immediately.
    if (task_is_watched(cur_pid, cur_tgid)) {
        *out_pid  = cur_pid;
        *out_tgid = cur_tgid;
        *out_ppid = cur_ppid;
        return 1;
    }

    // Slow path: walk the ancestor chain via task_struct->real_parent,
    // checking each ancestor's TGID against watched_pids AND
    // root_parent_tgid. This closes the race where wake_up_new_task
    // didn't propagate the watched-bit for an INTERMEDIATE ancestor
    // (e.g. cargo's worker thread that then spawns rustc — if the
    // worker's task_storage wasn't set in time, the immediate-parent
    // descent check misses rustc, but the grandparent — cargo or
    // cargo's coordinator — is still in watched_pids).
    //
    // BPF verifier limitation: only bpf_get_current_task_btf() returns
    // a trusted pointer accepted by bpf_task_storage_get. Ancestor
    // pointers obtained via BPF_CORE_READ are "scalar" from the
    // verifier's view — we can READ from them (tgid) but can't pass
    // them to task_storage_get. So we check watched_pids[ancestor.tgid]
    // and the root_parent_tgid bootstrap match. wake_up_new_task
    // always writes BOTH task_storage AND watched_pids, so this is
    // sufficient — any propagation that set task_storage also set
    // watched_pids.
    //
    // Walk depth 6: covers commandrun.test → go.runtime → cargo →
    // cargo.coordinator → cargo.worker → rustc with one to spare.
    int matched_by_descent = 0;
    __u32 *root = bpf_map_lookup_elem(&root_parent_tgid, &zero);
    if (bpf_map_lookup_elem(&watched_pids, &cur_ppid)) {
        matched_by_descent = 1;
    } else if (root && cur_ppid == *root && *root != 0) {
        matched_by_descent = 1;
    } else if (t) {
        struct task_struct *ancestor = BPF_CORE_READ(t, real_parent);
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            if (!ancestor) break;
            __u32 atgid = BPF_CORE_READ(ancestor, tgid);
            if (atgid != 0) {
                if (bpf_map_lookup_elem(&watched_pids, &atgid)) {
                    matched_by_descent = 1;
                    break;
                }
                if (root && atgid == *root && *root != 0) {
                    matched_by_descent = 1;
                    break;
                }
            }
            ancestor = BPF_CORE_READ(ancestor, real_parent);
        }
    }
    if (!matched_by_descent) {
        return 0;
    }
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &cur_pid, &one, BPF_ANY);
    task_set_watched();

    *out_pid  = cur_pid;
    *out_tgid = cur_tgid;
    *out_ppid = cur_ppid;
    return 1;
}

// fill_hdr populates the cilock_evt_hdr with cached pid/tgid/ppid and
// the current timestamp. Sets the event_type discriminator.
static __always_inline void
fill_hdr(struct cilock_evt_hdr *h, __u32 evt, __u32 pid, __u32 tgid, __u32 ppid)
{
    h->event_type   = evt;
    h->_pad0        = 0;
    h->timestamp_ns = bpf_ktime_get_ns();
    h->pid          = pid;
    h->tgid         = tgid;
    h->ppid         = ppid;
    h->_pad1        = 0;
}

// ───── openat / openat2 (kprobe+kretprobe pair) ─────────────────────
// kprobe stashes (pathname, flags) at syscall entry; kretprobe reads
// the stash + the return-value fd and emits the event. This gives us
// the actual fd the tracee got, so userspace can read via
// /proc/<pid>/fd/<fd> — same open-file-description, race-narrowed.

static __always_inline void
stash_openat_args(int dirfd, const char *pathname, __u32 flags)
{
    if (!pathname) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    __u32 z = 0;
    struct openat_event *s = bpf_map_lookup_elem(&openat_stash_scratch, &z);
    if (!s) return;

    // Populate the event as much as we can at entry. The fd field is
    // filled in by the kretprobe; everything else is final.
    __builtin_memset(s, 0, offsetof(struct openat_event, comm));
    fill_hdr(&s->hdr, EVT_OPENAT, cur_pid, cur_tgid, cur_ppid);
    s->dirfd        = dirfd;
    s->fd           = 0; // placeholder; kretprobe fills in
    s->flags        = flags;
    s->size_at_open = 0;
    s->mtime_ns     = 0;
    bpf_get_current_comm(s->comm, sizeof(s->comm));
    long n = bpf_probe_read_user_str(s->path, MAX_PATH, pathname);
    if (n > 0) s->path_len = (__u32)n;

    __u64 key = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&openat_stash_map, &key, s, BPF_ANY);
}

static __always_inline void
emit_openat_ret(long ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct openat_event *ev = bpf_map_lookup_elem(&openat_stash_map, &key);
    if (!ev) return;

    // Patch in the fd from the syscall return value and submit.
    // ev was fully populated at kprobe time except fd; just update
    // the one field in-place and emit.
    ev->fd = (int)ret;

    // Walk fd → struct file → inode → i_size for V1.4 read-tap
    // full-read detection. Done in kernel here so userspace doesn't
    // need to stat(2). Best-effort: a failure leaves size_at_open=0
    // and userspace falls back to path-hash.
    if ((int)ret >= 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct files_struct *files = BPF_CORE_READ(task, files);
            if (files) {
                struct fdtable *fdt = BPF_CORE_READ(files, fdt);
                __u32 max_fds = 0;
                if (fdt) max_fds = BPF_CORE_READ(fdt, max_fds);
                if (fdt && (__u32)ret < max_fds) {
                    struct file **fd_array = BPF_CORE_READ(fdt, fd);
                    struct file *file = NULL;
                    if (fd_array) bpf_probe_read_kernel(&file, sizeof(file), &fd_array[(int)ret]);
                    if (file) {
                        struct inode *inode = BPF_CORE_READ(file, f_inode);
                        if (inode) {
                            ev->size_at_open = (__u64)BPF_CORE_READ(inode, i_size);
                            // mtime layout varies across kernels; skip
                            // for V1.4 — userspace doesn't need it yet
                            // (full-read check uses size only).
                        }
                        // Absolute-path resolution via bpf_d_path()
                        // was tried in a V2 draft but the helper is
                        // restricted from kprobes on most kernels
                        // (returns "unknown func bpf_d_path"). Path
                        // resolution moved to userspace: the dispatcher
                        // reads /proc/<pid>/cwd to make relative paths
                        // absolute before hashing.
                    }
                }
            }
        }
    }

    // V2 Phase 8 stage 4: if fentry/security_file_open stashed a
    // canonical absolute path for this (task, file) tuple, replace
    // the raw bpf_probe_read_user_str path with it. The canonical
    // path eliminates userspace cwd resolution entirely.
    if ((int)ret >= 0) {
        struct task_struct *task = bpf_get_current_task_btf();
        if (task) {
            struct files_struct *files = BPF_CORE_READ(task, files);
            if (files) {
                struct fdtable *fdt = BPF_CORE_READ(files, fdt);
                __u32 max_fds2 = 0;
                if (fdt) max_fds2 = BPF_CORE_READ(fdt, max_fds);
                if (fdt && (__u32)ret < max_fds2) {
                    struct file **fd_array = BPF_CORE_READ(fdt, fd);
                    struct file *file = NULL;
                    if (fd_array) bpf_probe_read_kernel(&file, sizeof(file), &fd_array[(int)ret]);
                    if (file) {
                        struct dpath_key k = {
                            .task = (__u64)task,
                            .file = (__u64)file,
                        };
                        struct dpath_value *v = bpf_map_lookup_elem(&d_path_stash, &k);
                        if (v && v->path_len > 0 && v->path_len <= CLOSE_PATH_LEN) {
                            __builtin_memcpy(ev->path, v->path, CLOSE_PATH_LEN);
                            ev->path_len = v->path_len;
                            bpf_map_delete_elem(&d_path_stash, &k);
                        }
                    }
                }
            }
        }
    }

    if (bpf_ringbuf_output(&events, ev, sizeof(struct openat_event), 0) < 0)
        bump_drop(DROP_BUCKET_OPENAT);

    // V2 Phase 8 stage 2: stash (path, size_at_open) keyed by
    // (current_task, fd) so the close kprobe can emit the path
    // INLINE. Only on success (fd >= 0) and only for path lengths
    // that fit in CLOSE_PATH_LEN. Paths longer than 256 bytes are
    // rare in build workloads (PATH_MAX=4096 but actual paths are
    // ~64-80 bytes typical) — those skip the fd_table population
    // and the close event surfaces path_len=0 to userspace, which
    // continues to work via the legacy openPaths cache.
    if (ev->fd >= 0 && ev->path_len > 0 && ev->path_len <= CLOSE_PATH_LEN) {
        fd_table_set(ev->fd, ev->path, ev->path_len, ev->size_at_open);
    }

    bpf_map_delete_elem(&openat_stash_map, &key);
}

SEC("kprobe/__arm64_sys_openat")
int BPF_KPROBE(kprobe_openat_arm64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    stash_openat_args(dirfd, pathname, flags);
    return 0;
}

SEC("kretprobe/__arm64_sys_openat")
int BPF_KRETPROBE(kretprobe_openat_arm64, long ret)
{
    emit_openat_ret(ret);
    return 0;
}

SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(kprobe_openat_x64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    stash_openat_args(dirfd, pathname, flags);
    return 0;
}

SEC("kretprobe/__x64_sys_openat")
int BPF_KRETPROBE(kretprobe_openat_x64, long ret)
{
    emit_openat_ret(ret);
    return 0;
}

// openat2 uses struct open_how* (PARM3) — we use 0 for flags; for V1.3
// we don't differentiate openat2 (rare).
SEC("kprobe/__arm64_sys_openat2")
int BPF_KPROBE(kprobe_openat2_arm64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    stash_openat_args(dirfd, pathname, 0);
    return 0;
}

SEC("kretprobe/__arm64_sys_openat2")
int BPF_KRETPROBE(kretprobe_openat2_arm64, long ret)
{
    emit_openat_ret(ret);
    return 0;
}

SEC("kprobe/__x64_sys_openat2")
int BPF_KPROBE(kprobe_openat2_x64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    stash_openat_args(dirfd, pathname, 0);
    return 0;
}

SEC("kretprobe/__x64_sys_openat2")
int BPF_KRETPROBE(kretprobe_openat2_x64, long ret)
{
    emit_openat_ret(ret);
    return 0;
}

// ───── execve ──────────────────────────────────────────────────────
// argv[0] is the filename the caller passed. The actual loaded binary
// is /proc/<pid>/exe which userspace reads on receipt of this event.

static __always_inline void
emit_execve(const char *filename)
{
    if (!filename) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    __u32 z = 0;
    struct file_mutation_event *scratch_ev = bpf_map_lookup_elem(&scratch, &z);
    if (!scratch_ev) return;
    struct execve_event *ev = (struct execve_event *)scratch_ev;

    __builtin_memset(ev, 0, sizeof(struct execve_event) - MAX_PATH);
    fill_hdr(&ev->hdr, EVT_EXECVE, cur_pid, cur_tgid, cur_ppid);
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    (void)bpf_probe_read_user_str(ev->filename, MAX_PATH, filename);

    bpf_ringbuf_output(&events, ev, sizeof(struct execve_event), 0);
}

SEC("kprobe/__arm64_sys_execve")
int BPF_KPROBE(kprobe_execve_arm64, struct pt_regs *regs)
{
    const char *filename = (const char *)PT_REGS_PARM1_CORE_SYSCALL(regs);
    emit_execve(filename);
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(kprobe_execve_x64, struct pt_regs *regs)
{
    const char *filename = (const char *)PT_REGS_PARM1_CORE_SYSCALL(regs);
    emit_execve(filename);
    return 0;
}

// ───── unlinkat ────────────────────────────────────────────────────

static __always_inline void
emit_unlinkat(const char *pathname, __u32 flags)
{
    if (!pathname) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    __u32 z = 0;
    struct file_mutation_event *ev = bpf_map_lookup_elem(&scratch, &z);
    if (!ev) return;

    __builtin_memset(ev, 0, sizeof(struct file_mutation_event) - 2*MAX_PATH);
    fill_hdr(&ev->hdr, EVT_UNLINKAT, cur_pid, cur_tgid, cur_ppid);
    ev->mode = 0;
    ev->flags = flags;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    (void)bpf_probe_read_user_str(ev->path,  MAX_PATH, pathname);
    ev->path2[0] = '\0';

    bpf_ringbuf_output(&events, ev, sizeof(struct file_mutation_event), 0);
}

SEC("kprobe/__arm64_sys_unlinkat")
int BPF_KPROBE(kprobe_unlinkat_arm64, struct pt_regs *regs)
{
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_unlinkat(pathname, flags);
    return 0;
}

SEC("kprobe/__x64_sys_unlinkat")
int BPF_KPROBE(kprobe_unlinkat_x64, struct pt_regs *regs)
{
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_unlinkat(pathname, flags);
    return 0;
}

// ───── renameat2 ───────────────────────────────────────────────────

static __always_inline void
emit_renameat2(const char *oldpath, const char *newpath, __u32 flags)
{
    if (!oldpath || !newpath) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    __u32 z = 0;
    struct file_mutation_event *ev = bpf_map_lookup_elem(&scratch, &z);
    if (!ev) return;

    __builtin_memset(ev, 0, sizeof(struct file_mutation_event) - 2*MAX_PATH);
    fill_hdr(&ev->hdr, EVT_RENAMEAT, cur_pid, cur_tgid, cur_ppid);
    ev->mode = 0;
    ev->flags = flags;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    (void)bpf_probe_read_user_str(ev->path,  MAX_PATH, oldpath);
    (void)bpf_probe_read_user_str(ev->path2, MAX_PATH, newpath);

    bpf_ringbuf_output(&events, ev, sizeof(struct file_mutation_event), 0);
}

SEC("kprobe/__arm64_sys_renameat2")
int BPF_KPROBE(kprobe_renameat2_arm64, struct pt_regs *regs)
{
    const char *oldpath = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    const char *newpath = (const char *)PT_REGS_PARM4_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM5_CORE_SYSCALL(regs);
    emit_renameat2(oldpath, newpath, flags);
    return 0;
}

SEC("kprobe/__x64_sys_renameat2")
int BPF_KPROBE(kprobe_renameat2_x64, struct pt_regs *regs)
{
    const char *oldpath = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    const char *newpath = (const char *)PT_REGS_PARM4_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM5_CORE_SYSCALL(regs);
    emit_renameat2(oldpath, newpath, flags);
    return 0;
}

// renameat (the older 4-arg syscall). Go's runtime uses SYS_RENAMEAT
// directly via syscall.Renameat — not the libc wrapper that routes
// through renameat2. Without this hook, every Go-built binary went
// silent because `go build` writes to /tmp/go-build*/b001/exe/a.out
// then renameat()-moves it to the final output path; the rename was
// invisible and the binary never landed in products.
SEC("kprobe/__arm64_sys_renameat")
int BPF_KPROBE(kprobe_renameat_arm64, struct pt_regs *regs)
{
    const char *oldpath = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    const char *newpath = (const char *)PT_REGS_PARM4_CORE_SYSCALL(regs);
    emit_renameat2(oldpath, newpath, 0);
    return 0;
}

SEC("kprobe/__x64_sys_renameat")
int BPF_KPROBE(kprobe_renameat_x64, struct pt_regs *regs)
{
    const char *oldpath = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    const char *newpath = (const char *)PT_REGS_PARM4_CORE_SYSCALL(regs);
    emit_renameat2(oldpath, newpath, 0);
    return 0;
}

// ───── fchmodat ────────────────────────────────────────────────────

static __always_inline void
emit_fchmodat(const char *pathname, __u32 mode)
{
    if (!pathname) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    __u32 z = 0;
    struct file_mutation_event *ev = bpf_map_lookup_elem(&scratch, &z);
    if (!ev) return;

    __builtin_memset(ev, 0, sizeof(struct file_mutation_event) - 2*MAX_PATH);
    fill_hdr(&ev->hdr, EVT_FCHMODAT, cur_pid, cur_tgid, cur_ppid);
    ev->mode = mode;
    ev->flags = 0;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    (void)bpf_probe_read_user_str(ev->path,  MAX_PATH, pathname);
    ev->path2[0] = '\0';

    bpf_ringbuf_output(&events, ev, sizeof(struct file_mutation_event), 0);
}

SEC("kprobe/__arm64_sys_fchmodat")
int BPF_KPROBE(kprobe_fchmodat_arm64, struct pt_regs *regs)
{
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 mode = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_fchmodat(pathname, mode);
    return 0;
}

SEC("kprobe/__x64_sys_fchmodat")
int BPF_KPROBE(kprobe_fchmodat_x64, struct pt_regs *regs)
{
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 mode = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_fchmodat(pathname, mode);
    return 0;
}

// ───── security events (memfd_create, ptrace, mount, mprotect, etc.) ─

static __always_inline void
emit_security(__u32 syscall_nr,
              __u64 arg0, __u64 arg1, __u64 arg2, __u64 arg3)
{
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    struct security_event ev = {};
    fill_hdr(&ev.hdr, EVT_SECURITY, cur_pid, cur_tgid, cur_ppid);
    ev.syscall_nr = syscall_nr;
    ev.args[0] = arg0;
    ev.args[1] = arg1;
    ev.args[2] = arg2;
    ev.args[3] = arg3;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

// Cilock-internal event tags. Userspace dispatches on these (not on
// raw kernel syscall numbers, which differ across architectures and
// would alias on a uint32 switch). Each value below is a stable
// internal contract between this file and openat_consumer.go.
#define CILOCK_SEC_PTRACE        100
#define CILOCK_SEC_MEMFD_CREATE  101
#define CILOCK_SEC_MOUNT         102
#define CILOCK_SEC_MPROTECT      103
#define CILOCK_SEC_PRCTL         104
#define CILOCK_SEC_SETSID        105
#define CILOCK_SEC_SETNS         106
#define CILOCK_SEC_INIT_MODULE   107
#define CILOCK_SEC_FINIT_MODULE  108
#define CILOCK_SEC_CLONE         109
#define CILOCK_SEC_CLONE3        110
#define CILOCK_SEC_DUP2          111
#define CILOCK_SEC_DUP3          112
// Zero-copy / mmap content-bypass syscalls. These transfer file
// bytes without firing our read kprobe (which means read-tap can't
// see the bytes). Flag them via SECURITY events so the verifier
// knows the attestation may have content gaps for files touched
// via these paths. Full content capture requires hooks at the
// vfs_copy_file_range / do_splice / filemap_map_pages level —
// tracked separately. These syscall-entry hooks are the minimum
// adversarial coverage so the gap is at least VISIBLE.
#define CILOCK_SEC_COPY_FILE_RANGE 113
#define CILOCK_SEC_SPLICE          114
#define CILOCK_SEC_SENDFILE        115
#define CILOCK_SEC_MMAP            116

// Note: PT_REGS_PARMn_CORE_SYSCALL reads syscall args 1-based; the
// emit_security helper takes arg0..arg3 in 0-based order.
#define DEFINE_SECURITY_KPROBE(name, sym, syscall_nr)                          \
    SEC("kprobe/" sym)                                                         \
    int BPF_KPROBE(kprobe_##name, struct pt_regs *regs)                        \
    {                                                                          \
        __u64 a0 = (__u64)PT_REGS_PARM1_CORE_SYSCALL(regs);                    \
        __u64 a1 = (__u64)PT_REGS_PARM2_CORE_SYSCALL(regs);                    \
        __u64 a2 = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);                    \
        __u64 a3 = (__u64)PT_REGS_PARM4_CORE_SYSCALL(regs);                    \
        emit_security(syscall_nr, a0, a1, a2, a3);                             \
        return 0;                                                              \
    }

// arm64 set
DEFINE_SECURITY_KPROBE(ptrace_arm64,       "__arm64_sys_ptrace",       CILOCK_SEC_PTRACE)
DEFINE_SECURITY_KPROBE(memfd_create_arm64, "__arm64_sys_memfd_create", CILOCK_SEC_MEMFD_CREATE)
DEFINE_SECURITY_KPROBE(mount_arm64,        "__arm64_sys_mount",        CILOCK_SEC_MOUNT)
DEFINE_SECURITY_KPROBE(mprotect_arm64,     "__arm64_sys_mprotect",     CILOCK_SEC_MPROTECT)
DEFINE_SECURITY_KPROBE(prctl_arm64,        "__arm64_sys_prctl",        CILOCK_SEC_PRCTL)
DEFINE_SECURITY_KPROBE(setsid_arm64,       "__arm64_sys_setsid",       CILOCK_SEC_SETSID)
DEFINE_SECURITY_KPROBE(setns_arm64,        "__arm64_sys_setns",        CILOCK_SEC_SETNS)
DEFINE_SECURITY_KPROBE(init_module_arm64,  "__arm64_sys_init_module",  CILOCK_SEC_INIT_MODULE)
DEFINE_SECURITY_KPROBE(finit_module_arm64, "__arm64_sys_finit_module", CILOCK_SEC_FINIT_MODULE)
DEFINE_SECURITY_KPROBE(clone_arm64,        "__arm64_sys_clone",        CILOCK_SEC_CLONE)
DEFINE_SECURITY_KPROBE(clone3_arm64,       "__arm64_sys_clone3",       CILOCK_SEC_CLONE3)
DEFINE_SECURITY_KPROBE(dup3_arm64,         "__arm64_sys_dup3",         CILOCK_SEC_DUP3)
DEFINE_SECURITY_KPROBE(copy_file_range_arm64, "__arm64_sys_copy_file_range", CILOCK_SEC_COPY_FILE_RANGE)
DEFINE_SECURITY_KPROBE(splice_arm64,       "__arm64_sys_splice",       CILOCK_SEC_SPLICE)
DEFINE_SECURITY_KPROBE(sendfile_arm64,     "__arm64_sys_sendfile",     CILOCK_SEC_SENDFILE)
DEFINE_SECURITY_KPROBE(sendfile64_arm64,   "__arm64_sys_sendfile64",   CILOCK_SEC_SENDFILE)

// x64 set
DEFINE_SECURITY_KPROBE(ptrace_x64,       "__x64_sys_ptrace",       CILOCK_SEC_PTRACE)
DEFINE_SECURITY_KPROBE(memfd_create_x64, "__x64_sys_memfd_create", CILOCK_SEC_MEMFD_CREATE)
DEFINE_SECURITY_KPROBE(mount_x64,        "__x64_sys_mount",        CILOCK_SEC_MOUNT)
DEFINE_SECURITY_KPROBE(mprotect_x64,     "__x64_sys_mprotect",     CILOCK_SEC_MPROTECT)
DEFINE_SECURITY_KPROBE(prctl_x64,        "__x64_sys_prctl",        CILOCK_SEC_PRCTL)
DEFINE_SECURITY_KPROBE(setsid_x64,       "__x64_sys_setsid",       CILOCK_SEC_SETSID)
DEFINE_SECURITY_KPROBE(setns_x64,        "__x64_sys_setns",        CILOCK_SEC_SETNS)
DEFINE_SECURITY_KPROBE(init_module_x64,  "__x64_sys_init_module",  CILOCK_SEC_INIT_MODULE)
DEFINE_SECURITY_KPROBE(finit_module_x64, "__x64_sys_finit_module", CILOCK_SEC_FINIT_MODULE)
DEFINE_SECURITY_KPROBE(clone_x64,        "__x64_sys_clone",        CILOCK_SEC_CLONE)
DEFINE_SECURITY_KPROBE(clone3_x64,       "__x64_sys_clone3",       CILOCK_SEC_CLONE3)
DEFINE_SECURITY_KPROBE(dup2_x64,         "__x64_sys_dup2",         CILOCK_SEC_DUP2)
DEFINE_SECURITY_KPROBE(dup3_x64,         "__x64_sys_dup3",         CILOCK_SEC_DUP3)
DEFINE_SECURITY_KPROBE(copy_file_range_x64, "__x64_sys_copy_file_range", CILOCK_SEC_COPY_FILE_RANGE)
DEFINE_SECURITY_KPROBE(splice_x64,       "__x64_sys_splice",       CILOCK_SEC_SPLICE)
DEFINE_SECURITY_KPROBE(sendfile_x64,     "__x64_sys_sendfile",     CILOCK_SEC_SENDFILE)
DEFINE_SECURITY_KPROBE(sendfile64_x64,   "__x64_sys_sendfile64",   CILOCK_SEC_SENDFILE)

// ───── write / pwrite64 ────────────────────────────────────────────
// write(fd, buf, count) — emit (fd, bytes). High-volume; userspace
// resolves the path via /proc/<pid>/fd/<fd>.

static __always_inline void
emit_write(int fd, __u64 bytes)
{
    // Drop stdio writes (fd 0/1/2) — Go's compile/asm/link spam
    // these and ptrace also reports them, but the volume hurts more
    // here. Keep all other fds for parity.
    if (fd < 0 || fd > 1024 * 1024) return; // sanity

    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    struct write_event ev = {};
    fill_hdr(&ev.hdr, EVT_WRITE, cur_pid, cur_tgid, cur_ppid);
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    ev.fd = fd;
    ev.bytes = bytes;
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

SEC("kprobe/__arm64_sys_write")
int BPF_KPROBE(kprobe_write_arm64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 bytes = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_write(fd, bytes);
    return 0;
}

SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(kprobe_write_x64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 bytes = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_write(fd, bytes);
    return 0;
}

SEC("kprobe/__arm64_sys_pwrite64")
int BPF_KPROBE(kprobe_pwrite_arm64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 bytes = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_write(fd, bytes);
    return 0;
}

SEC("kprobe/__x64_sys_pwrite64")
int BPF_KPROBE(kprobe_pwrite_x64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 bytes = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_write(fd, bytes);
    return 0;
}

// ───── socket / connect / bind ─────────────────────────────────────

static __always_inline void
emit_socket(int family, int type, int protocol)
{
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    struct net_event ev = {};
    fill_hdr(&ev.hdr, EVT_SOCKET, cur_pid, cur_tgid, cur_ppid);
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    ev.fd = -1; // socket() return value is in kretprobe; not captured here
    ev.family = family;
    ev.type = type;
    ev.protocol = protocol;
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

static __always_inline void
emit_connect_or_bind(__u32 evt, int fd, const void *addr_user, __u64 addr_len)
{
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    struct net_event ev = {};
    fill_hdr(&ev.hdr, evt, cur_pid, cur_tgid, cur_ppid);
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    ev.fd = fd;
    if (addr_user && addr_len > 0) {
        __u64 n = addr_len > sizeof(ev.addr) ? sizeof(ev.addr) : addr_len;
        (void)bpf_probe_read_user(ev.addr, n, addr_user);
        // First 2 bytes of sockaddr are sa_family (sa_family_t = u16).
        ev.family = ((__u32)(__u8)ev.addr[0]) | (((__u32)(__u8)ev.addr[1]) << 8);
    }
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

SEC("kprobe/__arm64_sys_socket")
int BPF_KPROBE(kprobe_socket_arm64, struct pt_regs *regs)
{
    int family = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    int type = (int)PT_REGS_PARM2_CORE_SYSCALL(regs);
    int protocol = (int)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_socket(family, type, protocol);
    return 0;
}

SEC("kprobe/__x64_sys_socket")
int BPF_KPROBE(kprobe_socket_x64, struct pt_regs *regs)
{
    int family = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    int type = (int)PT_REGS_PARM2_CORE_SYSCALL(regs);
    int protocol = (int)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_socket(family, type, protocol);
    return 0;
}

SEC("kprobe/__arm64_sys_connect")
int BPF_KPROBE(kprobe_connect_arm64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const void *addr = (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 addr_len = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_connect_or_bind(EVT_CONNECT, fd, addr, addr_len);
    return 0;
}

SEC("kprobe/__x64_sys_connect")
int BPF_KPROBE(kprobe_connect_x64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const void *addr = (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 addr_len = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_connect_or_bind(EVT_CONNECT, fd, addr, addr_len);
    return 0;
}

SEC("kprobe/__arm64_sys_bind")
int BPF_KPROBE(kprobe_bind_arm64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const void *addr = (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 addr_len = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_connect_or_bind(EVT_BIND, fd, addr, addr_len);
    return 0;
}

SEC("kprobe/__x64_sys_bind")
int BPF_KPROBE(kprobe_bind_x64, struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const void *addr = (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 addr_len = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_connect_or_bind(EVT_BIND, fd, addr, addr_len);
    return 0;
}

// ───── read / pread64 — read-tap for race-free hashing ─────────────
// V1.4: capture bytes the kernel copied to the tracee, so userspace
// can hash content without re-reading the file (which races against
// concurrent writers).
//
// Design: kprobe at syscall entry stashes (fd, user_buf, count).
// kretprobe at syscall exit copies up to READ_CHUNK_BYTES from the
// user buffer via bpf_probe_read_user — at that moment the tracee
// thread is still in kernel context, so it cannot race itself.
//
// Threat model: tamper-proof against the calling thread (blocked
// in kernel) and external processes (cannot reach the tracee VM).
// NOT tamper-proof against sibling threads of the tracee that share
// the address space and could overwrite the buffer between kernel
// copy_to_user and our bpf_probe_read_user. For CI workloads
// (compilers, linkers) this is acceptable. The fully-tamper-proof
// path needs a kernel hook on the copy primitives, all of which
// were inlined/notrace on Linux 6.8 as of 2026-05-23.

static __always_inline bool
read_tap_on(void)
{
    __u32 z = 0;
    __u8 *enabled = bpf_map_lookup_elem(&read_tap_enabled, &z);
    return enabled && *enabled == 1;
}

static __always_inline void
stash_read(int fd, __u64 buf, __u64 count)
{
    if (!read_tap_on()) return;
    if (fd < 0) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;
    __u64 key = bpf_get_current_pid_tgid();
    struct read_stash s = {
        .user_buf = buf,
        .count    = count,
        .fd       = fd,
    };
    bpf_map_update_elem(&read_stash_map, &key, &s, BPF_ANY);
}

// MAX_READ_CHUNKS bounds the per-syscall chunk count for verifier
// loop-bound safety. 8 * READ_CHUNK_BYTES = 128 KB per syscall.
// `cat` issues 64 KB reads, gcc/Go typically <= 32 KB; this covers
// real-world build workloads. Reads > 128 KB get truncated with a
// last-chunk marker (chunk_len < requested) so userspace knows.
#define MAX_READ_CHUNKS 8

static __always_inline void
emit_read_chunk(long ret)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct read_stash *s = bpf_map_lookup_elem(&read_stash_map, &key);
    if (!s) return;
    if (ret <= 0) goto done;

    // Filter was checked at kprobe entry — the same task is
    // returning to user mode now, so we can re-derive (pid, tgid,
    // ppid) from current without re-running the 3-hash-lookup
    // emit_filter(). Saves ~150ns per syscall.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 cur_pid  = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 cur_tgid = (__u32)(pid_tgid >> 32);
    __u32 cur_ppid = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *p = BPF_CORE_READ(task, real_parent);
        if (p) cur_ppid = BPF_CORE_READ(p, tgid);
    }

    __u64 want_total = (__u64)ret;
    __u64 done_bytes = 0;
    __u32 seq = 0;

    // Cache comm once per syscall — same value across all chunks.
    char comm_cache[TASK_COMM_LEN];
    bpf_get_current_comm(comm_cache, sizeof(comm_cache));

    // Reserve directly in the ringbuf — zero-copy from user buffer
    // to ringbuf memory. Saves one 16KB memcpy vs the older
    // bpf_ringbuf_output (which copies from local scratch). Each
    // chunk is its own ringbuf record; we just call reserve N times.
    #pragma unroll
    for (int i = 0; i < MAX_READ_CHUNKS; i++) {
        if (done_bytes >= want_total) break;
        __u64 remaining = want_total - done_bytes;
        __u32 n = (remaining > (__u64)READ_CHUNK_BYTES)
                  ? (__u32)READ_CHUNK_BYTES
                  : (__u32)remaining;
        if (n == 0 || n > READ_CHUNK_BYTES) break;

        struct read_chunk_event *ev =
            bpf_ringbuf_reserve(&read_tap_events, sizeof(*ev), 0);
        if (!ev) {
            bump_drop(DROP_BUCKET_READTAP);
            break; // read-tap ringbuf full; partial digest in userspace.
                   // `events` ringbuf is unaffected — classification stays intact.
        }

        fill_hdr(&ev->hdr, EVT_READ_CHUNK, cur_pid, cur_tgid, cur_ppid);
        __builtin_memcpy(ev->comm, comm_cache, TASK_COMM_LEN);
        ev->fd        = s->fd;
        ev->seq       = seq;
        ev->chunk_len = n;
        ev->_pad      = 0;

        // Direct user→ringbuf copy. No intermediate buffer.
        long rc = bpf_probe_read_user(ev->data, n,
            (const void *)(s->user_buf + done_bytes));
        if (rc < 0) {
            // Failed read — discard rather than submit garbage.
            // bump a drop so userspace knows attestation has gaps.
            bpf_ringbuf_discard(ev, 0);
            bump_drop(DROP_BUCKET_READTAP);
            break;
        }
        bpf_ringbuf_submit(ev, 0);

        done_bytes += n;
        seq++;
    }

done:
    bpf_map_delete_elem(&read_stash_map, &key);
}

SEC("kprobe/__arm64_sys_read")
int BPF_KPROBE(kprobe_read_arm64, struct pt_regs *regs)
{
    int fd      = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 buf   = (__u64)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 count = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    stash_read(fd, buf, count);
    return 0;
}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(kprobe_read_x64, struct pt_regs *regs)
{
    int fd      = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 buf   = (__u64)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 count = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    stash_read(fd, buf, count);
    return 0;
}

SEC("kretprobe/__arm64_sys_read")
int BPF_KRETPROBE(kretprobe_read_arm64, long ret)
{
    emit_read_chunk(ret);
    return 0;
}

SEC("kretprobe/__x64_sys_read")
int BPF_KRETPROBE(kretprobe_read_x64, long ret)
{
    emit_read_chunk(ret);
    return 0;
}

SEC("kprobe/__arm64_sys_pread64")
int BPF_KPROBE(kprobe_pread64_arm64, struct pt_regs *regs)
{
    int fd      = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 buf   = (__u64)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 count = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    stash_read(fd, buf, count);
    return 0;
}

SEC("kprobe/__x64_sys_pread64")
int BPF_KPROBE(kprobe_pread64_x64, struct pt_regs *regs)
{
    int fd      = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    __u64 buf   = (__u64)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 count = (__u64)PT_REGS_PARM3_CORE_SYSCALL(regs);
    stash_read(fd, buf, count);
    return 0;
}

SEC("kretprobe/__arm64_sys_pread64")
int BPF_KRETPROBE(kretprobe_pread64_arm64, long ret)
{
    emit_read_chunk(ret);
    return 0;
}

SEC("kretprobe/__x64_sys_pread64")
int BPF_KRETPROBE(kretprobe_pread64_x64, long ret)
{
    emit_read_chunk(ret);
    return 0;
}

// ───── close — finalize per-(pid, fd) hash on userspace side ──────
// Kprobe at entry, fd still valid. Signals userspace to finalize
// the running SHA-256 for (pid, fd) and persist the digest.
// Userspace skips emission if the read_tap never saw any bytes
// for this fd — pure-write fds don't generate spurious entries.

static __always_inline void
emit_close(int fd)
{
    if (!read_tap_on()) return;
    if (fd < 0) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    struct close_event ev = {};
    fill_hdr(&ev.hdr, EVT_CLOSE, cur_pid, cur_tgid, cur_ppid);
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    ev.fd = fd;

    // V2 Phase 8 stage 2: pull path + size_at_open from the
    // kernel-side fd_table. The matching openat kretprobe populated
    // it; we copy out then drop. If no entry (close on an inherited
    // fd, or LRU-evicted), path_len stays 0 and userspace falls
    // back to its in-flight state.
    struct fd_entry *e = fd_table_take(fd);
    if (e) {
        ev.path_len = e->path_len;
        ev.size_at_open = e->size_at_open;
        if (e->path_len <= CLOSE_PATH_LEN) {
            __builtin_memcpy(ev.path, e->path, CLOSE_PATH_LEN);
        }
    }

    if (bpf_ringbuf_output(&events, &ev, sizeof(ev), 0) < 0)
        bump_drop(DROP_BUCKET_READTAP);

    if (e) fd_table_drop(fd);
}

SEC("kprobe/__arm64_sys_close")
int BPF_KPROBE(kprobe_close_arm64, struct pt_regs *regs)
{
    emit_close((int)PT_REGS_PARM1_CORE_SYSCALL(regs));
    return 0;
}

SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(kprobe_close_x64, struct pt_regs *regs)
{
    emit_close((int)PT_REGS_PARM1_CORE_SYSCALL(regs));
    return 0;
}

// ───── kprobe/wake_up_new_task — canonical fork hook ────────────
//
// Tetragon-pattern primary fork-watch (V2 Phase 8). Hooked at the
// kernel function that wakes a freshly-cloned task for the first
// time. By the time wake_up_new_task runs:
//   - The child task_struct is fully initialized (pid, tgid, mm, fs)
//   - The child has NOT yet executed its first instruction
//   - We're in the parent's kernel context (bpf_get_current_*
//     returns the parent)
//
// This is the canonical fork hook used by Tetragon (cilium/tetragon
// `bpf_fork.c`). It's strictly better than raw_tp/sched_process_fork
// for our use because:
//   1. Fires LATER in the fork sequence, when the child's data is
//      stable (vs raw_tp which fires earlier with partial init)
//   2. No kretprobe slot pressure (unlike __x64_sys_clone kretprobe)
//   3. Single hook covers fork, vfork, clone, clone3 — they all
//      route through wake_up_new_task
//
// We KEEP raw_tp/sched_process_fork (below) as a fallback on
// kernels where wake_up_new_task isn't kprobeable. The kprobe is
// the primary; raw_tp is the safety net.

// V2 Phase 8 stage 4: fentry/security_file_open + bpf_d_path. The
// security_file_open hook fires inside the kernel's open path with
// a fully-resolved struct file *. bpf_d_path on file->f_path returns
// the kernel-canonical absolute path — no userspace cwd resolution
// needed, no /proc readlinks, no fast-fork-and-exit cascade race.
//
// Behavior: when the fentry probe attaches, every emit_filter-passing
// open writes the absolute path into a per-task stash keyed by
// (task, file*). The openat kretprobe (which still owns fd discovery)
// looks up the stash and uses the bpf_d_path path INSTEAD of the
// raw bpf_probe_read_user_str path. If fentry doesn't attach (older
// kernel, missing BTF, bpf_d_path not allowlisted on this kernel's
// security_file_open), we fall back to the user-provided pathname
// + userspace cwd resolution as before.

SEC("fentry/security_file_open")
int BPF_PROG(fentry_security_file_open, struct file *file)
{
    if (!file) return 0;

    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&filter_enabled, &zero);
    if (!enabled || *enabled == 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 cur_pid  = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 cur_tgid = (__u32)(pid_tgid >> 32);
    if (!task_is_watched(cur_pid, cur_tgid)) return 0;

    struct dpath_value *v = bpf_map_lookup_elem(&dpath_scratch, &zero);
    if (!v) return 0;
    __builtin_memset(v, 0, sizeof(*v));

    long n = bpf_d_path(&file->f_path, v->path, CLOSE_PATH_LEN);
    if (n <= 0 || n > CLOSE_PATH_LEN) return 0;
    v->path_len = (__u32)n;

    struct dpath_key k = {
        .task = (__u64)bpf_get_current_task_btf(),
        .file = (__u64)file,
    };
    bpf_map_update_elem(&d_path_stash, &k, v, BPF_ANY);
    return 0;
}

// V2 Phase 8 stage 3: fentry/wake_up_new_task. Same semantics as the
// kprobe below, but fentry args are BTF-typed trusted pointers — so
// we can pass the child task_struct directly to bpf_task_storage_get
// and set the watched-bit on the child's per-task storage AT FORK
// TIME (eliminates the lazy-promotion-on-first-syscall hop).
//
// Userspace prefers this program over the kprobe (attaches fentry
// first; falls back to kprobe on kernels without CONFIG_FENTRY or
// when the BTF info for wake_up_new_task isn't available). Only one
// is attached at a time — both firing would double-write.
SEC("fentry/wake_up_new_task")
int BPF_PROG(fentry_wake_up_new_task, struct task_struct *p)
{
    if (!p) return 0;

    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&filter_enabled, &zero);
    if (!enabled || *enabled == 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid  = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 parent_tgid = (__u32)(pid_tgid >> 32);

    __u32 child_pid  = BPF_CORE_READ(p, pid);
    __u32 child_tgid = BPF_CORE_READ(p, tgid);
    if (child_pid == 0) return 0;

    int parent_watched = 0;
    {
        struct task_state *pts = bpf_task_storage_get(&task_storage,
            bpf_get_current_task_btf(), NULL, 0);
        if (pts && pts->watched) parent_watched = 1;
    }
    if (!parent_watched) {
        if (bpf_map_lookup_elem(&watched_pids, &parent_pid) ||
            bpf_map_lookup_elem(&watched_pids, &parent_tgid)) {
            parent_watched = 1;
        } else {
            __u32 *root = bpf_map_lookup_elem(&root_parent_tgid, &zero);
            if (root && parent_tgid == *root && *root != 0) {
                parent_watched = 1;
            }
        }
    }
    if (!parent_watched) return 0;

    // fentry advantage: p is a trusted BTF pointer (verified by the
    // kernel from the function's BTF), so bpf_task_storage_get
    // accepts it directly. Set the child's watched-bit kernel-side
    // — no lazy promotion needed; the child's first syscall hits
    // task_storage immediately.
    struct task_state init = {.watched = 1};
    bpf_task_storage_get(&task_storage, p, &init,
        BPF_LOCAL_STORAGE_GET_F_CREATE);

    // Also maintain watched_pids for the other fork hooks (raw_tp,
    // clone-kretprobes) that still consult it. Removable once those
    // also migrate or are dropped.
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &one, BPF_ANY);
    if (child_pid != child_tgid) {
        bpf_map_update_elem(&watched_pids, &child_tgid, &one, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(kprobe_wake_up_new_task, struct task_struct *p)
{
    if (!p) return 0;

    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&filter_enabled, &zero);
    if (!enabled || *enabled == 0) return 0;

    // bpf_get_current_pid_tgid returns the PARENT's pid+tgid because
    // wake_up_new_task runs in the parent's kernel context.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid  = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 parent_tgid = (__u32)(pid_tgid >> 32);

    __u32 child_pid  = BPF_CORE_READ(p, pid);
    __u32 child_tgid = BPF_CORE_READ(p, tgid);
    if (child_pid == 0) return 0;

    // Match parent in watched set. Check parent's task_storage first
    // (canonical fast path — current=parent in this hook), fall back
    // to watched_pids (bootstrap channel until stage 2).
    int parent_watched = 0;
    {
        struct task_state *pts = bpf_task_storage_get(&task_storage,
            bpf_get_current_task_btf(), NULL, 0);
        if (pts && pts->watched) parent_watched = 1;
    }
    if (!parent_watched) {
        if (bpf_map_lookup_elem(&watched_pids, &parent_pid) ||
            bpf_map_lookup_elem(&watched_pids, &parent_tgid)) {
            parent_watched = 1;
        } else {
            __u32 *root = bpf_map_lookup_elem(&root_parent_tgid, &zero);
            if (root && parent_tgid == *root && *root != 0) {
                parent_watched = 1;
            }
        }
    }
    if (!parent_watched) return 0;

    // Mark child via watched_pids only. The child's task_storage is
    // populated LAZILY by emit_filter's descent path on the child's
    // first syscall — `p` is a kprobe argument (untrusted pointer)
    // and bpf_task_storage_get rejects it; we'd need fentry for
    // direct child task_storage access. Lazy propagation costs one
    // extra map lookup on the child's first syscall, then constant
    // time after that.
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &one, BPF_ANY);
    if (child_pid != child_tgid) {
        bpf_map_update_elem(&watched_pids, &child_tgid, &one, BPF_ANY);
    }
    return 0;
}

// ───── raw_tp/sched_process_fork — fallback (early child-pid registration) ──
//
// The watched_pids set is the gate: kprobes only emit events for
// pids in this set. Until now we relied on the "first openat from
// the child fires emit_filter, which sees its parent in watched
// and auto-adds the child" mechanism. That has a race: a child
// process that exec's a fast-exit tool (gcc → cc1 → as → ld) can
// open and close files in MICROSECONDS. If the kernel-side ringbuf
// drains slowly, by the time userspace processes those events the
// process has exited; worse, the FIRST openat may have been dropped
// because the child's pid wasn't yet in watched.
//
// V1 hooked the trace event via `tracepoint/sched/sched_process_fork`
// with a hand-rolled args struct. Field offsets in that struct went
// stale on some 5.x+ kernels (the `tgid` companion fields were
// added/reordered), so `child_pid` would silently read partial
// garbage and the propagation would no-op. The fix is to switch to
// the raw tracepoint: args are the kernel `task_struct *` pointers
// themselves, and we read `tgid`/`pid` via BPF_CORE_READ — relocated
// by libbpf against the host BTF.
//
// Belt + braces: the clone-family kretprobes below give a second
// signal in case raw_tp ever misses (e.g., on a host without
// BPF_PROG_TYPE_RAW_TRACEPOINT support).

SEC("raw_tracepoint/sched_process_fork")
int raw_tp_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child  = (struct task_struct *)ctx->args[1];
    if (!parent || !child) return 0;

    __u32 parent_pid  = BPF_CORE_READ(parent, pid);
    __u32 parent_tgid = BPF_CORE_READ(parent, tgid);
    __u32 child_pid   = BPF_CORE_READ(child, pid);
    __u32 child_tgid  = BPF_CORE_READ(child, tgid);

    // Match by either pid (LWP, what emit_filter writes) or tgid
    // (process leader, what the userspace bootstrap registers).
    if (!bpf_map_lookup_elem(&watched_pids, &parent_pid) &&
        !bpf_map_lookup_elem(&watched_pids, &parent_tgid)) {
        return 0;
    }

    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &one, BPF_ANY);
    if (child_pid != child_tgid)
        bpf_map_update_elem(&watched_pids, &child_tgid, &one, BPF_ANY);
    return 0;
}

// ───── clone-family kretprobes — defense-in-depth fork watch ─────
//
// Defense in depth alongside raw_tp/sched_process_fork. raw_tp is the
// canonical primary hook (per Tetragon/Trail of Bits research), but
// empirically — on Linux 6.8 / aarch64 / colima — removing these
// kretprobes regressed the ForkChain test pass rate from ~80% to ~50%.
// They ARE providing real redundancy.
//
// Scale risk: kernel default kretprobe pool is 4096 slots. Under
// hyper-forking workloads (kernel compile, parallel cargo) the pool
// can exhaust and kretprobes silently miss. We mitigate by setting
// `KprobeOptions.RetprobeMaxActive=65536` at attach time in the
// userspace consumer (see openat_consumer.go).
//
// Each kretprobe runs in the parent task context — bpf_get_current_pid_tgid()
// yields the parent's (pid, tgid). The return value is the child's pid.

static __always_inline void
emit_fork_ret(long ret)
{
    if (ret <= 0) return;

    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&filter_enabled, &zero);
    if (!enabled || *enabled == 0) return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 cur_pid  = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 cur_tgid = (__u32)(pid_tgid >> 32);

    if (!bpf_map_lookup_elem(&watched_pids, &cur_pid) &&
        !bpf_map_lookup_elem(&watched_pids, &cur_tgid)) {
        return;
    }

    __u32 child_pid = (__u32)ret;
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &one, BPF_ANY);
}

SEC("kretprobe/__x64_sys_clone")
int BPF_KRETPROBE(kretprobe_clone_x64, long ret)
{
    emit_fork_ret(ret);
    return 0;
}

SEC("kretprobe/__x64_sys_clone3")
int BPF_KRETPROBE(kretprobe_clone3_x64, long ret)
{
    emit_fork_ret(ret);
    return 0;
}

SEC("kretprobe/__x64_sys_vfork")
int BPF_KRETPROBE(kretprobe_vfork_x64, long ret)
{
    emit_fork_ret(ret);
    return 0;
}

SEC("kretprobe/__x64_sys_fork")
int BPF_KRETPROBE(kretprobe_fork_x64, long ret)
{
    emit_fork_ret(ret);
    return 0;
}

SEC("kretprobe/__arm64_sys_clone")
int BPF_KRETPROBE(kretprobe_clone_arm64, long ret)
{
    emit_fork_ret(ret);
    return 0;
}

SEC("kretprobe/__arm64_sys_clone3")
int BPF_KRETPROBE(kretprobe_clone3_arm64, long ret)
{
    emit_fork_ret(ret);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
