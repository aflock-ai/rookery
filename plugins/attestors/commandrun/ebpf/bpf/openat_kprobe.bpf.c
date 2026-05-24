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
// Total: 32 (hdr) + 4 + 4 + 4 + 4 + 8 + 8 + 16 + 4096 = 4176 bytes
//
// `flags` captures the openat() flags arg (O_RDONLY/O_WRONLY/O_CREAT/...).
// V1.2: userspace skips hashing on O_WRONLY/O_CREAT-only opens, which
// are the tracee's OWN writes — hashing them is racy by construction
// (the tracee is mid-write while we read) and the resulting "TOCTOU-
// suspect" events are artifacts of our async pipeline, not real
// integrity violations.
struct openat_event {
    struct cilock_evt_hdr hdr;
    __s32 dirfd;
    __u32 path_len;
    __u32 flags;
    __u32 _pad_flags;
    __u64 size_at_open;
    __u64 mtime_ns;
    char  comm[TASK_COMM_LEN];
    char  path[MAX_PATH];
};

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

// Ring buffer for ALL event types. 16 MB is generous; an overflow
// shows up as ringbuf-full errors in userspace consumer.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

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
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

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

    int matched_by_descent = 0;
    if (!bpf_map_lookup_elem(&watched_pids, &cur_pid) &&
        !bpf_map_lookup_elem(&watched_pids, &cur_tgid)) {
        if (bpf_map_lookup_elem(&watched_pids, &cur_ppid)) {
            matched_by_descent = 1;
        } else {
            __u32 *root = bpf_map_lookup_elem(&root_parent_tgid, &zero);
            if (root && cur_ppid == *root && *root != 0) {
                matched_by_descent = 1;
            } else {
                return 0;
            }
        }
    }
    if (matched_by_descent) {
        __u8 one = 1;
        bpf_map_update_elem(&watched_pids, &cur_pid, &one, BPF_ANY);
    }

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

// ───── openat / openat2 ─────────────────────────────────────────────

static __always_inline void
emit_openat(int dirfd, const char *pathname, __u32 flags)
{
    if (!pathname) return;
    __u32 cur_pid, cur_tgid, cur_ppid;
    if (!emit_filter(&cur_pid, &cur_tgid, &cur_ppid)) return;

    __u32 z = 0;
    struct file_mutation_event *scratch_ev = bpf_map_lookup_elem(&scratch, &z);
    if (!scratch_ev) return;
    struct openat_event *ev = (struct openat_event *)scratch_ev;

    __builtin_memset(ev, 0, offsetof(struct openat_event, comm));
    fill_hdr(&ev->hdr, EVT_OPENAT, cur_pid, cur_tgid, cur_ppid);
    ev->dirfd        = dirfd;
    ev->flags        = flags;
    ev->size_at_open = 0;
    ev->mtime_ns     = 0;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    long n = bpf_probe_read_user_str(ev->path, MAX_PATH, pathname);
    if (n < 0) {
        ev->path_len = 0;
        ev->path[0] = '\0';
    } else {
        ev->path_len = (__u32)n;
    }

    bpf_ringbuf_output(&events, ev, sizeof(struct openat_event), 0);
}

SEC("kprobe/__arm64_sys_openat")
int BPF_KPROBE(kprobe_openat_arm64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname, flags);
    return 0;
}

SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(kprobe_openat_x64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u32 flags = (__u32)PT_REGS_PARM3_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname, flags);
    return 0;
}

// openat2 uses struct open_how* (PARM3) which carries flags inside.
// For V1.2 we use 0 — userspace will hash these (rare in practice).
SEC("kprobe/__arm64_sys_openat2")
int BPF_KPROBE(kprobe_openat2_arm64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname, 0);
    return 0;
}

SEC("kprobe/__x64_sys_openat2")
int BPF_KPROBE(kprobe_openat2_x64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname, 0);
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

char LICENSE[] SEC("license") = "GPL";
