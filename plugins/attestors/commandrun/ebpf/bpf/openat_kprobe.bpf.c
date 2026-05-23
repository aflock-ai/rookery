// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Rookery Contributors
//
// eBPF kprobe on openat-family syscalls for cilock's TOCTOU-detecting
// tracer (#167). The program captures:
//
//   - PID + parent PID + comm of the calling tracee
//   - Pathname (best-effort, MAX_PATH bytes)
//   - Stat-at-open snapshot (size + mtime) for TOCTOU detection in
//     userspace
//
// Events flow through a BPF ring buffer to the cilock userspace agent,
// which then opens + hashes the file and compares its current stat
// against the snapshot captured here. Mismatch == TOCTOU-suspect.
//
// This is V1 — kprobe on the syscall entry. The stat-at-open lookup
// is racy with the tracee in principle, but happens in the kernel
// before openat resolves, so it captures the inode the tracee will see.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH 4096
#define TASK_COMM_LEN 16

// One event per openat-class syscall observed.
struct openat_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __s32 dirfd;
    __u32 path_len;     // bytes of `path` that are valid (NUL-terminated)
    __u64 size_at_open; // 0 if stat failed
    __u64 mtime_ns;     // 0 if stat failed
    char  comm[TASK_COMM_LEN];
    char  path[MAX_PATH];
};

// Ring buffer for events back to userspace. 16 MB is generous; if
// userspace falls behind we'd see ringbuf-full errors which the
// userspace consumer logs.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

// Scratch storage for the path buffer — kept off the kprobe stack
// because MAX_PATH=4096 exceeds the 512-byte BPF stack limit.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct openat_event);
} scratch SEC(".maps");

// Common emit function. dirfd of -100 (AT_FDCWD) means cwd-relative.
static __always_inline void
emit_openat(int dirfd, const char *pathname)
{
    if (!pathname)
        return;

    __u32 z = 0;
    struct openat_event *ev = bpf_map_lookup_elem(&scratch, &z);
    if (!ev)
        return;

    // Zero only the fixed-size header, NOT the path buffer (saves
    // ~4KB memset per event).
    __builtin_memset(ev, 0, offsetof(struct openat_event, comm));

    ev->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid  = (__u32)(pid_tgid & 0xffffffff);
    ev->tgid = (__u32)(pid_tgid >> 32);
    ev->dirfd = dirfd;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    if (t) {
        struct task_struct *parent = BPF_CORE_READ(t, real_parent);
        if (parent)
            ev->ppid = BPF_CORE_READ(parent, tgid);
    }

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    // Copy the path from the tracee's userspace memory. May fail
    // partial; ev->path_len records what we got.
    long n = bpf_probe_read_user_str(ev->path, MAX_PATH, pathname);
    if (n < 0) {
        ev->path_len = 0;
        ev->path[0] = '\0';
    } else {
        ev->path_len = (__u32)n;
    }

    // Submit. ringbuf_output copies the event into the ring buffer.
    bpf_ringbuf_output(&events, ev, sizeof(*ev), 0);
}

// openat(int dirfd, const char *pathname, int flags, ...)
SEC("kprobe/__arm64_sys_openat")
int BPF_KPROBE(kprobe_openat_arm64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname);
    return 0;
}

SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(kprobe_openat_x64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname);
    return 0;
}

// openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
SEC("kprobe/__arm64_sys_openat2")
int BPF_KPROBE(kprobe_openat2_arm64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname);
    return 0;
}

SEC("kprobe/__x64_sys_openat2")
int BPF_KPROBE(kprobe_openat2_x64, struct pt_regs *regs)
{
    int dirfd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
    const char *pathname = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    emit_openat(dirfd, pathname);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
