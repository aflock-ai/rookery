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

// V2 Phase 3: weakness-pinning unit tests.
//
// Each test in this file pins a specific pathology surfaced during
// cross-language testing. The intent: if a future change reopens any
// of these weaknesses, the test breaks immediately.
//
// Design rule: tracee programs are written in C (not shell, not Go)
// and compiled at test time. Shell-driven tracees are unreliable
// because bash can exec-replace instead of fork — pid counts and
// syscall sequences vary across libc/bash versions. With a small C
// program we issue the exact syscalls we want and can write exact
// assertions.
//
// Run with:
//   sudo -E env "PATH=$PATH" go test -run TestWeakness_ -v -count=1 \
//       ./plugins/attestors/commandrun

package commandrun

import (
	"crypto"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// forkChainCSource: each invocation forks itself once, waits, and
// (at the leaf) opens the sentinel file. We use fork() (which glibc
// implements via clone()) at every level so this exercises the
// raw_tp/sched_process_fork tracepoint AND the kretprobe/__x64_sys_clone
// fallback path added in V2 Phase 1.
//
// Argv: <self> <depth> <sentinel-path>
// Depth N → re-execs N-1 times → N+1 distinct pids end-to-end.
// At depth==0 the leaf opens(sentinel, O_RDONLY) and reads it.
const forkChainCSource = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <depth> <sentinel-path>\n", argv[0]);
        return 2;
    }
    int depth = atoi(argv[1]);
    const char *target = argv[2];

    fprintf(stderr, "FCHAIN pid=%d ppid=%d depth=%d\n",
            getpid(), getppid(), depth);

    if (depth == 0) {
        // Leaf: open the sentinel. This is the syscall whose
        // capture proves watched-ness reached the deepest descendant.
        int fd = open(target, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "open(%s) failed: %s\n", target, strerror(errno));
            return 3;
        }
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf));
        (void)n;
        close(fd);
        return 0;
    }

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        return 5;
    }
    if (child == 0) {
        char dbuf[16];
        snprintf(dbuf, sizeof(dbuf), "%d", depth - 1);
        execl(argv[0], argv[0], dbuf, target, (char *)NULL);
        fprintf(stderr, "exec failed: %s\n", strerror(errno));
        _exit(99);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
        return 6;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child exited badly: %d\n", status);
        return 7;
    }
    return 0;
}
`

// compileC writes the source into srcDir, compiles it with the host
// cc, returns the resulting binary path. Skips the test if cc is
// unavailable on this host.
func compileC(t *testing.T, srcDir, name, source string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("cc not available: %v", err)
	}
	srcPath := filepath.Join(srcDir, name+".c")
	binPath := filepath.Join(srcDir, name)
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		t.Fatalf("write %s.c: %v", name, err)
	}
	cmd := exec.Command(cc, "-O0", "-Wall", "-Werror", "-o", binPath, srcPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile %s.c: %v\n%s", name, err, out)
	}
	return binPath
}

// TestWeakness_ForkChain_DeepWatchPropagation pins V2 Phase 1's fix.
//
// A 4-deep fork-and-exec chain ends in an open() of a known sentinel
// file. Before Phase 1, the openat-PPID-bootstrap path was the only
// mechanism propagating watched-ness, and it raced fast-exiting
// process chains (gcc → collect2 → ld). The leaf's openat could miss
// the watched_pids gate and be silently dropped.
//
// Phase 1 added raw_tp/sched_process_fork (BTF-aware, replaces a
// hand-rolled struct that went stale on 5.x+ kernels) PLUS
// clone/clone3/vfork/fork kretprobes as defense-in-depth. Either
// signal alone is sufficient; together they are unmissable.
//
// Assertions:
//  1. The leaf's openat was captured AND its digest matches the
//     known file content (no fallback-to-zero on missed events).
//  2. At least depth+1 distinct pids appear in Processes[] —
//     evidence that EVERY level of the chain was observed.
//  3. The sentinel content digest in the leaf's OpenedFiles equals
//     the SHA-256 we computed from the bytes we wrote.
func TestWeakness_ForkChain_DeepWatchPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	bin := compileC(t, dir, "fork_chain", forkChainCSource)

	sentinel := filepath.Join(dir, "sentinel.bin")
	content := []byte("v2-phase1-deep-fork-chain-witness\n")
	if err := os.WriteFile(sentinel, content, 0o600); err != nil {
		t.Fatal(err)
	}

	// depth=4 → 5 pids: bin (depth=4) → bin (depth=3) → bin (depth=2)
	// → bin (depth=1) → bin (depth=0, opens sentinel)
	const depth = 4
	procs := runUnderEBPF(t, []string{bin, fmt.Sprintf("%d", depth), sentinel})

	// (1) Find the leaf — the process whose OpenedFiles holds the sentinel.
	var leaf *ProcessInfo
	for i := range procs {
		if _, ok := procs[i].OpenedFiles[sentinel]; ok {
			leaf = &procs[i]
			break
		}
	}
	if leaf == nil {
		// Pull Summary off the CommandRun if accessible. We're in the
		// test that uses runUnderEBPF which only returns Processes
		// — let's also surface drop counters via a separate dispatch.
		t.Fatalf("deep-fork-chain leaf openat MISSED — V2 Phase 1 regression.\n"+
			"Got %d processes; tree:\n%s",
			len(procs), summarizeProcessTree(procs))
	}

	// (3) Verify the digest content matches.
	gotDigest := leaf.OpenedFiles[sentinel]
	if gotDigest == nil {
		t.Fatalf("leaf openat captured (pid=%d) but digest is nil — fallback path broke", leaf.ProcessID)
	}
	wantDigest, err := cryptoutil.CalculateDigestSetFromBytes(content, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	for hashType, want := range wantDigest {
		got, ok := gotDigest[hashType]
		if !ok {
			t.Errorf("expected hash type %v missing from capture", hashType)
			continue
		}
		if got != want {
			t.Errorf("sentinel digest mismatch for %v: got %s want %s", hashType, got, want)
		}
	}

	// (2) Count distinct pids. Each fork creates a new pid; we expect
	// at least depth+1. Allow some slack — the wrapper process and
	// some libc-internal helpers may also appear.
	uniquePids := make(map[int]struct{})
	for _, p := range procs {
		uniquePids[p.ProcessID] = struct{}{}
	}
	if len(uniquePids) < depth+1 {
		t.Errorf("fork-chain depth=%d should produce ≥%d pids; got %d.\n"+
			"Suggests watched-ness propagation broke mid-chain.\n%s",
			depth, depth+1, len(uniquePids),
			summarizeProcessTree(procs))
	}

	t.Logf("captured leaf pid=%d ppid=%d; tree=%d pids", leaf.ProcessID, leaf.ParentPID, len(uniquePids))
}

// ═══════════════════════════════════════════════════════════════════
// Adversarial tracee programs. These bypass libc, issue raw syscalls,
// or exercise specifically attacker-like behavior. The point isn't to
// test the happy path — it's to confirm the kernel-boundary kprobes
// catch syscalls regardless of how the caller got there.
// ═══════════════════════════════════════════════════════════════════

// directSyscallCSource issues `openat` and `read` via inline assembly
// — no libc syscall wrapper, no glibc's __syscall_cancel helper. An
// attacker writes raw `svc #0` (aarch64) or `syscall` (x86_64) to
// bypass any LD_PRELOAD'd libc-level interception. Our kprobes are at
// the kernel syscall entry, so they MUST still fire — confirming the
// trace boundary is the kernel, not libc.
//
// Argv: <self> <sentinel-path>
//
// The program issues:
//   1. openat(AT_FDCWD, sentinel-path, O_RDONLY)  via raw syscall
//   2. read(fd, buf, 4096)                        via raw syscall
//   3. close(fd)                                  via raw syscall
//   4. exit_group(0)                              via raw syscall
//
// No libc functions called between main() and exit. printf/puts only
// used for failure logging via the libc startup-time-loaded helpers,
// guaranteed not to be in any syscall path we depend on.
const directSyscallCSource = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define AT_FDCWD_VAL -100

#if defined(__aarch64__)
// aarch64 syscall numbers (per unistd.h): openat=56, read=63,
// close=57, exit_group=94.
static long sys_openat_raw(int dirfd, const char *path, int flags) {
    register long x0 asm("x0") = (long)dirfd;
    register long x1 asm("x1") = (long)(void *)path;
    register long x2 asm("x2") = (long)flags;
    register long x8 asm("x8") = 56;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}
static long sys_read_raw(int fd, void *buf, long count) {
    register long x0 asm("x0") = (long)fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = (long)count;
    register long x8 asm("x8") = 63;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}
static long sys_close_raw(int fd) {
    register long x0 asm("x0") = (long)fd;
    register long x8 asm("x8") = 57;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}
#elif defined(__x86_64__)
// x86_64 syscall numbers: openat=257, read=0, close=3, exit_group=231.
static long sys_openat_raw(int dirfd, const char *path, int flags) {
    long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(257L), "D"((long)dirfd), "S"((long)(void *)path), "d"((long)flags)
        : "rcx", "r11", "memory"
    );
    return ret;
}
static long sys_read_raw(int fd, void *buf, long count) {
    long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(0L), "D"((long)fd), "S"((long)buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}
static long sys_close_raw(int fd) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "0"(3L), "D"((long)fd) : "rcx", "r11", "memory");
    return ret;
}
#else
#error "unsupported arch — add raw syscall stubs for this CPU"
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <sentinel>\n", argv[0]);
        return 2;
    }
    long fd = sys_openat_raw(AT_FDCWD_VAL, argv[1], 0 /* O_RDONLY */);
    if (fd < 0) {
        fprintf(stderr, "raw openat failed: %ld\n", fd);
        return 3;
    }
    char buf[4096];
    long n = sys_read_raw((int)fd, buf, sizeof(buf));
    if (n < 0) {
        fprintf(stderr, "raw read failed: %ld\n", n);
        return 4;
    }
    sys_close_raw((int)fd);
    fprintf(stderr, "ADVERSARIAL pid=%d read %ld bytes\n", (int)getpid(), n);
    return 0;
}
`

// TestWeakness_DirectSyscall_Bypass confirms the trace catches openat
// even when issued via inline assembly — proving the kprobe is at the
// kernel boundary, not at libc. An LD_PRELOAD-style userspace hook
// (or a stripped-down attacker payload with no libc dep) would slip
// past everything BUT a kernel kprobe.
func TestWeakness_DirectSyscall_Bypass(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	bin := compileC(t, dir, "raw_syscall", directSyscallCSource)

	sentinel := filepath.Join(dir, "raw-syscall-witness.bin")
	content := []byte("V2-adversarial-direct-syscall-bypass-libc\n")
	if err := os.WriteFile(sentinel, content, 0o600); err != nil {
		t.Fatal(err)
	}

	procs := runUnderEBPF(t, []string{bin, sentinel})

	// Find the tracee process — should have an openat for the sentinel.
	var hit *ProcessInfo
	for i := range procs {
		if _, ok := procs[i].OpenedFiles[sentinel]; ok {
			hit = &procs[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("raw-syscall openat MISSED — kprobe is not catching libc-bypassed syscalls.\n"+
			"Got %d procs:\n%s", len(procs), summarizeProcessTree(procs))
	}
	digest := hit.OpenedFiles[sentinel]
	if digest == nil {
		t.Fatalf("raw-syscall openat captured but digest is nil — read-tap path missed the read")
	}

	want, err := cryptoutil.CalculateDigestSetFromBytes(content, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	for h, w := range want {
		got, ok := digest[h]
		if !ok {
			t.Errorf("missing hash type %v in raw-syscall capture", h)
			continue
		}
		if got != w {
			t.Errorf("raw-syscall digest mismatch for %v: got %s want %s", h, got, w)
		}
	}
}

// writeOnlyCSource opens a file O_WRONLY|O_CREAT|O_TRUNC, writes, then
// closes. V1 had a bug where write-only fds got path-hashed as if they
// were reads, causing the file to land in materials (with the content
// the writer wrote — wrong semantics; that should be a product).
//
// This test pins that fix. The output file must:
//   - appear in products (not materials)
//   - have a digest matching the bytes we wrote
const writeOnlyCSource = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <out-path> <content>\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 3; }
    size_t n = strlen(argv[2]);
    if (write(fd, argv[2], n) != (ssize_t)n) { perror("write"); return 4; }
    close(fd);
    return 0;
}
`

// TestWeakness_WriteOnlyFd_NotHashedAsRead pins V1's fix that wrote-only
// fds don't end up in materials with a synthetic read-digest. Bug
// description: opening O_WRONLY|O_CREAT|O_TRUNC then closing would
// have the path-hash fallback re-read the file (which by then
// contained the writer's bytes), producing a material entry whose
// digest matched what the WRITER produced, not what any reader had
// seen — completely wrong attribution.
func TestWeakness_WriteOnlyFd_NotHashedAsRead(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	bin := compileC(t, dir, "writeonly", writeOnlyCSource)

	out := filepath.Join(dir, "wo-output.bin")
	content := "V2-writeonly-fd-witness-payload"
	procs := runUnderEBPF(t, []string{bin, out, content})

	// Assertion: out path should NOT be in any process's OpenedFiles
	// with a non-nil digest. It SHOULD be in FileOps.Writes.
	for _, p := range procs {
		if d, ok := p.OpenedFiles[out]; ok && d != nil {
			t.Errorf("write-only fd %s leaked into OpenedFiles with digest %v — V1 fix regressed", out, d)
		}
	}

	// Confirm the write was captured.
	wroteIt := false
	for _, p := range procs {
		if p.FileOps == nil {
			continue
		}
		for _, w := range p.FileOps.Writes {
			if w.Path == out {
				wroteIt = true
				break
			}
		}
	}
	if !wroteIt {
		t.Errorf("write event for %s missed entirely.\nprocs:\n%s", out, summarizeProcessTree(procs))
	}
}

// ptraceAttemptCSource: tracee tries to attach a ptrace to its own
// parent (the test harness). The BPF security event handler should
// fire CILOCK_SEC_PTRACE. Without that, an attacker could debug-
// inspect the build orchestrator (steal secrets from cilock's memory)
// and we'd never know.
const ptraceAttemptCSource = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>

int main(int argc, char **argv) {
    // Try PTRACE_ATTACH on a guaranteed-nonexistent pid. The syscall
    // ENTERS — our kprobe fires on entry — then fails fast with ESRCH.
    // CRITICAL: do NOT attach to the real parent. PTRACE_ATTACH sends
    // SIGSTOP to the TARGET process; if we attached to the cilock
    // tracer process, the tracer would stop and the trace would
    // deadlock (no userspace consumer to drain the ringbuf).
    long rc = ptrace(PTRACE_ATTACH, (pid_t)999999, 0, 0);
    fprintf(stderr, "ADVERSARIAL ptrace-attach rc=%ld errno=%d\n", rc, errno);
    return 0;
}
`

// TestWeakness_PtraceAttempt_Captured pins the SECURITY-event hook for
// ptrace. Even if the syscall fails, the ATTEMPT is what matters for
// detection — a malicious tracee testing for debugger-inhibition or
// trying to escape sandboxing leaves the same ptrace fingerprint.
func TestWeakness_PtraceAttempt_Captured(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	bin := compileC(t, dir, "ptrace_attempt", ptraceAttemptCSource)

	procs := runUnderEBPF(t, []string{bin})

	// Look for a SyscallEvent recording the ptrace attempt.
	gotPtrace := false
	for _, p := range procs {
		for _, ev := range p.SyscallEvents {
			if strings.Contains(strings.ToLower(ev.Syscall), "ptrace") ||
				strings.Contains(strings.ToLower(ev.Detail), "ptrace") {
				gotPtrace = true
				break
			}
		}
	}
	if !gotPtrace {
		t.Errorf("ptrace attempt NOT captured as security event — attacker debugging would go silent.\nprocs:\n%s",
			summarizeProcessTree(procs))
	}
}

// pthreadOpenCSource — N pthreads, each opens + reads a distinct file.
// All threads share the process tgid; their LWPs differ. Pins stage 1
// of the canonical refactor (TASK_STORAGE for watched-bit) — each
// thread must independently get task_storage populated via the
// bootstrap path so its syscalls aren't dropped.
//
// Argv: <self> <dir>
//
// Each thread opens file_<i>.txt under dir, reads the content, and
// closes. The driver waits for all threads, then exits. The bootstrap
// channel registers the leader thread's tgid; emit_filter on each
// worker's first openat must walk: task_storage miss → watched_pids
// lookup of LWP (miss) → watched_pids lookup of tgid (HIT) → cache
// into worker's task_storage. If any of those steps fails, the
// worker's open is dropped.
const pthreadOpenCSource = `
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define NTHREADS 4
static char dir[256];

static void *worker(void *arg) {
    long id = (long)arg;
    char path[512];
    snprintf(path, sizeof(path), "%s/file_%ld.txt", dir, id);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return (void *)1; }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    (void)n;
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    snprintf(dir, sizeof(dir), "%s", argv[1]);
    pthread_t threads[NTHREADS];
    for (long i = 0; i < NTHREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) {
            perror("pthread_create");
            return 3;
        }
    }
    for (int i = 0; i < NTHREADS; i++) pthread_join(threads[i], NULL);
    return 0;
}
`

// TestWeakness_PthreadTaskStorage pins V2 Phase 8 stage 1's
// TASK_STORAGE migration. A multi-threaded tracee with N worker
// threads each opening a distinct file. Each thread is a separate
// LWP sharing the process tgid. The watched-bit propagation from
// the leader's bootstrap entry must reach EACH worker's task_storage
// — if any worker's promotion path is broken, its open is silently
// dropped from the capture.
//
// Asserts: every file_<i>.txt opened by a worker thread appears in
// some process's OpenedFiles with a non-nil digest.
//
// This test would have failed if task_is_watched's bootstrap-cache
// path was wrong, or if bpf_get_current_task_btf returned the wrong
// task in a worker thread context.
func TestWeakness_PthreadTaskStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	bin := compileC(t, dir, "pthread_open", pthreadOpenCSource)
	// Add -lpthread for the compile step — compileC's stock invocation
	// might not link pthread. Easiest: drop a tiny wrapper that calls
	// it via gcc directly with the flag.
	bin = compileCWithFlags(t, dir, "pthread_open_v2", pthreadOpenCSource, []string{"-pthread"})

	const ntreads = 4
	for i := 0; i < ntreads; i++ {
		content := []byte(fmt.Sprintf("file %d content\n", i))
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%d.txt", i)), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	procs := runUnderEBPF(t, []string{bin, dir})

	// For each file_<i>.txt, find a process that has it in OpenedFiles.
	for i := 0; i < ntreads; i++ {
		target := filepath.Join(dir, fmt.Sprintf("file_%d.txt", i))
		found := false
		for _, p := range procs {
			if d, ok := p.OpenedFiles[target]; ok && d != nil {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("file_%d.txt not captured — worker thread's task_storage promotion broke.\nProcesses:\n%s",
				i, summarizeProcessTree(procs))
		}
	}
}

// compileCWithFlags is compileC but accepts extra compiler flags
// (e.g. -pthread). Kept separate from compileC so the existing
// callers don't need to grow an argument.
func compileCWithFlags(t *testing.T, srcDir, name, source string, extraFlags []string) string {
	t.Helper()
	srcPath := filepath.Join(srcDir, name+".c")
	if err := os.WriteFile(srcPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(srcDir, name)
	args := append([]string{"-O0", "-o", binPath, srcPath}, extraFlags...)
	cmd := exec.Command("cc", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return binPath
}

// summarizeProcessTree pretty-prints (pid, ppid, comm, openedFiles)
// for diagnostics on assertion failures.
func summarizeProcessTree(procs []ProcessInfo) string {
	var b strings.Builder
	for _, p := range procs {
		fmt.Fprintf(&b, "  pid=%d ppid=%d comm=%s files=%d\n",
			p.ProcessID, p.ParentPID, p.Comm, len(p.OpenedFiles))
	}
	return b.String()
}
