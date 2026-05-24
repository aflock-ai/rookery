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
		t.Fatalf("deep-fork-chain leaf openat MISSED — V2 Phase 1 regression.\n"+
			"Got %d processes; tree:\n%s\nopened files:\n%s",
			len(procs), summarizeProcessTree(procs), summarizeOpenedFiles(procs))
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
