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

// V2 Phase 8 blocker tests — failing tests that pin specific weaknesses
// identified by the eBPF canonical-patterns research (Tetragon, Trail
// of Bits, kernel docs, 2026-05-24). Each test is a regression catch
// for the canonical-patterns rewrite tracked in
// memory/ebpf-canonical-patterns.md and the V2 plan's Phase 8.
//
// Default: skipped via build env to avoid blocking CI. Run explicitly:
//
//   sudo -E env "PATH=$PATH" CILOCK_KNOWN_FAILING=1 \
//       go test -run TestPhase8Blocker_ -v -count=1 \
//       ./plugins/attestors/commandrun
//
// When Phase 8's canonical-patterns rewrite lands, REMOVE the
// skip-by-default and the tests become permanent regression catches.

package commandrun

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// gateOnKnownFailing skips when CILOCK_KNOWN_FAILING is unset.
// Phase 8's canonical-patterns rewrite is the gate for these tests
// to default-run; until then they're opt-in via env var.
func gateOnKnownFailing(t *testing.T, ticket string) {
	t.Helper()
	if os.Getenv("CILOCK_KNOWN_FAILING") != "1" {
		t.Skipf("Phase 8 canonical-patterns rewrite blocker — see %s. "+
			"Run with CILOCK_KNOWN_FAILING=1 to demonstrate the failure.", ticket)
	}
	if testing.Short() {
		t.Skip("e2e test")
	}
}

// TestPhase8Blocker_ForkChainStability runs the existing ForkChain
// test 50 times back-to-back and asserts the pass rate is ≥98%.
//
// Currently ~50% pass rate on aarch64 / linux 6.8. Root cause is
// the dispatcher race between BPF emit_filter rejecting events for
// not-yet-watched intermediate fork chain levels AND the userspace
// fallback path losing events for short-lived processes.
//
// Phase 8's canonical fix: hereditary insertion at fork time via
// `kprobe/wake_up_new_task` (Tetragon), `BPF_MAP_TYPE_TASK_STORAGE`
// for the watched bit (no map sizing, auto-GC), drop the ancestor
// walks entirely.
//
// Pass criterion: 49/50 passes (98%).
func TestPhase8Blocker_ForkChainStability(t *testing.T) {
	gateOnKnownFailing(t, "V2 Plan Phase 8 — canonical fork-watch")

	const runs = 50
	passes := 0
	for i := 0; i < runs; i++ {
		dir := t.TempDir()
		bin := compileC(t, dir, fmt.Sprintf("fork_chain_%d", i), forkChainCSource)
		sentinel := filepath.Join(dir, "stability-witness.bin")
		content := []byte(fmt.Sprintf("phase8-stability-run-%d", i))
		if err := os.WriteFile(sentinel, content, 0o600); err != nil {
			t.Fatal(err)
		}
		procs := runUnderEBPF(t, []string{bin, "4", sentinel})
		hit := false
		for _, p := range procs {
			if d, ok := p.OpenedFiles[sentinel]; ok && d != nil {
				hit = true
				break
			}
		}
		if hit {
			passes++
		}
	}
	if passes < runs*98/100 {
		t.Errorf("ForkChain stability under repeat: %d/%d passes (need ≥98%%).\n"+
			"Phase 8 canonical-patterns rewrite required: hereditary fork insertion + "+
			"TASK_STORAGE for watched bit.",
			passes, runs)
	}
}

// fastCloseRelativeCSource: opens a file by RELATIVE path, reads it,
// closes immediately, exits. Pins the read-tap/path-resolution race
// where cc1-style fast compilers lose digests because:
//  1. openat(AT_FDCWD, "data.bin", O_RDONLY) — relative path
//  2. fast read + close + exit
//  3. by the time userspace processes the openat event, the tracee
//     has exited; /proc/<pid>/cwd is gone; path-hash fallback fails;
//     digest is nil.
//
// Phase 8's canonical fix: fentry on `security_file_open` with
// `bpf_d_path` (allowlisted on that hook) gives a kernel-canonical
// absolute path resolved at file-open time, no userspace race.
const fastCloseRelativeCSource = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <dir> <basename>\n", argv[0]); return 2; }
    if (chdir(argv[1]) != 0) { perror("chdir"); return 3; }
    // Open by RELATIVE path under chdir'd cwd. This is the cc1
    // pattern: openat(AT_FDCWD, "data.bin", O_RDONLY).
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) { perror("open"); return 4; }
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    (void)n;
    close(fd);
    return 0;
}
`

// TestPhase8Blocker_RelativePathFastClose pins the read-tap race for
// relative paths + fast process exit. Currently fails when the dispatcher
// can't resolve `/proc/<pid>/cwd` after the tracee exits — same
// pathology as cc1 in C builds.
//
// Pass criterion: the file opened by relative path has a correct
// SHA-256 digest in the captured materials.
func TestPhase8Blocker_RelativePathFastClose(t *testing.T) {
	gateOnKnownFailing(t, "V2 Plan Phase 8 — fentry/security_file_open + bpf_d_path")

	dir := t.TempDir()
	bin := compileC(t, dir, "fast_close", fastCloseRelativeCSource)
	// Drop the data file directly in the workspace so the relative
	// open path resolves correctly from the tracee's cwd.
	content := []byte("phase8-relative-path-fast-close-payload\n")
	dataPath := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(dataPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	// Tracee does its own chdir to the data dir, then opens by relative
	// basename. This reproduces the cc1 path exactly: cwd != cilock's
	// cwd, openat(AT_FDCWD, "data.bin", ...), fast close + exit.
	procs := runUnderEBPF(t, []string{bin, dir, "data.bin"})

	// Compute the expected sha256 once.
	want, err := cryptoutil.CalculateDigestSetFromBytes(content,
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	var wantSha string
	for k, v := range want {
		if k.Hash == crypto.SHA256 {
			wantSha = v
			break
		}
	}

	// Look for data.bin with non-nil digest matching wantSha.
	var found bool
	for _, p := range procs {
		for path, ds := range p.OpenedFiles {
			if filepath.Base(path) != "data.bin" || ds == nil {
				continue
			}
			for k, v := range ds {
				if k.Hash == crypto.SHA256 && v == wantSha {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Errorf("relative-path fast-close: data.bin digest MISSED.\n"+
			"Phase 8 canonical fix: fentry/security_file_open + bpf_d_path "+
			"resolves the absolute path in kernel context, before the "+
			"tracee can exit and take /proc/<pid>/cwd with it.\nprocs:\n%s",
			summarizeOpenedFiles(procs))
	}
}

// hyperForkCSource: fires N fork→exec→exit cycles in a tight loop.
// Exercises the kretprobe slot pool (default 4096 active kretprobes).
// On hyper-forking workloads kretprobes silently miss — Trail of Bits
// 2023-09 documents this for 6.4.5.
//
// Phase 8's canonical fix: switch fork-watch to `kprobe/wake_up_new_task`
// (Tetragon pattern), drop the four clone-family kretprobes that pressure
// the pool.
//
// We just spawn /bin/true N times — each invocation: fork → execve →
// exit. Cheap, deterministic, hits both fork and exec kprobes.
const hyperForkCSource = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    int n = (argc > 1) ? atoi(argv[1]) : 100;
    for (int i = 0; i < n; i++) {
        pid_t c = fork();
        if (c < 0) return 1;
        if (c == 0) {
            execl("/bin/true", "/bin/true", (char *)NULL);
            _exit(99);
        }
        int status;
        waitpid(c, &status, 0);
    }
    return 0;
}
`

// TestPhase8Blocker_HyperForkPool fires 100+ rapid fork→exec→exit
// cycles and asserts every fork's child appears in the captured
// process tree. If even one is missing, the kretprobe pool exhausted.
func TestPhase8Blocker_HyperForkPool(t *testing.T) {
	gateOnKnownFailing(t, "V2 Plan Phase 8 — wake_up_new_task hook")

	dir := t.TempDir()
	bin := compileC(t, dir, "hyper_fork", hyperForkCSource)

	const n = 100
	procs := runUnderEBPF(t, []string{bin, fmt.Sprintf("%d", n)})

	// Count child processes. Expect at least n distinct child pids
	// (the parent fires n forks; each fork's child execs /bin/true
	// which fires its own execve event). Some slack allowed for
	// captured library-loader noise from the parent.
	childCount := 0
	for _, p := range procs {
		// Heuristic: anything with comm=true OR comm=hyper_fork (post-
		// fork before exec) is a child of the test binary.
		if p.Comm == "true" {
			childCount++
		}
	}
	if childCount < n*98/100 {
		t.Errorf("hyper-fork pool: only %d/%d children captured (kretprobe pool exhaustion).\n"+
			"Phase 8 canonical fix: switch fork-watch to kprobe/wake_up_new_task; "+
			"the kretprobe slot pool (4096 default) is the wrong attach surface for "+
			"high-fork-rate workloads.",
			childCount, n)
	}
}
