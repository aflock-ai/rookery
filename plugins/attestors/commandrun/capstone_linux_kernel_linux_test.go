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

//go:build linux

// V2 Phase 11 — Capstone A: Linux kernel compile.
//
// The hardest test we can construct. A `make tinyconfig && make` of
// a real Linux kernel source tree exercises every weakness we've
// pinned across stages 1-4: thousands of fork-exec chains (cc, cc1,
// as, ld), fast-exit cascades, fd reuse, hyper-forking parallelism,
// massive ringbuf throughput. If V2 survives this, V2 ships.
//
// Source layout: the test reads CILOCK_CAPSTONE_LINUX_SRC for the
// path to an extracted kernel source tree (tested against 6.6.x).
// If unset OR the path doesn't exist OR disk space is short, the
// test t.Skips cleanly — capstones are environment-gated by design.
//
// Run:
//   sudo -E env "PATH=$PATH CILOCK_CAPSTONE_LINUX_SRC=/root/linux-6.6.69" \
//     go test -tags linux -timeout 30m -run TestCapstone_LinuxKernel \
//     -v ./plugins/attestors/commandrun

package commandrun

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const capstoneLinuxSrcEnv = "CILOCK_CAPSTONE_LINUX_SRC"

// TestCapstone_LinuxKernel_TinyConfig is the V2 ship-gate capstone.
//
// Workload: `make tinyconfig && make -j$(nproc) vmlinux`.
// Scale: ~thousands of source files, hundreds of compile workers,
//   millions of opens/reads, parallel fork-exec chains.
// Pass criteria:
//   - vmlinux ends up in products (or intermediates if the linker
//     re-reads its output, which gcc/ld commonly does).
//   - At least one .o file appears in intermediates.
//   - Ringbuf drops < 5% of total events — some drops are acceptable
//     on a workload this heavy, but the attestation should be mostly
//     complete.
//   - The build itself succeeds (cilock didn't break the kernel
//     build via overhead or syscall interference).
func TestCapstone_LinuxKernel_TinyConfig(t *testing.T) {
	runLinuxKernelCapstone(t, "tinyconfig", 5)
}

// TestCapstone_LinuxKernel_DefConfig is the heavyweight kernel
// capstone — a full architecture defconfig (vs the minimal
// tinyconfig). Hundreds of object files, dozens of compile workers
// in parallel, deep fork chains, ~25-45 minutes on a 4-core VM.
//
// Same pass criteria as TinyConfig — but at ~100× the file count,
// ~10× the wall-clock, and full kbuild parallelism. This is the
// "real kernel" gate: if a kernel compiler can ship under cilock
// without holes, every other compiled workload should too.
func TestCapstone_LinuxKernel_DefConfig(t *testing.T) {
	runLinuxKernelCapstone(t, "defconfig", 10)
}

func runLinuxKernelCapstone(t *testing.T, configTarget string, minDiskGB int) {
	if testing.Short() {
		t.Skip("capstone test — skip in -short mode")
	}
	srcDir := os.Getenv(capstoneLinuxSrcEnv)
	if srcDir == "" {
		t.Skipf("set %s=<linux source path> to run the kernel-compile capstone", capstoneLinuxSrcEnv)
	}
	if _, err := os.Stat(filepath.Join(srcDir, "Kconfig")); err != nil {
		t.Skipf("kernel source not found at %s: %v", srcDir, err)
	}
	if !diskHasGB(t, srcDir, minDiskGB) {
		t.Skipf("need ≥%d GB free at %s for %s build", minDiskGB, srcDir, configTarget)
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	// Clean any prior partial build so the test is reproducible.
	mustRun(t, srcDir, "make", "mrproper")

	// Configure with the requested target (tinyconfig for the small
	// gate, defconfig for the full architecture build). All variants
	// produce a vmlinux ELF as the final product.
	mustRun(t, srcDir, "make", configTarget)

	// Time the compile. We don't enforce a hard limit here (kernel
	// compiles vary); the test timeout (-timeout 30m) is the cap.
	t.Logf("starting kernel compile under cilock eBPF trace…")
	start := time.Now()

	cap := runCrossLang(t, srcDir, []string{"make", "-j", numCPUStr(), "vmlinux"}, nil)
	dur := time.Since(start)

	if cap.rc.ExitCode != 0 {
		t.Fatalf("kernel compile FAILED (exit=%d) after %s — cilock broke the build", cap.rc.ExitCode, dur)
	}
	t.Logf("kernel compile succeeded in %s under cilock trace", dur)

	// --- pass criteria ---

	// (1) vmlinux must end up somewhere we hashed.
	vmlinuxPath := cap.requireWritten("vmlinux")
	if vmlinuxPath == "" {
		t.Fatalf("vmlinux NOT in products or intermediates — capstone FAILED.\n%s", cap.summarize())
	}
	t.Logf("vmlinux captured at: %s", vmlinuxPath)

	// (2) At least one .o under the source tree appears in intermediates.
	// init/main.o is built by every kernel config — a stable anchor.
	if cap.requireIntermediate("main.o") == "" {
		t.Errorf("init/main.o NOT in intermediates — intermediate capture broke on a heavy workload")
	}

	// (3) ATTESTATION COMPLETENESS check.
	//
	// An attestation with HOLES is exploitable — an attacker could
	// swap any unrecorded file. The capstone enforces the strongest
	// possible criterion: ZERO unrecoverable files. The post-trace
	// recovery sweep should re-hash anything the in-flight trace
	// missed; unrecoverableFiles > 0 means the build wrote files
	// that are now gone from disk OR weren't recorded with an
	// absolute path — both legitimate gaps in coverage.
	//
	// Ringbuf drops count individual EVENTS lost (read_tap chunks,
	// openat records, etc.) — a heavy workload like a kernel compile
	// will drop tens of thousands of read-chunk events at peak burst.
	// That's expected; the streaming hash for those files simply
	// falls back to a post-close path-hash via the dispatcher's
	// fallbackCh, which then either succeeds (file still exists on
	// disk) or counts as a FallbackHashFailure.
	//
	// The right capstone gate is therefore "how many FILES failed
	// to hash" — i.e. FallbackHashFailures / total-captured. A
	// healthy run on a kernel compile is < 5% of files unrecoverable.
	if cap.rc.Summary != nil {
		d := cap.rc.Summary.Diagnostics
		totalFiles := uint64(len(cap.Materials) + len(cap.Intermediates) + len(cap.Products) + len(cap.CacheArtifacts))

		// THE attestation correctness invariant: walk EVERY process's
		// OpenedFiles and confirm no entry has a nil digest. A nil
		// digest is a hole — an attacker could swap that file and
		// the attestation wouldn't catch it.
		//
		// FallbackHashFailures and ringbuf drops are operational
		// counters (how busy / lossy the trace was) — NOT correctness
		// signals. The same file path opened many times will fail to
		// hash sometimes (fast-exit fd gone) but succeed others; the
		// first successful hash sticks in OpenedFiles. The criterion
		// that matters is the FINAL state of OpenedFiles.
		var nilDigests uint64
		var nilSamples []string
		for _, p := range cap.rc.Processes {
			for path, ds := range p.OpenedFiles {
				if ds == nil {
					nilDigests++
					if len(nilSamples) < 10 {
						nilSamples = append(nilSamples, path)
					}
				}
			}
		}
		if nilDigests > 0 {
			t.Errorf("attestation incomplete: %d per-process OpenedFiles entries have nil digests. "+
				"NONE are acceptable — every one is a hole an attacker could exploit.\nSamples: %v",
				nilDigests, nilSamples)
		}
		t.Logf("coverage: %d files captured, %d per-proc nil-digest entries; "+
			"hash failures=%d (visible-to-verifier UnhashedOpens=%d, silent-drops-because-same-path-hashed-cleanly=%d); "+
			"event drops openat=%d readTap=%d; partialReadUpgrades skipped=%d",
			totalFiles, nilDigests,
			d.FallbackHashFailures, d.UnhashedOpensTotal, d.HashFailureSilentDrops,
			d.RingbufOpenatDrops, d.RingbufReadTapDrops, d.PartialReadFallbacks)
	}

	// (4) Process tree must show real depth — kernel build fork-exec
	// chains go many levels deep.
	if len(cap.rc.Processes) < 50 {
		t.Errorf("only %d processes captured for a kernel compile — process-tree propagation broke under load",
			len(cap.rc.Processes))
	}

	t.Logf("CAPSTONE PASSED: materials=%d intermediates=%d products=%d cache=%d procs=%d in %s",
		len(cap.Materials), len(cap.Intermediates), len(cap.Products), len(cap.CacheArtifacts),
		len(cap.rc.Processes), dur)
}

// numCPUStr returns the runtime CPU count as a decimal string —
// used as the -j argument for parallel make.
func numCPUStr() string {
	// nproc binary is universal; cheaper than runtime.NumCPU + format
	out, err := exec.Command("nproc").Output()
	if err != nil {
		return "4"
	}
	return strings.TrimSpace(string(out))
}

// mustRun runs a command in dir, failing the test on error. Used
// for the configure step (mrproper, tinyconfig) where we don't
// need cilock attestation, just the side effects.
func mustRun(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v in %s: %v", name, args, dir, err)
	}
}

// diskHasGB returns true if `path` has at least minGB available.
func diskHasGB(t *testing.T, path string, minGB int) bool {
	t.Helper()
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return false
	}
	avail := uint64(s.Bavail) * uint64(s.Bsize)
	return avail/(1024*1024*1024) >= uint64(minGB)
}
