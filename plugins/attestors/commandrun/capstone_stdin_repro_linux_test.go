// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

// Reproducer for the capstone build-breaks-under-cilock failure.
//
// The kernel-compile capstone failed in 1.7s with "gcc: unknown C
// compiler" — Linux's cc-version.sh pipes a heredoc to `gcc -E -P -x c -`
// and parses the preprocessor output to detect the compiler. Under
// cilock the gcc process saw EMPTY input, suggesting cilock was
// consuming bytes from gcc's stdin somehow.
//
// HYPOTHESIS: the dispatcher's race-tight CaptureFileForLaterHash
// opens /proc/<pid>/fd/<fd> for every observed openat — but if the
// tracee opens /proc/self/fd/0 (or any path that resolves to a
// pipe), our os.Open + later os.Read DRAINS data the tracee was
// supposed to read.

package commandrun

import (
	"os"
	"strings"
	"testing"
)

// TestCapstoneRepro_KernelSyncconfig runs `make syncconfig` against
// the Linux source — the first step of `make vmlinux` and the one
// that fails on the capstone with "gcc: unknown C compiler". Much
// faster than a full kernel compile (~1-2s), so iteration cycles are
// short. Set CILOCK_CAPSTONE_LINUX_SRC to the kernel source path.
func TestCapstoneRepro_KernelSyncconfig(t *testing.T) {
	if testing.Short() {
		t.Skip("repro test")
	}
	srcDir := os.Getenv(capstoneLinuxSrcEnv)
	if srcDir == "" {
		t.Skipf("set %s to run the syncconfig repro", capstoneLinuxSrcEnv)
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)
	mustRun(t, srcDir, "make", "mrproper")
	mustRun(t, srcDir, "make", "tinyconfig")

	cap := runCrossLang(t, srcDir, []string{"make", "syncconfig"}, nil)
	if cap.rc.ExitCode != 0 {
		t.Fatalf("make syncconfig under cilock FAILED (exit=%d). This is the same failure as the kernel-compile capstone; fix here.\nstdout:\n%s\nstderr:\n%s",
			cap.rc.ExitCode, cap.rc.Stdout, cap.rc.Stderr)
	}
}

// TestCapstoneRepro_GccPreprocessorStdin repro exactly the workload
// that breaks the kernel-compile capstone: pipe a heredoc to
// `gcc -E -P -x c -` (kernel scripts/cc-version.sh) and assert the
// preprocessor output contains the expected macro expansion. If
// cilock is corrupting gcc's stdin under trace, this is what
// reproduces it.
func TestCapstoneRepro_GccPreprocessorStdin(t *testing.T) {
	if testing.Short() {
		t.Skip("repro test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)
	dir := freshWorkspace(t, "repro-cpp")

	// Heredoc piped to gcc -E -P -x c - — exact replica of kernel's
	// scripts/cc-version.sh. Expected output: "GCC 13 ..." for gcc 13.
	script := `cat <<EOF | gcc -E -P -x c - 2>/dev/null
#if defined(__GNUC__)
GCC __GNUC__ __GNUC_MINOR__ __GNUC_PATCHLEVEL__
#else
unknown
#endif
EOF`
	cap := runCrossLang(t, dir, []string{"sh", "-c", script}, nil)
	if cap.rc.ExitCode != 0 {
		t.Fatalf("gcc preprocessor pipeline under cilock FAILED (exit=%d) — see stderr above", cap.rc.ExitCode)
	}
	if !strings.Contains(cap.rc.Stdout, "GCC") {
		t.Errorf("gcc preprocessor saw empty/garbled stdin under cilock — got stdout %q (expected to contain \"GCC\")",
			cap.rc.Stdout)
	}
}

// TestCapstoneRepro_StdinPipeNotDrained pins the contract:
// running a tracee that reads bytes from stdin (or any pipe) MUST
// NOT see those bytes consumed by cilock. The simplest reproducer:
// pipe a heredoc into `cat` under cilock; the tracee's output must
// match the input verbatim.
//
// FAILS on the known bug. PASSES once CaptureFileForLaterHash
// stops opening pipe-backed fds.
func TestCapstoneRepro_StdinPipeNotDrained(t *testing.T) {
	if testing.Short() {
		t.Skip("repro test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := freshWorkspace(t, "repro-stdin")
	// Sentinel bytes that MUST round-trip through stdin → tracee → stdout.
	const sentinel = "CILOCK-PIPE-TEST-PAYLOAD-12345"
	// Use a shell that reads stdin into a variable and emits it back.
	// `sh -c 'cat'` is the simplest "echo stdin to stdout" pipeline.
	// We pipe sentinel through cilock-traced `cat` and assert the
	// tracee's stdout contains the sentinel.
	script := "echo '" + sentinel + "' | cat"
	cap := runCrossLang(t, dir, []string{"sh", "-c", script}, nil)
	if cap.rc.ExitCode != 0 {
		t.Fatalf("sh -c 'echo|cat' under cilock FAILED (exit=%d) — cilock broke a trivial pipe", cap.rc.ExitCode)
	}
	if !strings.Contains(cap.rc.Stdout, sentinel) {
		t.Errorf("stdin was DRAINED by cilock — tracee's stdout missing the piped sentinel.\nExpected to find %q in:\n%s",
			sentinel, cap.rc.Stdout)
	}
	_ = os.Stdout
}
