// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

// V2 Phase 11 — capstone reproducer tests.
//
// These tests reproduce the failure modes seen on the full kernel-
// compile capstone (TestCapstone_LinuxKernel_TinyConfig) using
// smaller workloads that run in seconds instead of minutes. Each
// reproducer pins a SPECIFIC correctness invariant the attestation
// must hold; if it breaks, fixing it here unblocks the capstone
// too without requiring 30-minute iteration cycles.
//
// All tests in this file FAIL on a known-broken state and PASS only
// when the underlying root cause is fixed. They are RED-GREEN tests
// — do not delete them after they pass; they are regression catches.

package commandrun

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCapstoneRepro_NoNilDigests reproduces the "attestation has
// holes" failure from the kernel-compile capstone.
//
// Workload: build N tiny C programs in parallel via `make -j N`.
// Each cc invocation opens dozens of header files and writes a .o,
// matching the per-cc syscall pattern of a kernel build.
//
// Invariant: EVERY file in OpenedFiles (= every file the tracee
// opened with a read flag) must have a non-nil digest. A nil digest
// is a HOLE in the attestation — an attacker could swap the
// unhashed file and the attestation wouldn't catch it. This is the
// strongest possible correctness criterion; relaxing it
// (e.g. "≤5% nil") would mean shipping an attestation system that
// silently produces gaps.
func TestCapstoneRepro_NoNilDigests(t *testing.T) {
	if testing.Short() {
		t.Skip("repro test — heavyweight workload, skip in -short")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := freshWorkspace(t, "repro-nil")

	// 12 tiny C programs + a Makefile that builds them in parallel.
	// Picks a small enough N that the ringbuf can't blame "too much
	// event volume" — if THIS reproduces a hole, the bug is real.
	const N = 12
	for i := 0; i < N; i++ {
		src := fmt.Sprintf(`#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) { puts("hello %d"); return 0; }
`, i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("prog%d.c", i)), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var mf strings.Builder
	mf.WriteString("all:")
	for i := 0; i < N; i++ {
		fmt.Fprintf(&mf, " prog%d", i)
	}
	mf.WriteByte('\n')
	for i := 0; i < N; i++ {
		fmt.Fprintf(&mf, "prog%d: prog%d.c\n\tcc -O0 -o prog%d prog%d.c\n", i, i, i, i)
	}
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(mf.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	cap := runCrossLang(t, dir, []string{"make", "-j", fmt.Sprintf("%d", N)}, nil)
	if cap.rc.ExitCode != 0 {
		t.Fatalf("make -j %d FAILED (exit=%d) — cilock broke the parallel build BEFORE we could check for nil digests",
			N, cap.rc.ExitCode)
	}

	// (1) Each output binary must be in products or intermediates.
	for i := 0; i < N; i++ {
		want := fmt.Sprintf("prog%d", i)
		if cap.requireWritten(want) == "" {
			t.Errorf("output binary %s NOT in products/intermediates — process-tree propagation broke on parallel forks", want)
		}
	}

	// (2) Every entry in OpenedFiles must have a non-nil digest.
	// Files we COULDN'T hash live in UnhashedOpens with an explicit
	// Reason — they're visible to verifiers, but don't pollute the
	// "files with content" view with nil-digest holes.
	var nilCount int
	var nilSamples []string
	for _, p := range cap.rc.Processes {
		for path, ds := range p.OpenedFiles {
			if ds == nil {
				nilCount++
				if len(nilSamples) < 10 {
					nilSamples = append(nilSamples, fmt.Sprintf("pid=%d %s", p.ProcessID, path))
				}
			}
		}
	}
	if nilCount > 0 {
		t.Errorf("attestation has %d nil-digest entries in OpenedFiles. These are holes — should be in UnhashedOpens (with Reason) instead.\nSamples:\n%s",
			nilCount, strings.Join(nilSamples, "\n"))
	}

	// (2b) Every UnhashedOpens entry must have a non-empty Reason —
	// recording an entry without explaining why we couldn't hash it
	// would defeat the purpose (verifier can't judge benign vs
	// adversarial).
	var unreasonCount int
	var unhashedSamples []string
	for _, p := range cap.rc.Processes {
		for _, u := range p.UnhashedOpens {
			if u.Reason == "" {
				unreasonCount++
			}
			if len(unhashedSamples) < 5 {
				unhashedSamples = append(unhashedSamples, fmt.Sprintf("pid=%d %s (reason=%q)", p.ProcessID, u.Path, u.Reason))
			}
		}
	}
	if unreasonCount > 0 {
		t.Errorf("%d UnhashedOpens entries lack a Reason — every gap must be explainable", unreasonCount)
	}
	if len(unhashedSamples) > 0 {
		t.Logf("unhashed opens (visible to verifiers): %s", strings.Join(unhashedSamples, "; "))
	}

	// (3) Surface diagnostic counters so we know HOW the failure happened.
	if cap.rc.Summary != nil {
		d := cap.rc.Summary.Diagnostics
		t.Logf("diagnostics: openatDrops=%d readTapDrops=%d partialReadFallbacks=%d fallbackHashFailures=%d procs=%d totalFiles=%d",
			d.RingbufOpenatDrops, d.RingbufReadTapDrops, d.PartialReadFallbacks, d.FallbackHashFailures,
			len(cap.rc.Processes),
			len(cap.Materials)+len(cap.Intermediates)+len(cap.Products)+len(cap.CacheArtifacts))
	}
}

// TestCapstoneRepro_BuildSucceedsUnderTrace pins the most basic
// invariant: cilock running its trace MUST NOT break the build.
//
// The kernel-compile capstone failed with exit=2 in <2s after we
// changed the hasher pool design (e.g. recursive lock deadlock on
// pctx.mu via cachedDigest). This test catches that class of bug
// using a small workload — the build is trivially correct outside
// cilock, so any failure under trace is cilock's fault.
//
// Invariant: a `make -j 4 all` over a handful of small targets
// completes with exit code 0 in under ~30 seconds.
func TestCapstoneRepro_BuildSucceedsUnderTrace(t *testing.T) {
	if testing.Short() {
		t.Skip("repro test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	dir := freshWorkspace(t, "repro-build")

	src := []byte(`#include <stdio.h>
int main(void) { puts("ok"); return 0; }
`)
	if err := os.WriteFile(filepath.Join(dir, "src.c"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	// 8 targets sharing one source — exercises the dispatcher
	// without needing many disk-distinct files.
	var mf strings.Builder
	mf.WriteString("all:")
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&mf, " out%d", i)
	}
	mf.WriteByte('\n')
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&mf, "out%d: src.c\n\tcc -O0 -o out%d src.c\n", i, i)
	}
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(mf.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	cap := runCrossLang(t, dir, []string{"make", "-j", "4"}, nil)
	if cap.rc.ExitCode != 0 {
		t.Fatalf("make -j 4 under cilock FAILED with exit=%d — cilock is breaking the build (works fine outside cilock)", cap.rc.ExitCode)
	}
	for i := 0; i < 8; i++ {
		want := fmt.Sprintf("out%d", i)
		if cap.requireWritten(want) == "" {
			t.Errorf("output %s missing — parallel build coverage broke", want)
		}
	}
}
