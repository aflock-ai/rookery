// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

// V2 Phase 11 — Capstone D: long-running single attestation session.
//
// Bazel and Buck2 persistent build servers stay resident across many
// builds. cilock attesting such a server runs ONE Attest() call that
// observes thousands of compile-link cycles. This capstone simulates
// that pattern by wrapping a shell loop that iterates N small builds
// under a single trace.
//
// Pass criteria:
//   - Zero nil-digest entries across the merged attestation.
//   - All N output binaries appear in products or intermediates.
//   - No ringbuf drops.
//   - Userspace state (digestCache, openPaths, process map) growth
//     is BOUNDED — final size proportional to unique files, not to
//     iteration count.
//
// Growth audit: the test logs the captured-process count and the
// total OpenedFiles entries. Future regressions can compare across
// runs.

package commandrun

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCapstone_LongRunningSession runs N sequential small C builds
// inside one cilock attestation. N=20 by default; can be tuned via
// CILOCK_TEST_LONGSESSION_N for stress runs.
func TestCapstone_LongRunningSession(t *testing.T) {
	if testing.Short() {
		t.Skip("capstone test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	N := 20
	if v := os.Getenv("CILOCK_TEST_LONGSESSION_N"); v != "" {
		var got int
		if _, err := fmt.Sscanf(v, "%d", &got); err == nil && got > 0 {
			N = got
		}
	}
	t.Logf("running %d sequential builds in one attestation session", N)

	dir := freshWorkspace(t, "longsession")

	// One C source per iteration; each gets a unique sentinel so the
	// merged attestation can be checked for ALL of them.
	var script strings.Builder
	script.WriteString("set -e\n")
	for i := 0; i < N; i++ {
		src := fmt.Sprintf(`#include <stdio.h>
int main(void) { puts("LONGSESSION-ITER-%d"); return 0; }
`, i)
		path := filepath.Join(dir, fmt.Sprintf("prog%d.c", i))
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&script, "cc -O0 -o prog%d prog%d.c\n", i, i)
	}
	scriptPath := filepath.Join(dir, "build.sh")
	if err := os.WriteFile(scriptPath, []byte(script.String()), 0o755); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	cap := runCrossLang(t, dir, []string{"sh", scriptPath}, nil)
	dur := time.Since(start)
	if cap.rc.ExitCode != 0 {
		t.Fatalf("long-running session FAILED (exit=%d) after %s", cap.rc.ExitCode, dur)
	}
	t.Logf("session completed in %s (%v per iteration avg)", dur, dur/time.Duration(N))

	// (1) Every output binary must be present somewhere.
	missing := 0
	for i := 0; i < N; i++ {
		want := fmt.Sprintf("prog%d", i)
		if cap.requireWritten(want) == "" {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d/%d binaries missing from products/intermediates — coverage degraded over the long session", missing, N)
	}

	// (2) Zero nil-digest entries.
	var nilDigests int
	for _, p := range cap.rc.Processes {
		for _, ds := range p.OpenedFiles {
			if ds == nil {
				nilDigests++
			}
		}
	}
	if nilDigests > 0 {
		t.Errorf("attestation incomplete: %d nil-digest entries in long session", nilDigests)
	}

	// (3) Zero ringbuf drops.
	if cap.rc.Summary != nil {
		d := cap.rc.Summary.Diagnostics
		if d.RingbufOpenatDrops > 0 || d.RingbufReadTapDrops > 0 {
			t.Errorf("ringbuf drops over long session: openat=%d readTap=%d", d.RingbufOpenatDrops, d.RingbufReadTapDrops)
		}
		t.Logf("session diagnostics: hashFailures=%d UnhashedOpens=%d silentDrops=%d procs=%d",
			d.FallbackHashFailures, d.UnhashedOpensTotal, d.HashFailureSilentDrops, len(cap.rc.Processes))
	}

	// (4) Growth audit: total OpenedFiles entries. Should scale with
	// unique files (system headers + N source files + N binaries),
	// not with N^2 or unbounded.
	var totalOpened int
	for _, p := range cap.rc.Processes {
		totalOpened += len(p.OpenedFiles)
	}
	t.Logf("growth: %d total OpenedFiles entries across %d processes (N=%d iterations)",
		totalOpened, len(cap.rc.Processes), N)
}
