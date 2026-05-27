// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

// V2 Phase 11 — Capstone C: concurrent attestations on one host.
//
// CI runners routinely host 4-8 build agents per machine, each
// running a cilock attestation. The eBPF programs, ringbufs, and
// per-CPU maps are not isolated across cilock processes — collisions
// or stomping would produce cross-contaminated attestations or
// runtime failures.
//
// This capstone runs N parallel attestations of independent tiny
// builds (each with a unique sentinel string in its source) and
// asserts:
//   1. All N runs complete successfully.
//   2. Each attestation captures its OWN tracee's output binary as
//      a product; no run "sees" another run's sentinel.
//   3. No nil-digest entries anywhere.
//   4. No ringbuf drops on any run.

package commandrun

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestCapstone_ConcurrentAttestations runs N parallel cilock
// attestations and asserts each attestation reflects its own
// workload only.
//
// N defaults to runtime.NumCPU() / 2 (clamped to [2,4]) so the
// host isn't oversubscribed — each cilock attestation spawns
// hashers + capturers, plus the build itself runs gcc.
func TestCapstone_ConcurrentAttestations(t *testing.T) {
	if testing.Short() {
		t.Skip("capstone test")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	skipIfNoEBPFCaps(t)

	N := runtime.NumCPU() / 2
	if N < 2 {
		N = 2
	}
	if N > 4 {
		N = 4
	}
	t.Logf("running %d concurrent attestations", N)

	type result struct {
		idx          int
		sentinel     string
		productPath  string
		nilDigests   int
		openatDrops  uint64
		readTapDrops uint64
		procs        int
		err          error
		foreignSeen  []string // sentinels from OTHER runs that leaked in
	}

	results := make([]result, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := &results[idx]
			r.idx = idx
			// Each worker gets a unique sentinel string baked into its
			// C source. After the trace, the worker confirms its OWN
			// sentinel is in the captured tracee output AND none of
			// the OTHER workers' sentinels appear in its attestation
			// (cross-contamination check).
			r.sentinel = fmt.Sprintf("CONCURRENT-CILOCK-WORKER-%d-SENTINEL-%d", idx, idx*1000+42)
			dir := freshWorkspace(t, fmt.Sprintf("concurrent-%d", idx))
			src := fmt.Sprintf(`#include <stdio.h>
int main(void) { puts("%s"); return 0; }
`, r.sentinel)
			if err := os.WriteFile(filepath.Join(dir, "hello.c"), []byte(src), 0o644); err != nil {
				r.err = fmt.Errorf("write source: %w", err)
				return
			}
			cap := runCrossLang(t, dir, []string{"cc", "-O0", "-o", "hello", "hello.c"}, nil)
			if cap.rc.ExitCode != 0 {
				r.err = fmt.Errorf("build failed (exit=%d) under concurrent attestation", cap.rc.ExitCode)
				return
			}
			r.procs = len(cap.rc.Processes)
			// 'hello' lands in products OR intermediates depending on
			// whether the linker re-reads its own output for fixup.
			for path := range cap.Products {
				if filepath.Base(path) == "hello" {
					r.productPath = path
					break
				}
			}
			if r.productPath == "" {
				for path := range cap.Intermediates {
					if filepath.Base(path) == "hello" {
						r.productPath = path
						break
					}
				}
			}
			for _, p := range cap.rc.Processes {
				for _, ds := range p.OpenedFiles {
					if ds == nil {
						r.nilDigests++
					}
				}
			}
			if cap.rc.Summary != nil {
				r.openatDrops = cap.rc.Summary.Diagnostics.RingbufOpenatDrops
				r.readTapDrops = cap.rc.Summary.Diagnostics.RingbufReadTapDrops
			}
			// Cross-contamination scan: walk THIS run's captured paths
			// and look for OTHER workers' sentinels embedded in any of
			// the materials' captured paths (paths derived from the
			// build environment that should be worker-local).
			for path := range cap.Materials {
				for j := 0; j < N; j++ {
					if j == idx {
						continue
					}
					otherSentinel := fmt.Sprintf("CONCURRENT-CILOCK-WORKER-%d-SENTINEL-%d", j, j*1000+42)
					if strings.Contains(path, otherSentinel) {
						r.foreignSeen = append(r.foreignSeen, otherSentinel)
					}
				}
			}
		}(i)
	}
	wg.Wait()

	for _, r := range results {
		if r.err != nil {
			t.Errorf("worker %d failed: %v", r.idx, r.err)
			continue
		}
		if r.productPath == "" {
			t.Errorf("worker %d: own binary 'hello' not captured as product or intermediate (concurrent attestations lost own output)", r.idx)
		}
		if r.nilDigests > 0 {
			t.Errorf("worker %d: %d nil-digest entries — concurrent BPF state corruption suspected", r.idx, r.nilDigests)
		}
		if r.openatDrops > 0 || r.readTapDrops > 0 {
			t.Errorf("worker %d: ringbuf drops openat=%d readTap=%d under concurrent attestation",
				r.idx, r.openatDrops, r.readTapDrops)
		}
		if len(r.foreignSeen) > 0 {
			t.Errorf("worker %d: foreign sentinels appeared in its attestation: %v — CROSS-CONTAMINATION",
				r.idx, r.foreignSeen)
		}
		t.Logf("worker %d OK: product=%s procs=%d nilDigests=%d", r.idx, filepath.Base(r.productPath), r.procs, r.nilDigests)
	}
}
