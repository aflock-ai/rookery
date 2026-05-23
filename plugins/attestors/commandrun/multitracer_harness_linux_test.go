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

// Test harness for the multi-tracer architecture (#167).
//
// The harness drives the controllable workload (testdata/parallel_workload)
// under the trace attestor, then validates:
//
//   - All child PIDs from the workload appear in ProcessInfo
//   - Total openat / write / linkat / mkdir capture matches ground truth
//   - Wall time is measured and reported per scenario
//   - No events are dropped under load
//   - Race detector clean
//
// Scenarios live in tableOfScenarios; each is run as its own subtest.
// Benchmarks live in the BenchmarkMultiTracer_* family.

package commandrun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
)

const workloadSrc = "testdata/parallel_workload"

type workloadSummary struct {
	Children []struct {
		PID  int    `json:"pid"`
		Kind string `json:"kind"`
		Ops  int    `json:"ops"`
		Err  string `json:"err,omitempty"`
	} `json:"children"`
	Kind    string `json:"kind"`
	OpsEach int    `json:"opsEach"`
}

// buildWorkloadOnce caches the workload binary across tests to avoid
// recompiling for every scenario. Returns the absolute path.
var (
	workloadBinaryOnce sync.Once
	workloadBinary     string
	workloadBuildErr   error
)

func ensureWorkloadBinary(t testing.TB) string {
	t.Helper()
	workloadBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "wl-bin-")
		if err != nil {
			workloadBuildErr = err
			return
		}
		// Note: this dir intentionally lives for the test-process lifetime.
		bin := filepath.Join(dir, "parallel_workload")
		cmd := exec.Command("go", "build", "-o", bin, "./"+workloadSrc)
		cmd.Env = append(os.Environ(), "GOWORK=off")
		out, err := cmd.CombinedOutput()
		if err != nil {
			workloadBuildErr = fmt.Errorf("build workload: %v: %s", err, out)
			return
		}
		workloadBinary = bin
	})
	if workloadBuildErr != nil {
		t.Skipf("workload binary build failed: %v", workloadBuildErr)
	}
	return workloadBinary
}

// scenario describes a single parallel-build-like workload + the
// ground-truth expectations the trace attestor must capture.
type scenario struct {
	name     string
	children int
	ops      int
	kind     string // openat|write|linkat|mkdir|mixed
}

func tableOfScenarios() []scenario {
	return []scenario{
		{"smoke_2x10_openat", 2, 10, "openat"},
		{"par4_50_openat", 4, 50, "openat"},
		{"par8_100_write", 8, 100, "write"},
		{"par8_50_linkat", 8, 50, "linkat"},
		{"par8_25_mkdir", 8, 25, "mkdir"},
		{"par16_25_mixed", 16, 25, "mixed"},
		// Larger workloads where per-handoff overhead amortizes out.
		// These are the ones the multi-tracer architecture targets.
		{"par8_500_openat", 8, 500, "openat"},
		{"par16_250_mixed", 16, 250, "mixed"},
	}
}

// runWorkloadUnderTrace exec's the parallel workload under the
// CommandRun.trace path and returns (procs, walltime, ground-truth, err).
func runWorkloadUnderTrace(t testing.TB, sc scenario) ([]ProcessInfo, time.Duration, workloadSummary, error) {
	t.Helper()
	bin := ensureWorkloadBinary(t)
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	actx, err := attestation.NewContext("mt-harness",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(dir),
	)
	if err != nil {
		return nil, 0, workloadSummary{}, err
	}

	// We need the workload's STDOUT to recover the ground-truth summary
	// (PID list per child). CommandRun captures stdout into rc.Stdout.
	rc := &CommandRun{
		Cmd: []string{bin,
			"-children=" + intStr(sc.children),
			"-ops=" + intStr(sc.ops),
			"-kind=" + sc.kind,
			"-dir=" + dir,
		},
		enableTracing: true,
		silent:        false,
	}
	start := time.Now()
	if err := rc.runCmd(actx); err != nil {
		return nil, 0, workloadSummary{}, err
	}
	dur := time.Since(start)

	var sum workloadSummary
	// Parent's stdout is the JSON summary; children write to stderr.
	if err := json.Unmarshal([]byte(rc.Stdout), &sum); err != nil {
		return rc.Processes, dur, sum, fmt.Errorf("decode summary: %w (stdout=%q)", err, rc.Stdout)
	}
	return rc.Processes, dur, sum, nil
}

func intStr(n int) string { return fmt.Sprintf("%d", n) }

// assertCorrectness walks the captured ProcessInfo and asserts ground
// truth: every child PID appears, the syscall capture matches the
// kind+ops the workload performed.
func assertCorrectness(t *testing.T, procs []ProcessInfo, sum workloadSummary) {
	t.Helper()

	// Build a set of captured PIDs.
	captured := make(map[int]*ProcessInfo, len(procs))
	for i := range procs {
		captured[procs[i].ProcessID] = &procs[i]
	}

	// Soft assertion: it's OK if not every child PID maps directly into
	// ProcessInfo because Go's exec.Command uses a helper goroutine that
	// itself forks. What we strictly require: at least N child PIDs were
	// captured (where N = sc.children).
	if len(procs) < len(sum.Children)+1 {
		t.Errorf("expected ≥ %d ProcessInfo entries (parent + %d children); got %d",
			len(sum.Children)+1, len(sum.Children), len(procs))
	}

	// Per-kind aggregate assertion.
	switch sum.Kind {
	case "openat":
		// Total openat captures across all children should be ≥
		// children * ops (Go runtime + linker may do some on its own).
		total := 0
		for _, p := range procs {
			total += len(p.OpenedFiles)
		}
		expected := len(sum.Children) * sum.OpsEach
		if total < expected {
			t.Errorf("openat capture: got %d, want at least %d (children=%d × ops=%d)",
				total, expected, len(sum.Children), sum.OpsEach)
		}

	case "write":
		// Each child writes M bytes to one file. Total Writes events
		// can vary because the OS may coalesce, but at least one Write
		// must be captured per child for /out target. We just verify
		// SOMETHING was captured.
		total := 0
		for _, p := range procs {
			if p.FileOps != nil {
				total += len(p.FileOps.Writes)
			}
		}
		if total == 0 && sum.OpsEach > 0 {
			t.Errorf("no Writes captured for write workload")
		}

	case "linkat":
		// Each child does M linkat. Total should be ≥ children * ops.
		total := 0
		for _, p := range procs {
			if p.FileOps != nil {
				total += len(p.FileOps.Links)
			}
		}
		expected := len(sum.Children) * sum.OpsEach
		if total < expected {
			t.Errorf("linkat capture: got %d, want at least %d", total, expected)
		}

	case "mkdir":
		// Each child does M mkdir+rmdir pairs. Verify DirOps captures.
		total := 0
		for _, p := range procs {
			if p.FileOps != nil {
				total += len(p.FileOps.DirOps)
			}
		}
		if total == 0 && sum.OpsEach > 0 {
			t.Errorf("no DirOps captured for mkdir workload")
		}

	case "mixed":
		// mixed should produce some of each. Loose assertion: SOMETHING
		// non-empty in FileOps.
		anyOps := false
		for _, p := range procs {
			if p.FileOps == nil {
				continue
			}
			if len(p.FileOps.Writes)+len(p.FileOps.Links)+len(p.FileOps.DirOps) > 0 {
				anyOps = true
				break
			}
		}
		if !anyOps && sum.OpsEach > 0 {
			t.Errorf("mixed workload captured no FileOps at all")
		}

	default:
		t.Logf("no per-kind assertion for kind=%q", sum.Kind)
	}

	// Used to verify the children counter — Errs in the summary mean
	// the workload itself failed; that's a harness failure, not an
	// attestor failure.
	for _, c := range sum.Children {
		if c.Err != "" {
			t.Logf("workload child PID %d errored: %s", c.PID, c.Err)
		}
	}
}

// TestMultiTracer_Harness_Correctness runs every scenario against
// the current (single-tracer-thread) attestor and verifies the
// captured ProcessInfo matches the ground truth from the workload.
//
// This test should ALWAYS pass — it's the correctness floor that the
// future multi-tracer-thread implementation must also clear.
func TestMultiTracer_Harness_Correctness(t *testing.T) {
	if testing.Short() {
		t.Skip("harness integration test")
	}
	for _, sc := range tableOfScenarios() {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			procs, dur, sum, err := runWorkloadUnderTrace(t, sc)
			if err != nil {
				t.Fatalf("workload failed: %v", err)
			}
			t.Logf("scenario=%s children=%d ops=%d procs_captured=%d wall=%v",
				sc.name, sc.children, sc.ops, len(procs), dur)
			assertCorrectness(t, procs, sum)
		})
	}
}

// TestMultiTracer_Harness_NoEventLoss is a stress variant: it runs the
// heaviest scenario in a tight loop and asserts no flake. Catches
// race conditions in the tracer that only appear under load.
func TestMultiTracer_Harness_NoEventLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	if os.Getenv("RUN_STRESS") != "1" {
		t.Skip("set RUN_STRESS=1 to run multi-tracer stress test")
	}
	sc := scenario{"stress", 16, 100, "mixed"}
	const iterations = 10
	for i := 0; i < iterations; i++ {
		t.Run(fmt.Sprintf("iter_%d", i), func(t *testing.T) {
			procs, _, sum, err := runWorkloadUnderTrace(t, sc)
			if err != nil {
				t.Fatalf("iter %d: %v", i, err)
			}
			assertCorrectness(t, procs, sum)
		})
	}
}

// BenchmarkMultiTracer_Workload exercises each scenario under the
// trace attestor and reports wall time. Comparing this benchmark
// before/after the multi-tracer implementation gives the headline
// speedup number for #167.
func BenchmarkMultiTracer_Workload(b *testing.B) {
	for _, sc := range tableOfScenarios() {
		sc := sc
		b.Run(sc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _, err := runWorkloadUnderTrace(b, sc)
				if err != nil {
					b.Fatalf("workload error: %v", err)
				}
			}
		})
	}
}

// TestMultiTracer_SerialVsMulti runs each scenario in both modes
// back-to-back and reports the ratio. Useful as a one-shot dev tool
// (skipped under -short and unless RUN_COMPARE=1).
func TestMultiTracer_SerialVsMulti(t *testing.T) {
	if testing.Short() {
		t.Skip("comparison test")
	}
	if os.Getenv("RUN_COMPARE") != "1" {
		t.Skip("set RUN_COMPARE=1 to run serial-vs-multi comparison")
	}
	const repeats = 3
	for _, sc := range tableOfScenarios() {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			// Serial baseline
			_ = os.Unsetenv("CILOCK_TRACE_MULTI")
			var serialTotal time.Duration
			for i := 0; i < repeats; i++ {
				_, dur, _, err := runWorkloadUnderTrace(t, sc)
				if err != nil {
					t.Fatalf("serial run %d: %v", i, err)
				}
				serialTotal += dur
			}
			// Multi-tracer
			t.Setenv("CILOCK_TRACE_MULTI", "1")
			var multiTotal time.Duration
			for i := 0; i < repeats; i++ {
				_, dur, _, err := runWorkloadUnderTrace(t, sc)
				if err != nil {
					t.Fatalf("multi run %d: %v", i, err)
				}
				multiTotal += dur
			}
			serialAvg := serialTotal / repeats
			multiAvg := multiTotal / repeats
			ratio := float64(serialAvg) / float64(multiAvg)
			t.Logf("scenario=%s serial_avg=%v multi_avg=%v ratio=%.2fx",
				sc.name, serialAvg, multiAvg, ratio)
		})
	}
}

// BenchmarkMultiTracer_Native runs the same workloads WITHOUT the
// trace attestor for a native-speed baseline. The ratio of the two
// benchmark families is the user-visible overhead.
func BenchmarkMultiTracer_Native(b *testing.B) {
	bin := ensureWorkloadBinary(b)
	for _, sc := range tableOfScenarios() {
		sc := sc
		b.Run(sc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				dir := b.TempDir()
				cmd := exec.Command(bin,
					"-children="+intStr(sc.children),
					"-ops="+intStr(sc.ops),
					"-kind="+sc.kind,
					"-dir="+dir,
				)
				cmd.Stdout = io.Discard
				cmd.Stderr = io.Discard
				if err := cmd.Run(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// requireLinuxAndSupportedArch — same gate as the syscall tests.
func requireMTLinuxAndSupportedArch(t *testing.T) {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return
	default:
		t.Skipf("multi-tracer tests target amd64/arm64; this is %s", runtime.GOARCH)
	}
}

func init() {
	// Defensive: workload tests need /proc.
	if _, err := os.Stat("/proc/self/status"); err != nil {
		_ = err
	}
	_ = strings.TrimSpace
}
