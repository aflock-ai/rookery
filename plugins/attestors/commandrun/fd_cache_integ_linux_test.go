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

// Integration tests that exercise the fd→path cache via real ptrace
// runs. These complement the unit tests in fd_cache_linux_test.go which
// hit the cache mutators directly. Here we drive a real workload under
// the tracer and assert that file writes are correctly attributed.

package commandrun

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_FDCache_WriteAttribution_Cached verifies that writes
// to a file opened *during* the trace are attributed to that file's
// path. With the cache, this works because openat-exit populates the
// cache; the SYS_WRITE handler then resolves via cache, not readlink.
//
// We use `tee` because it opens the destination as a regular fd (≥3)
// and writes via SYS_WRITE on that fd directly — unlike `cp` (which on
// modern coreutils uses copy_file_range and is not tracked by the
// SYS_WRITE handler) and unlike shell redirects (which dup2 onto fd 1
// and are filtered by the pre-existing `fd > 2` guard).
func TestIntegration_FDCache_WriteAttribution_Cached(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if _, err := exec.LookPath("tee"); err != nil {
		t.Skip("tee not in PATH")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not in PATH")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "cache-attributed.txt")

	procs := runTracedCommand(t, dir, []string{
		"sh", "-c", "echo hello-from-fd-cache | tee " + target + " > /dev/null",
	})

	// Find any process whose FileOps.Writes mentions `target`.
	found := findProcessWith(procs, func(p *ProcessInfo) bool {
		if p.FileOps == nil {
			return false
		}
		for _, w := range p.FileOps.Writes {
			if w.Path == target && w.Bytes > 0 {
				return true
			}
		}
		return false
	})
	require.NotNil(t, found, "expected write to %s captured; procs=%+v", target, procs)

	// Final assertion: the file exists with the expected content.
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(content), "hello-from-fd-cache")
}

// TestIntegration_FDCache_FDReuse_TracedWorkload is the production
// counterpart to TestFDCache_FDReuse_CorrectnessOnCloseThenReopen. We
// run three sequential `tee` invocations which each open+close their
// own destination fd. The cache must evict between each tee so the
// writes attribute to the correct path.
//
// We use a single sh -c so all three invocations run in the same
// traced child tree and the same per-pid cache could (if buggy) carry
// stale entries across — exposing close-eviction bugs that the unit
// test cannot.
func TestIntegration_FDCache_FDReuse_TracedWorkload(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not in PATH")
	}
	if _, err := exec.LookPath("tee"); err != nil {
		t.Skip("tee not in PATH")
	}
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	c := filepath.Join(dir, "c.txt")

	script := strings.Join([]string{
		"echo A | tee " + a + " > /dev/null",
		"echo B | tee " + b + " > /dev/null",
		"echo C | tee " + c + " > /dev/null",
	}, " && ")

	procs := runTracedCommand(t, dir, []string{"sh", "-c", script})

	for _, want := range []string{a, b, c} {
		found := findProcessWith(procs, func(p *ProcessInfo) bool {
			if p.FileOps == nil {
				return false
			}
			for _, w := range p.FileOps.Writes {
				if w.Path == want && w.Bytes > 0 {
					return true
				}
			}
			return false
		})
		assert.NotNil(t, found, "expected write to %s captured under fd-reuse workload", want)
	}
}

// TestIntegration_FDCache_LargeFileWriteHeavy is the write-heavy
// correctness test. We use `tee` reading from a multi-MiB source so it
// emits many write() syscalls against the destination fd. With the
// cache, each write() resolves the fd in O(1); without it, each was a
// readlink of /proc/<pid>/fd/<fd>.
//
// The assertion targets correctness only — the benchmark
// (BenchmarkFDCache_WriteHeavy) is where we observe the throughput
// difference.
func TestIntegration_FDCache_LargeFileWriteHeavy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if _, err := exec.LookPath("tee"); err != nil {
		t.Skip("tee not in PATH")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not in PATH")
	}
	if _, err := exec.LookPath("head"); err != nil {
		t.Skip("head not in PATH")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "dst.bin")

	// head -c 512K /dev/zero | tee dst.bin > /dev/null produces ~512KiB
	// of writes against tee's output fd.
	procs := runTracedCommand(t, dir, []string{
		"sh", "-c", "head -c 524288 /dev/zero | tee " + target + " > /dev/null",
	})

	totalBytes := 0
	found := findProcessWith(procs, func(p *ProcessInfo) bool {
		if p.FileOps == nil {
			return false
		}
		ok := false
		for _, w := range p.FileOps.Writes {
			if w.Path == target {
				totalBytes += w.Bytes
				ok = true
			}
		}
		return ok
	})
	require.NotNil(t, found, "expected tee writes to %s captured", target)
	assert.Greater(t, totalBytes, 100*1024,
		"expected >100KB of attributed writes; got %d", totalBytes)
}

// TestIntegration_FDCache_VerifyJSONFieldAbsent verifies the new
// openedFDs field does NOT appear in the JSON wire format. The whole
// design intent is to keep this internal to the tracer.
func TestIntegration_FDCache_VerifyJSONFieldAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true not in PATH")
	}

	procs := runTracedCommand(t, t.TempDir(), []string{"true"})
	require.NotEmpty(t, procs)

	// Marshal a process to JSON and assert the field name is nowhere in it.
	pi := procs[0]
	pi.openedFDs = map[int]string{99: "/should-not-appear"}

	// json package isn't imported here to keep dep noise low; use the
	// already-imported encoding/json via the existing assert helper.
	jsonBytes, err := marshalProcInfoForTest(pi)
	require.NoError(t, err)
	assert.NotContains(t, string(jsonBytes), "openedFDs",
		"unexported openedFDs must not leak into JSON output")
	assert.NotContains(t, string(jsonBytes), "should-not-appear",
		"sentinel path from cache must not appear in JSON")
}
