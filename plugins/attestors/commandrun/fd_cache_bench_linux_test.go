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

// Benchmarks that quantify the fd→path cache win on write-heavy
// workloads. Two complementary benchmarks:
//
//   - BenchmarkResolveFD_CacheHit vs BenchmarkResolveFD_Readlink isolate
//     the per-call cost. Sub-microsecond cache hit (~4ns) vs ~840ns
//     readlink → ~200× faster per resolveFD invocation.
//   - BenchmarkFDCache_WriteStorm_* runs a real traced workload that
//     emits N writes on a single fd. The cache effect is masked by
//     ptrace overhead (the kernel pays two stops per syscall regardless)
//     so the macro speedup is small in percentage terms, but the
//     allocation/readlink reduction is large and matters for
//     write-heavy CI runs (Go linker, log writers).
//
// Run with:
//
//	go test -bench=BenchmarkFDCache -benchmem -run=^$ ./...
//	go test -bench=BenchmarkResolveFD -benchmem -run=^$ ./...

package commandrun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// BenchmarkResolveFD_CacheHit measures the cost of resolveFD when the
// requested fd is already in the cache. This is the optimized path on
// every SYS_WRITE after the openat-exit has populated the cache.
func BenchmarkResolveFD_CacheHit(b *testing.B) {
	p := newBenchContext()
	pi := p.getProcInfo(1)
	pi.openedFDs[42] = "/tmp/bench-cache-hit"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.resolveFD(1, 42)
	}
}

// BenchmarkResolveFD_Readlink measures the cost of resolveFD when the
// cache misses and we fall back to /proc/<pid>/fd/<fd> readlink. We
// resolve fd 0 (stdin) of the current process — it always exists and
// readlink succeeds. Empty cache forces the miss.
func BenchmarkResolveFD_Readlink(b *testing.B) {
	p := newBenchContext()
	pid := os.Getpid()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.resolveFD(pid, 0)
	}
}

func newBenchContext() *ptraceContext {
	return &ptraceContext{
		processes:       make(map[int]*ProcessInfo),
		tlsPendingFDs:   make(map[string]int),
		pendingSyscalls: make(map[int]*pendingSyscall),
	}
}

// writeStorm is a tiny helper command that opens a file and emits N
// small write() syscalls — the worst-case workload for the
// pre-optimization codepath (N writes × 1 readlink each). We build it
// once via `go run` so the benchmark exercises a real ptrace path
// without depending on a shell command whose write() count is unclear.
const writeStormProgram = `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: writestorm <output> <count>")
		os.Exit(2)
	}
	path := os.Args[1]
	count := 0
	fmt.Sscanf(os.Args[2], "%d", &count)
	f, err := os.Create(path)
	if err != nil { panic(err) }
	defer f.Close()
	buf := []byte("x\n")
	for i := 0; i < count; i++ {
		if _, err := f.Write(buf); err != nil { panic(err) }
	}
}
`

// BenchmarkFDCache_WriteStorm_Cached builds a small helper that
// fires 5000 write() syscalls on a single fd and traces it. With the
// cache, each write hits the in-process map. Without the cache (the
// _DisabledCache sibling below), each write does a readlink.
func BenchmarkFDCache_WriteStorm_Cached(b *testing.B) {
	binPath := buildWriteStormBinary(b)
	runWriteStormBench(b, binPath, false)
}

// BenchmarkFDCache_WriteStorm_DisabledCache is the control: same
// workload, same binary, but the resolveFD cache is bypassed so every
// write triggers a readlink. The wall-time delta vs the _Cached
// variant quantifies the cache's contribution.
func BenchmarkFDCache_WriteStorm_DisabledCache(b *testing.B) {
	binPath := buildWriteStormBinary(b)
	runWriteStormBench(b, binPath, true)
}

func buildWriteStormBinary(b *testing.B) string {
	b.Helper()
	srcDir := b.TempDir()
	srcFile := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(srcFile, []byte(writeStormProgram), 0o600); err != nil {
		b.Fatal(err)
	}
	// Build into the same temp dir to keep the binary alongside the source.
	binPath := filepath.Join(srcDir, "writestorm")
	cmd := exec.Command("go", "build", "-o", binPath, srcFile)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("building writestorm helper: %v\n%s", err, out)
	}
	return binPath
}

func runWriteStormBench(b *testing.B, binPath string, disableCache bool) {
	if disableCache {
		bypassFDCacheForBench = true
		defer func() { bypassFDCacheForBench = false }()
	}

	dir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target := filepath.Join(dir, fmt.Sprintf("writestorm-%d.out", i))
		ctx, cancel := context.WithCancel(context.Background())
		actx, err := attestation.NewContext("bench-writestorm",
			[]attestation.Attestor{},
			attestation.WithContext(ctx),
			attestation.WithWorkingDir(dir),
		)
		if err != nil {
			cancel()
			b.Fatal(err)
		}

		rc := &CommandRun{
			Cmd:           []string{binPath, target, "10000"},
			enableTracing: true,
			silent:        true,
		}
		if err := rc.runCmd(actx); err != nil {
			cancel()
			b.Fatalf("trace failed: %v", err)
		}
		cancel()
	}
}

