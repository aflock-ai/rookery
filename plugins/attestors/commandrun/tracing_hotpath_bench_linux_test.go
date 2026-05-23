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

package commandrun

import (
	"testing"
	"time"
)

// These benchmarks exercise the trace attestor's allocation hot path WITHOUT
// requiring an actual ptrace event loop. They simulate the steady state of:
//
//   - SYS_WRITE: append FileWrite{} structs to procInfo.FileOps.Writes
//   - SYS_PRCTL / SYS_SETSID / etc.: append SyscallEvent{} to procInfo.SyscallEvents
//   - syscall-arg reads: scratch []byte buffer sized MAX_PATH_LEN
//
// The goal is to measure B/op and allocs/op so PR-7 (sync.Pool for the
// hot-path scratch buffer + pre-grown slab slices) can show a delta.
//
// Run with:
//   go test -bench=BenchmarkHotPath -benchmem -benchtime=2s ./...

// BenchmarkHotPath_FileWrite simulates a write-heavy build that fires SYS_WRITE
// repeatedly (e.g. compiling a large project that emits many object files).
// Each iteration captures the realistic per-run cost: one FileActivity
// allocation + N slice grows + N timestamp formats.
func BenchmarkHotPath_FileWrite(b *testing.B) {
	const writesPerRun = 1024
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pi := &ProcessInfo{}
		ensureFileOpsForBench(pi)
		for w := 0; w < writesPerRun; w++ {
			pi.FileOps.Writes = append(pi.FileOps.Writes, FileWrite{
				Path:      "/tmp/output.o",
				Bytes:     4096,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
	}
}

// BenchmarkHotPath_SyscallEvent simulates a build that fires many notable
// syscalls (sandboxed: prctl, setsid, etc.). Each event allocates: the
// timestamp string, the detail string, and (for events with Args) the
// []int slice literal.
func BenchmarkHotPath_SyscallEvent(b *testing.B) {
	const eventsPerRun = 256
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pi := &ProcessInfo{}
		for e := 0; e < eventsPerRun; e++ {
			pi.SyscallEvents = append(pi.SyscallEvents, SyscallEvent{
				Syscall:   "prctl",
				Detail:    "PR_SET_NAME: renamed process to 'worker' — hiding malicious process identity",
				Args:      []int{15, 42},
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
	}
}

// benchReadBufSink is a package-level sink that defeats the escape-analysis
// elision the compiler would otherwise perform on acquireReadBuf — without
// it, BenchmarkHotPath_ReadBuffer would report 0 allocs (the compiler
// proves the make() doesn't escape and stack-allocates it). We want to
// measure the real cost the trace attestor pays, which DOES escape via
// ProcessVMReadv → kernel.
var benchReadBufSink []byte

// BenchmarkHotPath_ReadBuffer measures the cost of a single MAX_PATH_LEN
// scratch buffer allocation (readSyscallReg / parseSockaddr / extractTLSSNI
// all do this on every syscall that reads tracee memory).
func BenchmarkHotPath_ReadBuffer(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := acquireReadBuf(MAX_PATH_LEN)
		copy(buf, "/usr/local/bin/myprog")
		// Force escape so the compiler can't prove the buffer is
		// stack-confined. Mirrors the real-world unix.ProcessVMReadv
		// call, which crosses the cgo / syscall boundary.
		benchReadBufSink = buf
		releaseReadBuf(buf)
	}
}

// BenchmarkHotPath_Mixed mixes write events, syscall events, and one read
// buffer per "syscall" to approximate the steady-state mix of a heavy build.
// This is the most representative number for the PR.
func BenchmarkHotPath_Mixed(b *testing.B) {
	const syscallsPerRun = 512
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pi := &ProcessInfo{}
		ensureFileOpsForBench(pi)
		for s := 0; s < syscallsPerRun; s++ {
			// 80% writes, 20% syscall events — matches the rough mix
			// in captured Go build traces.
			if s%5 != 0 {
				buf := acquireReadBuf(MAX_PATH_LEN)
				copy(buf, "/tmp/output.o")
				releaseReadBuf(buf)

				pi.FileOps.Writes = append(pi.FileOps.Writes, FileWrite{
					Path:      "/tmp/output.o",
					Bytes:     4096,
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				})
			} else {
				pi.SyscallEvents = append(pi.SyscallEvents, SyscallEvent{
					Syscall:   "prctl",
					Detail:    "PR_SET_NAME: renamed process",
					Args:      []int{15, 42},
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				})
			}
		}
	}
}

// ensureFileOpsForBench mirrors the ensureFileOps method without needing a
// ptraceContext receiver — keeps the benchmark independent of the rest of
// the trace machinery.
func ensureFileOpsForBench(pi *ProcessInfo) {
	if pi.FileOps == nil {
		pi.FileOps = newFileActivity()
	}
}
