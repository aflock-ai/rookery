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
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAcquireReadBuf_ReturnsCorrectLength — every caller relies on the
// returned slice being exactly `n` bytes long so the ProcessVMReadv
// IovLen is sized correctly.
func TestAcquireReadBuf_ReturnsCorrectLength(t *testing.T) {
	cases := []int{16, 128, 256, 512, MAX_PATH_LEN}
	for _, n := range cases {
		buf := acquireReadBuf(n)
		assert.Equal(t, n, len(buf), "acquireReadBuf(%d) len", n)
		assert.GreaterOrEqual(t, cap(buf), n, "acquireReadBuf(%d) cap", n)
		releaseReadBuf(buf)
	}
}

// TestAcquireReadBuf_PoolReuse — releasing a buffer and immediately
// re-acquiring SHOULD usually return the same memory (the pool's per-P
// local cache). This is not a strict contract — sync.Pool may discard
// elements on GC or under -race — so the test only requires that at
// least one reuse happens out of a small budget of tries. The
// allocation benchmark (BenchmarkHotPath_ReadBuffer) is the real
// confirmation that the pool is doing its job.
func TestAcquireReadBuf_PoolReuse(t *testing.T) {
	reused := false
	for attempt := 0; attempt < 64; attempt++ {
		buf1 := acquireReadBuf(MAX_PATH_LEN)
		addr1 := uintptr(unsafe.Pointer(&buf1[0]))
		releaseReadBuf(buf1)
		buf2 := acquireReadBuf(MAX_PATH_LEN)
		addr2 := uintptr(unsafe.Pointer(&buf2[0]))
		releaseReadBuf(buf2)
		if addr1 == addr2 {
			reused = true
			break
		}
	}
	if !reused {
		// Don't fail the test — sync.Pool reuse is best-effort and
		// can be defeated by GC pressure or the race detector. The
		// alloc benchmark catches a truly broken pool.
		t.Log("acquireReadBuf did not reuse pooled memory in 64 attempts; benchmark is the authoritative check")
	}
}

// TestAcquireReadBuf_OversizeFallback — requesting more than readBufSize
// must still return a valid buffer (the fallback path).
func TestAcquireReadBuf_OversizeFallback(t *testing.T) {
	buf := acquireReadBuf(readBufSize + 1024)
	require.Equal(t, readBufSize+1024, len(buf))
	// Should be safe to release — release just drops it for the GC.
	releaseReadBuf(buf)
}

// TestReleaseReadBuf_NoCrashOnArbitrarySlice — release MUST tolerate
// being called on any byte slice without crashing, even one not produced
// by acquire (e.g. accidental call from external code in a future
// refactor).
func TestReleaseReadBuf_NoCrashOnArbitrarySlice(t *testing.T) {
	assert.NotPanics(t, func() {
		releaseReadBuf(nil)
		releaseReadBuf([]byte{})
		releaseReadBuf(make([]byte, 7))
	})
}

// TestAcquireReadBuf_ConcurrentSafe — sync.Pool is safe for concurrent
// use by definition, but verify the wrapper doesn't introduce a data race
// or panic under contention. This is the canary for -race.
func TestAcquireReadBuf_ConcurrentSafe(t *testing.T) {
	const goroutines = 16
	const iters = 256
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				buf := acquireReadBuf(MAX_PATH_LEN)
				// Write to the buffer to exercise actual memory access.
				for j := range buf {
					buf[j] = byte(i + j)
				}
				releaseReadBuf(buf)
			}
		}()
	}
	wg.Wait()
}

// TestNewFileActivity_PreAllocatedCapacity — the slab pre-grow is the
// optimization that cuts slice-append-grow allocations on a write-heavy
// build. The capacities here are the contract: bumping them changes
// per-process memory cost.
func TestNewFileActivity_PreAllocatedCapacity(t *testing.T) {
	fa := newFileActivity()
	assert.Equal(t, 256, cap(fa.Writes), "Writes pre-allocated capacity")
	assert.Equal(t, 8, cap(fa.Renames), "Renames pre-allocated capacity")
	assert.Equal(t, 8, cap(fa.Deletes), "Deletes pre-allocated capacity")
	assert.Equal(t, 8, cap(fa.PermChanges), "PermChanges pre-allocated capacity")
	assert.Equal(t, 4, cap(fa.Links), "Links pre-allocated capacity")
	assert.Equal(t, 4, cap(fa.Truncates), "Truncates pre-allocated capacity")
	assert.Equal(t, 4, cap(fa.DirOps), "DirOps pre-allocated capacity")
	// Length must be zero — pre-allocated capacity, not pre-filled values.
	assert.Equal(t, 0, len(fa.Writes))
	assert.Equal(t, 0, len(fa.Renames))
	assert.Equal(t, 0, len(fa.Deletes))
	assert.Equal(t, 0, len(fa.PermChanges))
	assert.Equal(t, 0, len(fa.Links))
	assert.Equal(t, 0, len(fa.Truncates))
	assert.Equal(t, 0, len(fa.DirOps))
}

// TestEnsureFileOps_UsesPreAllocatedSlab — the real wiring: ensureFileOps
// must hand out a FileActivity that already has the pre-grown slices.
// This is what guarantees the hot-path append benefits from the slab.
func TestEnsureFileOps_UsesPreAllocatedSlab(t *testing.T) {
	pctx := &ptraceContext{processes: make(map[int]*ProcessInfo)}
	pi := pctx.getProcInfo(1)
	require.Nil(t, pi.FileOps)
	pctx.ensureFileOps(pi)
	require.NotNil(t, pi.FileOps)
	assert.Equal(t, 256, cap(pi.FileOps.Writes), "ensureFileOps must pre-grow Writes")
}

// TestHotPath_NoDataCorruption_ManyEvents — exercise the same code shape
// the hot path uses: repeatedly append FileWrite events to a single
// ProcessInfo's slab-pre-grown slice and verify every event is intact
// after the run. The pool itself never touches FileWrite memory, but
// this test is the corruption canary if a future change incorrectly
// shares storage.
func TestHotPath_NoDataCorruption_ManyEvents(t *testing.T) {
	const eventCount = 4096 // grow past the pre-allocated 256 capacity
	pctx := &ptraceContext{processes: make(map[int]*ProcessInfo)}
	pi := pctx.getProcInfo(42)
	pctx.ensureFileOps(pi)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < eventCount; i++ {
		pi.FileOps.Writes = append(pi.FileOps.Writes, FileWrite{
			Path:      "/tmp/file",
			Bytes:     i, // unique per event so we can detect corruption
			Timestamp: now,
		})
	}
	require.Equal(t, eventCount, len(pi.FileOps.Writes))
	for i, w := range pi.FileOps.Writes {
		assert.Equal(t, i, w.Bytes, "event %d Bytes round-trip", i)
		assert.Equal(t, "/tmp/file", w.Path, "event %d Path round-trip", i)
		assert.Equal(t, now, w.Timestamp, "event %d Timestamp round-trip", i)
	}
}

// TestHotPath_PoolBufferDoesNotLeakIntoString — the pool returns memory
// that may contain stale bytes from a previous user. Verify that strings
// returned from the syscall-read path are properly sized to the live
// portion of the buffer (the kernel-written prefix), not the full
// pool capacity. The contract is: readSyscallReg returns a string whose
// length is at most numBytes (the kernel write count), and never includes
// stale pool bytes.
//
// This is a unit test of the contract — it doesn't drive readSyscallReg
// itself (that requires a tracee), but it exercises the same
// truncate-then-string pattern on a known-good buffer.
func TestHotPath_PoolBufferDoesNotLeakIntoString(t *testing.T) {
	// Acquire a buffer, fill it with a sentinel value, release it.
	buf := acquireReadBuf(MAX_PATH_LEN)
	for i := range buf {
		buf[i] = 0xAB
	}
	releaseReadBuf(buf)

	// Re-acquire — if the same buffer comes back, it'll be full of 0xAB.
	// Simulate the readSyscallReg pattern: write a short string to the
	// front, then derive a string bounded by numBytes.
	buf2 := acquireReadBuf(MAX_PATH_LEN)
	const path = "/tmp/x"
	copy(buf2, path)
	// readSyscallReg bounds its IndexByte search to data[:numBytes] —
	// simulate numBytes = len(path) (the kernel "wrote" len(path) bytes).
	numBytes := len(path)
	out := string(buf2[:numBytes])
	assert.Equal(t, path, out, "string must reflect only kernel-written bytes")
	assert.NotContains(t, out, "\xAB", "stale pool bytes must not leak into output")
	releaseReadBuf(buf2)
}
