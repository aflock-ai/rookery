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

import "sync"

// Hot-path allocator helpers for the ptrace event loop. The trace attestor
// fires on EVERY syscall in the traced subtree — for a write-heavy build
// that's easily 100K+ events. This file holds the two complementary
// optimizations that cut allocator pressure on that path:
//
//  1. sync.Pool-backed scratch buffer for ProcessVMReadv (acquireReadBuf /
//     releaseReadBuf). Every readSyscallReg / parseSockaddr / extractTLSSNI
//     call previously did `make([]byte, n)` on entry; the kernel then
//     COPIES tracee memory into that buffer and we COPY OUT into a string
//     before the function returns. The buffer's lifetime is the syscall
//     handler scope — a textbook fit for sync.Pool.
//
//  2. Pre-grown slab capacity on FileActivity slices (newFileActivity).
//     The default `append` doubles the slice's underlying array each grow,
//     which means a process emitting N writes allocates log2(N)+1 backing
//     arrays. Pre-sizing the largest-frequency slice (`Writes`) to 256
//     covers a typical Go test binary with zero grows and a multi-thousand-
//     write build with one.
//
// Why NOT pool the event structs (FileWrite, SyscallEvent) themselves?
// Because they're stored BY VALUE in slices and outlive the syscall handler.
// Returning them to a pool while still referenced by ProcessInfo would be
// a use-after-free. The append-growth slab approach captures most of the
// available win without that risk.

// readBufSize is the buffer size pooled for ProcessVMReadv reads. All four
// call sites in tracing_linux.go ask for one of {MAX_PATH_LEN, 256, 128, 16,
// 512} — MAX_PATH_LEN (4096) is the dominant size and the only one large
// enough that a make() is non-trivial. We pool ONE size (MAX_PATH_LEN) and
// hand out shorter sub-slices when the caller asks for less; this keeps
// the pool simple and avoids fragmentation.
const readBufSize = MAX_PATH_LEN

// readBufPool holds reusable MAX_PATH_LEN-sized byte arrays for syscall
// memory reads. We pool *[readBufSize]byte (an ARRAY POINTER) — not a
// *[]byte slice header — because:
//
//   - sync.Pool wraps elements in interface{}. A *[N]byte is a single
//     machine word; the interface wrap is escape-free. A *[]byte forces
//     a slice-header heap alloc on every Put (24 bytes on 64-bit), which
//     defeats much of the pool's purpose.
//   - The backing array is allocated ONCE by New(); subsequent Get/Put
//     cycles touch only the pointer.
//
// The result: acquire/release round-trips at zero allocs after pool
// warm-up. See BenchmarkHotPath_ReadBuffer for the measured number.
var readBufPool = sync.Pool{
	New: func() any {
		var a [readBufSize]byte
		return &a
	},
}

// acquireReadBuf returns a scratch byte slice of length n suitable for
// reading a tracee's memory. The returned slice is drawn from a sync.Pool;
// the caller MUST call releaseReadBuf on the SAME slice (not a sub-slice)
// when done. Failure to release just leaks the buffer to the GC — it
// doesn't corrupt anything, but the optimization is wasted.
//
// Contract:
//   - n must be <= readBufSize (MAX_PATH_LEN). Callers in this package
//     already cap their requests at MAX_PATH_LEN or smaller constants
//     (16, 128, 256, 512).
//   - The returned bytes are NOT zeroed. Callers must not read positions
//     they haven't first written. All current call sites pass the buffer
//     to ProcessVMReadv, which writes 'numBytes' bytes; subsequent reads
//     are bounded by `data[:numBytes]` or by bytes.IndexByte(data, 0)
//     followed by truncation — both safe even with stale bytes.
//   - The returned slice must not be retained beyond the calling function.
func acquireReadBuf(n int) []byte {
	if n > readBufSize {
		// Out of pooled range — fall back to a one-shot allocation.
		// This path should never fire given the current call sites
		// (all are <= MAX_PATH_LEN), but the guard keeps the pool
		// contract safe if someone adds a larger read later.
		return make([]byte, n)
	}
	arr := readBufPool.Get().(*[readBufSize]byte)
	return arr[:n]
}

// releaseReadBuf returns a buffer that was previously handed out by
// acquireReadBuf. After calling release, the caller MUST NOT touch the
// slice — the pool may hand it to another goroutine immediately.
//
// Buffers larger than readBufSize (from the fallback path) are dropped
// on the floor, not pooled — they'd skew the pool size distribution.
func releaseReadBuf(buf []byte) {
	if cap(buf) != readBufSize {
		return // fallback alloc — let GC handle it
	}
	// Recover the underlying [readBufSize]byte array via a slice→array
	// pointer conversion (Go 1.17+). The conversion checks at runtime
	// that len(buf[:readBufSize]) == readBufSize, which we guaranteed
	// above by the cap() check.
	arr := (*[readBufSize]byte)(buf[:readBufSize])
	readBufPool.Put(arr)
}

// newFileActivity constructs a FileActivity with pre-allocated slice
// capacity for the highest-frequency event types. The capacity here is
// the "slab" — we pay it once on first ensureFileOps() and amortize the
// per-append slice-grow cost across the rest of the trace.
//
// Capacity rationale (calibrated against captured Go-build traces):
//
//   - Writes: 256 covers ~30k-event builds with one realloc and a typical
//     ~1k-event build with none. SYS_WRITE is by far the highest-frequency
//     mutator in normal builds.
//   - Renames/Deletes/PermChanges: 8 each — these are rare in normal
//     builds (atomic rename, rm, chmod). A small constant pre-alloc
//     saves the first grow without wasting much.
//   - Links/Truncates/DirOps: 4 each — same logic, even rarer.
//
// Memory cost: if the pre-allocated slice never sees an append, the wasted
// capacity is roughly 256 * sizeof(FileWrite) ≈ 6 KB per ProcessInfo plus
// a few hundred bytes for the smaller slices — acceptable for any
// reasonable trace, and a one-time cost (the FileActivity is allocated
// lazily on first file-mutation syscall).
func newFileActivity() *FileActivity {
	return &FileActivity{
		Writes:      make([]FileWrite, 0, 256),
		Renames:     make([]FileRename, 0, 8),
		Deletes:     make([]FileDelete, 0, 8),
		PermChanges: make([]FilePermChange, 0, 8),
		Links:       make([]FileLink, 0, 4),
		Truncates:   make([]FileTruncate, 0, 4),
		DirOps:      make([]DirOp, 0, 4),
	}
}
