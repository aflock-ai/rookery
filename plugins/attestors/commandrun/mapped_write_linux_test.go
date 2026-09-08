// jade:ring local
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

// The mapped-write residual, written from the attacker's capability.
//
// A tracee can hold a writable MAP_SHARED mapping of a file it owns and
// change the file's contents through that mapping. The kernel stamps a
// file's timestamps on the write FAULT that first makes a clean page
// writable, not on the stores that follow while the page is already dirty
// and the PTE already writable. So after one fault, further content changes
// land with:
//
//	ctime unchanged, mtime unchanged, dev/ino unchanged, size unchanged.
//
// Nothing built out of stat(2) can see that -- not a comparison of two
// stats, not a longer wait before the first one.
//
// The window is wide but not literally unbounded: writeback can clean and
// write-protect the pages, after which the next store faults again and does
// stamp. It is attacker-influenced (the tracee chooses when to store) and
// entirely invisible from our side, which is what matters. These tests do
// not try to measure its length; they establish that it exists.
//
// They are the positive control for that claim (a check that COULD NOT RUN
// must never wear the value of one that FOUND NOTHING), and the regression
// for the consequence: because no read can be shown untorn, no digest may be
// served from a memo. See the mapped-write note on ebpf.SettleWindow.

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

// mappedPageSize is the mapping length used by these tests: several pages,
// so "dirty every page first" is a real step rather than an accident of a
// single-page file.
const mappedPageSize = 3 * 4096

// mapSharedWritable maps the whole of `path` PROT_READ|PROT_WRITE MAP_SHARED
// and returns the mapping. The mapping outlives the descriptor, which is the
// point: the tracee needs no open file and no syscall at all to keep
// rewriting the file once it holds this.
func mapSharedWritable(t *testing.T, path string, size int) []byte {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	m, err := syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Skipf("skipping: MAP_SHARED of a temp file is unavailable here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(m) })
	return m
}

// statKey is the four fields every stat-based identity check in this package
// compares: (device, inode, ctime, size). It is deliberately the same tuple
// as the production checks so a mismatch here means a mismatch there.
type statKey struct {
	dev, ino uint64
	ctimeSec int64
	ctimeNs  int64
	size     int64
	mtime    time.Time
}

func statKeyOf(t *testing.T, path string) statKey {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("skipping: no kernel stat available on this platform")
	}
	//nolint:unconvert // Stat_t field widths differ across GOARCH.
	return statKey{
		dev:      uint64(sys.Dev),
		ino:      uint64(sys.Ino),
		ctimeSec: int64(sys.Ctim.Sec),
		ctimeNs:  int64(sys.Ctim.Nsec),
		size:     st.Size(),
		mtime:    st.ModTime(),
	}
}

// stageDirtyMapping writes `content` to a new file, maps it writable, dirties
// every page through the mapping, and then waits until the resulting ctime is
// outside ebpf.SettleWindow.
//
// Dirtying BEFORE the wait is the whole trick, and getting it backwards is
// how a naive probe talks itself out of a real finding: on a filesystem that
// stamps the write fault (ext4 via ext4_page_mkwrite), the first store
// through a fresh mapping DOES move ctime. Taking that as proof that mapped
// writes are visible is wrong -- it is the fault that was visible, once.
// Absorb it here, wait it out, and every store afterwards is silent.
func stageDirtyMapping(t *testing.T, path string, content []byte) []byte {
	t.Helper()
	if len(content) != mappedPageSize {
		t.Fatalf("fixture: content is %d bytes, want %d", len(content), mappedPageSize)
	}
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	m := mapSharedWritable(t, path, mappedPageSize)
	// Take the write fault on every page, storing the bytes that are
	// already there so the file's content is unchanged by this step.
	copy(m, content)
	// Now wait the fault's timestamp out. From here the pages are dirty and
	// the PTEs writable, so a store does not fault -- until writeback
	// intervenes, which the callers' stat assertions would catch.
	waitPastSettleWindow(t, path)
	return m
}

// waitPastSettleWindow sleeps until `path`'s ctime is comfortably outside
// ebpf.SettleWindow, so a read of it settles immediately and the production
// code is exercised on its aged path rather than its waiting one.
func waitPastSettleWindow(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctim := st.Sys().(*syscall.Stat_t).Ctim
	age := time.Since(time.Unix(int64(ctim.Sec), int64(ctim.Nsec))) //nolint:unconvert // Timespec field widths differ across GOARCH
	if wait := ebpf.SettleWindow + 20*time.Millisecond - age; wait > 0 {
		time.Sleep(wait)
	}
}

// TestMappedWrite_ChangesContentWithoutMovingAnyStatField is the positive
// control for the residual this package documents rather than fixes. It
// asserts the attacker's capability directly: after the mapping is dirty,
// the file's bytes change and (dev, ino, ctime, mtime, size) do not.
//
// If the stats DO move, the test skips with both of them printed rather than
// passing quietly. That is a "could not stage it here", not a refutation:
// the likeliest cause is writeback having write-protected the pages between
// the two stores, which re-arms the fault. Treat a skip as an unmeasured
// run, never as evidence that mapped stores are observable.
func TestMappedWrite_ChangesContentWithoutMovingAnyStatField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mapped")
	a := bytes.Repeat([]byte("A"), mappedPageSize)
	b := bytes.Repeat([]byte("B"), mappedPageSize)

	m := stageDirtyMapping(t, path, a)
	before := statKeyOf(t, path)

	// The second write: stores into pages that are already dirty and
	// already writable in the PTE. No fault, so no file_update_time.
	copy(m, b)

	after := statKeyOf(t, path)
	if before != after {
		t.Skipf("skipping: the stats moved across the second store (before=%+v after=%+v), so this run did not stage the case. "+
			"That is an UNMEASURED run, not a refutation: the likeliest cause is writeback having cleaned and write-protected the pages "+
			"between the two stores, which re-arms the fault. It does not show that this kernel or filesystem stamps stores through an "+
			"established mapping, and nothing here licenses relying on mapped writes being observable.", before, after)
	}

	// The bytes really did change: mmap and read(2) share the page cache on
	// Linux, so a reader sees B with no msync.
	got, err := os.ReadFile(path) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, b) {
		t.Fatalf("fixture: read(2) did not observe the mapped store; got %q... want %q...", got[:8], b[:8])
	}
	t.Logf("content changed A->B with every stat field identical: dev=%d ino=%d ctime=%d.%09d size=%d mtime=%v",
		after.dev, after.ino, after.ctimeSec, after.ctimeNs, after.size, after.mtime)
}

// TestDigestBinding_MappedRewriteIsNeverServedAStaleDigest is the regression
// the eighth review round asked for: "add a regression using a persistent
// writable mapping".
//
// Hash A while the file is aged and settled -- the most favourable case any
// stat-based cache has, and precisely the case a freshness rule admits.
// Then change the content to B through the still-live mapping. Every field
// a cache could key on is unchanged, so a cache MUST return A's digest for
// B's bytes. The only implementation that passes is one that does not serve
// digests from a memo at all.
func TestDigestBinding_MappedRewriteIsNeverServedAStaleDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	a := bytes.Repeat([]byte("A"), mappedPageSize)
	b := bytes.Repeat([]byte("B"), mappedPageSize)

	m := stageDirtyMapping(t, path, a)
	before := statKeyOf(t, path)

	pctx := newDigestTestContext(t)
	first, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("first hash: no digest for an aged, settled, undisturbed file")
	}
	if got, want := firstHex(first), sha256Hex(t, a); got != want {
		t.Fatalf("first hash: got %s want %s", got, want)
	}

	copy(m, b)

	if after := statKeyOf(t, path); before != after {
		t.Skipf("skipping: the stats moved across the mapped rewrite (before=%+v after=%+v), so the attack was not staged on this run "+
			"(most likely writeback re-armed the write fault). An UNMEASURED run, not evidence that the attack is unavailable here; "+
			"see TestMappedWrite_ChangesContentWithoutMovingAnyStatField.", before, after)
	}

	second, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("second hash: no digest")
	}
	if got, want := firstHex(second), sha256Hex(t, b); got != want {
		t.Fatalf("a digest was served for bytes it does not describe: got %s (A) want %s (B). "+
			"Every stat field was identical across the mapped rewrite, so no stat-keyed memo "+
			"can be correct here; the digest must be recomputed on every read.", got, want)
	}
}
