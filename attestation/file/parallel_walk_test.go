// jade:ring local

package file

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// Two symlinks to one target from different directories: the walker records
// the target once, under the FIRST link in filepath.Walk's order. A parallel
// scan must not let scheduling decide which one that is, or the material
// tree's root would change between runs of an unchanged tree.
func TestSymlinkRecordingIsDeterministicUnderTheParallelScan(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "m", "z", "target"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "target", "f"), []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"z", "m", "a"} {
		if err := os.Symlink(filepath.Join(root, "target"), filepath.Join(root, d, "link")); err != nil {
			t.Fatal(err)
		}
	}
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	for i := 0; i < 8; i++ {
		m, err := RecordArtifacts(root, nil, hashes, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := m[filepath.Join("a", "link", "f")]; !ok {
			t.Fatalf("run %d: the target was not recorded under the first link in walk order; got %v", i, keys(m))
		}
		for _, later := range []string{filepath.Join("m", "link", "f"), filepath.Join("z", "link", "f")} {
			if _, ok := m[later]; ok {
				t.Fatalf("run %d: the target was recorded a second time under %s", i, later)
			}
		}
	}
}

func TestWalkOrderLessIsDepthFirstLexical(t *testing.T) {
	cases := [][2]string{{"a", "b"}, {"a/b", "a-b"}, {"a/b", "a/c"}, {"a", "a/b"}, {"x/y/z", "x/z"}}
	for _, c := range cases {
		if !walkOrderLess(c[0], c[1]) || walkOrderLess(c[1], c[0]) {
			t.Errorf("want %q before %q", c[0], c[1])
		}
	}
}

func keys(m map[string]cryptoutil.DigestSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A cached directory handle points at an inode, not a name. If the directory
// is renamed away and replaced between the walk and the open, the handle still
// resolves to the OLD directory, so the worker would hash the old directory's
// file and record it under the new path — one file's bytes under another
// file's name. The walk refuses instead.
// The mirror of the test below, and the reason the handle cache is gone.
//
// Here the walk saw the file AFTER the directory was replaced, so the file it
// described and the file at that path are the same one — and recording its
// digest is CORRECT, not a refusal. This test used to assert a refusal, which
// was only ever true because a cached directory handle opened the OLD file; with
// the open resolved from the top root there is no stale handle to catch, so the
// assertion was rewritten rather than deleted. It now guards the property that
// actually matters: the bytes recorded are the ones the path names NOW.
func TestAReplacedDirectoryRecordsTheCurrentFileNotTheReplacedOne(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	top, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = top.Close() }()

	// d is replaced wholesale, and only then does the walk see the file.
	if err := os.Rename(dir, filepath.Join(root, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	replaced := filepath.Join(dir, "f")
	if err := os.WriteFile(replaced, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	walked, err := os.Lstat(replaced)
	if err != nil {
		t.Fatal(err)
	}

	got, err := hashInRoot(top, filepath.Join("d", "f"), walked, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		t.Fatalf("the walk saw the current file; hashing it must succeed: %v", err)
	}
	want := sha256.Sum256([]byte("replacement"))
	stale := sha256.Sum256([]byte("original"))
	switch got[cryptoutil.DigestValue{Hash: crypto.SHA256}] {
	case hex.EncodeToString(want[:]):
		// correct: the bytes at the path as it stands now
	case hex.EncodeToString(stale[:]):
		t.Fatal("recorded the REPLACED file's digest under the current path")
	default:
		t.Fatalf("unexpected digest: %v", got)
	}
}

func TestAWideTreeDoesNotSpawnAGoroutinePerDirectory(t *testing.T) {
	root := t.TempDir()
	const dirs = 800
	for i := range dirs {
		d := filepath.Join(root, fmt.Sprintf("d%04d", i))
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// NumGoroutine reads concurrently changing scheduler counters and can
	// transiently overcount freed goroutines from earlier package tests.
	// Count complete stack snapshots instead; retain the bound below.
	stacks := make([]byte, 1<<20)
	count := func() int {
		n := runtime.Stack(stacks, true)
		if n == len(stacks) {
			return len(stacks) // a truncated snapshot must fail the bound
		}
		return bytes.Count(stacks[:n], []byte("\ngoroutine ")) + 1
	}
	before := count()
	peak := before
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if n := count(); n > peak {
					peak = n
				}
				runtime.Gosched()
			}
		}
	}()

	// fn runs on the pool's workers, so the count is atomic — see
	// parallelWalk's contract.
	var seen atomic.Int64
	err := parallelWalk(root, func(_ string, info fs.FileInfo) error {
		if info.Mode().IsRegular() {
			seen.Add(1)
		}
		return nil
	})
	close(stop)
	wg.Wait()

	if err != nil {
		t.Fatal(err)
	}
	if seen.Load() != dirs {
		t.Fatalf("saw %d files, want %d", seen.Load(), dirs)
	}
	// The pool is GOMAXPROCS workers plus this test's sampler; a per-directory
	// spawn would put hundreds here.
	if grew := peak - before; grew > 4*runtime.GOMAXPROCS(0)+8 {
		t.Fatalf("goroutines grew by %d while walking %d directories; the pool must be bounded", grew, dirs)
	}
}

// Codex, #9436: the ordering that TestAReplacedDirectoryIsRefusedNotRecorded
// misses, and the one the walk actually produces. The walker lstats a file and
// a worker opens it LATER, so `walked` describes the file as it was BEFORE any
// replacement — not after.
//
//	prime the handle for d
//	walked := lstat(d/f)        <- the ORIGINAL file
//	rename d away; create a new d with a new d/f
//	hash d/f
//
// A cached handle opens the OLD d/f, and os.SameFile(walked, hashed) SUCCEEDS
// because both describe the old inode. The guard passes and the old file's
// digest is recorded under a path that now names a different file. That is
// EVIDENCE_UNBOUND: the digest is bound to the inode observed, but published
// under a path that no longer resolves to it.
func TestAReplacedDirectoryIsRefusedWhenTheWalkSawTheOriginal(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dir, "f")
	if err := os.WriteFile(original, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	top, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = top.Close() }()
	// The walk saw the ORIGINAL file. This is the ordering that matters.
	walked, err := os.Lstat(original)
	if err != nil {
		t.Fatal(err)
	}

	// Only now is d replaced wholesale.
	if err := os.Rename(dir, filepath.Join(root, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := hashInRoot(top, filepath.Join("d", "f"), walked, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err == nil {
		t.Fatalf("recorded a digest for d/f through a stale handle; the bytes hashed were the REPLACED file's, not the current d/f: %v", got)
	}
	if !strings.Contains(err.Error(), "changed identity between the walk and the open") {
		t.Fatalf("error should name the mechanism, got: %v", err)
	}
}

// vanishingEntry is a directory entry whose Info() reports that the file is
// gone — exactly the readdir/lstat interleaving, without racing for it.
type vanishingEntry struct{ name string }

func (v vanishingEntry) Name() string      { return v.name }
func (v vanishingEntry) IsDir() bool       { return false }
func (v vanishingEntry) Type() fs.FileMode { return 0 }
func (v vanishingEntry) Info() (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: v.name, Err: fs.ErrNotExist}
}

// A file removed between enumeration and lstat is a DETECTED inconsistency in
// the tree being attested. Skipping it omits it from a SUCCESSFUL inventory,
// which is a silent hole in signed evidence: remove a file after enumeration
// and recreate it, and nothing records that it was ever there. The walk this
// replaced returned the error from its callback and aborted.
func TestAVanishedEntryFailsTheWalkRatherThanBeingSkipped(t *testing.T) {
	var visited int
	w := &parallelWalker{fn: func(path string, info fs.FileInfo) error {
		visited++
		return nil
	}}
	w.cond = sync.NewCond(&w.mu)

	if w.visitEntry(filepath.Join("d", "gone.txt"), vanishingEntry{name: "gone.txt"}) {
		t.Fatal("the scan continued past a vanished entry; it would land in a successful inventory with the file silently absent")
	}
	if w.firstErr == nil {
		t.Fatal("no error recorded, so the walk would report success for an inventory it knows is incomplete")
	}
	if !errors.Is(w.firstErr, fs.ErrNotExist) {
		t.Errorf("the recorded error should name the missing file, got: %v", w.firstErr)
	}
	if !w.stop.Load() {
		t.Error("the walk was not stopped, so other workers keep recording into an inventory already known to be wrong")
	}
	if visited != 0 {
		t.Errorf("the callback ran %d times for an entry that could not be stat'd", visited)
	}
}
