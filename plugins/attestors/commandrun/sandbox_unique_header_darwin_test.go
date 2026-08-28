//go:build darwin

package commandrun

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The fallback pid parser runs exactly when the strict grammar failed — an
// exec path with a newline in it — and it was non-greedy, so a planted
// header in the process NAME won: the report was attributed to pid 1,
// launchd, read as a stranger's, and the build's own unreadable exec was
// dropped instead of refusing. A pid is recoverable only when both readings
// of the line agree on it.
func TestUnparseablePidNeedsAUniqueReading(t *testing.T) {
	t.Parallel()
	// Planted "(1) allow process-fork " ahead of the kernel's own triple.
	if pid, ok := unparseableReportPid("Sandbox: x(1) allow process-fork sh(4242) allow process-exec* /tmp/a\nb"); ok {
		t.Errorf("a planted header was accepted as the reporter's pid (%d); the build's unreadable exec would be filed as a stranger's", pid)
	}
	// One reading only: the kernel's. Recoverable.
	pid, ok := unparseableReportPid("Sandbox: sh(4242) allow process-exec* /tmp/a\nb")
	if !ok || pid != 4242 {
		t.Fatalf("an unambiguous unparseable report lost its pid: pid=%d ok=%v", pid, ok)
	}
}

// ctime is not a counter. A filesystem with coarse or cached timestamps can
// report the same ctime for an in-place rewrite that kept the size, so
// "stamp unchanged" is only proof of untouched-ness once the clock has moved
// past the granularity. Within it, the bytes must be read.
func TestPinReuseRehashesWhileTheStampCouldStillCollide(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	const body = "#!/bin/sh\necho A\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	first := s.pin(path, time.Now(), true)
	if first == 0 {
		t.Fatal("pin failed")
	}
	// Rewrite in place, same length, and make the recorded stamp claim the
	// inode never moved — what a 1-second-granularity filesystem reports.
	rewriteInPlace(t, path, "#!/bin/sh\necho B\n")
	for id, img := range s.pinned {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, stamp, err := imageIdentityOf(f)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		img.stamp = stamp
		img.hashedAt = time.Unix(stamp.ctimeSec, stamp.ctimeNsec) // hashed within the same tick
		s.pinned[id] = img
	}
	second := s.pin(path, time.Now(), true)
	if second == first {
		t.Fatal("a rewritten inode reused its pin because the stamp looked unchanged; the second exec would be attested with the first exec's bytes")
	}
}

// The settled rule itself: a stamp is only trustworthy once the clock has
// moved a full granularity past the moment the bytes were read.
func TestStampSettledNeedsAFullTick(t *testing.T) {
	t.Parallel()
	st := inodeStamp{ctimeSec: 1000, ctimeNsec: 0, size: 10}
	if stampSettled(st, time.Unix(1000, 500)) {
		t.Error("a stamp hashed inside the same second was trusted")
	}
	if !stampSettled(st, time.Unix(1002, 0)) {
		t.Error("a stamp two seconds older than the hash was not trusted; every repeat exec would re-read its image")
	}
}
