//go:build darwin

package commandrun

import (
	"github.com/aflock-ai/rookery/attestation/cryptoutil"

	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ctimeOf reads the inode's change time — the field pin compares against the
// report, and the one os.Chtimes cannot set.
func ctimeOf(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat of %s carried no Stat_t", path)
	}
	return time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec)
}

// THE RENAME-OVER DURING DELIVERY LATENCY. The report names a path; the
// collector opens that path when the report reaches it, which is after the
// exec — the unified log is a queue, not a callback. A build can exec
// disallowed image A and rename allowed image B over that path before the
// open runs. B is unchanged from there to the end of the run, so the
// end-of-run content check sees nothing wrong and B's digest would be signed
// as the image that executed. Nothing in the report names the vnode, so no
// later check can catch it.
//
// The one thing that separates them is that the file which ACTUALLY ran
// existed before the kernel reported the exec: a rename or a create sets the
// inode's ctime, so an inode whose ctime is later than the report's own
// timestamp is provably not what ran. It gets no digest, and the exec then
// counts as attributed-but-undigested, which refuses the trace.
//
// This is a bound, not a fix, and the label says so: the digest binds
// collector-open time, not exec time. A same-tick replacement on a
// whole-second filesystem, or a symlink retargeted to a pre-existing inode,
// still passes — see darwinTraceLimitations.
func TestImageReplacedDuringDeliveryLatencyGetsNoDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sh")

	// The exec the kernel reported. Its report is stamped now.
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho ran\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	reportedAt := time.Now()

	s := pinSession()
	if id := s.pin(path, reportedAt, true); id == 0 {
		t.Fatalf("the inode that actually ran was refused a pin (failures=%d)", s.pinFailures)
	}

	// Now the swap, in the window before the collector opened the path: a
	// DIFFERENT inode renamed over the same name. Its ctime is later than the
	// report, which is the only evidence that it is not what ran.
	other := filepath.Join(dir, "staged")
	if err := os.WriteFile(other, []byte("#!/bin/sh\necho attacker\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	// The check has exactly one input, and on a filesystem whose ctime is
	// whole-second the swap can land inside the report's own tick — the
	// stated residual. Say so out loud instead of failing as if the code
	// were wrong: the assertion below is only meaningful once the two
	// timestamps are distinguishable at all.
	if swapped := ctimeOf(t, path); !swapped.After(reportedAt) {
		t.Skipf("this filesystem could not distinguish the swap (ctime %v) from the report (%v) — "+
			"the same-tick replacement this test's subject cannot catch", swapped, reportedAt)
	}

	s2 := pinSession()
	if id := s2.pin(path, reportedAt, true); id != 0 {
		t.Fatalf("pin %d: an inode created AFTER the exec was reported was measured as the image that ran — "+
			"a disallowed binary's event would carry an allowed binary's digest", id)
	}
	if s2.pinFailures != 1 {
		t.Fatalf("pinFailures = %d, want 1 — the refusal has to be counted, or the exec is silently undigested "+
			"instead of refusing the trace", s2.pinFailures)
	}
}

// A report whose timestamp could not be parsed leaves nothing to compare the
// inode's ctime against, so the replaced-image case above cannot be ruled
// out. A check that cannot run must not pass by default.
func TestPinWithoutAReportTimeFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	if id := s.pin(path, time.Time{}, false); id != 0 {
		t.Fatalf("pin %d: an unparseable report time was treated as permission to skip the replacement check", id)
	}
	if s.pinFailures != 1 {
		t.Fatalf("pinFailures = %d, want 1", s.pinFailures)
	}
}

// THE SYMLINK RETARGET, which the ctime check does NOT catch — asserted here
// rather than described, so the residual cannot quietly stop being true.
//
// openImage follows symlinks, and the collector opens the reported path after
// report delivery. So a tracee can exec image A through a symlink, retarget
// that symlink at a PRE-EXISTING image B before the open, and B is measured
// for A's exec event: retargeting sets the SYMLINK's ctime, not B's, and B was
// created before the report, so the replacement check (which stats the
// followed target) passes. B is unchanged from there to the end of the run, so
// the end-of-run content check passes too.
//
// This is why the field is named PathDigestAtCollectorOpen and not Digest, and
// why DigestSource says "collector-open-path-hash": the measurement is an
// observation of a PATH, and a consumer that reads it as the bytes that
// executed is reading a claim this backend cannot make. Closing it needs the
// vnode the kernel loaded, which needs Endpoint Security, which the
// install-nothing constraint rules out.
func TestSymlinkRetargetToOlderInodeIsNotCaught(t *testing.T) {
	dir := t.TempDir()
	realA := filepath.Join(dir, "A")
	realB := filepath.Join(dir, "B")
	link := filepath.Join(dir, "tool")

	// B exists BEFORE the exec is reported — that is the whole trick.
	if err := os.WriteFile(realB, []byte("#!/bin/sh\necho attacker\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realA, []byte("#!/bin/sh\necho ran\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realA, link); err != nil {
		t.Fatal(err)
	}
	reportedAt := time.Now()

	// The swap, inside the delivery window: repoint the symlink at B.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realB, link); err != nil {
		t.Fatal(err)
	}

	s := pinSession()
	id := s.pin(link, reportedAt, true)
	if id == 0 {
		// If this ever starts failing closed, the residual has been fixed and
		// this test should become an assertion that it IS caught.
		t.Skipf("the retarget was refused a pin (failures=%d) — the residual this test documents no longer "+
			"exists, so invert the assertion", s.pinFailures)
	}
	digests := s.hashPinnedImages(sha256Only)
	got, ok := digests[id]
	if !ok {
		t.Fatalf("pin %d produced no digest", id)
	}
	wantB := digestOfFile(t, realB)
	wantA := digestOfFile(t, realA)
	if hexOf(t, got) == hexOf(t, wantA) {
		t.Fatalf("the digest matched image A: the collector is binding the executed vnode after all, which " +
			"this backend has no way to do — check what changed before trusting it")
	}
	if hexOf(t, got) != hexOf(t, wantB) {
		t.Fatalf("digest = %s, want B's (%s): the retargeted target is what gets measured",
			hexOf(t, got), hexOf(t, wantB))
	}
	// Stated, not implied: the signed evidence for A's exec carries B's bytes.
	// The NAME and DigestSource are what stop a consumer reading that as "A ran
	// these bytes".
}

// digestOfFile measures a file the same way hashPinnedImages does, so the two
// are comparable.
func digestOfFile(t *testing.T, path string) cryptoutil.DigestSet {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromFile(path, sha256Only)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}
