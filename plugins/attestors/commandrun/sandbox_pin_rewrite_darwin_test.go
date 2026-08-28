// Copyright 2026 TestifySec, Inc.
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

//go:build darwin

package commandrun

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A pinned fd holds an INODE, not bytes: rewriting the same inode in place
// after the exec changes what a later digest reads, and macOS does not enforce
// ETXTBSY, so a build can do exactly that between its exec and the session's
// snapshot. The signed digest would then describe bytes that never ran —
// worse than no digest. The pin therefore records the inode's ctime and size
// at report time, and hashing REFUSES an inode whose identity moved: the
// digest is dropped and counted in pinFailures (surfacing as imagesUnhashed),
// which fails toward "we cannot prove which bytes ran" instead of toward a
// confident wrong answer.
func TestInPlaceRewriteAfterPinDropsTheDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho executed-bytes\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	s := pinSession()
	pin := s.pin(path, time.Now(), true)
	if pin == 0 {
		t.Fatal("pin failed for a readable file")
	}

	// Rewrite the SAME inode: O_WRONLY on the existing path, no rename.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("#!/bin/sh\necho replaced-bytes-same-inode\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	digests := s.hashPinnedImages(sha256Only)
	failures := s.pinFailures
	s.mu.Unlock()

	if _, ok := digests[pin]; ok {
		t.Fatalf("an inode rewritten after its exec was digested anyway — the signed digest would describe bytes that never ran")
	}
	if failures == 0 {
		t.Error("the refused digest was not counted in pinFailures; the gap must be visible in imagesUnhashed")
	}
}

// The happy path must keep its digest: an inode that did NOT change between
// report time and hashing is measured normally.
func TestUnchangedInodeKeepsItsDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho executed-bytes\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	pin := s.pin(path, time.Now(), true)
	if pin == 0 {
		t.Fatal("pin failed for a readable file")
	}
	s.mu.Lock()
	digests := s.hashPinnedImages(sha256Only)
	s.mu.Unlock()
	if _, ok := digests[pin]; !ok {
		t.Fatal("an untouched inode lost its digest")
	}
}

// Same inode, rewritten between two execs: the second exec loaded different
// bytes than the first, so reusing the first pin would name the wrong bytes
// for one of them. The rewritten inode must get a pin of its own, hashed
// then, and the first pin must be retired — its digest refused at the end.
func TestRewrittenInodeGetsItsOwnPinAndRetiresTheOld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho first-bytes\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	first := s.pin(path, time.Now(), true)
	if first == 0 {
		t.Fatal("pin failed for a readable file")
	}
	rewriteInPlace(t, path, "#!/bin/sh\necho second-bytes-same-inode\n")
	second := s.pin(path, time.Now(), true)
	if second == 0 {
		t.Fatal("pin failed after the rewrite")
	}
	if second == first {
		t.Fatalf("the rewritten inode reused pin %d — the second exec would be signed with the first exec's bytes", first)
	}

	s.mu.Lock()
	digests := s.hashPinnedImages(sha256Only)
	s.mu.Unlock()
	if _, ok := digests[first]; ok {
		t.Fatal("the retired pin was digested — the first exec's bytes are gone and must not be described")
	}
	if _, ok := digests[second]; !ok {
		t.Fatal("the current inode lost its digest")
	}
}

// The ABA shape: execute A, rewrite to B, execute B, put A back before the run
// ends. A single path-keyed pin compared by content at the end would sign A
// for both execs, since the bytes match again. Instead the second exec's
// rehash retires the first pin (refused for good), and the second pin's bytes
// no longer match what it hashed, so BOTH digests must be refused.
func TestRestoredBytesDoNotResurrectAPin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	const a = "#!/bin/sh\necho A\n"
	if err := os.WriteFile(path, []byte(a), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	first := s.pin(path, time.Now(), true)
	rewriteInPlace(t, path, "#!/bin/sh\necho B-B-B-B\n")
	second := s.pin(path, time.Now(), true)
	rewriteInPlace(t, path, a)

	s.mu.Lock()
	digests := s.hashPinnedImages(sha256Only)
	failures := s.pinFailures
	s.mu.Unlock()
	for name, pin := range map[string]pinID{"first": first, "second": second} {
		if _, ok := digests[pin]; ok {
			t.Errorf("the %s pin was digested although the inode was rewritten after it — the digest would be a guess", name)
		}
	}
	if failures < 2 {
		t.Errorf("pinFailures = %d, want at least 2: both refusals must surface in imagesUnhashed", failures)
	}
}

// rewriteInPlace replaces the content of the SAME inode: O_TRUNC on the
// existing path, no rename.
func rewriteInPlace(t *testing.T, path, body string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// A hard link or chmod moves the inode's ctime without changing a byte. That
// must NOT retire the pin: the rehash finds the same bytes and the pin is
// reused, or every build that links its tools would lose their digests.
func TestTouchedButUnchangedInodeKeepsItsPin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho same-bytes\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	first := s.pin(path, time.Now(), true)
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if again := s.pin(path, time.Now(), true); again != first {
		t.Fatalf("a chmod retired pin %d for a new pin %d although the bytes did not change", first, again)
	}
	s.mu.Lock()
	digests := s.hashPinnedImages(sha256Only)
	retired := int(s.retiredPins)
	s.mu.Unlock()
	if _, ok := digests[first]; !ok || retired != 0 {
		t.Fatalf("unchanged bytes lost their digest (present=%v, retired=%d)", ok, retired)
	}
}

// The reported path is the tracee's to arrange after the exec. Pointed at a
// FIFO or a device, a naive open-and-read-to-EOF would block the collector
// goroutine forever and, with it, shutdown. Both must be refused promptly.
func TestPinRefusesFIFOsAndDevicesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	dev := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", dev); err != nil {
		t.Fatal(err)
	}
	done := make(chan [2]pinID, 1)
	go func() {
		s := pinSession()
		done <- [2]pinID{s.pin(fifo, time.Now(), true), s.pin(dev, time.Now(), true)}
	}()
	select {
	case pins := <-done:
		if pins[0] != 0 || pins[1] != 0 {
			t.Fatalf("pins = %v, want both refused", pins)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pin blocked on a FIFO or a device — the collector would never shut down")
	}
}

// A multi-gigabyte image is not read; it is refused a digest and counted.
func TestPinRefusesOversizedImages(t *testing.T) {
	old := maxImageBytes
	maxImageBytes = 1024
	t.Cleanup(func() { maxImageBytes = old })
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, 2048), 0o700); err != nil {
		t.Fatal(err)
	}
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, make([]byte, 1024), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	if s.pin(big, time.Now(), true) != 0 || s.pinFailures != 1 {
		t.Fatalf("an image over the cap was hashed (failures=%d)", s.pinFailures)
	}
	if s.pin(small, time.Now(), true) == 0 {
		t.Fatal("an image exactly at the cap was refused")
	}
}

// Retiring a pin closes its fd at once; a tracee rewriting one inode in a
// loop cannot make the session hold descriptors it will never use.
func TestRetiredPinsHoldNoDescriptors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	s := pinSession()
	for i := 0; i < 20; i++ {
		rewriteInPlaceOrCreate(t, path, fmt.Sprintf("#!/bin/sh\necho %d\n", i))
		if s.pin(path, time.Now(), true) == 0 {
			t.Fatalf("pin %d failed", i)
		}
	}
	if s.retiredPins != 19 || len(s.pinned) != 1 {
		t.Fatalf("retiredPins=%d pinned=%d, want 19 retired and exactly one live pin", s.retiredPins, len(s.pinned))
	}
	for _, img := range s.pinned {
		_ = img.file.Close()
	}
}

func rewriteInPlaceOrCreate(t *testing.T, path, body string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
