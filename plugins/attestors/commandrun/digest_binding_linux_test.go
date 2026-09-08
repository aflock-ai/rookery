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

// Forgeries a same-uid tracee can perform against the digest fields a
// process allowlist would read. Found by the 2026-09-07 cilockd adversary
// review and by eight rounds of review on judge#9044; written from the
// attacker's capability, not from the fix.
//
// The original defect: the per-trace digest memo was keyed by
// (path, size, mtime). The file's owner sets mtime with utimensat(2) and
// pads size with truncate(2), so a trojan copied over an already-hashed
// path, padded to the same size and stamped with the same mtime, was served
// the genuine digest from the memo on every later exec.
//
// The memo is now gone entirely -- see the no-memo note above digestForPath
// and mapped_write_linux_test.go for why no key could have survived -- so
// these read as regressions against a memo being reintroduced under any key.

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

// stagedWriteDelay is how long a staged writer waits after being released
// before it rewrites the file under a hash that is already running.
//
// It establishes the ordering the torn-read regressions depend on -- the
// write must BEGIN after the hasher's pre-read fstat -- by margin, not by
// synchronisation. User space cannot synchronise with an fstat taken inside
// the hasher, so the writer is parked on a channel released immediately
// before the call, the file is aged so the settle inside the call is a
// no-op, and the delay is then far longer than the microseconds between the
// release and that fstat while still landing well inside a 24 MiB read.
//
// If a test using it ever fails with a digest of neither whole content, the
// overwhelmingly likely cause is the bracket having been weakened. The other
// explanation is the documented in-flight-write residual (ext4 stamps in
// file_modified() before copying, so a write that stamped and then stalled
// past the settle window is invisible), which would require this process to
// be descheduled for longer than the delay at exactly the wrong moment.
const stagedWriteDelay = 10 * time.Millisecond

func newDigestTestContext(t *testing.T) *ptraceContext {
	t.Helper()
	return &ptraceContext{
		processes: make(map[int]*ProcessInfo),
		hash:      []cryptoutil.DigestValue{{Hash: crypto.SHA256}},
	}
}

func sha256Hex(t *testing.T, b []byte) string {
	t.Helper()
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func firstHex(ds cryptoutil.DigestSet) string {
	for _, v := range ds {
		return v
	}
	return ""
}

// waitForCtimeTick blocks until the kernel's inode clock has advanced past
// the ctime of `path`. Linux stamps ctime from the coarse clock (jiffy
// resolution, ~1-4 ms), so two writes inside one tick share a ctime. Tests
// that want the two states to be distinguishable to a stat wait for the
// clock to move. Measured on 6.8: consecutive writes 2 ms apart already
// differ; the loop is a guard, not a delay.
func waitForCtimeTick(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	orig := st.Sys().(*syscall.Stat_t).Ctim
	probe := path + ".tick"
	for i := range 2000 {
		if err := os.WriteFile(probe, []byte{byte(i)}, 0o644); err != nil {
			t.Fatal(err)
		}
		ps, err := os.Stat(probe)
		if err != nil {
			t.Fatal(err)
		}
		if ps.Sys().(*syscall.Stat_t).Ctim != orig {
			_ = os.Remove(probe)
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("kernel inode clock did not advance in 2 s")
}

// requireKernelIdentityMoved asserts that (dev, ino, ctime) differs between
// two stats of the same path. After waitForCtimeTick this is a hard
// assertion: an attacker can pin size and mtime; they cannot pin ctime
// against a write(2), nor keep the inode across a replacement.
func requireKernelIdentityMoved(t *testing.T, before, after os.FileInfo) {
	t.Helper()
	b := before.Sys().(*syscall.Stat_t)
	a := after.Sys().(*syscall.Stat_t)
	if b.Dev == a.Dev && b.Ino == a.Ino && b.Ctim == a.Ctim {
		t.Fatalf("kernel identity did not move across the rewrite: dev=%d ino=%d ctime=%d.%09d", a.Dev, a.Ino, a.Ctim.Sec, a.Ctim.Nsec)
	}
}

// TestDigestBinding_ForgedMtimeAndSizeDoesNotServeStaleDigest is the
// original forgery. Hash the genuine image once, then replace the bytes at
// the same path with a same-size trojan carrying the original mtime. The
// second lookup must return the trojan's digest.
func TestDigestBinding_ForgedMtimeAndSizeDoesNotServeStaleDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	genuine := []byte("GENUINE-IMAGE-0123456789abcdef\n")
	trojan := []byte("TROJAN--IMAGE-0123456789abcdef\n") // same length
	if len(genuine) != len(trojan) {
		t.Fatalf("fixture: lengths differ %d != %d", len(genuine), len(trojan))
	}
	if err := os.WriteFile(path, genuine, 0o755); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)
	first, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("first lookup: no digest")
	}
	if got, want := firstHex(first), sha256Hex(t, genuine); got != want {
		t.Fatalf("first lookup: got %s want %s", got, want)
	}

	// The attacker's three commands: cp trojan P; truncate -s <size> P;
	// touch -r <original> P. Size and mtime now match what was hashed.
	waitForCtimeTick(t, path)
	if err := os.WriteFile(path, trojan, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != int64(len(genuine)) || !st.ModTime().Equal(stamp) {
		t.Fatalf("fixture: forgery did not reproduce size/mtime (size=%d mtime=%v)", st.Size(), st.ModTime())
	}
	requireKernelIdentityMoved(t, before, st)

	second, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("second lookup: no digest")
	}
	if got, want := firstHex(second), sha256Hex(t, trojan); got != want {
		t.Fatalf("a stale digest was served for forged (size,mtime): got %s (genuine) want %s (trojan)", got, want)
	}
}

// TestDigestBinding_SamePathRewrittenInPlaceIsRehashed covers the variant
// where the file is rewritten through the same inode (open O_TRUNC + write)
// rather than replaced.
func TestDigestBinding_SamePathRewrittenInPlaceIsRehashed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("v1-content-abcdefgh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)
	if _, ok := pctx.digestForPath(path); !ok {
		t.Fatal("first lookup: no digest")
	}
	waitForCtimeTick(t, path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	v2 := []byte("v2-content-abcdefgh\n")
	if _, err := f.Write(v2); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Pin mtime back to what the FIRST stat saw, as the attacker would --
	// `before`, taken above the rewrite, not a stat taken after it (which
	// would make this a no-op and quietly stop staging the forgery).
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("fixture: mtime was not restored (%v != %v), so the forgery is not staged", after.ModTime(), before.ModTime())
	}
	requireKernelIdentityMoved(t, before, after)
	got, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("second lookup: no digest")
	}
	if firstHex(got) != sha256Hex(t, v2) {
		t.Fatalf("in-place rewrite served stale digest: got %s want %s", firstHex(got), sha256Hex(t, v2))
	}
}

// TestDigestBinding_ImmediateRewriteIsRehashed rewrites a same-size file
// through the same inode the instant the first hash returns, with no tick
// wait and no mtime games.
//
// Do not read it as a same-tick reproduction, which is what an earlier name
// claimed. It cannot be one: the first digestForPath settles, so it does not
// return until the file's ctime is at least a window old, and the rewrite is
// necessarily outside the tick the file was written in. With no memo there
// is also no key for a same-tick rewrite to collide with -- that was the
// subject of rounds 1 through 3 and it is gone. What survives is the
// property a returning memo would break under ANY key: back-to-back reads of
// a path whose bytes changed must return the new bytes.
func TestDigestBinding_ImmediateRewriteIsRehashed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	a := []byte("A-content-0123456789abcdef\n")
	b := []byte("B-content-0123456789abcdef\n") // same length, same inode
	if len(a) != len(b) {
		t.Fatalf("fixture: lengths differ %d != %d", len(a), len(b))
	}
	if err := os.WriteFile(path, a, 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)
	first, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("first lookup: no digest")
	}
	if got, want := firstHex(first), sha256Hex(t, a); got != want {
		t.Fatalf("first lookup: got %s want %s", got, want)
	}
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	second, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("second lookup: no digest")
	}
	if got, want := firstHex(second), sha256Hex(t, b); got != want {
		t.Fatalf("an immediate rewrite was served the stale digest: got %s (A) want %s (B)", got, want)
	}
}

// TestDigestForPath_YoungFileIsWaitedOutNotDropped is the positive control
// on the settle wait: a file written a moment ago must still end up hashed
// and recorded, after the wait, rather than refused. The alternative
// considered and rejected was to refuse ambiguous reads outright, which
// would have dropped every just-written material from the evidence.
func TestDigestForPath_YoungFileIsWaitedOutNotDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "just-written")
	content := []byte("written a moment ago\n")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)
	// Precondition, checked as late as possible: the file must still be
	// inside the window when the timed call starts, or there is no wait to
	// observe and a "did it wait" assertion would be measuring nothing. A
	// loaded machine can age the fixture past the window between the write
	// above and here.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctim := st.Sys().(*syscall.Stat_t).Ctim
	age := time.Since(time.Unix(int64(ctim.Sec), int64(ctim.Nsec))) //nolint:unconvert // Timespec field widths differ across GOARCH
	start := time.Now()
	d, ok := pctx.digestForPath(path)
	elapsed := time.Since(start)
	if !ok {
		t.Fatal("a young but undisturbed file must be hashed after the wait, not dropped")
	}
	if got, want := firstHex(d), sha256Hex(t, content); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}
	// Assert against the wait that was actually owed. A flat 1 ms would fail
	// on a fixture that had only 0.5 ms left to run, which is a real outcome
	// on a loaded machine and not a missing wait.
	owed := ebpf.SettleWindow - age
	if owed < 2*time.Millisecond {
		t.Skipf("skipping the wait assertion: the fixture was %v old when the call began, leaving only %v to wait out (the digest above was still checked)", age, owed)
	}
	if elapsed < owed/2 {
		t.Fatalf("returned in %v for a file %v old; at least %v of the %v window was still owed", elapsed, age, owed, ebpf.SettleWindow)
	}
}

// TestDigestOpenFile_HashesTheDescriptorNotTheName is the round-4 defect,
// staged deterministically instead of raced. The code used to stat a NAME
// and then open that name again -- two resolutions -- so a symlink flipped
// between them let one file's bytes be described by another file's stat.
//
// The racing version of this test that stood here previously could not
// detect it: a mis-attributed result is still one of the two targets'
// digests, so the assertion passed either way. This replaces the race with a
// staged swap -- open through the symlink, THEN repoint it, then hash -- so
// any read of the NAME after the open answers with the other file, every
// time, with no scheduling luck required.
//
// Be clear about its strength. digestOpenFile is handed a descriptor and has
// no path to re-resolve, so today the property holds by signature and this
// test pins that shape rather than discriminating between two live
// behaviours. It goes red the moment someone reintroduces a name into the
// hashing path, which is exactly how round 4's defect was written. The
// descriptor-based half of the same rule -- that the REGULAR-FILE check is
// made on the opened descriptor, not on an earlier stat of the name -- is
// the discriminating one, and it is covered by
// TestDigestOpenFile_NonRegularDescriptorIsRefused and
// TestDigestForPath_NonRegularPathIsNeverHashed.
func TestDigestOpenFile_HashesTheDescriptorNotTheName(t *testing.T) {
	dir := t.TempDir()
	opened := filepath.Join(dir, "opened")
	swapped := filepath.Join(dir, "swapped")
	link := filepath.Join(dir, "tool")

	openedBytes := []byte("OPENED-content-0123456789a\n")
	swappedBytes := []byte("SWAPPED-content-012345678a\n") // same length
	if len(openedBytes) != len(swappedBytes) {
		t.Fatalf("fixture: lengths differ %d != %d", len(openedBytes), len(swappedBytes))
	}
	if err := os.WriteFile(opened, openedBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(swapped, swappedBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(opened, link); err != nil {
		t.Fatal(err)
	}

	f, err := openForHashing(link)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// Repoint the name. rename(2) is atomic, so `link` resolves to the other
	// real file from here on -- but the descriptor above still holds the
	// first one.
	next := link + ".next"
	if err := os.Symlink(swapped, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, link); err != nil {
		t.Fatal(err)
	}
	// Precondition: the name really does resolve elsewhere now, so a
	// name-based implementation would answer differently.
	nowBytes, err := os.ReadFile(link) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nowBytes, swappedBytes) {
		t.Fatalf("fixture: the symlink was not repointed; it still reads %q", nowBytes)
	}

	d, err := pctxDigest(t, f)
	if err != nil {
		t.Fatalf("a quiet regular file must hash: %v", err)
	}
	if got, want := firstHex(d), sha256Hex(t, openedBytes); got != want {
		t.Fatalf("the hash followed the NAME rather than the descriptor: got %s (the file the symlink points at now) want %s (the file the open resolved to)",
			got, want)
	}
}

// pctxDigest is digestOpenFile with a throwaway context, for tests that care
// about the descriptor rather than the trace.
func pctxDigest(t *testing.T, f *os.File) (cryptoutil.DigestSet, error) {
	t.Helper()
	return newDigestTestContext(t).digestOpenFile(f)
}

// TestDigestForPath_NonRegularPathIsNeverHashed pins the tightening that
// comes with resolving once: the descriptor's own fstat decides what may be
// hashed, so a FIFO is refused instead of being opened by name and drained
// out from under the tracee. O_NONBLOCK is what keeps the open itself from
// hanging on a writer that never arrives.
func TestDigestForPath_NonRegularPathIsNeverHashed(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("skipping: mkfifo unavailable here: %v", err)
	}
	pctx := newDigestTestContext(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, ok := pctx.digestForPath(fifo); ok {
			t.Error("a FIFO must never yield a digest")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("digestForPath blocked on a FIFO with no writer")
	}
}

// ---------------------------------------------------------------------------
// Round 5: a read that cannot be shown free of observable change is a
// REFUSAL, not a digest with a weaker label. The two used to share a code
// path, so a torn read came back as "fine, just not cacheable" and its
// digest reached attestation.
// ---------------------------------------------------------------------------

// TestObservedUnchanged_TornReadIsRefused is the deterministic seam:
// observedUnchanged is a pure function of the two fstats, so the torn read
// is constructed rather than raced.
func TestObservedUnchanged_TornReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	a := []byte("A-content-0123456789abcdef\n")
	b := []byte("B-content-0123456789abcdef\n") // same length
	if err := os.WriteFile(path, a, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	waitForCtimeTick(t, path)
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	requireKernelIdentityMoved(t, before, after)

	if err := observedUnchanged(before, after); !errors.Is(err, errTornRead) {
		t.Fatalf("error = %v, want errTornRead", err)
	}
	// And the same two stats, unchanged, are accepted -- so the check is
	// aimed at movement, not at reads.
	if err := observedUnchanged(before, before); err != nil {
		t.Fatalf("two identical stats must be accepted, got %v", err)
	}
}

// TestObservedUnchanged_UncomparableInputsAreRefused: a check that could not
// run must not answer permissively. Missing stats are "could not check",
// which is not "checked and fine".
func TestObservedUnchanged_UncomparableInputsAreRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("content\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		before, after os.FileInfo
		want          error
	}{
		{"no pre-read stat", nil, fi, errUncomparableRead},
		{"no post-read stat", fi, nil, errUncomparableRead},
		{"not a regular file", dirInfo, dirInfo, errNotRegularFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := observedUnchanged(tc.before, tc.after); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestDigestOpenFile_NonRegularDescriptorIsRefused pins that digestOpenFile
// propagates the refusal rather than degrading it, on the one failure that
// can be staged deterministically end to end.
func TestDigestOpenFile_NonRegularDescriptorIsRefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("skipping: mkfifo unavailable here: %v", err)
	}
	f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pctx := newDigestTestContext(t)
	d, err := pctx.digestOpenFile(f)
	if !errors.Is(err, errNotRegularFile) {
		t.Fatalf("error = %v, want errNotRegularFile", err)
	}
	if d != nil {
		t.Fatalf("a refused read must yield no digest, got %s", firstHex(d))
	}
}

// TestDigestForPath_ConcurrentRewriteNeverReturnsATornDigest is the
// end-to-end assertion the reviewer asked for: what matters is that NOTHING
// is returned, not merely that nothing is memoised. A writer rewrites the
// file in place while the hash runs; a read the bracket rejects must come
// back as no digest at all, and a read it ACCEPTS must carry one of the two
// whole contents.
//
// The tear is STAGED, not raced, and the ordering is what makes both halves
// sound:
//
//  1. The file is aged past the settle window before each pass, so
//     digestOpenFile's settle returns at once and its pre-read fstat is
//     taken within microseconds of the call.
//  2. The writer is parked on a channel released immediately before that
//     call and then waits stagedWriteDelay, so its rewrite begins well after
//     the pre-read fstat.
//
// Step 2 is a MARGIN, not a synchronisation: the fstat happens inside the
// hasher and user space has nothing to synchronise against, so the ordering
// is established by making the delay orders of magnitude larger than the gap
// it has to cover, never by proof. See stagedWriteDelay, which also names
// the in-flight-write residual as the other explanation for a failure here.
//
// A write that begins after a stat taken on a settled file carries a later
// ctime, so a tear staged this way is one the bracket is supposed to catch.
// That closes the hole the reviewer found in the previous version --
// which rewrote in a tight loop, so SettleForRead refused every call before
// any byte was read, the bracket was never reached, and deleting
// observedUnchanged left the test passing on 40 refusals and zero reads. It
// also removes the converse ambiguity: an in-flight write that stamped ctime
// and then stalled past the window can legitimately produce a mixed digest
// the bracket accepts (ext4 stamps in file_modified() before copying; see
// ebpf.TOCTOUStable), and staging the ordering keeps that documented
// residual out of this test's assertions.
//
// Refusals are classified: only errTornRead means "the read completed and
// the post-read comparison rejected it". Counting every refusal as a
// detection lets a build that refuses everything look like one that detects
// everything.
func TestDigestForPath_ConcurrentRewriteNeverReturnsATornDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")

	// Large enough that the read spans many milliseconds, so the staged
	// write lands inside it rather than after it.
	const size = 24 << 20
	a := make([]byte, size)
	b := make([]byte, size)
	for i := range a {
		a[i] = byte('A' + i%23)
		b[i] = byte('a' + i%23)
	}
	if err := os.WriteFile(path, a, 0o644); err != nil {
		t.Fatal(err)
	}
	wantA, wantB := sha256Hex(t, a), sha256Hex(t, b)

	// The writer rewrites through the SAME inode at the SAME size, so only
	// ctime separates the two states -- exactly what the bracket compares,
	// and what a size-only check could not see.
	rewrite := func(i int) {
		content := a
		if i%2 == 1 {
			content = b
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		_, _ = f.WriteAt(content, 0)
		_ = f.Close()
	}

	pctx := newDigestTestContext(t)
	torn, unread, returns := 0, 0, 0
	for i := range 20 {
		// (1) Age the file, so the settle inside digestOpenFile is a no-op
		// and its pre-read fstat is taken essentially at the call.
		waitPastSettleWindow(t, path)

		f, err := openForHashing(path)
		if err != nil {
			unread++
			continue
		}

		// (2) Fire the rewrite after the hash call has begun. The
		// goroutine is parked on a channel FIRST, so the only thing
		// between the signal and the write is the delay; the signal is
		// sent on the line before the call.
		start := make(chan struct{})
		written := make(chan struct{})
		go func() {
			defer close(written)
			<-start
			time.Sleep(stagedWriteDelay)
			rewrite(i)
		}()

		close(start)
		d, err := pctx.digestOpenFile(f)
		_ = f.Close()
		<-written

		switch {
		case errors.Is(err, errTornRead):
			// The read ran to completion and the bracket rejected it.
			torn++
			if d != nil {
				t.Fatalf("a rejected read must carry no digest, got %s", firstHex(d))
			}
		case err != nil:
			// Refused before or during the read (never settled, I/O error).
			// Safe, but it exercises nothing about the bracket.
			unread++
		default:
			returns++
			if got := firstHex(d); got != wantA && got != wantB {
				t.Fatalf("a read the bracket ACCEPTED returned a digest of neither whole content -- torn bytes reached attestation: got %s. "+
					"The rewrite was staged to begin after the pre-read fstat of a settled file, so its ctime is necessarily later and the bracket was required to catch it.", got)
			}
		}
	}

	if torn == 0 {
		t.Skipf("skipping: in 20 staged passes no read completed and was then rejected by the post-read comparison (%d refused before the bracket, %d accepted), so the mechanism under test was never reached", unread, returns)
	}
	t.Logf("%d reads rejected by the bracket with no digest, %d accepted (all of a whole content), %d refused before the bracket", torn, returns, unread)

	// Positive control. Refusing everything would satisfy the loop above, so
	// prove the same call still returns a digest once the writer has stopped
	// and the file is quiet: the refusal is aimed at torn reads, not at reads.
	waitPastSettleWindow(t, path)
	d, ok := pctx.digestForPath(path)
	if !ok {
		t.Fatal("with no writer running, a quiet file must still yield a digest")
	}
	if got := firstHex(d); got != wantA && got != wantB {
		t.Fatalf("quiet read returned a digest of neither content: %s", got)
	}
}
