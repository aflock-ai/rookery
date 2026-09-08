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

// The rule these tests enforce: ExeDigestSourceMappedImage is claimed only
// when the bytes measured are PROVABLY the bytes the kernel mapped for the
// exec being described. Two independent things have to hold, and each of
// these tests removes exactly one of them:
//
//  1. BOUND — the measured file is the image THIS exec event produced, on
//     evidence the tracee could not have manufactured after the fact.
//  2. PROTECTED — write protection demonstrably held across the WHOLE
//     measurement, so the bytes hashed are the bytes that ran.
//
// Where either cannot be proven the record must say so: the weaker
// ExeDigestSourcePathHash label plus an ExeDigestDowngradeReason, so a
// verifier sees a deliberate downgrade rather than a missing field. A label
// the producer cannot substantiate is worse than an honest weaker one,
// because a policy will trust it (Codex review of judge#9045, round 3).

package commandrun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

// linkOrSkip hardlinks src to dst so both names share ONE inode. A hardlink
// (not a copy) is the point: it makes the pathname's kernel identity equal
// to the running binary's, which is the strongest case the old userspace
// binding could see, and it still is not proof of what this exec ran.
func linkOrSkip(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.Link(src, dst); err != nil {
		t.Skip("cannot hardlink across filesystems:", err)
	}
}

// TestEBPFExecve_NeverClaimsMappedImage is finding 1 (Codex round 3,
// exec_binding_linux.go:83), reduced to the fact that produces it.
//
// The eBPF execve event is emitted from a SYSCALL-ENTRY kprobe
// (SEC("kprobe/__x64_sys_execve") in ebpf/bpf/openat_kprobe.bpf.c). At that
// instant the kernel has not resolved, opened, or mapped anything, so the
// event carries only the pathname string the caller passed — ebpf.ExecveEvent
// has no device, inode, or any other kernel identity to bind to.
//
// Every comparand the userspace binding used was therefore RE-DERIVED after
// the exec: it stat'd the pathname when it got round to processing the event.
// A tracee that replaces that pathname and execs again before the event is
// drained makes the stat and /proc/<pid>/exe describe the SAME later image,
// so the old code adopted it and labelled it mapped-image for the EARLIER
// event. Here the pathname is a hardlink to the running test binary, which is
// exactly the state that race leaves behind: the identity check passes
// perfectly, and it still proves nothing about what this event's exec ran.
//
// No amount of userspace sequencing repairs this, because the sequence
// counter only counts events already DRAINED — a queued exec is invisible to
// it. So the eBPF backend does not get to claim mapped-image at all, and must
// say why it downgraded.
func TestEBPFExecve_NeverClaimsMappedImage(t *testing.T) {
	self := os.Getpid()
	exe := selfExe(t)
	dir := t.TempDir()
	named := filepath.Join(dir, "named-at-exec")
	linkOrSkip(t, exe, named)

	pctx := newDigestTestContext(t)
	recordEBPFExecve(pctx, &ebpf.ExecveEvent{
		EventHeader: ebpf.EventHeader{PID: uint32(self), PPID: 1},
		Comm:        "test",
		Filename:    named,
	})

	pi := pctx.processes[self]
	if pi == nil {
		t.Fatal("no ProcessInfo recorded")
	}
	if pi.ExeDigestSource == ExeDigestSourceMappedImage {
		t.Fatalf("ExeDigestSource = %q: the eBPF execve event is a syscall-ENTRY kprobe "+
			"carrying no kernel identity, so no /proc read can be proven to describe THIS "+
			"exec; mapped-image must never be claimed here", pi.ExeDigestSource)
	}
	if pi.ExeDigestSource != ExeDigestSourcePathHash {
		t.Fatalf("ExeDigestSource = %q, want %q", pi.ExeDigestSource, ExeDigestSourcePathHash)
	}
	if pi.ExeDigestDowngradeReason == "" {
		t.Fatal("ExeDigestDowngradeReason is empty: a verifier must see a DELIBERATE " +
			"downgrade, not a missing field")
	}
	if pi.ExeDigestDowngradeReason != ExeDigestDowngradeNotKernelBound {
		t.Fatalf("ExeDigestDowngradeReason = %q, want %q",
			pi.ExeDigestDowngradeReason, ExeDigestDowngradeNotKernelBound)
	}
}

// TestProvenMappedImage_UnprotectedIsRefused is finding 2 (Codex round 3,
// exec_binding_linux.go:126): opening the image pins the inode but does NOT
// keep its contents write-protected once the last executing reference is
// gone. ETXTBSY is what forbids writing a running image, and it lapses when
// the process exits. A measurement that completes after that can hash bytes
// which never executed.
//
// The rewrite here is deliberately SAME-INODE and SAME-SIZE, which is the
// case an identity tuple cannot see (the same shape as judge#9044: a rewrite
// inside one ctime tick defeats a (dev, ino, ctime, size) key). So the stat
// comparison is not what saves us and cannot be what the code relies on --
// the proof has to be that write protection HELD, which is why the
// measurement takes an explicit stillProtected predicate rather than
// inferring protection from a stat it took itself.
func TestProvenMappedImage_UnprotectedIsRefused(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, []byte("AAAAAAAA"), 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)

	// Protection is gone (the tracee exited), and the same inode is rewritten
	// in place with the SAME number of bytes, so dev/ino/size are untouched.
	if _, ok := pctx.provenMappedImage(image, func() imageProtection { return protectionNotGuaranteed }); ok {
		t.Fatal("adopted a mapped-image digest with no proof that write protection " +
			"held across the measurement: after the tracee exits ETXTBSY lapses and " +
			"the bytes hashed need never have executed")
	}

	// Positive control: with protection proven to hold, the same file IS
	// adopted -- so the refusal above is the protection check doing work, not
	// the measurement being broken.
	if _, ok := pctx.provenMappedImage(image, func() imageProtection { return protectionGuaranteed }); !ok {
		t.Fatal("refused a protected image: the measurement itself is broken, " +
			"so the negative case above proves nothing")
	}
}

// TestProvenMappedImage_MeasuresTheDescriptorNotTheName pins the ONE-
// RESOLUTION rule: exePath is resolved once, by the open, and the bytes and
// every stat come from that descriptor. A name retargeted afterwards must not
// change what was measured.
//
// The name is a SYMLINK and the hook retargets it mid-read, which is the
// production shape rather than a stand-in: /proc/<pid>/exe is a symlink, and
// "stat the name, then open the name" is two resolutions with a window
// between them -- the mechanism openForHashing exists to close.
//
// Retargeting is what makes this test able to fail at all. The version it
// replaces renamed a different FILE over the path, which drops the original
// inode's link count and therefore moves its ctime; the bracket refused on
// that ctime move before the digest was ever compared, and the test's
// `if !ok { return }` escape swallowed it. Instrumented, that test took the
// escape on every run and reached its assertion on none -- it asserted
// nothing, and a mutation that hashed the NAME instead of the descriptor
// survived it. Retargeting a symlink touches only the symlink's own inode, so
// the target is undisturbed, a correct implementation SUCCEEDS, and there is
// no escape hatch here: a refusal is a failure.
func TestProvenMappedImage_MeasuresTheDescriptorNotTheName(t *testing.T) {
	dir := t.TempDir()
	realA := filepath.Join(dir, "real-a")
	realB := filepath.Join(dir, "real-b")
	if err := os.WriteFile(realA, []byte("AAAAAAAA"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realB, []byte("BBBBBBBB"), 0o755); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(dir, "image")
	if err := os.Symlink(realA, image); err != nil {
		t.Skip("cannot create a symlink here:", err)
	}

	pctx := newDigestTestContext(t)
	retargeted := false
	pctx.testDuringHashedRead = func() {
		// Atomically point the NAME at a different file, without touching
		// the inode the descriptor already holds.
		tmp := filepath.Join(dir, "swap")
		if err := os.Symlink(realB, tmp); err != nil {
			return
		}
		if err := os.Rename(tmp, image); err != nil {
			return
		}
		retargeted = true
	}

	d, ok := pctx.provenMappedImage(image, func() imageProtection { return protectionGuaranteed })
	if !retargeted {
		t.Fatal("the symlink was never retargeted, so this run did not stage the case")
	}
	if !ok {
		t.Fatal("refused a measurement whose target inode never changed: only the NAME was " +
			"retargeted, and the descriptor's own identity held still, so there was nothing to refuse")
	}
	if got, want := firstHex(d), sha256Hex(t, []byte("AAAAAAAA")); got != want {
		t.Fatalf("measured the retargeted name, not the descriptor that was opened and fstat'd: "+
			"got %s (the new target) want %s (the file the open resolved to). The path must be "+
			"resolved exactly once, by the open.", got, want)
	}
}

// TestExeDigestSourceSurvivesV02Wire is a WIRE-FORMAT REGRESSION GUARD. Do not
// delete it as redundant with the unit tests above: they prove the producer
// COMPUTES the right label, and this proves the label still exists by the time
// a verifier reads the signed document. Those failed independently once
// already, and only this one caught it.
//
// It is the sibling the label audit turned up, and it defeated the whole
// feature rather than one case of it.
//
// Type = V02PredicateType, so V02Process IS what every signed command-run
// attestation carries. It interned ExeDigest but had no field for the label,
// so the producer dropped ExeDigestSource on the way to the wire: a verifier
// received a bare ExeDigest with nothing saying whether it measured the
// mapped image or a pathname, which is precisely the "no way to tell" this
// PR set out to end. The label is only worth having if it is still there
// when a verifier reads the signed document.
func TestExeDigestSourceSurvivesV02Wire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		reason string
	}{
		{"mapped image", ExeDigestSourceMappedImage, ""},
		{"downgraded path hash", ExeDigestSourcePathHash, ExeDigestDowngradeNotKernelBound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := &CommandRun{Processes: []ProcessInfo{{
				ProcessID:                1,
				ExeDigestSource:          tc.source,
				ExeDigestDowngradeReason: tc.reason,
			}}}
			b, err := rc.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			// The label must be IN THE BYTES, not merely reconstructible.
			// A json tag changed to "-" would still round-trip through a
			// sufficiently clever decoder while telling a verifier nothing.
			if tc.source != "" && !bytes.Contains(b, []byte(tc.source)) {
				t.Fatalf("the v0.2 wire bytes do not contain the label %q at all: %s", tc.source, b)
			}
			var got CommandRun
			if err := got.UnmarshalJSON(b); err != nil {
				t.Fatal(err)
			}
			if len(got.Processes) != 1 {
				t.Fatalf("got %d processes, want 1", len(got.Processes))
			}
			if got.Processes[0].ExeDigestSource != tc.source {
				t.Fatalf("ExeDigestSource did not survive the v0.2 wire: got %q want %q "+
					"-- a verifier cannot refuse a path hash it cannot see",
					got.Processes[0].ExeDigestSource, tc.source)
			}
			if got.Processes[0].ExeDigestDowngradeReason != tc.reason {
				t.Fatalf("ExeDigestDowngradeReason did not survive the v0.2 wire: got %q want %q",
					got.Processes[0].ExeDigestDowngradeReason, tc.reason)
			}
		})
	}
}

// sanity: the constants the tests above name must be distinct, or an
// assertion that a downgrade happened would pass on the mapped-image value.
func TestExeDigestLabelsAreDistinct(t *testing.T) {
	if ExeDigestSourceMappedImage == ExeDigestSourcePathHash {
		t.Fatal("the two ExeDigestSource values are equal")
	}
}

// TestProtectionIsThreeStateAndUnknownIsRefused is finding 1 of round 4.
//
// Round 3 proved that /proc/<pid>/exe still resolves and called that
// protection. It is not: resolving proves a live process still maps the
// image, which is what puts ETXTBSY in force -- but ETXTBSY does not deny the
// write on Linux 6.11 and 6.12, an exception this package documents in two
// places. On those kernels another process rewrites the executing inode while
// both the link check and the (device, inode) comparison keep succeeding, and
// the rewritten bytes get labelled mapped-image.
//
// So the predicate answers in three states, and only "guaranteed" earns the
// label. UNKNOWN IS NOT PERMISSION: a producer that cannot tell whether writes
// were possible is in exactly the position of one that knows they were, and
// both downgrade.
func TestProtectionIsThreeStateAndUnknownIsRefused(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, []byte("AAAAAAAA"), 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)

	for _, tc := range []struct {
		name  string
		state imageProtection
		want  bool
	}{
		{"guaranteed is adopted", protectionGuaranteed, true},
		{"not guaranteed is refused", protectionNotGuaranteed, false},
		{"unknown is refused", protectionUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := pctx.provenMappedImage(image, func() imageProtection { return tc.state })
			if ok != tc.want {
				t.Fatalf("provenMappedImage adopted=%v, want %v for protection %v "+
					"(unknown is not permission)", ok, tc.want, tc.state)
			}
		})
	}
}

// TestETXTBSYProtectionByKernelRelease pins the kernel gate itself, so the
// three-state answer can be tested without running on a 6.11 kernel.
//
// The exception encoded here is the one this package already states: an
// in-place write to a mapped image is ETXTBSY-denied on every kernel EXCEPT
// v6.11 and v6.12. An unparseable release is unknown, never guaranteed --
// failing to read the version is not evidence that the version is safe.
func TestETXTBSYProtectionByKernelRelease(t *testing.T) {
	for _, tc := range []struct {
		release string
		want    imageProtection
	}{
		{"6.11.0-19-generic", protectionNotGuaranteed},
		{"6.11.9", protectionNotGuaranteed},
		{"6.12.0", protectionNotGuaranteed},
		{"6.12.44-1-lts", protectionNotGuaranteed},
		{"6.10.14-amd64", protectionGuaranteed},
		{"6.13.0-rc1", protectionGuaranteed},
		{"6.8.0-45-generic", protectionGuaranteed},
		{"5.15.0-118-generic", protectionGuaranteed},
		{"7.0.1", protectionGuaranteed},
		{"", protectionUnknown},
		{"not-a-version", protectionUnknown},
		{"6", protectionUnknown},
		{"6.x.1", protectionUnknown},
	} {
		t.Run(tc.release, func(t *testing.T) {
			if got := etxtbsyProtectionForRelease(tc.release); got != tc.want {
				t.Fatalf("etxtbsyProtectionForRelease(%q) = %v, want %v", tc.release, got, tc.want)
			}
		})
	}
}

// TestEBPFExecve_ProgramPathAndDigestDescribeTheSameBytes is finding 2 of
// round 4, which was a regression I introduced in round 3.
//
// Lifting the /proc/<pid>/exe readlink out of its guard made it replace
// Program unconditionally while ProgramDigest stayed conditional, so the two
// stopped moving together. For a shell script that is not cosmetic: the caller
// execs the SCRIPT, /proc/<pid>/exe is the INTERPRETER, and the signed record
// ended up naming the interpreter's path beside the script's digest -- a path
// and a digest that describe different bytes, which is precisely the
// unbound-evidence shape this PR exists to remove.
//
// The bytes differ on purpose, so a mismatch cannot pass by coincidence: the
// assertion re-hashes whatever path was recorded and requires it to equal the
// digest that was recorded next to it.
func TestEBPFExecve_ProgramPathAndDigestDescribeTheSameBytes(t *testing.T) {
	self := os.Getpid()
	dir := t.TempDir()
	script := filepath.Join(dir, "build.sh")
	scriptBytes := []byte("#!/bin/sh\necho these-bytes-are-not-the-interpreter\n")
	if err := os.WriteFile(script, scriptBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	pctx := newDigestTestContext(t)
	recordEBPFExecve(pctx, &ebpf.ExecveEvent{
		EventHeader: ebpf.EventHeader{PID: uint32(self), PPID: 1},
		Comm:        "sh",
		Filename:    script,
	})

	pi := pctx.processes[self]
	if pi == nil {
		t.Fatal("no ProcessInfo recorded")
	}
	if pi.Program == "" || pi.ProgramDigest == nil {
		t.Fatalf("Program=%q ProgramDigest=%v: both or neither", pi.Program, pi.ProgramDigest)
	}
	// The invariant: whatever path is recorded, the digest beside it is a
	// digest OF THAT PATH.
	want, err := cryptoutil.CalculateDigestSetFromFile(pi.Program, pctx.hash)
	if err != nil {
		t.Fatal(err)
	}
	if firstHex(pi.ProgramDigest) != firstHex(want) {
		t.Fatalf("Program %q and ProgramDigest describe different bytes: digest=%s but that path hashes to %s "+
			"(a path and the digest that describes it move together or not at all)",
			pi.Program, firstHex(pi.ProgramDigest), firstHex(want))
	}
	// And specifically: the caller named the script, so that is what the
	// record must carry -- not the interpreter /proc/<pid>/exe points at.
	if pi.Program != script {
		t.Fatalf("Program = %q, want the pathname the caller exec'd (%q)", pi.Program, script)
	}
}

// TestEBPFExecve_PathHashIsLabelledNotBorrowed is the laundering case. When
// /proc/<pid>/exe cannot be read (the pid is gone, or was never a real pid),
// the only digest the handler can compute is of the pathname the caller
// named. That digest must not be published as ExeDigest with no source; it
// must be labelled as a path hash so a verifier can refuse it.
func TestEBPFExecve_PathHashIsLabelledNotBorrowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short-lived")
	content := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)
	// A pid that does not exist: /proc/<pid>/exe is unreadable, exactly the
	// sub-millisecond-process case the fallback was written for.
	const deadPID = 2147483000
	recordEBPFExecve(pctx, &ebpf.ExecveEvent{EventHeader: ebpf.EventHeader{PID: deadPID, PPID: 1}, Comm: "short-lived", Filename: path})

	pi := pctx.processes[deadPID]
	if pi == nil {
		t.Fatal("no ProcessInfo recorded")
	}
	if pi.ExeDigestSource == "" {
		t.Fatalf("ExeDigest published with no source: exedigest=%v (a verifier cannot tell a path hash from the mapped image)", pi.ExeDigest)
	}
	if pi.ExeDigestSource != ExeDigestSourcePathHash {
		t.Fatalf("ExeDigestSource = %q, want %q for a /proc-less exec", pi.ExeDigestSource, ExeDigestSourcePathHash)
	}
	if firstHex(pi.ExeDigest) != sha256Hex(t, content) {
		t.Fatalf("path-hash digest mismatch: got %s want %s", firstHex(pi.ExeDigest), sha256Hex(t, content))
	}
}

// selfExe returns the running test binary's path, the file /proc/self/exe
// maps, or skips when /proc is unavailable.
func selfExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Skip("no /proc/self/exe:", err)
	}
	return exe
}

// copyFile copies src to dst (a new inode with the same bytes).
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestEBPFExecve_MappedImageDowngradesWithAReason replaces what used to be
// this file's positive control. It asserted that an eBPF execve event whose
// filename is the running binary yields mapped-image; that assertion is now
// wrong on purpose.
//
// The eBPF execve event is emitted from a syscall-ENTRY kprobe and carries no
// kernel identity (see ExeDigestDowngradeNotKernelBound), so this backend
// cannot prove the digest describes the image THIS exec mapped, however well
// the pathname happens to stat. It therefore always downgrades, and the
// record has to say why. The mapped-image positive control now lives on the
// primitive that can actually prove it, provenMappedImage.
func TestEBPFExecve_MappedImageDowngradesWithAReason(t *testing.T) {
	self := os.Getpid()
	exe := selfExe(t)
	pctx := newDigestTestContext(t)
	recordEBPFExecve(pctx, &ebpf.ExecveEvent{EventHeader: ebpf.EventHeader{PID: uint32(self), PPID: 1}, Comm: "test", Filename: exe})

	pi := pctx.processes[self]
	if pi == nil {
		t.Fatal("no ProcessInfo recorded")
	}
	if pi.ExeDigestSource != ExeDigestSourcePathHash {
		t.Fatalf("ExeDigestSource = %q, want %q: the eBPF backend cannot bind a /proc read to an exec event", pi.ExeDigestSource, ExeDigestSourcePathHash)
	}
	if pi.ExeDigestDowngradeReason != ExeDigestDowngradeNotKernelBound {
		t.Fatalf("ExeDigestDowngradeReason = %q, want %q", pi.ExeDigestDowngradeReason, ExeDigestDowngradeNotKernelBound)
	}
	// The published digest is the pathname's bytes, which for this event is
	// the running binary -- the value is right, the CLAIM about it is what
	// changed.
	want, err := cryptoutil.CalculateDigestSetFromFile(exe, pctx.hash)
	if err != nil {
		t.Fatal(err)
	}
	if firstHex(pi.ExeDigest) != firstHex(want) {
		t.Fatalf("ExeDigest is not the named path's hash: got %s want %s", firstHex(pi.ExeDigest), firstHex(want))
	}
}

// TestEBPFExecve_MappedImageNotAdoptedForAnotherInode keeps the case Codex
// named in round 2 -- the event names file A while /proc/<pid>/exe is B --
// as a regression against the label ever coming back on this path. Here A is
// a temp COPY of the test binary (same bytes, different inode) and B is the
// running test binary.
func TestEBPFExecve_MappedImageNotAdoptedForAnotherInode(t *testing.T) {
	self := os.Getpid()
	exe := selfExe(t)
	dir := t.TempDir()
	copied := filepath.Join(dir, "tool-copy")
	copyFile(t, exe, copied)
	pctx := newDigestTestContext(t)
	recordEBPFExecve(pctx, &ebpf.ExecveEvent{EventHeader: ebpf.EventHeader{PID: uint32(self), PPID: 1}, Comm: "test", Filename: copied})

	pi := pctx.processes[self]
	if pi == nil {
		t.Fatal("no ProcessInfo recorded")
	}
	if pi.ExeDigestSource != ExeDigestSourcePathHash {
		t.Fatalf("ExeDigestSource = %q, want %q: /proc/<pid>/exe is another inode than the event's file and must not be adopted", pi.ExeDigestSource, ExeDigestSourcePathHash)
	}
	want, err := cryptoutil.CalculateDigestSetFromFile(copied, pctx.hash)
	if err != nil {
		t.Fatal(err)
	}
	if firstHex(pi.ExeDigest) != firstHex(want) {
		t.Fatalf("ExeDigest is not the event file's path hash: got %s want %s", firstHex(pi.ExeDigest), firstHex(want))
	}
}

// TestProvenMappedImage_MappedRewriteIsNeverServedAStaleDigest is the
// no-memo regression for the EXECUTED-IMAGE path specifically.
//
// mapped_write_linux_test.go already asserts this for digestForPath. This one
// exists because that is not the same test: ExeDigest is the single value a
// process allowlist reads, so a memo reintroduced on THIS path is worth more
// to an attacker than a memo anywhere else in the package, and a revision of
// this file had exactly one -- provenMappedImage served the executed-image
// digest through a cache keyed on (dev, ino, ctime, size). A regression that
// only covers digestForPath would have passed against it.
//
// The staging is the attacker's actual capability, not a stand-in for it: a
// writable MAP_SHARED mapping whose pages are already dirty. Stores through
// it move no stat field at all, so every key a memo could use is identical
// across the rewrite and a memo MUST return the stale digest. The only
// implementation that passes is one that measures afresh on every call.
//
// Read the skip as "not staged here", never as a pass.
func TestProvenMappedImage_MappedRewriteIsNeverServedAStaleDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image")
	a := bytes.Repeat([]byte("A"), mappedPageSize)
	b := bytes.Repeat([]byte("B"), mappedPageSize)

	m := stageDirtyMapping(t, path, a)
	before := statKeyOf(t, path)

	pctx := newDigestTestContext(t)
	guaranteed := func() imageProtection { return protectionGuaranteed }

	first, ok := pctx.provenMappedImage(path, guaranteed)
	if !ok {
		t.Fatal("first measurement: refused an aged, settled, undisturbed image")
	}
	if got, want := firstHex(first), sha256Hex(t, a); got != want {
		t.Fatalf("first measurement: got %s want %s", got, want)
	}

	// The silent rewrite. No syscall, no write fault (the pages are already
	// dirty), so nothing a stat can see moves.
	copy(m, b)

	if after := statKeyOf(t, path); before != after {
		t.Skipf("skipping: the stats moved across the mapped rewrite (before=%+v after=%+v), so the attack was not staged on "+
			"this run (most likely writeback re-armed the write fault). An UNMEASURED run, not evidence that the attack is "+
			"unavailable here; see TestMappedWrite_ChangesContentWithoutMovingAnyStatField.", before, after)
	}

	second, ok := pctx.provenMappedImage(path, guaranteed)
	if !ok {
		t.Fatal("second measurement: refused")
	}
	if got, want := firstHex(second), sha256Hex(t, b); got != want {
		t.Fatalf("the EXECUTED-IMAGE digest was served from a memo: got %s (the first call's bytes) want %s (the bytes on disk now). "+
			"Every stat field was identical across the mapped rewrite, so no stat-keyed memo can be correct on this path. "+
			"ExeDigest is what a process allowlist compares against; it must be measured afresh on every call.", got, want)
	}
}

// The two tests below exist because a mutation survived the suite.
//
// provenMappedImage consults protectedBy TWICE, before and after the read,
// and its doc comment says why: the property has to hold ACROSS the
// measurement, not at one instant of it. Every other test in this file passes
// a CONSTANT predicate, so it cannot tell the two calls apart -- deleting
// either one leaves the other to refuse, and the whole suite stays green
// against half the check. Both were verified to survive before these were
// written.
//
// A predicate that CHANGES its answer mid-read is what distinguishes them.
// The flip is driven by testDuringHashedRead, which fires inside
// digestOpenFile between the pre-read fstat and the hash, so "before the
// read" and "after the read" are real positions in time rather than a call
// count a mutation can shift.

// TestProvenMappedImage_ProtectionThatLapsesDuringTheReadIsRefused covers the
// real failure: protection held when we looked, and was gone by the time the
// bytes were in hand. That is the tracee-exits-mid-measurement window --
// ETXTBSY lapses with the last executing reference, and the same inode can
// then be rewritten in place under the descriptor being hashed. A digest
// measured across that window may cover bytes that never executed, so it must
// not be labelled mapped-image.
//
// Deleting the post-read check makes this test fail; the pre-read check alone
// cannot see a lapse that happens after it.
func TestProvenMappedImage_ProtectionThatLapsesDuringTheReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, bytes.Repeat([]byte("A"), 4096), 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)

	readStarted := false
	pctx.testDuringHashedRead = func() { readStarted = true }
	lapses := func() imageProtection {
		if readStarted {
			return protectionNotGuaranteed
		}
		return protectionGuaranteed
	}

	if d, ok := pctx.provenMappedImage(image, lapses); ok {
		t.Fatalf("mapped-image was claimed for a measurement whose write protection lapsed during the read "+
			"(digest %s). Protection must be re-checked AFTER the read: the bytes hashed can be bytes that "+
			"never executed once the last executing reference is gone.", firstHex(d))
	}
	if !readStarted {
		t.Fatal("the read never started, so this run did not exercise the lapse -- the refusal above proves nothing")
	}
}

// TestProvenMappedImage_ProtectionThatOnlyArrivesAfterTheReadIsRefused is the
// other half. Here protection was NOT in force when the read began and is
// reported in force afterwards. Adopting that would mean measuring bytes
// while they were writable and then excusing it with a later observation --
// the "re-observe the world after the fact" reasoning this file rejects.
//
// Deleting the pre-read check makes this test fail; the post-read check alone
// is happy to accept protection that arrived too late.
func TestProvenMappedImage_ProtectionThatOnlyArrivesAfterTheReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, bytes.Repeat([]byte("A"), 4096), 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)

	readStarted := false
	pctx.testDuringHashedRead = func() { readStarted = true }
	arrivesLate := func() imageProtection {
		if readStarted {
			return protectionGuaranteed
		}
		return protectionNotGuaranteed
	}

	if d, ok := pctx.provenMappedImage(image, arrivesLate); ok {
		t.Fatalf("mapped-image was claimed for a measurement that began while writes were possible "+
			"(digest %s). Protection must be established BEFORE the read; observing it afterwards says "+
			"nothing about the bytes already hashed.", firstHex(d))
	}
}

// TestProvenMappedImage_ResolvesTheNameExactlyOnce asserts the ONE-RESOLUTION
// rule as a count, because nothing else can.
//
// openForHashing's contract is that exePath is turned into a descriptor once
// and every byte and every stat afterwards comes from that descriptor. An
// implementation that instead re-resolved the name for the read is the
// classic stat-then-open window: two resolutions with a gap between them, and
// a symlink or rename in that gap describes one file with another file's
// bytes.
//
// That defect is INVISIBLE to behavioural testing here. Any hook a test can
// install fires inside digestOpenFile -- after every open -- so a one-open
// implementation and a two-open implementation return the same digest from
// the same stats on every input. Verified, not assumed: a mutation replacing
// the descriptor read with p.digestForPath(exePath) passed every other test
// in this package, including the symlink-retarget one written to catch it.
// The resolution count is the only observable that separates them.
func TestProvenMappedImage_ResolvesTheNameExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "image")
	if err := os.WriteFile(image, []byte("AAAAAAAA"), 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)

	before := pathResolutions.Load()
	if _, ok := pctx.provenMappedImage(image, func() imageProtection { return protectionGuaranteed }); !ok {
		t.Fatal("refused a protected, undisturbed image, so the count below measures nothing")
	}
	if got := pathResolutions.Load() - before; got != 1 {
		t.Fatalf("the executed-image measurement resolved its pathname %d times, want exactly 1. "+
			"Each extra resolution is a fresh stat-then-open window: the name can point somewhere "+
			"else by the second one, and the digest would then describe a file the first resolution "+
			"never saw. Resolve once, then use the descriptor.", got)
	}
}

// TestEBPFExecve_ASecondExecClearsThePreviousDigest covers the half of the
// pairing rule the test above cannot reach.
//
// TestEBPFExecve_ProgramPathAndDigestDescribeTheSameBytes only ever exercises
// setProgram with a digest in hand, so an implementation that writes the path
// unconditionally but skips a NIL digest passes it -- verified: a mutation
// doing exactly that survived the whole suite. Yet nil is the interesting
// argument. It is how a caller says "this path, and no digest is available",
// and if it fails to clear what was there the record keeps the PREVIOUS
// exec's digest beside the CURRENT exec's path: a path and a digest
// describing different bytes, in signed evidence, which is the shape
// setProgram exists to make unrepresentable.
//
// A pid that execs twice, where the second image cannot be hashed, is the
// ordinary way to reach it -- a build tool that execs a helper which has
// already been cleaned up.
func TestEBPFExecve_ASecondExecClearsThePreviousDigest(t *testing.T) {
	self := os.Getpid()
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	if err := os.WriteFile(first, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pctx := newDigestTestContext(t)

	recordEBPFExecve(pctx, &ebpf.ExecveEvent{
		EventHeader: ebpf.EventHeader{PID: uint32(self), PPID: 1},
		Comm:        "first", Filename: first,
	})
	pi := pctx.processes[self]
	if pi == nil || pi.ProgramDigest == nil {
		t.Fatal("setup: the first exec recorded no digest, so the clear below proves nothing")
	}

	// Second exec of the same pid, naming an image that no longer exists.
	// There is no digest to record for it.
	gone := filepath.Join(dir, "already-cleaned-up")
	recordEBPFExecve(pctx, &ebpf.ExecveEvent{
		EventHeader: ebpf.EventHeader{PID: uint32(self), PPID: 1},
		Comm:        "second", Filename: gone,
	})

	pi = pctx.processes[self]
	if pi.Program != gone {
		t.Fatalf("Program = %q, want %q: the second exec's path was not recorded", pi.Program, gone)
	}
	if pi.ProgramDigest != nil {
		t.Fatalf("Program moved to %q but ProgramDigest kept %s, the digest of %q. "+
			"A path and a digest that describe different bytes is exactly what pairing the two "+
			"writes is for: a nil digest must CLEAR, not be skipped.",
			gone, firstHex(pi.ProgramDigest), first)
	}
}

// TestMeasureExecutedImage_ASecondExecNeverInheritsTheFirstsDigest is the
// leak the local reviewer caught on the ptrace backend.
//
// execve replaces the pid's image outright, so a digest recorded for an
// earlier exec on the same pid describes an image that no longer exists. The
// handler wrote ExeDigest only inside `if proven { ... }` and applied its
// downgrade only when ExeDigest was nil, so a second exec that FAILED its
// mapped-image proof fell through both: the first exec's digest stayed, still
// labelled mapped-image, and was signed as the second exec's executed image.
// That is the strongest label the attestor has, attached to bytes from a
// different program -- the exact confusion ExeDigestSource exists to end,
// arriving through the field meant to end it.
//
// The test drives measureExecutedImage itself, twice, which is why the
// sequence was lifted out of the syscall handler: covering it in place would
// need a live traced process stopped at two real execve returns. Deleting the
// reset from that function fails this test.
//
// The second exec's proof is made to fail by naming an image that does not
// exist, which is the ordinary sub-millisecond-process case rather than a
// contrived one.
func TestMeasureExecutedImage_ASecondExecNeverInheritsTheFirstsDigest(t *testing.T) {
	dir := t.TempDir()
	pctx := newDigestTestContext(t)
	procInfo := pctx.getProcInfo(4321)

	// Exec 1: a real image, proven and labelled mapped-image. Seeded through
	// the same setter production uses, because whether provenMappedImage
	// succeeds here depends on the running kernel's ETXTBSY behaviour and
	// this test is about what happens NEXT.
	firstImage := filepath.Join(dir, "first-image")
	firstBytes := []byte("the first exec's image")
	if err := os.WriteFile(firstImage, firstBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	firstDigest, ok := pctx.digestForPath(firstImage)
	if !ok {
		t.Fatal("setup: could not hash the first image")
	}
	procInfo.setExeDigest(firstDigest, ExeDigestSourceMappedImage, "")
	procInfo.setProgram(firstImage, firstDigest)

	// Exec 2: a different program, and an exe path that cannot be measured.
	secondProgram := filepath.Join(dir, "second-program")
	secondBytes := []byte("the second exec's program, entirely different bytes")
	if err := os.WriteFile(secondProgram, secondBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	missingExe := filepath.Join(dir, "no-such-proc-exe")

	pctx.measureExecutedImage(procInfo, missingExe, secondProgram)

	if got, want := firstHex(procInfo.ExeDigest), sha256Hex(t, firstBytes); got == want {
		t.Fatalf("the second exec was recorded with the FIRST exec's ExeDigest (%s). Every execve "+
			"replaces the pid's image, so the previous exec's digest must be dropped before the new "+
			"one is measured -- otherwise a failed proof silently keeps it.", got)
	}
	if procInfo.ExeDigestSource == ExeDigestSourceMappedImage {
		t.Fatalf("the second exec kept the mapped-image label with no mapped image proven for it. "+
			"A stale digest is bad; a stale digest still wearing the strongest label is worse, because "+
			"that label is what a policy trusts. ExeDigest=%s", firstHex(procInfo.ExeDigest))
	}
	// Having reset, the handler must still produce an honest record: the
	// named path's bytes, labelled as a path hash, with the reason recorded.
	if procInfo.ExeDigestSource != ExeDigestSourcePathHash {
		t.Fatalf("ExeDigestSource = %q, want %q", procInfo.ExeDigestSource, ExeDigestSourcePathHash)
	}
	if procInfo.ExeDigestDowngradeReason != ExeDigestDowngradeUnprotected {
		t.Fatalf("ExeDigestDowngradeReason = %q, want %q", procInfo.ExeDigestDowngradeReason, ExeDigestDowngradeUnprotected)
	}
	if got, want := firstHex(procInfo.ExeDigest), sha256Hex(t, secondBytes); got != want {
		t.Fatalf("ExeDigest = %s, want %s (the second exec's own program)", got, want)
	}
	if procInfo.Program != secondProgram {
		t.Fatalf("Program = %q, want %q", procInfo.Program, secondProgram)
	}
}

// TestMeasureExecutedImage_UnmeasurableExecLeavesNoLabelledDigest covers the
// case where the pid's image cannot be measured AND no program path is
// available: the record must carry nothing rather than something unlabelled.
//
// An ExeDigest with an empty ExeDigestSource is the state a verifier cannot
// interpret -- it cannot tell a mapped image from a path hash -- so it must
// not be reachable.
func TestMeasureExecutedImage_UnmeasurableExecLeavesNoLabelledDigest(t *testing.T) {
	dir := t.TempDir()
	pctx := newDigestTestContext(t)
	procInfo := pctx.getProcInfo(999)

	pctx.measureExecutedImage(procInfo, filepath.Join(dir, "gone"), "")

	if procInfo.ExeDigest != nil && procInfo.ExeDigestSource == "" {
		t.Fatalf("ExeDigest %s was published with no source. A verifier cannot tell an unlabelled "+
			"digest from a mapped-image one, which is the ambiguity this labelling exists to remove.",
			firstHex(procInfo.ExeDigest))
	}
}

// TestPredicateSchemaAdvertisesTheExeDigestLabels closes the gap the local
// reviewer raised: policy verification targets the VERSIONED predicate
// schema, so a field the schema does not describe is a field a verifier may
// legitimately reject.
//
// Today Schema() is jsonschema.Reflect over the live struct, so the labels
// are carried automatically and this test passes for free. That is exactly
// why it is worth writing down. The failure mode is not someone forgetting to
// add a field -- it is someone replacing the reflected schema with a
// hand-maintained one, which is a normal thing to do and would silently drop
// whichever fields were not transcribed. If such a schema also set
// additionalProperties:false, documents carrying these labels would fail
// validation and be discarded on a fail-closed evidence path: the label this
// change adds would take the evidence down with it.
func TestPredicateSchemaAdvertisesTheExeDigestLabels(t *testing.T) {
	schema := (&CommandRun{}).Schema()
	if schema == nil {
		t.Fatal("CommandRun.Schema() returned nil")
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	// The JSON tags as they appear on the wire in ProcessInfo.
	for _, field := range []string{"exedigestSource", "exedigestDowngradeReason"} {
		if !bytes.Contains(raw, []byte(`"`+field+`"`)) {
			t.Fatalf("the predicate schema does not describe %q. Policy verification targets the "+
				"versioned schema, so a label the schema omits is one a verifier may reject -- and on a "+
				"fail-closed path that discards the whole document rather than just the label.", field)
		}
	}
}

// TestMeasureExecutedImage_UnreadableArgvNeverInheritsThePreviousProgram is
// the sibling of the reset defect above, one field over, and it is the case
// the earlier empty-filename test could not reach: that one started from an
// EMPTY record, so nothing was there to be inherited and it would have passed
// against the broken code.
//
// Reading argv[0] out of a stopped tracee can fail. When it did, `program`
// was "" and the program pair was left alone -- so it still held the PREVIOUS
// exec's path and digest. The mapped-image proof then failed too, and the
// downgrade reads ProgramDigest rather than `program`, so it copied the
// previous program's digest into THIS exec's ExeDigest and signed it as the
// executed image. Every guard on the path was written in terms of the new
// exec; the stale value arrived through the one field nobody reset.
//
// The two digests are different bytes on purpose, so an inherited value
// cannot pass by coincidence.
func TestMeasureExecutedImage_UnreadableArgvNeverInheritsThePreviousProgram(t *testing.T) {
	dir := t.TempDir()
	pctx := newDigestTestContext(t)
	procInfo := pctx.getProcInfo(7777)

	// A fully populated previous exec.
	previous := filepath.Join(dir, "previous-program")
	previousBytes := []byte("the previous exec's program bytes")
	if err := os.WriteFile(previous, previousBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	previousDigest, ok := pctx.digestForPath(previous)
	if !ok {
		t.Fatal("setup: could not hash the previous program")
	}
	procInfo.setProgram(previous, previousDigest)
	procInfo.setExeDigest(previousDigest, ExeDigestSourceMappedImage, "")

	// The next exec: argv[0] could not be read (program ""), and the image
	// cannot be measured either.
	pctx.measureExecutedImage(procInfo, filepath.Join(dir, "no-such-proc-exe"), "")

	if procInfo.Program == previous {
		t.Fatalf("Program still names the PREVIOUS exec's path %q. argv[0] was unreadable for this "+
			"exec, so the honest record is an empty Program, not the last program's name.", previous)
	}
	if procInfo.ProgramDigest != nil {
		t.Fatalf("ProgramDigest kept %s from the previous exec. The pair must be reset unconditionally, "+
			"not only when a new path happens to be readable.", firstHex(procInfo.ProgramDigest))
	}
	if procInfo.ExeDigest != nil {
		t.Fatalf("ExeDigest = %s, want none. Nothing about this exec could be measured -- no image, no "+
			"argv[0] -- so the only honest record is an absent digest. A value here is the previous "+
			"exec's bytes signed as this one's executed image, which is the whole defect.",
			firstHex(procInfo.ExeDigest))
	}
	if procInfo.ExeDigestSource != "" {
		t.Fatalf("ExeDigestSource = %q with no digest to label", procInfo.ExeDigestSource)
	}
	if procInfo.ExeDigestDowngradeReason != "" {
		t.Fatalf("ExeDigestDowngradeReason = %q with no digest to explain", procInfo.ExeDigestDowngradeReason)
	}
}

// TestStillMapping_AnonymousImageIsRefused is the memfd hole (Codex review of
// judge#9045).
//
// A process can execute a memfd through /proc/self/fd/N. Every signal
// stillMapping used to read then says "protected": /proc/<pid>/exe resolves for
// the whole run, the stat succeeds, and the (device, inode) tuple never moves.
// None of that is write protection. An unsealed memfd stays writable to anyone
// still holding a descriptor or a shared mapping of it, so a helper can replace
// the bytes between the exec and the hash, and the digest would have been
// signed as mapped-image -- the strongest label the attestor has, on bytes that
// never ran.
//
// The test builds the attacker's object exactly: a real memfd, still open, with
// content, addressed through /proc/self/fd/N the way an execveat'd image is
// addressed through /proc/<pid>/exe. The retained descriptor IS the retained
// writer; nothing here has to exec to make the point, because what stillMapping
// inspects is the image, not the process.
//
// The discriminator is st_nlink == 0 -- the kernel's own statement that nothing
// can reach these bytes by name. That is a property of the inode, so the same
// refusal covers a file unlinked after exec without naming either case.
func TestStillMapping_AnonymousImageIsRefused(t *testing.T) {
	fd, err := unix.MemfdCreate("judge-9045-anonymous-image", 0)
	if err != nil {
		t.Skip("memfd_create unavailable here:", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if _, err := unix.Write(fd, []byte("#!/bin/sh\nexit 0\n")); err != nil {
		t.Fatal(err)
	}

	// How an execveat'd memfd appears to this code: a magic link that resolves
	// for as long as the descriptor lives.
	exePath := fmt.Sprintf("/proc/self/fd/%d", fd)

	// Positive control. If the path does not even stat, the refusal below would
	// be the ordinary missing-image refusal and would prove nothing about
	// anonymity.
	if _, err := os.Stat(exePath); err != nil {
		t.Skipf("the memfd is not reachable at %s (%v), so this run did not stage the case", exePath, err)
	}
	named, known := namedImage(exePath)
	if !known {
		t.Fatalf("could not read the memfd's stat through %s, so the case was not staged", exePath)
	}
	if named {
		t.Fatalf("the memfd reports a directory entry (st_nlink > 0), which contradicts what memfd_create " +
			"creates; this test's discriminator does not hold on this kernel")
	}

	if got := stillMapping(exePath)(); got == protectionGuaranteed {
		t.Fatalf("stillMapping returned %v for an ANONYMOUS image. /proc/<pid>/exe resolving is not write "+
			"protection: an unsealed memfd is writable through any retained descriptor or shared mapping, so "+
			"its bytes can be replaced under the measurement and would be signed as mapped-image -- the "+
			"strongest label this attestor has, on bytes that never executed.", got)
	}
}

// TestStillMapping_NamedImageIsStillAdopted is the positive control for the
// test above. Refusing everything would satisfy it, and that would be a
// regression of its own: the ptrace backend exists to claim mapped-image where
// it genuinely holds.
//
// The filesystem probe is STUBBED so this control isolates the property it was
// written for -- that a named image reaches the ETXTBSY question -- from the
// separate filesystem gate. Without the stub the assertion silently depends on
// where t.TempDir() lands: it holds on tmpfs and ext4 and FAILS on overlayfs,
// where the gate refuses on purpose and the running kernel would still say
// guaranteed. A container is exactly where CI runs (Codex review of
// judge#9045), so that was a real break, not a hypothetical one. The
// filesystem gate has its own tests either side of this one.
func TestStillMapping_NamedImageIsStillAdopted(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(image, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	named, known := namedImage(image)
	if !known || !named {
		t.Fatalf("a freshly written file reports named=%v known=%v, want both true", named, known)
	}

	restore := imageFilesystemProbe
	t.Cleanup(func() { imageFilesystemProbe = restore })
	imageFilesystemProbe = func(string) (bool, bool) { return true, true }

	if got := stillMapping(image)(); got != runningKernelETXTBSYProtection() {
		t.Fatalf("stillMapping(%q) = %v, want the running kernel's answer %v: an ordinary named image on a "+
			"kernel-owned filesystem must still reach the ETXTBSY question rather than being refused before it",
			image, got, runningKernelETXTBSYProtection())
	}
}

// TestKernelOwnsTheBytesByFilesystem is the FUSE hole (Codex review of
// judge#9045), pinned the same way the ETXTBSY kernel-version exception is:
// as a table over the exact values the decision reads.
//
// ETXTBSY is a VFS-level deny on i_writecount. It refuses a local
// open(O_WRONLY) of a mapped executable, and that is all it does. It says
// nothing whatever about a filesystem whose bytes are supplied by user space:
// a FUSE daemon can return different content on every read while device,
// inode, ctime and size all stay exactly as they were -- so not only does the
// exe link keep resolving, the bracket digestOpenFile puts around the hash
// sees nothing move either. Bytes that never executed would have been signed
// mapped-image.
//
// A network filesystem is the same argument with the authority on another
// machine.
//
// The table is the contract. An unrecognised magic must be REFUSED rather than
// assumed benign, which is the direction the whole file fails in.
func TestKernelOwnsTheBytesByFilesystem(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic int64
		want  bool
	}{
		{"ext4", magicExt234, true},
		{"xfs", magicXfs, true},
		{"btrfs", magicBtrfs, true},
		{"f2fs", magicF2fs, true},
		{"erofs", magicErofs, true},
		{"squashfs", magicSquashfs, true},
		{"isofs", magicIsofs, true},
		{"tmpfs", magicTmpfs, true},

		// The finding. A user-space daemon owns these bytes.
		{"fuse", 0x65735546, false},
		{"nfs", 0x6969, false},
		{"smb/cifs", 0xFF534D42, false},
		{"9p", 0x01021997, false},
		{"ceph", 0x00C36400, false},

		// Excluded on purpose: an overlay's lower layer can be FUSE
		// (fuse-overlayfs), and this code cannot see through to it.
		{"overlayfs", 0x794C7630, false},

		// Unknown is not permission.
		{"zero", 0, false},
		{"unrecognised", 0x1234567, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelOwnsTheBytes(tc.magic); got != tc.want {
				t.Fatalf("kernelOwnsTheBytes(%#x) = %v, want %v", tc.magic, got, tc.want)
			}
		})
	}
}

// TestStillMapping_ImageOnAnUnownedFilesystemIsRefused drives the refusal
// through stillMapping itself rather than the classifier, so deleting the
// filesystem check from the predicate -- and not just breaking the table --
// fails a test.
//
// It reads the real filesystem under t.TempDir() and asserts stillMapping's
// answer agrees with what kernelOwnsTheBytes says about it. On an ordinary
// runner that directory is tmpfs or ext4 and the image is adopted; were the
// tests ever run with TMPDIR on a FUSE mount, the same assertion demands the
// refusal instead. Either way the two must not disagree, which is the property
// the deleted check would break.
func TestStillMapping_ImageOnAnUnownedFilesystemIsRefused(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(image, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	owned, known := imageOnKernelOwnedFilesystem(image)
	if !known {
		t.Skip("could not identify the filesystem under t.TempDir(), so this run did not stage the case")
	}

	// Deliberately branches on what the runner actually provides rather than
	// assuming it: on tmpfs or ext4 the image is adopted, on overlayfs (a
	// container, i.e. CI) it is refused, and both are correct answers for
	// their filesystem. The seam-driven test below covers the refusal on
	// machines that never present an unowned one.
	got := stillMapping(image)()
	if owned {
		if got != runningKernelETXTBSYProtection() {
			t.Fatalf("stillMapping = %v on a kernel-owned filesystem, want the running kernel's answer %v",
				got, runningKernelETXTBSYProtection())
		}
		return
	}
	if got == protectionGuaranteed {
		t.Fatalf("stillMapping returned %v for an image on a filesystem whose bytes the kernel does not "+
			"serve. ETXTBSY denies a local writable open; it cannot stop a user-space daemon from returning "+
			"different content on the next read, and every field the hash bracket compares would stay put.", got)
	}
}

// TestStillMapping_RefusesAnImageOnAFilesystemTheKernelDoesNotServe drives the
// refusal through stillMapping on a filesystem the runner does not have.
//
// The table test above covers the classifier, and the temp-dir test covers the
// case the runner happens to provide. Neither can catch the check being deleted
// from stillMapping: every path a test can create is on tmpfs or ext4, both
// kernel-owned, so the predicate answers the same with the call and without it.
// Verified -- removing the call passed the entire suite before this test
// existed. That is what imageFilesystemProbe is for.
//
// Both directions are asserted from the same seam, so a stub that simply
// refused everything would fail the second half.
func TestStillMapping_RefusesAnImageOnAFilesystemTheKernelDoesNotServe(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(image, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	restore := imageFilesystemProbe
	t.Cleanup(func() { imageFilesystemProbe = restore })

	for _, tc := range []struct {
		name         string
		owned, known bool
		wantRefusal  bool
	}{
		// The finding: a FUSE daemon owns the bytes, so ETXTBSY protects
		// nothing that matters and the label must not be claimed.
		{"user-space filesystem", false, true, true},
		// A statfs that did not answer is not an answer in this code's favour.
		{"filesystem unidentifiable", false, false, true},
		// The control. Refusing everything would satisfy the two cases above
		// and would be its own regression.
		{"kernel-owned filesystem", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imageFilesystemProbe = func(string) (bool, bool) { return tc.owned, tc.known }

			got := stillMapping(image)()
			if tc.wantRefusal {
				if got == protectionGuaranteed {
					t.Fatalf("stillMapping = %v, want a refusal: the image's bytes are not served by the "+
						"kernel (owned=%v known=%v), so ETXTBSY -- a deny on a local writable open -- "+
						"establishes nothing about them, and a mapped-image label would be unearned.",
						got, tc.owned, tc.known)
				}
				return
			}
			if got != runningKernelETXTBSYProtection() {
				t.Fatalf("stillMapping = %v on a kernel-owned filesystem, want the running kernel's "+
					"answer %v: an ordinary image must still reach the ETXTBSY question.",
					got, runningKernelETXTBSYProtection())
			}
		})
	}
}
