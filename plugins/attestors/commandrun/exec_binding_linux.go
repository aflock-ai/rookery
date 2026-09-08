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
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// imageProtection is a three-state answer to one question: for the WHOLE time
// we were measuring these bytes, could anything have written them?
//
// Three states, not two, because "I could not tell" is a real and common
// answer and it must not be spelled the same as "no". Only protectionGuaranteed
// earns ExeDigestSourceMappedImage; the other two downgrade identically.
// Unknown is not permission.
type imageProtection int

const (
	// protectionUnknown: the answer could not be established. Treated exactly
	// as protectionNotGuaranteed at the label.
	protectionUnknown imageProtection = iota
	// protectionNotGuaranteed: writes were possible during the measurement.
	protectionNotGuaranteed
	// protectionGuaranteed: writes were impossible for the whole measurement.
	protectionGuaranteed
)

func (p imageProtection) String() string {
	switch p {
	case protectionGuaranteed:
		return "guaranteed"
	case protectionNotGuaranteed:
		return "not-guaranteed"
	default:
		return "unknown"
	}
}

// etxtbsyProtectionForRelease says whether ETXTBSY can be relied on to deny an
// in-place write to a mapped executable on the kernel named by a uname
// release string.
//
// ETXTBSY denies that write on every kernel EXCEPT v6.11 and v6.12 — the
// exception this package states beside ExeDigestSourceMappedImage. On those
// two the write succeeds while the file stays mapped, so a measurement can
// cover bytes that never executed even though the process is alive and the
// (device, inode) tuple never moves. Hence: not guaranteed there.
//
// A release that cannot be parsed is UNKNOWN, never guaranteed. Failing to
// read the version is not evidence that the version is safe.
//
// Assumption worth naming: this trusts the documented exception to be the
// complete list. A future kernel that reintroduces the hole would be reported
// guaranteed until this list is updated, which is why the constant lives next
// to the prose that justifies it rather than being inlined at the call site.
func etxtbsyProtectionForRelease(release string) imageProtection {
	major, minor, ok := parseKernelRelease(release)
	if !ok {
		return protectionUnknown
	}
	if major == 6 && (minor == 11 || minor == 12) {
		return protectionNotGuaranteed
	}
	return protectionGuaranteed
}

// parseKernelRelease pulls major and minor out of a uname release such as
// "6.8.0-45-generic". Anything that does not start with <int>.<int> is not a
// release this code understands, and says so rather than guessing.
func parseKernelRelease(release string) (major, minor int, ok bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 3 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

var (
	kernelProtectionOnce sync.Once
	kernelProtection     imageProtection
)

// runningKernelETXTBSYProtection is etxtbsyProtectionForRelease for the kernel
// we are running on, resolved once. A uname that fails is unknown.
func runningKernelETXTBSYProtection() imageProtection {
	kernelProtectionOnce.Do(func() {
		var u unix.Utsname
		if err := unix.Uname(&u); err != nil {
			kernelProtection = protectionUnknown
			return
		}
		release := string(u.Release[:])
		if i := strings.IndexByte(release, 0); i >= 0 {
			release = release[:i]
		}
		kernelProtection = etxtbsyProtectionForRelease(release)
	})
	return kernelProtection
}

// The rule, stated once and enforced by provenMappedImage:
//
//	ExeDigestSourceMappedImage is claimed only when the bytes measured are
//	PROVABLY the bytes the kernel mapped for the exec being described.
//
// Two independent properties have to hold.
//
//	BOUND      the measured file is the image THIS exec produced, on evidence
//	           the tracee could not have manufactured after the fact.
//	PROTECTED  write protection demonstrably held across the WHOLE
//	           measurement, so the bytes hashed are the bytes that ran.
//
// Neither is established by re-observing the world after the exec. A pathname
// is mutable and a stat of it is a fresh observation, not a record of what
// happened; ETXTBSY protects a mapped image only while a live process still
// maps it. So BOUND is the caller's obligation — only a backend that holds
// the tracee still across the measurement, or that carries kernel-captured
// identity in its event, has it — and PROTECTED is this file's, enforced
// below.
//
// Where either cannot be proven the record says so: ExeDigestSourcePathHash
// plus an ExeDigestDowngradeReason. A label the producer cannot substantiate
// is worse than an honest weaker one, because a policy will trust it.

// namedImage reports whether `path` resolves to a file that still has a
// directory entry, following symlinks as execve does.
//
// `named` is true only when the stat succeeded, the target is not a directory,
// and st_nlink is at least 1. `known` is false when the stat failed or carried
// no kernel stat to read, and the caller treats that as a refusal: a fact that
// could not be established is not a fact in this file's favour.
//
// st_nlink == 0 is the kernel's own statement that nothing can reach these
// bytes by name — a memfd, or a file unlinked after it was executed. It is a
// property of the inode rather than a name pattern, so it needs no list of
// special paths to recognise.
//
// This file deliberately does NOT define its own identity type, and this
// function deliberately does not return one. An earlier revision carried a
// local (device, inode) `fileIdentity`, which collided with the
// (device, inode, ctime, size) one judge#9044 introduced for bracketing a read.
// Nor is nlink added to THAT tuple: it is the comparison bracketing a read, and
// a hardlink created while the file is being hashed changes no byte. Folding
// nlink in would turn a harmless link into a torn read.
func namedImage(path string) (named, known bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false, false
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false
	}
	return sys.Nlink > 0, true
}

// provenMappedImage measures the image at exePath and reports whether the
// result may be labelled ExeDigestSourceMappedImage.
//
// It hashes through ONE descriptor: exePath is opened once, the DESCRIPTOR is
// fstat'd, and the bytes are read through that descriptor — never by
// re-resolving the name. Re-resolving is what let a rename between the stat
// and the read substitute a different file, and it is why the ptrace backend's
// old stat-then-hash-by-path measurement was a sibling of the bug Codex cited
// on the eBPF side.
//
// protectedBy is the caller's answer to "were writes to these bytes impossible
// for the whole measurement". It is consulted BEFORE and AFTER the read,
// because the property has to hold ACROSS the measurement, not at one instant
// of it: opening the image pins the inode but does not protect its contents,
// and ETXTBSY lapses the moment the last executing reference goes away. A
// tracee that exits mid-measurement opens a window in which the same inode can
// be rewritten in place, and a same-size rewrite moves no field of any
// identity tuple — so the tuple cannot be what rules it out.
//
// The answer is three-state and ONLY protectionGuaranteed adopts. Round 3
// treated "the exe link still resolves" as protection and documented the
// Linux 6.11/6.12 ETXTBSY exception as a residual; that was the rule stated in
// this file being applied to everything except this file. Documenting a hole
// is right only when nothing better exists, and here something better does:
// downgrade. protectionUnknown is refused for the same reason — a producer
// that cannot tell whether writes were possible is in the position of one that
// knows they were. Unknown is not permission.
//
// The measurement itself is delegated to digestOpenFile (tracing_linux.go),
// which is the ONE place in this package that turns an open descriptor into a
// digest. That matters for two reasons.
//
// First, it is memo-free, and this is the path where that is worth the most.
// The executed-image digest is the single value a process allowlist reads, so
// a memo here is a memo on the highest-value claim the attestor makes. An
// earlier revision of this function served it from a cache keyed on
// (dev, ino, ctime, size) — precisely the key judge#9044 removed, because a
// tracee holding a writable MAP_SHARED mapping can hold every one of those
// fields still while the contents change. Nothing may reintroduce a memo on
// this path, and TestProvenMappedImage_MappedRewriteIsNeverServedAStaleDigest
// stages exactly that capability and asserts the second call re-measures.
//
// Second, digestOpenFile brackets the read the way judge#9044 rounds 6-7
// established: ebpf.SettleForRead takes the pre-read fstat only once the
// file's ctime is outside the coarse-clock window, so a write beginning after
// it is stamped later and shows up in the comparison. A bracket taken with a
// bare f.Stat() has same-tick blindness and would silently be the weaker
// check. The cost is up to one settle window on a just-built binary, which in
// a build is the binaries it execs once.
//
// The comparison digestOpenFile makes covers the descriptor's file object
// being replaced as well as its (ctime, size) moving. It does not catch a
// same-inode rewrite through an established mapping — nothing in userspace
// does — which is what protectedBy exists to rule out instead.
//
// Returns (nil, false) whenever the claim cannot be made; the caller then
// downgrades and records why.
func (p *ptraceContext) provenMappedImage(exePath string, protectedBy func() imageProtection) (cryptoutil.DigestSet, bool) {
	if protectedBy == nil || protectedBy() != protectionGuaranteed {
		return nil, false
	}
	// Resolved exactly once; every stat below is an fstat of THIS descriptor,
	// so a name swapped afterwards cannot change what is hashed.
	f, err := openForHashing(exePath)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	d, err := p.digestOpenFile(f)
	if err != nil {
		return nil, false
	}

	// Re-checked last: protection must have held for the whole read, and the
	// only moment we can observe "it held until now" is after the read.
	if protectedBy() != protectionGuaranteed {
		return nil, false
	}
	return d, true
}

// Filesystem magics whose bytes the KERNEL owns: the page cache is backed by a
// block device or by kernel-managed memory, and no user-space process can serve
// different content for a read without going through a write the kernel
// accounts for. Values are from linux/magic.h.
//
// This list is an ALLOWLIST, and that direction is the whole point. A
// filesystem that is not on it is not judged hostile -- it is judged
// unestablished, which this file treats the same way.
const (
	magicBtrfs    = 0x9123683E
	magicErofs    = 0xE0F5E1E2
	magicExt234   = 0xEF53
	magicF2fs     = 0xF2F52010
	magicIsofs    = 0x9660
	magicSquashfs = 0x73717368
	magicTmpfs    = 0x01021994
	magicXfs      = 0x58465342
)

// kernelOwnsTheBytes reports whether a filesystem magic names a filesystem
// whose contents the kernel serves from its own storage.
//
// ETXTBSY is a VFS-level deny on i_writecount: it refuses a local
// open(O_WRONLY) of a mapped executable. It says NOTHING about a filesystem
// whose bytes come from user space. A FUSE daemon can return different content
// on every read while every field digestOpenFile brackets -- device, inode,
// ctime, size -- stays exactly as it was, so the read is not even torn as far
// as the stats can tell (Codex review of judge#9045). The same applies to a
// network filesystem, where the authority for the bytes is another machine.
//
// tmpfs is included deliberately. Its pages are kernel memory, so the only way
// to change them is a write through a handle -- which is precisely what
// ETXTBSY denies while the image is mapped, and what the st_nlink test above
// covers for the anonymous case.
//
// overlayfs is deliberately NOT included, and that is the expensive entry. A
// container image is usually an overlay, so excluding it means those execs
// downgrade to a labelled path hash. It is excluded because an overlay's layers
// can themselves be FUSE (fuse-overlayfs is the standard rootless stack), and
// this code cannot see through to them: adopting the magic would claim for the
// overlay exactly what cannot be claimed for its lower layer. A downgrade there
// is honest and says why; a mapped-image label would not be.
func kernelOwnsTheBytes(magic int64) bool {
	switch magic {
	case magicBtrfs, magicErofs, magicExt234, magicF2fs,
		magicIsofs, magicSquashfs, magicTmpfs, magicXfs:
		return true
	default:
		return false
	}
}

// imageOnKernelOwnedFilesystem reports whether the image at `path` lives on a
// filesystem kernelOwnsTheBytes accepts. `known` is false when the filesystem
// could not be identified at all, which the caller refuses on: a statfs that
// did not answer is not an answer in this code's favour.
func imageOnKernelOwnedFilesystem(path string) (owned, known bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, false
	}
	return kernelOwnsTheBytes(int64(st.Type)), true //nolint:unconvert // Statfs_t.Type width differs across GOARCH
}

// imageFilesystemProbe is imageOnKernelOwnedFilesystem, indirected so a test
// can present a filesystem the machine running the tests does not have.
//
// The seam exists because without it the refusal is UNTESTABLE, not merely
// awkward to test. Every path a test can create lives on whatever filesystem
// the runner provides -- tmpfs or ext4, both kernel-owned -- so the check
// always says yes, and an implementation that had dropped the check entirely
// produced identical behaviour on every input. Verified: deleting the call
// from stillMapping passed the whole suite until this indirection existed.
//
// Production never reassigns it.
var imageFilesystemProbe = imageOnKernelOwnedFilesystem

// stillMapping is the stillProtected predicate for a traced pid: /proc/<pid>/exe
// still resolves AND the image behind it is a named file, so a live process
// still maps an image whose write protection the kernel enforces.
//
// The resolving exe link is most of the proof. A process that has exited has no
// /proc/<pid> at all; one that is a zombie has no mm and so no exe link. The
// predicate therefore fails when write protection has lapsed, which is the
// window in which the same inode could be rewritten in place under the
// descriptor we are hashing.
//
// It does NOT need to compare identity: provenMappedImage already re-checks
// the descriptor's own identity across the read, and the ptrace backend calls
// this while the tracee is stopped at the execve return, where it cannot exec
// again.
//
// AN ANONYMOUS IMAGE IS REFUSED, and it is the case the resolving link alone
// gets wrong (Codex review of judge#9045). A process can execute a memfd
// through /proc/self/fd/N. /proc/<pid>/exe then resolves for the whole run, so
// the link test passes and the (device, inode) tuple never moves — but an
// unsealed memfd stays writable to anyone still holding a descriptor or a
// shared mapping of it, and such a helper can replace the bytes underneath the
// measurement. A file unlinked after exec is the same shape: the exe link keeps
// resolving to an inode that no longer has a name.
//
// Both are "the image has no directory entry", which namedImage reads straight
// off the inode as st_nlink == 0.
//
// Refusing rather than proving immutability is deliberate, and it is this
// file's standing rule applied to one more case. A seal check (F_GET_SEALS)
// would say whether one particular memfd is immutable, but an unsealed one
// would still have to downgrade, and an image whose protection cannot be
// established is in the same position as one known to be unprotected. Unknown
// is not permission. The caller then records ExeDigestSourcePathHash with
// ExeDigestDowngradeUnprotected: the producer looked, could not prove the bytes
// were write-protected for the whole measurement, and said so.
//
// AN IMAGE THE KERNEL DOES NOT SERVE IS REFUSED. ETXTBSY is a VFS deny on
// i_writecount, so it stops a local writable open; it says nothing about a
// filesystem whose bytes come from user space. A FUSE daemon can hand back
// different content on every read while device, inode, ctime and size all stay
// put, so even the bracket around the hash sees nothing move. See
// kernelOwnsTheBytes for which filesystems qualify and why overlayfs does not.
func stillMapping(exePath string) func() imageProtection {
	return func() imageProtection {
		named, known := namedImage(exePath)
		if !known || !named {
			return protectionNotGuaranteed
		}
		owned, fsKnown := imageFilesystemProbe(exePath)
		if !fsKnown || !owned {
			return protectionNotGuaranteed
		}
		return runningKernelETXTBSYProtection()
	}
}
