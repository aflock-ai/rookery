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

// TOCTOU-detecting hasher for eBPF mode (#167).
//
// Without CAP_SYS_ADMIN we can't *prevent* TOCTOU via fanotify
// pre-access, but we can *detect* it: after the BPF kprobe fires
// for an openat, userspace stats the path, opens + hashes the file,
// then stats again. If size/mtime changed between BPF-capture and
// our hash, the result is flagged TOCTOU-suspect. Verifiers can
// reject suspect hashes.
//
// For builds where files don't change after open (the honest case),
// the result is always TOCTOU-stable. For adversarial scenarios
// where the tracee modifies the file mid-trace, verifiers see the
// suspect flag.

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TOCTOUStatus classifies the result of a hash relative to file
// mutations observed between BPF capture and userspace hash.
type TOCTOUStatus string

const (
	// TOCTOUStable: NO CHANGE WAS OBSERVED across the read. The fstat taken
	// after it matched the one taken before it in (device, inode, ctime,
	// size), and the pre-read fstat was itself taken only once the file's
	// ctime was outside SettleWindow.
	//
	// Read that as the negative it is. "stable" is the absence of a
	// detection, not a proof of stability, and this package cannot produce
	// the latter. What the two halves buy is the SCOPE of the detection:
	//
	//   - The comparison alone catches a write that moves any of those four
	//     fields.
	//   - Settling first extends it to a same-size rewrite of the same inode
	//     inside one coarse timestamp tick. ctime comes from the coarse
	//     clock, so within a tick both fstats read identically while the
	//     digest combines bytes from two states; once the pre-read stat is
	//     older than the window, any write(2) after it is stamped later and
	//     the comparison sees it. See SettleWindow.
	//
	// TWO RESIDUALS neither half covers, and no stat-based check can:
	//
	//   - Mapped stores. The kernel stamps timestamps in the write FAULT
	//     that first makes a clean page writable, not in the stores that
	//     follow while the page is already dirty and the PTE already
	//     writable. So once a tracee holds a writable MAP_SHARED mapping and
	//     has faulted the pages in, it can change the file's contents with
	//     ctime, mtime, device, inode and size all unchanged, and a read
	//     torn by those stores is reported here as "stable". (Writeback can
	//     write-protect the pages again, after which the next store faults
	//     and does stamp -- so the window is not literally unbounded. It is
	//     wide, attacker-influenced, and entirely invisible from here, which
	//     is what matters.) Staged and asserted in commandrun's
	//     mapped_write_linux_test.go.
	//   - A write(2) already in flight. ext4 updates the timestamp in
	//     file_modified() during ext4_write_checks(), BEFORE copying the
	//     caller's bytes. A write that stamped ctime, then stalled past the
	//     settle window, can copy its data while we read and never stamp
	//     again. So "the compared fields did not move" does not even mean
	//     "no ordinary write reached the file during the read".
	//
	// Waiting longer before the first fstat helps with neither: it changes
	// when a stamp is read, not whether one was written. Nothing downstream
	// should read this status as more than "the checks this package can
	// perform found nothing".
	//
	// Closing the residuals needs a content-stability mechanism, and none is
	// available on the filesystems this runs on: STATX_CHANGE_COOKIE is
	// absent from the statx mask on overlayfs, ext4 and tmpfs alike, and
	// FS_IOC_ENABLE_VERITY returns EOPNOTSUPP on the ext4 filesystems here
	// because the verity feature flag is not set (it can be turned on with
	// `tune2fs -O verity` on an existing filesystem as well as at mkfs time,
	// so this is a deployment gap rather than a hard limit; ENOTTY on
	// overlayfs and tmpfs, which do not implement it at all). fs-verity is
	// the strongest of these: it makes the contents immutable and
	// kernel-checked on every read, which is an actual guarantee rather than
	// an observation. A change cookie is weaker -- an inode change counter
	// need not cover stores through already-writable PTEs, and it is not a
	// coherent snapshot -- but it would still be more than this. Carrying
	// that distinction per file needs a predicate field the wire does not
	// have yet, which is judge#9054.
	TOCTOUStable TOCTOUStatus = "stable"

	// TOCTOUSuspect: the file's size or mtime changed during hashing.
	// The hash may not represent what the tracee's openat saw.
	// Verifiers should treat the recorded digest with skepticism.
	TOCTOUSuspect TOCTOUStatus = "suspect"

	// TOCTOUMissing: the file was unlinked or unreadable by the time
	// we tried to hash it. No digest recorded.
	TOCTOUMissing TOCTOUStatus = "missing"

	// TOCTOUError: no digest could be produced that can be attributed to one
	// observed state of one file. That covers an I/O or permissions error,
	// and it also covers a read this package could not COMPARE: if the
	// descriptor's identity moved across the read, or either bracketing
	// fstat failed, the digest cannot be tied to what the stats saw. It may
	// be a mix of two states; it may equally be a whole state whose metadata
	// changed underneath (a chmod moves ctime and touches no content). The
	// stats cannot tell those apart, which is exactly why the answer is a
	// refusal rather than a guess. Such a
	// result carries no Digest at all, because a consumer holding one
	// cannot tell it from a good one, and recordEBPFOpenat's contract is
	// that an error records no OpenedFiles entry rather than a placeholder
	// (Codex review of judge#9044, round 5). "Could not check" must never
	// be reported as TOCTOUStable.
	TOCTOUError TOCTOUStatus = "error"
)

// HashResult is the outcome of one openat event's hash attempt.
type HashResult struct {
	Path   string
	Digest cryptoutil.DigestSet
	Status TOCTOUStatus
	Reason string // populated for non-stable statuses
	// NonRegular is true when the open targeted a non-regular file
	// (directory, char/block device, pipe, socket, symlink). These have
	// no hashable content and are NOT materials — callers suppress them
	// rather than recording a spurious "unhashed open" gap (e.g. every
	// build opens /dev/null).
	NonRegular bool

	// There is deliberately no stat reported alongside Digest. Earlier
	// revisions carried the bracketing fstats and the instant they were
	// taken so commandrun could key a per-trace digest memo on them. That
	// memo is gone -- a tracee holding a writable mapping can hold every
	// stat field still while the contents change, so no stat-derived key can
	// be correct (see TOCTOUStable and commandrun's digestForPath). Exposing
	// the stats again would only invite the same key to be rebuilt.
}

// SettleWindow is how far a file's ctime must be in the past before a
// bracketed read of it can OBSERVE a write(2) that lands DURING that read.
//
// The bracket compares (device, inode, ctime, size) either side of the read.
// ctime comes from the coarse clock, which advances once per tick, so a write
// at time W is stamped no earlier than W minus one tick. If the pre-read
// stat is taken at S and the file's ctime is C, then any write after S is
// stamped at least S minus one tick; for that to be distinguishable from C we
// need S - C to exceed one tick. Waiting until it does is what widens the
// bracket to cover the same-tick case: the ambiguity was never inherent to
// stat, it was inherent to statting a file that had just been written.
//
// What waiting does NOT do is make ctime a content version. A store through
// a writable mapping the tracee already holds updates no timestamp at all --
// the stamp belongs to the write fault that first dirtied the page, which
// may have happened long before -- so it is invisible however long the wait
// is. Nor does it cover a write(2) that stamped ctime and then stalled: ext4
// updates the timestamp before copying the caller's bytes, so the copy can
// land inside our read with no second stamp. This constant buys coverage of
// write(2) calls that BEGIN after the pre-read stat, and nothing beyond
// that; see TOCTOUStable for both residuals and commandrun's digestForPath
// for the consequence (no digest is memoised, and the measured cost of that
// on the hashing path, with the workload it was measured on).
//
// The value is a whole coarse-clock window rather than a bare tick so the
// margin does not depend on the kernel's CONFIG_HZ (10 ms at HZ=100, 4 ms at
// HZ=250, 1 ms at HZ=1000; consecutive writes measured ~2 ms apart on 6.8).
const SettleWindow = 50 * time.Millisecond

// settleAttempts bounds the wait. A file being rewritten in a loop never
// settles, and a hasher that waits forever on it stalls the trace, so the
// wait is capped and the read is refused instead.
const settleAttempts = 6

// ErrWillNotSettle reports a file whose ctime kept moving through
// settleAttempts waits. It is a refusal, not a degraded success: no digest is
// produced, because the pre-read fstat a bracket needs cannot be taken on a
// settled file, so a read of it could not be compared.
//
// Note what it does NOT say: that the contents were changing. Metadata-only
// churn (a chmod loop) moves ctime too. What is established is the inability
// to settle, which is enough to refuse and not enough to describe.
var ErrWillNotSettle = errors.New("file still being written after settle attempts; its ctime keeps moving, so a read of it cannot be compared against a settled identity")

// SettleForRead blocks until the descriptor's ctime is older than
// SettleWindow and returns the fstat taken at that point. That fstat is the
// one a caller must open its bracket with; taking it any earlier is what
// made the bracket unable to see a same-size rewrite inside one tick.
//
// It returns as soon as the file is already settled, which is the common
// case: a build mostly reads files it wrote long ago or never wrote at all.
func SettleForRead(f *os.File) (os.FileInfo, error) {
	for attempt := 0; ; attempt++ {
		at := time.Now()
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		sys, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			// No kernel identity: nothing to settle against, and the
			// caller's bracket cannot be evaluated either.
			return fi, nil
		}
		//nolint:unconvert // Stat_t field widths differ across GOARCH.
		ctime := time.Unix(int64(sys.Ctim.Sec), int64(sys.Ctim.Nsec))
		wait := SettleWindow - at.Sub(ctime)
		if wait <= 0 {
			return fi, nil
		}
		if attempt >= settleAttempts {
			return nil, ErrWillNotSettle
		}
		// A ctime in the future (clock skew, granularity) yields a wait
		// longer than the window; clamp so a skewed stamp cannot stall the
		// trace for an unbounded time.
		if wait > SettleWindow {
			wait = SettleWindow
		}
		time.Sleep(wait)
	}
}

// sameIdentity reports whether two stats agree on (device, inode, ctime,
// size). ctime is written by the kernel on data and metadata changes made
// through the write(2) family and is not settable from user space without
// CAP_SYS_TIME, which is why it is compared instead of mtime.
//
// It is a comparison of what the kernel reported, and its result is
// "nothing showed up", never "nothing happened". Three limits, in order of
// how easily each is forgotten:
//
//   - Same-tick writes. ctime comes from the coarse clock, so two writes
//     inside one tick carry one ctime and a same-size second write landing
//     during a read would leave both stats equal. Callers close this by
//     taking the first stat only after SettleForRead has put the file's
//     ctime outside the window. Passing this with an unsettled pre-read stat
//     proves nothing; see SettleWindow.
//   - Mapped writes. Stores through a writable mapping the tracee already
//     holds move no field compared here, at any wait.
//   - A write(2) that stamped and stalled. ext4 timestamps before it copies,
//     so an in-flight write can deliver its bytes during the read without a
//     second stamp.
//
// Nothing in this package closes the last two, and callers must not treat a
// true return as a verified read; see TOCTOUStable.
func sameIdentity(a, b os.FileInfo) bool {
	if a == nil || b == nil || a.Size() != b.Size() {
		return false
	}
	sa, aok := a.Sys().(*syscall.Stat_t)
	sb, bok := b.Sys().(*syscall.Stat_t)
	if !aok || !bok {
		return false
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino && sa.Ctim == sb.Ctim
}

// CaptureFileForLaterHash opens /proc/<pid>/fd/<fd> from the
// userspace tracer's PERSPECTIVE, returning an os.File that holds
// the underlying inode alive even if the tracee later closes its
// fd, exits, or unlinks the file. The hasher pool then reads from
// this os.File at its leisure.
//
// This is the race-tight capture pattern for the eBPF dispatcher:
// open IMMEDIATELY on event arrival (microseconds after the
// kernel openat returned to the tracee), then hand the open file
// to a worker pool for the (slow) hashing step. The race window
// shrinks from "hasher-pool-latency" (~ms or more under load) to
// "dispatcher-receive-window" (~us).
//
// Returns (nil, nil) when fd<0 (openat failed in the tracee) so
// the caller can short-circuit without an attestation entry.
// Returns (file, nil) on success; caller MUST close the file.
// Returns (nil, err) on real errors (process gone, permission).
//
// Refuses to return a handle to a non-regular file. /proc/<pid>/fd/<fd>
// can resolve to a pipe, socket, fifo, character device, or block
// device, especially if the tracee's openat referenced a path like
// /dev/stdin (→ inherited pipe) or if there's an fd-reuse race with
// the tracee swapping the fd to a pipe after openat. Reading such a
// captured handle would drain bytes the tracee was waiting for —
// exactly what broke the kernel-build syncconfig earlier. We stat
// the just-opened fd and abort if it's not a regular file. The
// caller treats `(nil, nil)` here as "no capture; let the slow path
// produce an UnhashedOpens entry with a reason."
func CaptureFileForLaterHash(pid uint32, fd int32) (*os.File, error) {
	if fd < 0 {
		return nil, nil
	}
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	f, err := os.Open(fdPath) //nolint:gosec // G304: /proc/<pid>/fd/<fd>, by-design read
	if err != nil {
		return nil, err
	}
	st, ferr := f.Stat()
	if ferr != nil {
		_ = f.Close()
		return nil, ferr
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil
	}
	return f, nil
}

// HashCapturedFile hashes a previously-captured os.File (from
// CaptureFileForLaterHash). The file is closed by this function.
// statBefore can be nil — caller is free to skip the pre-stat if
// the path may already be gone.
func HashCapturedFile(path string, f *os.File, statBefore os.FileInfo, hashFuncs []cryptoutil.DigestValue) HashResult {
	r := HashResult{Path: path}
	defer func() { _ = f.Close() }()
	// Settle first, then take the pre-read fstat: the bracket can only
	// detect a write during the read if the file's ctime is already outside
	// the coarse-clock window when the read starts (see SettleWindow).
	fdBefore, fdBeforeErr := SettleForRead(f)
	if errors.Is(fdBeforeErr, ErrWillNotSettle) {
		r.Status = TOCTOUError
		r.Reason = ErrWillNotSettle.Error()
		return r
	}
	digest, err := cryptoutil.CalculateDigestSet(f, hashFuncs)
	if err != nil {
		r.Status = TOCTOUError
		r.Reason = "hash via captured fd: " + err.Error()
		return r
	}
	// statAfter via the captured fd itself — robust even when the
	// path is unlinked (works against the inode, not the dirent).
	statAfter, ferr := f.Stat()

	// The bracket first, and the digest is not published until it passes.
	// The two fstats bracket the read; without both, or if they disagree,
	// no change can even be looked for and there is nothing to report.
	// Passing means no change was OBSERVED, which is what TOCTOUStable
	// claims and no more. The version this replaces set r.Digest before the
	// checks and fell through to TOCTOUStable whenever the identity
	// comparison failed, so a same-size rewrite landing during the read --
	// invisible to the size-only sameStatBasic below -- was published as
	// content that nothing had compared at all.
	if fdBeforeErr != nil || ferr != nil {
		r.Status = TOCTOUError
		r.Reason = "read could not be compared: fstat of the captured descriptor failed"
		return r
	}
	if !sameIdentity(fdBefore, statAfter) {
		r.Status = TOCTOUError
		r.Reason = "the captured descriptor's identity moved during the hash; the digest cannot be attributed to one observed state"
		return r
	}

	r.Digest = digest
	if statBefore != nil && !sameStatBasic(statBefore, statAfter) {
		// Nothing the bracket compares moved across the read, but the file
		// is not the state the dispatcher captured. That is the detection
		// this attestor exists to surface, so it keeps its digest and its
		// flag.
		r.Status = TOCTOUSuspect
		r.Reason = fmt.Sprintf("file mutated between capture and hash: size %d->%d",
			statBefore.Size(), statAfter.Size())
		return r
	}
	r.Status = TOCTOUStable
	return r
}

// nonRegularReason categorizes a non-regular file mode into a
// human-readable reason string. Distinguishing directories from
// pipes/sockets matters for verifier triage: directory accesses are
// expected (every gcc invocation opens locale + include dirs), while
// pipe/socket accesses are rare and worth flagging.
func nonRegularReason(m os.FileMode) string {
	switch {
	case m.IsDir():
		return "directory open (no content to hash)"
	case m&os.ModeSymlink != 0:
		return "symlink (kernel resolves; nothing to hash here)"
	case m&os.ModeNamedPipe != 0:
		return "named pipe (skipped to avoid draining tracee IO)"
	case m&os.ModeSocket != 0:
		return "socket (skipped to avoid draining tracee IO)"
	case m&os.ModeDevice != 0:
		return "device file (skipped to avoid driver-side side effects)"
	case m&os.ModeCharDevice != 0:
		return "char device (skipped to avoid driver-side side effects)"
	}
	return "non-regular file (skipped)"
}

// sameStatBasic compares size only (mtime check via os.FileInfo is
// unreliable for the captured-fd path since we can't compare against
// the disk dirent post-unlink). For CI / build workloads, size
// stability is sufficient to detect mutation between dispatcher
// capture and worker hash.
func sameStatBasic(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.Size() == b.Size()
}

// HashOpenatEvent stats + opens + hashes the file referenced by an
// openat event, and classifies the result by TOCTOU stability.
//
// V1.3 — prefer /proc/<pid>/fd/<fd> over the path. When the BPF
// kretprobe reported a valid fd, opening /proc/<pid>/fd/<fd> gives us
// the SAME open-file-description the tracee has. The kernel keeps
// that file alive (refcount via the tracee's fd table) even if the
// path is later unlinked or replaced via atomic rename. Race window
// shrinks to "between kretprobe and our open" instead of "between
// kprobe and our open" + we're robust to path replacement.
//
// Fallback: if fd is invalid (negative, meaning openat failed in the
// tracee) or /proc/<pid>/fd/<fd> isn't readable, fall back to the
// path. That preserves V1.2 behavior for openat2 + failed-open cases.
func HashOpenatEvent(ev *OpenatEvent, hashFuncs []cryptoutil.DigestValue) HashResult {
	return HashOpenatEventWithMode(ev, hashFuncs, false)
}

// HashOpenatEventWithMode lets the caller force path-only hashing.
// pathOnly=true skips the /proc/<pid>/fd/<fd> path entirely — used
// by the V1.4 read-tap partial-read fallback, which may run after
// the tracee has closed the fd (and a different file may have been
// assigned that fd in the meantime — fd reuse races would otherwise
// produce wrong-file digests).
func HashOpenatEventWithMode(ev *OpenatEvent, hashFuncs []cryptoutil.DigestValue, pathOnly bool) HashResult {
	if !pathOnly && ev.FD >= 0 {
		fdPath := fmt.Sprintf("/proc/%d/fd/%d", ev.PID, ev.FD)
		if res, ok := hashViaProcFD(fdPath, ev.Path, hashFuncs); ok {
			return res
		}
	}
	return hashViaPath(ev.Path, hashFuncs)
}

// hashViaProcFD opens /proc/<pid>/fd/<fd> (the tracee's actual file
// description). Returns (result, true) if the procfs entry was
// readable; (zero, false) if not — caller falls back to path-based.
//
// Critically, we still do the stat-before/stat-after comparison
// against the path (not the procfs entry, which returns the dynamic
// fd's stat). This catches the case where the tracee writes to its
// own fd while we hash — kernel page cache changes, our hash sees
// inconsistent state.
func hashViaProcFD(fdPath, origPath string, hashFuncs []cryptoutil.DigestValue) (HashResult, bool) {
	r := HashResult{Path: origPath}

	// stat-before via the original path (for TOCTOU comparison).
	statBefore, err := os.Stat(origPath)
	if err != nil {
		// Path gone but fd might still resolve — try anyway.
		statBefore = nil
	}

	// CRITICAL: refuse to open the fd if statBefore says it's not a
	// regular file. /proc/<pid>/fd/<fd> for a pipe/socket/fifo can
	// be OPENED — but reading from it DRAINS bytes the tracee was
	// supposed to read. e.g., when the tracee opens "/dev/stdin"
	// (resolved to the parent's pipe via /proc/self/fd/0), our
	// "hashing" of /proc/<pid>/fd/<fd> would empty the pipe and the
	// tracee subsequently reads garbage / nothing.
	//
	// This caused the kernel-build capstone to die at make syncconfig
	// with "gcc: unknown C compiler" — cc-version.sh's heredoc was
	// being drained by our hasher before gcc could read it.
	//
	// Bypass the entire fd-read path for non-regular files. The
	// fallback (hashViaPath) ALSO checks the file mode and refuses
	// non-regular files — so the overall result is TOCTOUError with
	// a clear reason, recorded into UnhashedOpens.
	if statBefore != nil && !statBefore.Mode().IsRegular() {
		r.Status = TOCTOUError
		r.Reason = nonRegularReason(statBefore.Mode())
		r.NonRegular = true
		return r, true
	}

	f, err := os.Open(fdPath) //nolint:gosec // G304: /proc/<pid>/fd/<fd>, by-design read
	if err != nil {
		return HashResult{}, false
	}
	// CRITICAL: fd-reuse defense. The BPF openat event captured
	// (pid, fd, path) at the moment of the tracee's openat. By the
	// time the userspace hasher pool reaches this point, the tracee
	// may have closed that fd and REUSED the fd number for a
	// different open — e.g. closed a regular file at fd=3, then
	// opened a PIPE at the same fd=3. /proc/<pid>/fd/<fd> now
	// points at the new (pipe) file. Reading from it DRAINS bytes
	// the tracee was waiting for.
	//
	// Detection: stat the just-opened fd. If its file type doesn't
	// match what we'd expect for a regular-file open (the only kind
	// we want to hash), abort. The kernel-build capstone died here
	// before this check: gcc's heredoc was being drained because
	// /proc/<gcc>/fd/3 (originally a .s file) was now a pipe for a
	// later child process.
	fst, ferr := SettleForRead(f)
	if errors.Is(ferr, ErrWillNotSettle) {
		_ = f.Close()
		r.Status = TOCTOUError
		r.Reason = ErrWillNotSettle.Error()
		return r, true
	}
	if ferr != nil || !fst.Mode().IsRegular() {
		// fd was reused for a non-regular file after the tracee's
		// openat — DON'T read from this fd (it'd drain the tracee's
		// pipe/socket). Return (zero, false) so the caller falls
		// back to hashViaPath, which opens the ORIGINAL path by name.
		// If the original path is still a regular file on disk
		// (common case: gcc/rustc opens main.rs, closes fd, fd gets
		// reused for a pipe — main.rs itself still exists), we can
		// safely read it by name. hashViaPath does its own IsRegular
		// check so we don't risk reading a pipe-by-name either.
		_ = f.Close()
		return HashResult{}, false
	}
	digest, hashErr := cryptoutil.CalculateDigestSet(f, hashFuncs)
	// fstat of the same descriptor after the read: with fst (taken before
	// it) this is the bracket the read is compared across. Neither stat is
	// reported to the caller -- see HashResult.
	fdAfter, fdAfterErr := f.Stat()
	_ = f.Close()
	if hashErr != nil {
		r.Status = TOCTOUError
		r.Reason = "hash via fd: " + hashErr.Error()
		return r, true
	}
	// VALIDITY first, exactly as in HashCapturedFile: the descriptor's own
	// two fstats bracket the read, and a read whose brackets disagree -- or
	// cannot be taken -- yields no digest at all. Agreement is not proof
	// that nothing was written, only that nothing observable was; see
	// TOCTOUStable.
	if fdAfterErr != nil {
		r.Status = TOCTOUError
		r.Reason = "read could not be compared: post-read fstat of the fd failed"
		return r, true
	}
	if !sameIdentity(fst, fdAfter) {
		r.Status = TOCTOUError
		r.Reason = "the fd's identity moved during the hash; the digest cannot be attributed to one observed state"
		return r, true
	}

	if statBefore == nil {
		// File was already unlinked at hash time; the fd content is
		// still the bytes that were read, and the bracketing fstats above
		// observed no change across the read.
		r.Digest = digest
		r.Status = TOCTOUStable
		return r, true
	}
	statAfter, err := os.Stat(origPath)
	if err != nil {
		r.Digest = digest
		r.Status = TOCTOUSuspect
		r.Reason = "file removed during hash (read via fd succeeded)"
		return r, true
	}
	if !sameStat(statBefore, statAfter) {
		r.Digest = digest
		r.Status = TOCTOUSuspect
		r.Reason = fmt.Sprintf("file modified during hash via fd: size %d->%d",
			statBefore.Size(), statAfter.Size())
		return r, true
	}

	r.Digest = digest
	r.Status = TOCTOUStable
	return r, true
}

// hashViaPath is the fallback used when fd-based access isn't available:
// open the path once, and let the descriptor answer every question after
// that.
//
// The version this replaces stat'd the name, opened the name again, and
// then stat'd the name a THIRD time, calling the read TOCTOUStable when the
// size and mtime matched across those separate resolutions. Both of those
// fields are settable by the file's owner (truncate(2), utimensat(2)) --
// which is what judge#9044 round 1 was about -- and the non-regular check
// sat on the first resolution while the open used the second, so a symlink
// flipped between them opened the pipe the check had just cleared.
//
// Now: one resolution, O_NONBLOCK so a FIFO cannot block the open, the
// regular-file check on the DESCRIPTOR, and the read bracketed by two
// fstats of that same descriptor. Stable means those two fstats agree; a
// disagreement is an error with no digest, never a weaker label
// (judge#9044, round 5). The path is still stat'd around the read, but only
// to surface the weaker "the name moved" signal as TOCTOUSuspect.
func hashViaPath(path string, hashFuncs []cryptoutil.DigestValue) HashResult {
	r := HashResult{Path: path}

	statBefore, statBeforeErr := os.Stat(path)
	if statBeforeErr != nil && errors.Is(statBeforeErr, os.ErrNotExist) {
		r.Status = TOCTOUMissing
		r.Reason = "file removed before hash"
		return r
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: hashing a path the tracee named is this attestor's whole job
	if err != nil {
		r.Status = TOCTOUError
		r.Reason = "open: " + err.Error()
		return r
	}
	defer func() { _ = f.Close() }()

	fdBefore, fdBeforeErr := SettleForRead(f)
	if errors.Is(fdBeforeErr, ErrWillNotSettle) {
		r.Status = TOCTOUError
		r.Reason = ErrWillNotSettle.Error()
		return r
	}
	if fdBeforeErr != nil {
		r.Status = TOCTOUError
		r.Reason = "pre-read fstat: " + fdBeforeErr.Error()
		return r
	}
	// Refuse non-regular files, judged on the descriptor actually opened.
	// Reading a pipe/socket/fifo would drain bytes the tracee needs.
	if !fdBefore.Mode().IsRegular() {
		r.Status = TOCTOUError
		r.Reason = "non-regular file (pipe/socket/fifo/device); skipped to avoid draining tracee IO"
		r.NonRegular = true
		return r
	}

	digest, err := cryptoutil.CalculateDigestSet(f, hashFuncs)
	if err != nil {
		r.Status = TOCTOUError
		r.Reason = "hash: " + err.Error()
		return r
	}
	fdAfter, fdAfterErr := f.Stat()

	// VALIDITY: the descriptor's own two fstats bracket the bytes.
	if fdAfterErr != nil {
		r.Status = TOCTOUError
		r.Reason = "read could not be compared: post-read fstat failed"
		return r
	}
	if !sameIdentity(fdBefore, fdAfter) {
		r.Status = TOCTOUError
		r.Reason = "the descriptor's identity moved during the hash; the digest cannot be attributed to one observed state"
		return r
	}

	r.Digest = digest

	// Nothing the bracket compares moved across the read. Whether the NAME
	// still refers to that file is a separate question this path can also
	// answer, and it is weaker still.
	statAfter, statAfterErr := os.Stat(path)
	switch {
	case statBeforeErr != nil || statAfterErr != nil:
		r.Status = TOCTOUSuspect
		r.Reason = "file removed during hash (read through the descriptor succeeded)"
		return r
	case !sameStat(statBefore, statAfter):
		r.Status = TOCTOUSuspect
		r.Reason = fmt.Sprintf("file modified during hash: size %d->%d, mtime %v->%v",
			statBefore.Size(), statAfter.Size(),
			statBefore.ModTime().UnixNano(), statAfter.ModTime().UnixNano())
		return r
	}

	r.Status = TOCTOUStable
	return r
}

// sameStat returns true if two os.FileInfo values represent the same
// inode at the same size and mtime. Conservative — any change is
// treated as a TOCTOU signal.
func sameStat(a, b os.FileInfo) bool {
	if a.Size() != b.Size() {
		return false
	}
	if !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	// Inode comparison via Sys() — if the inode changed (e.g., path
	// rebound to a different file via rename), that's definitely a
	// TOCTOU event even if size and mtime happen to match.
	sa, aok := a.Sys().(*syscall.Stat_t)
	sb, bok := b.Sys().(*syscall.Stat_t)
	if aok && bok {
		if sa.Ino != sb.Ino || sa.Dev != sb.Dev {
			return false
		}
	}
	return true
}

// digestCloser wraps an *os.File so the cryptoutil API can read it
// (it takes an io.Reader) while we retain Close.
type digestCloser struct {
	io.Reader
	c io.Closer
}

func (d *digestCloser) Close() error { return d.c.Close() }
