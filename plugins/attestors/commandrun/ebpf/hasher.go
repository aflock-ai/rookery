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

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TOCTOUStatus classifies the result of a hash relative to file
// mutations observed between BPF capture and userspace hash.
type TOCTOUStatus string

const (
	// TOCTOUStable: stat at hash time matched stat just before hash.
	// The hashed content is what the tracee's openat saw.
	TOCTOUStable TOCTOUStatus = "stable"

	// TOCTOUSuspect: the file's size or mtime changed during hashing.
	// The hash may not represent what the tracee's openat saw.
	// Verifiers should treat the recorded digest with skepticism.
	TOCTOUSuspect TOCTOUStatus = "suspect"

	// TOCTOUMissing: the file was unlinked or unreadable by the time
	// we tried to hash it. No digest recorded.
	TOCTOUMissing TOCTOUStatus = "missing"

	// TOCTOUError: an I/O or permissions error prevented hashing.
	TOCTOUError TOCTOUStatus = "error"
)

// HashResult is the outcome of one openat event's hash attempt.
type HashResult struct {
	Path   string
	Digest cryptoutil.DigestSet
	Status TOCTOUStatus
	Reason string // populated for non-stable statuses
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

	f, err := os.Open(fdPath) //nolint:gosec // G304: /proc/<pid>/fd/<fd>, by-design read
	if err != nil {
		return HashResult{}, false
	}
	digest, hashErr := cryptoutil.CalculateDigestSet(f, hashFuncs)
	_ = f.Close()
	if hashErr != nil {
		r.Status = TOCTOUError
		r.Reason = "hash via fd: " + hashErr.Error()
		return r, true
	}

	if statBefore == nil {
		// File was already unlinked at hash time; the fd content is
		// still authoritative. Stable.
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

// hashViaPath is the original V1 path: stat-before, open path,
// hash, stat-after. Used when fd-based access isn't available.
func hashViaPath(path string, hashFuncs []cryptoutil.DigestValue) HashResult {
	r := HashResult{Path: path}

	statBefore, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.Status = TOCTOUMissing
			r.Reason = "file removed before hash"
			return r
		}
		r.Status = TOCTOUError
		r.Reason = "pre-hash stat: " + err.Error()
		return r
	}

	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		r.Status = TOCTOUError
		r.Reason = "open: " + err.Error()
		return r
	}
	digest, err := cryptoutil.CalculateDigestSet(f, hashFuncs)
	_ = f.Close()
	if err != nil {
		r.Status = TOCTOUError
		r.Reason = "hash: " + err.Error()
		return r
	}

	statAfter, err := os.Stat(path)
	if err != nil {
		r.Digest = digest
		r.Status = TOCTOUSuspect
		r.Reason = "file removed during hash"
		return r
	}

	if !sameStat(statBefore, statAfter) {
		r.Digest = digest
		r.Status = TOCTOUSuspect
		r.Reason = fmt.Sprintf("file modified during hash: size %d->%d, mtime %v->%v",
			statBefore.Size(), statAfter.Size(),
			statBefore.ModTime().UnixNano(), statAfter.ModTime().UnixNano())
		return r
	}

	r.Digest = digest
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
