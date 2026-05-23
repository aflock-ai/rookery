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

// HashOpenatEvent stats + opens + hashes the path referenced by an
// openat event, and classifies the result by TOCTOU stability.
//
// The TOCTOU window in this V1 design:
//
//  1. BPF kprobe fires (tracee enters openat).
//  2. Tracee continues (V1 doesn't gate on userspace).
//  3. Userspace receives event, stats path → got stat_before.
//  4. Userspace opens + reads + hashes file.
//  5. Userspace stats path again → got stat_after.
//  6. If stat_before == stat_after: TOCTOU-stable. Otherwise suspect.
//
// This catches the common case where a tracee modifies the file
// between its open and our hash. It cannot prevent the race — only
// detect it. For true prevention, see issue #174 (IMA integration)
// or fanotify-pre-access which requires CAP_SYS_ADMIN.
func HashOpenatEvent(ev *OpenatEvent, hashFuncs []cryptoutil.DigestValue) HashResult {
	r := HashResult{Path: ev.Path}

	statBefore, err := os.Stat(ev.Path)
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

	// Open the file and hash its content.
	f, err := os.Open(ev.Path) //nolint:gosec
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

	// Stat again post-hash to detect mid-hash mutations.
	statAfter, err := os.Stat(ev.Path)
	if err != nil {
		// If the file disappeared during hashing, our digest is of
		// the pre-unlink content. Flag suspect.
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
