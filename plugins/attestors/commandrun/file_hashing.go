// Copyright 2021 The Witness Contributors
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

// The open-once, settle, fstat, hash, fstat, compare bracket, moved out of
// tracing_linux.go so it builds on every platform, not only under the Linux
// tracers that first needed it. Only the identity source differs per OS:
// file_identity_linux.go, _darwin.go, _other.go.

package commandrun

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

// fileIdentity is the kernel's identity of an open file: device, inode,
// ctime and size. It is what the bracketing fstats around a read are
// compared on.
//
// It is a comparison, not a content version. ctime is written by the kernel
// on data and metadata changes made through the write(2) family and cannot
// be set from user space without CAP_SYS_TIME, which is why it beats mtime
// (utimensat(2)) and size (truncate(2)) -- the fields the original cache key
// used, and the forgery digest_binding_linux_test.go reproduces. It does NOT
// cover stores through an established writable mapping; see tracing_linux.go.
type fileIdentity struct {
	dev, ino  uint64
	ctimeSec  int64
	ctimeNsec int64
	size      int64
}

// A read is REFUSED when the bracketing fstats disagree, or cannot be
// compared at all, or the descriptor is not a regular file. Each is a
// refusal that yields NO digest: a digest whose bytes were never a single
// state of a file is worse than no digest, because it is signed as evidence
// and nothing downstream can tell it from a good one.
var (
	// errTornRead: the descriptor's identity moved across the read. The
	// bytes may be a mix of two states of the file, or the change may have
	// been metadata-only (a chmod moves ctime and touches no content) -- the
	// stats cannot tell those apart, so the digest cannot be attributed to
	// one observed state and is refused rather than guessed at.
	errTornRead = errors.New("the descriptor's identity moved while it was being hashed, so the digest cannot be attributed to one observed state")
	// errUncomparableRead: a stat needed to compare the read against the
	// descriptor's identity could not be taken. "Could not check" is not
	// "checked and fine"; the repo rule is that an error is never a
	// permissive answer.
	errUncomparableRead = errors.New("read could not be compared against the descriptor's identity")
	// errNotRegularFile: a directory, pipe, socket or device has no stable
	// content to hash, and its bytes are the tracee's rather than ours to
	// consume.
	errNotRegularFile = errors.New("not a regular file")
)

// observedUnchanged compares the two fstats that bracket a read and reports
// whether anything changed between them THAT A STAT CAN SHOW.
//
// Read the name literally. It does not verify the read, and nothing in this
// package does:
//
//   - What it establishes: none of (device, inode, ctime, size) moved
//     between the two fstats. Because ebpf.SettleForRead takes the first one
//     only once the file's ctime is outside the coarse-clock window, that
//     covers any write(2) that BEGINS after it -- such a write is stamped
//     later and shows up here. Without the wait, a same-size rewrite inside
//     one tick would leave both stats identical.
//   - What it does NOT establish: that the bytes hashed are one state of the
//     file. Two writers move nothing this compares. Stores through a
//     writable mapping the tracee already holds never stamp at all. And a
//     write(2) already in flight has stamped ctime before copying its bytes
//     (ext4 does this in file_modified() during ext4_write_checks), so it
//     can deliver them during the read with no second stamp. Neither is
//     closable with stat(2), and they are why no digest is memoised (see
//     tracing_linux.go). What dropping the memo buys is that a bad read stays
//     confined to the single read it occurred in, instead of being latched
//     into an answer served for the rest of the trace.
//
// A nil error therefore means "the compared fields did not move", which is
// strictly weaker than "the read was verified" and is the only claim the
// code is entitled to make.
func observedUnchanged(before, after os.FileInfo) error {
	if before == nil || after == nil {
		return errUncomparableRead
	}
	if !before.Mode().IsRegular() {
		return errNotRegularFile
	}
	ib, okBefore := identityFromInfo(before)
	ia, okAfter := identityFromInfo(after)
	if !okBefore || !okAfter {
		return errUncomparableRead
	}
	if ia != ib {
		return errTornRead
	}
	return nil
}

// openForHashing resolves `path` EXACTLY ONCE and hands back the descriptor
// that resolution produced. Every stat afterwards is an fstat of this
// descriptor, so a name swapped after the open cannot change what is hashed
// or what the digest is reported for.
//
// O_NONBLOCK keeps the open of a FIFO from blocking on a writer that will
// never come; digestOpenFile then refuses it, because the descriptor's fstat
// says it is not a regular file. That is stricter than the code this
// replaces, which stat'd the name, saw "not a directory", and went on to
// open and read it -- draining a pipe the tracee was waiting on, or reading
// a character device without end.
func openForHashing(path string) (*os.File, error) {
	pathResolutions.Add(1)
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: hashing a path the tracee named is this attestor's whole job
}

// pathResolutions counts name resolutions performed for hashing. Every open
// in this package's measurement path goes through openForHashing, so it is
// the number of times a pathname was turned into a file.
//
// It exists so the ONE-RESOLUTION rule can be ASSERTED rather than merely
// asserted-in-prose. "Resolve once, then use the descriptor" cannot be tested
// by observing behaviour: any hook a test can install fires inside
// digestOpenFile, which is after every open, so an implementation that
// resolves the name twice and one that resolves it once produce identical
// bytes and identical stats. The count is the only thing that differs, and
// without it a measurement rewritten to re-resolve the path passes the whole
// suite (verified: a mutation replacing provenMappedImage's descriptor read
// with a by-name read survived every other test in this package).
//
// Cost is one relaxed atomic add per file hashed, against a full SHA-256 of
// that file.
var pathResolutions atomic.Int64

// bracketedDigest hashes an already-open descriptor: settle, fstat, hash
// through f, fstat again, compare. Every failure is an error and NO digest.
// The error is returned rather than folded into a weaker success, because
// the caller cannot tell the two apart once a digest is in hand, and a
// digest of a torn read that reaches attestation is signed evidence for
// bytes that were never a state of the file.
//
// The digest it returns is a fresh measurement every time; see the no-memo
// note in tracing_linux.go for why there is nothing here to hit.
func bracketedDigest(f *os.File, hashes []cryptoutil.DigestValue, duringRead func()) (cryptoutil.DigestSet, error) {
	// Settle first: the bracket below can only show a write landing during
	// the read if the file's ctime is already outside the coarse-clock
	// window when the pre-read fstat is taken. See ebpf.SettleWindow.
	before, err := ebpf.SettleForRead(f)
	if err != nil {
		if errors.Is(err, ebpf.ErrWillNotSettle) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: pre-read fstat: %w", errUncomparableRead, err)
	}
	if !before.Mode().IsRegular() {
		return nil, errNotRegularFile
	}
	// The only window in which a test can act on the file BETWEEN the
	// pre-read fstat and the hash. It lives here, in the one function that
	// turns a descriptor into a digest, rather than in a caller: a hook in a
	// caller can only reach the outside of the bracket, which is the part
	// that is not interesting.
	if duringRead != nil {
		duringRead()
	}
	d, err := cryptoutil.CalculateDigestSet(f, hashes)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	after, err := f.Stat()
	if err != nil {
		// Nothing to compare the read against. Refuse: this is the
		// fail-open shape the repo has a standing rule against, and the
		// answer is not a digest with a weaker label.
		return nil, fmt.Errorf("%w: post-read fstat: %w", errUncomparableRead, err)
	}
	if err := observedUnchanged(before, after); err != nil {
		return nil, err
	}
	return d, nil
}
