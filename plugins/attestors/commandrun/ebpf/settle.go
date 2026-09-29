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

// Settling a file before a bracketed read. Portable, because the program
// record (commandrun's program_record.go) hashes argv[0] on every platform, not
// only under the Linux tracers that first needed it. The change-time source is
// per OS: settle_ctime_linux.go, settle_ctime_darwin.go, settle_ctime_other.go.

package ebpf

import (
	"errors"
	"os"
	"time"
)

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
		ctime, ok := changeTime(fi)
		if !ok {
			// No kernel change time: nothing to settle against, and the
			// caller's bracket cannot be evaluated either.
			return fi, nil
		}
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
