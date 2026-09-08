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

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

func ctimeOf(t *testing.T, fi os.FileInfo) time.Time {
	t.Helper()
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no kernel identity on the fixture")
	}
	return time.Unix(int64(sys.Ctim.Sec), int64(sys.Ctim.Nsec)) //nolint:unconvert
}

// TestSettleForRead_WaitsOutAYoungFile is the deterministic seam for round 7.
// A bracketed read can only detect a write landing during it if the pre-read
// stat is already outside the coarse-clock window, so SettleForRead must not
// return a stat that is younger than that -- however young the file is when
// it is called.
func TestSettleForRead_WaitsOutAYoungFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "just-written")
	if err := os.WriteFile(path, []byte("brand new bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// Precondition: the file really is inside the window, so the wait is
	// exercised rather than skipped.
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	age := time.Since(ctimeOf(t, fi))
	if age >= SettleWindow {
		t.Skipf("skipping: the fixture aged %v before the test could start, so the wait could not be staged", age)
	}

	start := time.Now()
	settled, err := SettleForRead(f)
	if err != nil {
		t.Fatalf("an undisturbed young file must settle, not fail: %v", err)
	}
	if got := time.Since(ctimeOf(t, settled)); got < SettleWindow {
		t.Fatalf("SettleForRead returned a stat only %v old; a bracket built on it cannot see a write inside the tick (need >= %v)", got, SettleWindow)
	}
	owed := SettleWindow - age
	if elapsed := time.Since(start); owed >= 2*time.Millisecond && elapsed < owed/2 {
		t.Fatalf("returned in %v for a file %v old; at least %v of the %v window was still owed", elapsed, age, owed, SettleWindow)
	}
}

// TestSettleForRead_ReturnsImmediatelyForAnAgedFile is the cost control: the
// common case is a file the build did not just write, and it must not pay.
func TestSettleForRead_ReturnsImmediatelyForAnAgedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aged")
	if err := os.WriteFile(path, []byte("older bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(SettleWindow + 20*time.Millisecond)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// Best of three: the assertion is "it did not deliberately sleep", and a
	// single sample cannot tell a sleep from the scheduler taking the CPU
	// away. One clean sample proves no sleep is on the code path; three
	// dirty ones mean the machine is too loaded to measure, which is a
	// "could not check", not a failure.
	best := time.Duration(1<<63 - 1)
	for range 3 {
		start := time.Now()
		if _, err := SettleForRead(f); err != nil {
			t.Fatalf("an aged file must settle immediately: %v", err)
		}
		if e := time.Since(start); e < best {
			best = e
		}
	}
	// FAIL, not skip. Skipping whenever the number is large cannot
	// distinguish a regression from load -- an unconditional
	// time.Sleep(SettleWindow) added to SettleForRead made an earlier
	// version of this test skip and the run pass. The threshold is set so a
	// deliberate wait always trips it (any real sleep here is a whole
	// window) while three consecutive scheduling stalls of 37 ms would be
	// needed to trip it spuriously.
	if limit := SettleWindow * 3 / 4; best > limit {
		t.Fatalf("the fastest of 3 SettleForRead calls on an aged file took %v (limit %v): the settle must be free for files the build did not just write", best, limit)
	}
}

// TestSettleForRead_RefusesAFileThatNeverSettles: the wait is bounded. A file
// being rewritten in a loop never leaves the window, and a hasher that waited
// on it forever would stall the trace, so it is refused instead. The refusal
// is distinct so a caller can report it rather than fold it into a generic
// stat error.
func TestSettleForRead_RefusesAFileThatNeverSettles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "churning")
	if err := os.WriteFile(path, []byte("churn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Keep bumping ctime so the file never leaves the window.
			w, err := os.OpenFile(path, os.O_WRONLY, 0o644)
			if err != nil {
				continue
			}
			_, _ = w.WriteAt([]byte("churn\n"), 0)
			_ = w.Close()
			time.Sleep(time.Millisecond)
		}
	}()
	defer func() { close(stop); <-done }()

	start := time.Now()
	settled, err := SettleForRead(f)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrWillNotSettle) {
		// Before calling this a failure, check the premise on the stat
		// SettleForRead actually RETURNED -- not on a fresh one. A fresh stat
		// races the churner: it can be young again by the time we take it
		// even though the call was correct, which turns a stalled churner
		// into a spurious failure. The returned stat is the observation the
		// contract is about: if it was genuinely outside the window, the file
		// did settle and returning it was right, so the churner stalled and
		// this run never staged "never settles". If it was inside the window,
		// SettleForRead broke its contract and that IS the bug.
		if err == nil && settled != nil {
			if age := time.Since(ctimeOf(t, settled)); age >= SettleWindow {
				t.Skipf("skipping: the churner stalled and the file genuinely settled (the returned stat was %v old, >= %v), so 'never settles' was never staged", age, SettleWindow)
			}
		}
		t.Fatalf("error = %v, want ErrWillNotSettle", err)
	}
	// Bounded: settleAttempts waits of at most one window each, plus slack.
	if max := time.Duration(settleAttempts+2) * SettleWindow; elapsed > max {
		t.Fatalf("waited %v on a file that never settles; the cap must bound it below %v", elapsed, max)
	}
}

// TestHashers_YoungFileIsHashedNotDropped is the positive control the round-7
// change turns on: an undisturbed file that was JUST written must still end up
// hashed and reported stable, after the wait, rather than refused. Waiting
// keeps the material in the evidence; refusing would have dropped it.
func TestHashers_YoungFileIsHashedNotDropped(t *testing.T) {
	content := []byte("written a moment ago\n")
	for _, producer := range []struct {
		name string
		run  func(t *testing.T, path string) HashResult
	}{
		{"HashCapturedFile", func(t *testing.T, path string) HashResult {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			fi, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			return HashCapturedFile(path, f, fi, hashFuncs(t))
		}},
		{"hashViaPath", func(t *testing.T, path string) HashResult {
			return hashViaPath(path, hashFuncs(t))
		}},
	} {
		t.Run(producer.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fresh")
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
			// No ageing, no quiescing: the file is written and hashed at once,
			// which before round 7 was the case whose bracket proved nothing.
			// Read the age as late as possible: a loaded machine can age the
			// fixture out of the window before the timed call even begins,
			// and then there is no wait to observe.
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			age := time.Since(ctimeOf(t, fi))
			start := time.Now()
			r := producer.run(t, path)
			elapsed := time.Since(start)
			if r.Status != TOCTOUStable {
				t.Fatalf("an undisturbed young file must be hashed and reported stable, got %q (%s)", r.Status, r.Reason)
			}
			if r.Digest == nil {
				t.Fatal("an undisturbed young file must keep its digest; waiting is not dropping")
			}
			requireStableCarriesADigest(t, producer.name, r)
			want, err := cryptoutil.CalculateDigestSetFromFile(path, hashFuncs(t))
			if err != nil {
				t.Fatal(err)
			}
			// Compare the digest VALUES, not the set sizes: two sets of the
			// same length can describe different bytes, which is the whole
			// subject of this file.
			if len(r.Digest) != len(want) {
				t.Fatalf("digest set size %d, want %d", len(r.Digest), len(want))
			}
			for algo, v := range want {
				if r.Digest[algo] != v {
					t.Fatalf("digest for %v = %q, want %q", algo, r.Digest[algo], v)
				}
			}
			// The producer waited rather than reading straight away: a bracket
			// opened on an unsettled stat cannot see a same-tick write. The
			// stats themselves are not exported (a memo keyed on them is the
			// thing this PR removed), so the wait is asserted through the one
			// observable it leaves behind.
			// Assert against the wait that was actually owed. A flat 1 ms
			// would fail on a fixture with only 0.5 ms left to run, which is
			// a real outcome on a loaded machine and not a missing wait.
			owed := SettleWindow - age
			if owed < 2*time.Millisecond {
				t.Skipf("skipping the wait assertion: the fixture was %v old when the call began, leaving only %v to wait out (the digest above was still checked)", age, owed)
			}
			if elapsed < owed/2 {
				t.Fatalf("returned in %v for a file %v old; at least %v of the %v window was still owed", elapsed, age, owed, SettleWindow)
			}
		})
	}
}

// The round-7 invariant "a stable result never carries a torn digest" used
// to be asserted here against a free-running writer. It has moved to
// TestHashers_TornReadIsAnErrorWithNoDigest in hasher_bracket_linux_test.go,
// which asserts the same property but STAGES the write to begin after the
// pre-read fstat. Without that ordering the assertion could fail against a
// correct implementation, because an in-flight write that stamped ctime and
// then stalled past the settle window legitimately produces a mixed digest
// the bracket accepts (see TOCTOUStable).

// sameDigestSet compares two digest sets by value. The map keys carry the
// hash algorithm, so equality of both key set and values is exactly "these
// describe the same bytes".
func sameDigestSet(got, want cryptoutil.DigestSet) bool {
	if len(got) != len(want) || len(got) == 0 {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
