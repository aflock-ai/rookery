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
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// A HashResult must not be able to carry a failed or absent check that a
// consumer can ignore. TOCTOUStable says only "no change was observed across
// the read"; the version these tests were written against applied it
// whenever the descriptor's identity comparison merely failed to run or
// failed outright. See judge#9044 round 5.
//
// Note what is NOT asserted anywhere here, because the code no longer claims
// it: that a stable read was verified. Stores through a writable mapping the
// tracee already holds are invisible to the bracket, so "stable" is the
// absence of a detection. See TOCTOUStable and commandrun's
// mapped_write_linux_test.go.

// stagedWriteDelay is how long a staged writer waits after being released
// before it rewrites the file under a hash that is already running.
//
// It establishes the ordering the torn-read regressions depend on -- the
// write must BEGIN after the producer's pre-read fstat -- by margin, not by
// synchronisation. User space cannot synchronise with an fstat taken inside
// the producer, so the writer is parked on a channel released immediately
// before the call, the file is aged so the settle inside the call is a
// no-op, and the delay is then far longer than the microseconds between the
// release and that fstat while still landing well inside a 24 MiB read.
//
// If a test using it ever fails with a digest of neither whole content, the
// overwhelmingly likely cause is the bracket having been weakened. The other
// explanation is the documented in-flight-write residual (see TOCTOUStable),
// which would require this process to be descheduled for longer than the
// delay at exactly the wrong moment.
const stagedWriteDelay = 10 * time.Millisecond

func hashFuncs(t *testing.T) []cryptoutil.DigestValue {
	t.Helper()
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

// isBracketRejection reports whether a Reason is the bracket refusing a read
// it completed -- as opposed to ErrWillNotSettle, which refuses before any
// byte is read.
//
// The substrings live in one place because they are load-bearing: a test
// that filters on a reason string it no longer matches skips every assertion
// behind it and reports a pass. TestBracketRejectionReasonsAreMatched pins
// them against the reasons the producers actually emit.
func isBracketRejection(reason string) bool {
	return strings.Contains(reason, "identity moved") ||
		strings.Contains(reason, "could not be compared")
}

// TestBracketRejectionReasonsAreMatched is the guard on that filter: it
// stages a real bracket rejection and asserts the matcher recognises it. If
// the production reasons are reworded again, this fails loudly instead of
// letting the racy tests quietly stop asserting.
func TestBracketRejectionReasonsAreMatched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "material")
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

	for range 10 {
		ageOut(t, path)
		go func() {
			time.Sleep(stagedWriteDelay)
			f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
			if err != nil {
				return
			}
			_, _ = f.WriteAt(b, 0)
			_ = f.Close()
		}()
		r := hashViaPath(path, hashFuncs(t))
		if r.Status != TOCTOUError || strings.Contains(r.Reason, "still being written") {
			continue
		}
		if !isBracketRejection(r.Reason) {
			t.Fatalf("a bracket rejection was not recognised by isBracketRejection; the production reason has drifted: %q", r.Reason)
		}
		return
	}
	t.Skip("skipping: no bracket rejection could be staged in 10 attempts, so the matcher was not exercised")
}

// requireStableCarriesADigest is the invariant every producer must satisfy on
// every result: a stable label implies a digest. "Could not check" must never
// wear the label of "checked and nothing showed up", and the two used to be
// indistinguishable to a consumer.
func requireStableCarriesADigest(t *testing.T, what string, r HashResult) {
	t.Helper()
	if r.Status != TOCTOUStable {
		return
	}
	if r.Digest == nil {
		t.Fatalf("%s: TOCTOUStable with no digest", what)
	}
}

// TestHashers_StableCarriesADigest is the deterministic positive control: on
// a quiet regular file every producer returns a stable result with a digest.
// It is also the shape assertion the racy tests reuse.
func TestHashers_StableCarriesADigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "material")
	if err := os.WriteFile(path, []byte("quiet bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	captured := HashCapturedFile(path, f, before, hashFuncs(t))
	requireStableCarriesADigest(t, "HashCapturedFile", captured)
	if captured.Status != TOCTOUStable {
		t.Fatalf("HashCapturedFile on a quiet file: status = %q (%s)", captured.Status, captured.Reason)
	}

	viaPath := hashViaPath(path, hashFuncs(t))
	requireStableCarriesADigest(t, "hashViaPath", viaPath)
	if viaPath.Status != TOCTOUStable {
		t.Fatalf("hashViaPath on a quiet file: status = %q (%s)", viaPath.Status, viaPath.Reason)
	}
	if viaPath.Digest == nil {
		t.Fatal("hashViaPath on a quiet file returned no digest")
	}

	fd, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fd.Close() }()
	ev := &OpenatEvent{PID: uint32(os.Getpid()), FD: int32(fd.Fd()), Path: path}
	viaFD := HashOpenatEvent(ev, hashFuncs(t))
	requireStableCarriesADigest(t, "HashOpenatEvent", viaFD)
	if viaFD.Status != TOCTOUStable {
		t.Fatalf("HashOpenatEvent on a quiet file: status = %q (%s)", viaFD.Status, viaFD.Reason)
	}
}

// TestHashers_TornReadIsAnErrorWithNoDigest stages a rewrite through the
// same inode while each producer hashes it. Two assertions, and the second
// is what gives the test teeth:
//
//   - A read the descriptor's own two fstats do not vouch for must come back
//     as TOCTOUError with NO digest. recordEBPFOpenat's contract is that an
//     error records no OpenedFiles entry, so torn bytes never become
//     evidence.
//   - A read reported TOCTOUStable must carry the digest of one of the two
//     WHOLE contents, checked against independently computed expectations.
//     Without this the test could only ever observe the implementation's own
//     rejection messages: disabling sameIdentity in both producers made the
//     previous version report zero rejections and SKIP, which is how a
//     removed check passed for a clean run.
//
// The tear is STAGED, not raced. The file is aged past the settle window
// before each pass, so the producer's pre-read fstat is taken within
// microseconds of the call; the writer is parked on a channel released
// immediately before that call and then waits stagedWriteDelay, so its
// rewrite begins well after the fstat and carries a later ctime. That is a
// tear the bracket is required to catch, and it keeps the documented
// in-flight-write residual (ext4 stamps in file_modified() before copying;
// see TOCTOUStable) out of the assertions.
//
// The ordering is a MARGIN, not a synchronisation -- the fstat is taken
// inside the producer and user space has nothing to synchronise against. See
// stagedWriteDelay.
func TestHashers_TornReadIsAnErrorWithNoDigest(t *testing.T) {
	// Large enough that the read spans the rewrite rather than finishing
	// before it starts.
	const size = 24 << 20
	a := make([]byte, size)
	b := make([]byte, size)
	for i := range a {
		a[i] = byte('A' + i%23)
		b[i] = byte('a' + i%23)
	}

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
			dir := t.TempDir()
			path := filepath.Join(dir, "material")
			if err := os.WriteFile(path, a, 0o644); err != nil {
				t.Fatal(err)
			}
			// Independent expectations, computed from the buffers rather
			// than by re-reading the file the writer is about to churn.
			wantA, wantB := digestOf(t, dir, "ref-a", a), digestOf(t, dir, "ref-b", b)

			rewrite := func(i int) {
				content := a
				if i%2 == 1 {
					content = b
				}
				// Same inode, same size: only ctime separates the two
				// states, which is exactly what the bracketing fstats
				// compare and what a size-only check cannot see.
				f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
				if err != nil {
					return
				}
				_, _ = f.WriteAt(content, 0)
				_ = f.Close()
			}

			torn, stable := 0, 0
			for i := range 20 {
				ageOut(t, path)

				// The writer is parked on a channel FIRST, so the only
				// thing between the release and the write is the delay,
				// and the release is on the line before the call. See
				// stagedWriteDelay for why this is a margin rather than a
				// synchronisation.
				start := make(chan struct{})
				written := make(chan struct{})
				go func() {
					defer close(written)
					<-start
					time.Sleep(stagedWriteDelay)
					rewrite(i)
				}()
				close(start)
				r := producer.run(t, path)
				<-written

				requireStableCarriesADigest(t, producer.name, r)
				if r.Status == TOCTOUStable {
					stable++
					if !sameDigestSet(r.Digest, wantA) && !sameDigestSet(r.Digest, wantB) {
						t.Fatalf("%s: a read reported STABLE carries a digest of neither whole content -- torn bytes reached evidence. "+
							"The rewrite was staged to begin after the pre-read fstat of a settled file, so its ctime is necessarily later and the bracket was required to catch it.", producer.name)
					}
					continue
				}
				// ONLY a bracket rejection counts as a detection.
				// "still being written" is ErrWillNotSettle -- refused
				// before a byte was read, which is safe but exercises
				// nothing here, and counting it would let an
				// implementation that refuses everything look like one
				// that detects everything.
				//
				// These substrings are the ones the producers actually
				// emit (see hasher.go). A matcher that has drifted from
				// them silently disables every assertion below it, which
				// is what happened when the reasons were reworded in the
				// commit before this one: both subtests skipped, and a
				// mutation that published digests on rejection passed.
				if !isBracketRejection(r.Reason) {
					continue
				}
				torn++
				if r.Status != TOCTOUError {
					t.Fatalf("%s: a read that could not be compared must be TOCTOUError, got %q (%s)", producer.name, r.Status, r.Reason)
				}
				if r.Digest != nil {
					t.Fatalf("%s: a torn read must carry NO digest, got one (%s)", producer.name, r.Reason)
				}
			}

			if torn == 0 {
				t.Skipf("skipping: in 20 staged passes no read completed and was then rejected by the bracket (%d reported stable, all of a whole content), so the rejection path was not reached for %s", stable, producer.name)
			}
			t.Logf("%s: %d torn reads refused with no digest, %d stable reads each carrying a whole content", producer.name, torn, stable)

			// Positive control: refusing everything would satisfy the loop
			// above. With no writer running the same producer must return a
			// digest again.
			ageOut(t, path)
			quiet := producer.run(t, path)
			requireStableCarriesADigest(t, producer.name+" (quiet)", quiet)
			if quiet.Status != TOCTOUStable || quiet.Digest == nil {
				t.Fatalf("%s: with no writer running, a quiet file must hash to a stable digest, got %q (%s)",
					producer.name, quiet.Status, quiet.Reason)
			}
			if !sameDigestSet(quiet.Digest, wantA) && !sameDigestSet(quiet.Digest, wantB) {
				t.Fatalf("%s: quiet read returned a digest of neither whole content", producer.name)
			}
		})
	}
}

// digestOf writes `content` to a scratch file and hashes it, giving an
// expectation computed independently of the file under test.
func digestOf(t *testing.T, dir, name string, content []byte) cryptoutil.DigestSet {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := cryptoutil.CalculateDigestSetFromFile(p, hashFuncs(t))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// ageOut sleeps until `path`'s ctime is outside SettleWindow, so the settle
// inside the producer is a no-op and its pre-read fstat is taken essentially
// at the call. Staging the rewrite after that point is what makes the tear
// one the bracket must catch.
func ageOut(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if wait := SettleWindow + 20*time.Millisecond - time.Since(ctimeOf(t, st)); wait > 0 {
		time.Sleep(wait)
	}
}
