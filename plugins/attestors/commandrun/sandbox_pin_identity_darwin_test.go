// Copyright 2026 TestifySec, Inc.
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

//go:build darwin

// What an exec digest is bound to, and what the tree build is allowed to read.
//
// Both properties here are invisible to an end-to-end trace that passes: a
// digest bound to the wrong bytes still produces a well-formed predicate, and a
// map read racing a map write is a scheduling accident that shows up as a
// fatal error in production and nothing at all in a quiet test run. So they are
// driven directly, through the session the collector writes into.

package commandrun

import (
	"crypto"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// pinSession builds a session with only the fields pinning touches.
func pinSession() *sandboxSession {
	return &sandboxSession{
		facts:      map[int]procFacts{},
		pinned:     map[imageIdentity]pinnedImage{},
		canaryPIDs: map[int]procFacts{},
	}
}

var sha256Only = []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

// hexOf is the single digest string in a set, so two measurements can be
// compared without the caller naming an algorithm.
func hexOf(t *testing.T, ds cryptoutil.DigestSet) string {
	t.Helper()
	for _, v := range ds {
		return v
	}
	t.Fatal("digest set is empty")
	return ""
}

// TestExecDigestFollowsTheBytesNotThePath is the attack an exec digest exists
// to prevent, run against the pinning code that has to stop it.
//
// A command execs /tmp/dir/tool, then renames different bytes over that path
// and execs it again. The two events loaded two different inodes, so they must
// carry two different digests. Keying the pin by path collapses them onto the
// first inode's digest: the signed predicate then names bytes that never ran
// for the second exec and omits the bytes that did — the precise inversion of
// what the measurement is for, and a build that reads as fully measured while
// the interesting half of it is unmeasured.
func TestExecDigestFollowsTheBytesNotThePath(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")

	writeFile(t, tool, "#!/bin/sh\necho first\n")
	s := pinSession()
	s.record(sandboxEvent{timestamp: nowReport(), pid: 4242, op: opExecStar, detail: tool})

	// Rename over the path, which is how a replacement gets a NEW inode. The
	// pinned fd keeps the old inode alive and readable.
	replacement := filepath.Join(dir, "tool.next")
	writeFile(t, replacement, "#!/bin/sh\necho second — completely different bytes\n")
	if err := os.Rename(replacement, tool); err != nil {
		t.Fatalf("rename: %v", err)
	}
	s.record(sandboxEvent{timestamp: nowReport(), pid: 4242, op: opExecStar, detail: tool})

	if len(s.events) != 2 {
		t.Fatalf("events = %d, want 2", len(s.events))
	}
	first, second := s.events[0], s.events[1]
	if first.pin == 0 || second.pin == 0 {
		t.Fatalf("an exec of a readable image carried no pin: first=%d second=%d", first.pin, second.pin)
	}
	if first.pin == second.pin {
		t.Fatal("two execs of the same path loaded different inodes and were given the SAME pin; " +
			"the second exec would be attested with the first inode's digest — bytes that never ran")
	}

	digests := s.hashPinnedImages(sha256Only)
	defer func() {
		for _, img := range s.pinned {
			_ = img.file.Close()
		}
	}()
	d1, ok1 := digests[first.pin]
	d2, ok2 := digests[second.pin]
	if !ok1 || !ok2 {
		t.Fatalf("missing digest: first=%v second=%v", ok1, ok2)
	}
	if hexOf(t, d1) == hexOf(t, d2) {
		t.Error("both execs were measured to the same digest even though the bytes differed")
	}

	// And the digest each event carries has to reach the process record —
	// on the per-exec SYSCALL EVENT, not ProgramDigest. This backend leaves
	// the generic first/last digest fields empty on purpose: they read as
	// "these bytes ran" and an allow report cannot support that, so the
	// evidence lives where its semantics are explicit and local.
	var p ProcessInfo
	recordDarwinExec(&p, &first, digests)
	if p.ProgramDigest != nil {
		t.Errorf("ProgramDigest was populated (%v); this backend cannot claim an exec succeeded", p.ProgramDigest)
	}
	if len(p.SyscallEvents) != 1 {
		t.Fatalf("syscall events = %d, want 1 execve", len(p.SyscallEvents))
	}
	if got := hexOf(t, p.SyscallEvents[0].PathDigestAtCollectorOpen); got != hexOf(t, d1) {
		t.Errorf("execve event pathDigestAtCollectorOpen = %s, want the bytes at that path when the collector "+
			"opened it (%s) — this asserts WHICH inode was measured, not that those bytes executed; the "+
			"backend cannot establish the latter", got, hexOf(t, d1))
	}
	if p.SyscallEvents[0].DigestSource != "collector-open-path-hash" {
		t.Errorf("digestSource = %q, want collector-open-path-hash", p.SyscallEvents[0].DigestSource)
	}
}

// TestEveryExecOccurrenceKeepsItsOwnDigest is the A→B→C attack: one pid execs
// the same path three times over three different inodes. ProgramDigest keeps
// the first measurement and ExeDigest the last, and OpenedFiles is path-keyed
// so it holds only the last — which leaves the MIDDLE bytes (the ones an
// attacker would put there) with no surviving measurement unless each exec
// EVENT carries its own digest. That per-event binding is what this test pins:
// every syscall event must name the digest of the inode that exec loaded, and
// an exec whose image could not be pinned must carry NO digest and an empty
// digestSource rather than borrowing a neighbor's.
func TestEveryExecOccurrenceKeepsItsOwnDigest(t *testing.T) {
	t.Parallel()
	const pid = 4242
	const path = "/tmp/tool"
	dA := cryptoutil.DigestSet{{Hash: crypto.SHA256}: "aaaa"}
	dB := cryptoutil.DigestSet{{Hash: crypto.SHA256}: "bbbb"}
	dC := cryptoutil.DigestSet{{Hash: crypto.SHA256}: "cccc"}
	digests := map[pinID]cryptoutil.DigestSet{1: dA, 2: dB, 3: dC}

	var p ProcessInfo
	events := []sandboxEvent{
		{pid: pid, op: opExecStar, detail: path, pin: 1},
		{pid: pid, op: opExecStar, detail: path, pin: 2},
		{pid: pid, op: opExecStar, detail: path, pin: 3},
		// A fourth exec whose image could not be pinned: no digest, stated.
		{pid: pid, op: opExecStar, detail: path, pin: 0},
	}
	for i := range events {
		recordDarwinExec(&p, &events[i], digests)
	}

	if len(p.SyscallEvents) != 4 {
		t.Fatalf("SyscallEvents = %d, want 4", len(p.SyscallEvents))
	}
	for i, want := range []cryptoutil.DigestSet{dA, dB, dC} {
		got := p.SyscallEvents[i].PathDigestAtCollectorOpen
		if len(got) == 0 {
			t.Fatalf("exec occurrence %d carries no digest — the per-exec measurement was lost "+
				"(only first/last survive in ProgramDigest/ExeDigest, and OpenedFiles keeps only the last)", i)
		}
		if hexOf(t, got) != hexOf(t, want) {
			t.Errorf("exec occurrence %d digest = %s, want %s — the event must name the inode IT loaded", i, hexOf(t, got), hexOf(t, want))
		}
		if p.SyscallEvents[i].DigestSource == "" {
			t.Errorf("exec occurrence %d has a digest but no digestSource", i)
		}
	}
	unpinned := p.SyscallEvents[3]
	if len(unpinned.PathDigestAtCollectorOpen) != 0 {
		t.Errorf("an unpinnable exec carries digest %v — it must state the gap, not borrow bytes", unpinned.PathDigestAtCollectorOpen)
	}
	if unpinned.DigestSource != "" {
		t.Errorf("an unpinnable exec claims digestSource %q, want empty (\"no digest captured\")", unpinned.DigestSource)
	}

	// The middle measurement must be reachable from the record without
	// correlating maps: OpenedFiles and the generic first/last digest fields
	// are no longer populated at all on this backend, so the per-exec events
	// are the ONLY place any occurrence survives — which is the point of this
	// test.
	if p.ProgramDigest != nil {
		t.Errorf("ProgramDigest = %v, want empty: an allow report cannot show which bytes ran", p.ProgramDigest)
	}
	if p.ExeDigest != nil {
		t.Errorf("ExeDigest = %v, want empty for the same reason", p.ExeDigest)
	}
	// OpenedFiles is withheld entirely on this backend: it is a generic map
	// whose consumers (bindScriptsToTrace, the product attestor) read a digest
	// in it as the bytes that were actually read, and a collector-time
	// observation cannot support that. Withholding is the same answer given to
	// ProgramDigest and ExeDigest above.
	if len(p.OpenedFiles) != 0 {
		t.Errorf("OpenedFiles = %v, want EMPTY: a generic file-digest map cannot carry a collector-time "+
			"observation without a consumer reading it as the bytes that ran", p.OpenedFiles)
	}
}

// TestRepeatedExecOfTheSameInodeReusesOnePin keeps the fix from becoming a leak.
// Real builds exec /bin/sh dozens of times; one pin and one fd must cover them
// all, or a long build exhausts its fd budget on identical bytes.
func TestRepeatedExecOfTheSameInodeReusesOnePin(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	writeFile(t, tool, "#!/bin/sh\nexit 0\n")

	s := pinSession()
	for range 5 {
		s.record(sandboxEvent{timestamp: nowReport(), pid: 7, op: opExecStar, detail: tool})
	}
	// A second name for the same inode is the same bytes and must not re-pin.
	alias := filepath.Join(dir, "alias")
	if err := os.Link(tool, alias); err != nil {
		t.Fatalf("link: %v", err)
	}
	s.record(sandboxEvent{timestamp: nowReport(), pid: 7, op: opExecStar, detail: alias})

	defer func() {
		for _, img := range s.pinned {
			_ = img.file.Close()
		}
	}()
	if len(s.pinned) != 1 {
		t.Errorf("pinned inodes = %d, want 1 — repeated execs of one inode must share a pin", len(s.pinned))
	}
	for i, ev := range s.events {
		if ev.pin != s.events[0].pin {
			t.Errorf("event %d has pin %d, want the shared pin %d", i, ev.pin, s.events[0].pin)
		}
	}
}

// TestUnreadableImageCarriesNoPin proves the zero value means "no digest" and
// never "the digest of something else". An image the tracer cannot open must
// leave the exec undigested and counted, not inherit a neighbour's measurement.
func TestUnreadableImageCarriesNoPin(t *testing.T) {
	s := pinSession()
	s.record(sandboxEvent{timestamp: nowReport(), pid: 9, op: opExecStar, detail: "/definitely/not/a/real/path"})
	if len(s.events) != 1 {
		t.Fatalf("events = %d, want 1", len(s.events))
	}
	if s.events[0].pin != 0 {
		t.Errorf("pin = %d, want 0 for an image that could not be opened", s.events[0].pin)
	}
	if s.pinFailures != 1 {
		t.Errorf("pinFailures = %d, want 1", s.pinFailures)
	}

	var p ProcessInfo
	recordDarwinExec(&p, &s.events[0], map[pinID]cryptoutil.DigestSet{})
	if len(p.ProgramDigest) != 0 {
		t.Errorf("an unpinnable image was given a digest anyway: %v", p.ProgramDigest)
	}
}

// TestTreeInputSurvivesAConcurrentCollector is the property that keeps the
// process crashing at all.
//
// buildDarwinTree reads facts and canaries with no lock held, while the
// collector's reader goroutine keeps writing s.facts for every machine-wide
// report until shutdown. Passing the live maps makes an unsynchronised map read
// concurrent with a map write, which the Go runtime answers with `fatal error:
// concurrent map read and map write` — unrecoverable, so the build dies after
// the command already ran and no attestation is produced.
//
// The test drives that shape directly: keep recording while the snapshot is
// read. Under -race it fails on the race itself; without -race it fails on the
// snapshot changing under the reader.
func TestTreeInputSurvivesAConcurrentCollector(t *testing.T) {
	s := pinSession()
	s.facts[1] = procFacts{ppid: 0, pgid: 1, ok: true}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for pid := 1000; ; pid++ {
			select {
			case <-stop:
				return
			default:
			}
			s.record(sandboxEvent{pid: pid, op: opFork})
		}
	}()
	defer func() { close(stop); wg.Wait() }()

	for range 200 {
		snap := s.snapshot(nil)
		facts := snap.facts

		before := len(facts)
		in := darwinTreeInput{rootPid: 1, members: map[int]bool{1: true}, facts: facts, canaries: snap.canaries}
		_ = provenParent(1, in)
		for pid := range facts {
			_ = facts[pid]
		}
		if len(facts) != before {
			t.Fatalf("the snapshot grew from %d to %d entries while it was being read, so it is "+
				"the collector's live map and not a copy", before, len(facts))
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// nowReport renders a timestamp in the unified log's own ndjson format, so a
// synthetic event exercises the same parse path a real report does.
func nowReport() string {
	return time.Now().Format("2006-01-02 15:04:05.999999-0700")
}
