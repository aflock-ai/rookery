//go:build darwin

package commandrun

import (
	"crypto"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// An exec the tree attributes to this build but cannot digest — its image
// was gone before the report arrived, or was rewritten under the pin — is a
// hole an image policy would walk through: the exec is signed, the policy
// looks for a digest, finds none, and approves. Refuse instead.
func TestAttributedExecWithoutDigestRefusesTheTrace(t *testing.T) {
	t.Parallel()
	const rootPid, child = 100, 101
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh", pin: 1},
			{pid: child, op: opExecStar, detail: "/tmp/vanished", pin: 0}, // pin failed: no bytes were read
		},
		members:  map[int]bool{rootPid: true, child: true},
		canaries: map[int]bool{},
		facts:    map[int]procFacts{rootPid: {ok: true}, child: {ppid: rootPid, ok: true}},
		digests:  map[pinID]cryptoutil.DigestSet{1: {cryptoutil.DigestValue{Hash: crypto.SHA256}: "aa"}},
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if diag.AttributedExecsUndigested != 1 {
		t.Fatalf("attributedExecsUndigested = %d, want 1 (the child's exec has no digest)", diag.AttributedExecsUndigested)
	}
	if err := refuseIncompleteTree(diag); err == nil {
		t.Fatal("a tree with an undigested attributed exec was signed — a digest-deny policy would approve the run")
	}

	// A digest for every attributed exec is the normal case and must not refuse.
	in.events[1].pin = 1
	diag = &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if diag.AttributedExecsUndigested != 0 {
		t.Fatalf("attributedExecsUndigested = %d, want 0", diag.AttributedExecsUndigested)
	}
	if err := refuseIncompleteTree(diag); err != nil {
		t.Fatalf("fully digested tree refused: %v", err)
	}
}

// A denied exec loaded no bytes and is not an exec without a digest.
func TestDeniedExecIsNotAnUndigestedExec(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	in := darwinTreeInput{
		rootPid:  rootPid,
		events:   []sandboxEvent{{pid: rootPid, op: opExecStar, detail: "/usr/bin/curl", denied: true}},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts:    map[int]procFacts{rootPid: {ok: true}},
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if diag.AttributedExecsUndigested != 0 || diag.DeniedReports != 1 {
		t.Fatalf("denied exec counted as undigested: %+v", diag)
	}
}

// An unproven exec may be another user's process, so the entry is a gap
// (pid, time) and nothing more — no path hash, no content digest.
func TestUnprovenExecWithUnreadableImageCarriesNoIdentity(t *testing.T) {
	t.Parallel()
	const rootPid, fast = 100, 555
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: fast, op: opExecStar, detail: "/Users/someone/private/tool", pin: 0, timestamp: "t1"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts:    map[int]procFacts{rootPid: {ok: true}, fast: {}},
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if len(diag.UnprovenExecs) != 1 {
		t.Fatalf("unprovenExecs = %+v, want the gap listed", diag.UnprovenExecs)
	}
	got := diag.UnprovenExecs[0]
	if got.PID != fast || got.Timestamp != "t1" {
		t.Fatalf("gap = %+v, want pid %d at t1", got, fast)
	}
}

// The end-of-run verification must not read an inode the tracee grew after
// its exec: a sparse truncate to terabytes costs the tracee nothing and would
// cost the tracer the whole read. The stamp says the inode moved; refuse it
// without reading, and never read past the pin bound in any case.
func TestEndOfRunHashRefusesAGrownInodeWithoutReadingIt(t *testing.T) {
	saved := maxImageBytes
	maxImageBytes = 4096
	t.Cleanup(func() { maxImageBytes = saved })

	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho executed-bytes\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := pinSession()
	pin := s.pin(path, time.Now(), true)
	if pin == 0 {
		t.Fatal("pin failed for a readable file")
	}
	if err := os.Truncate(path, 64<<20); err != nil { // sparse: no bytes written
		t.Fatal(err)
	}
	s.mu.Lock()
	digests := s.hashPinnedImages(sha256Only)
	s.mu.Unlock()
	if _, ok := digests[pin]; ok {
		t.Fatal("a grown inode was digested — the signed digest would describe bytes that never ran")
	}
	for _, img := range s.pinned {
		off, err := img.file.Seek(0, io.SeekCurrent)
		if err != nil {
			t.Fatal(err)
		}
		if off > maxImageBytes+1 {
			t.Fatalf("the end-of-run check read %d bytes of a grown inode; the bound is %d", off, maxImageBytes)
		}
	}
}

// The exit sweep runs while the collector is still writing s.facts for every
// machine-wide report that lands. It must read a snapshot taken under the
// lock — the live map beside a writer is a fatal concurrent-map error, not a
// recoverable one, and it would kill the build after the command already ran.
// (Meaningful under -race; the callsite in trace() uses the same method.)
func TestSweepReadsAFactsSnapshot(t *testing.T) {
	s := &sandboxSession{
		facts:      map[int]procFacts{},
		pinned:     map[imageIdentity]pinnedImage{},
		canaryPIDs: map[int]procFacts{},
		ourPids:    map[int]bool{},
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for pid := 1; ; pid++ {
			select {
			case <-stop:
				return
			default:
				s.record(sandboxEvent{pid: 1_000_000 + pid, op: opFork})
			}
		}
	}()
	for i := 0; i < 200; i++ {
		for pid, f := range s.factsSnapshot() {
			_ = pid
			_ = f.ok
		}
	}
	close(stop)
	wg.Wait()
}
