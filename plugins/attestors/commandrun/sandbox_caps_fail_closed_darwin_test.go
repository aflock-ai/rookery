//go:build darwin

package commandrun

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The pin cap bounds the fds held on DISTINCT images. A repeat exec of an
// inode already pinned holds nothing new and must reuse its pin — otherwise,
// past the cap, every further /bin/sh loses its digest and the run refuses.
func TestPinCapAppliesOnlyToNewInodes(t *testing.T) {
	saved := maxPinnedImages
	maxPinnedImages = 1
	t.Cleanup(func() { maxPinnedImages = saved })

	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho "+p+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s := pinSession()
	first := s.pin(a, time.Now(), true)
	if first == 0 {
		t.Fatal("first pin failed")
	}
	if again := s.pin(a, time.Now(), true); again != first {
		t.Fatalf("a repeat exec of an already-pinned inode got pin %d, want %d — the cap counted it as a new image", again, first)
	}
	if s.pinFailures != 0 {
		t.Fatalf("pinFailures = %d after a repeat of a pinned inode, want 0", s.pinFailures)
	}
	if got := s.pin(b, time.Now(), true); got != 0 || s.pinFailures != 1 {
		t.Fatalf("a NEW inode past the cap: pin=%d failures=%d, want 0 and 1", got, s.pinFailures)
	}
}

// A parent chain deeper than the walk's cap is not a proof of anything.
// Breaking out of the walk as if it had reached a stranger left the pid's
// facts intact, so buildDarwinTree treated its execs and connects as a
// stranger's and dropped them — a tracee only has to fork 65 deep behind
// one short-lived intermediate. Past the cap the pid is UNRESOLVED.
func TestAncestryWalkCapFailsClosed(t *testing.T) {
	t.Parallel()
	const rootPid, stranger = 100, 250
	root := procFacts{ppid: 50, pgid: rootPid, startSec: 1000, ok: true}
	// stranger (250) predates the root and hangs off launchd: a proof of
	// non-descent, readable, in facts. 300..366 is a linear chain on top of
	// it, every link started after the root. Without the cap, EVERY pid
	// resolves to the stranger and keeps its facts (deterministic: no pid is
	// poisoned, so none couples into another). With the cap, a pid whose
	// walk needs more than maxAncestryHops to reach the stranger fails closed.
	facts := map[int]procFacts{
		rootPid:  root,
		stranger: {ppid: 1, pgid: stranger, startSec: 900, ok: true},
	}
	parent := stranger
	for pid := 300; pid <= 366; pid++ {
		facts[pid] = procFacts{ppid: parent, pgid: pid, startSec: 1001, ok: true}
		parent = pid
	}
	poll := func(pid int) procFacts { return procFacts{} } // nothing polled: the chain is fully in facts
	unresolved := poisonUnresolvedAncestry(facts, rootPid, root, poll)

	// The deepest pid is more than maxAncestryHops from the stranger: unresolved.
	if _, ok := unresolved[366]; !ok || facts[366].ok {
		t.Fatalf("the deepest pid (%d hops to a proof of non-descent) kept proven facts; a tracee forking past the cap has its reports dropped as a stranger's", 366-300+2)
	}
	// A shallow pid reaches the stranger within the cap: it stays a stranger's, kept.
	if _, ok := unresolved[300]; ok || !facts[300].ok {
		t.Fatal("a shallow pid that reaches a proof of non-descent was poisoned; only chains past the cap are undecidable")
	}
}

// The "readable but irrelevant" skip must not swallow a report about an
// operation this backend DOES trace. A comm that fakes an unknown-op triple
// ahead of the kernel's own would otherwise hide the exec behind it.
func TestIrrelevantSkipCoversOnlyUntracedOps(t *testing.T) {
	t.Parallel()
	for _, msg := range []string{
		"Sandbox: passd(98302) deny(1) file-read-data /Library/Preferences/x.plist",
		"Sandbox: cfprefsd(120) allow mach-lookup com.apple.cfprefsd.daemon",
		"3 duplicate reports for Sandbox: nsurlsessiond(9) deny(1) file-read-metadata /var/db/x",
	} {
		if !irrelevantReport(msg) {
			t.Errorf("%q: a readable report about an op we do not trace must be skipped, not refused", msg)
		}
	}
	for _, msg := range []string{
		"Sandbox: sh(123) allow process-exec* /tmp/weird\npath",
		"Sandbox: curl(9) allow network-outbound remote:*:443",
		"Sandbox: x(1) allow zz sh(4242) allow process-exec* /tmp/evil",
	} {
		if irrelevantReport(msg) {
			t.Errorf("%q: a report about an op we DO trace was skipped as irrelevant — the exec or connect vanishes from the evidence", msg)
		}
	}
}
