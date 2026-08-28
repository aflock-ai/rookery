//go:build darwin

package commandrun

import (
	"os"
	"testing"
)

// Readable facts prove one parent edge, not non-descent. A pid whose chain
// runs into a process nothing could be read about — an intermediate that
// exited before its poll — is undecidable, and undecidable is unproven.
// Only a chain that reaches something provably not ours (an ancestor that
// predates the build, launchd, cilock itself) is a stranger's.
func TestUnresolvedAncestryIsUnprovenNotForeign(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	root := procFacts{ppid: 50, pgid: 100, startSec: 1000, startUsec: 0, ok: true}
	self := os.Getpid()
	facts := map[int]procFacts{
		rootPid: root,
		200:     {ppid: rootPid, startSec: 1001, ok: true},   // member
		300:     {ppid: 310, startSec: 1002, ok: true},       // parent 310 seen but unreadable
		310:     {},                                          // the intermediate: poll lost the race
		400:     {ppid: 410, startSec: 1003, ok: true},       // parent 410 never seen; poll finds it gone
		500:     {ppid: 510, startSec: 1004, ok: true},       // parent 510 never seen; predates the build → stranger
		600:     {ppid: 610, startSec: 1005, ok: true},       // parent 610 never seen; appeared after root → undecidable
		700:     {ppid: self, startSec: 1006, ok: true},      // cilock's own child (a probe): not ours-in-tree, not poisoned
		800:     {ppid: launchdPid, startSec: 900, ok: true}, // Safari
	}
	poll := func(pid int) procFacts {
		switch pid {
		case 510:
			return procFacts{ppid: 1, startSec: 500, ok: true}
		case 610:
			return procFacts{ppid: 1, startSec: 1004, ok: true}
		}
		return procFacts{}
	}
	originals := poisonUnresolvedAncestry(facts, rootPid, root, poll)
	if len(originals) != 3 {
		t.Fatalf("unresolved = %d, want 3 (300 via unreadable 310, 400 via vanished 410, 600 via after-root 610)", len(originals))
	}
	// The originals survive for the exit-time liveness check: an undecidable
	// process that outlives the command must still be able to refuse it.
	for _, pid := range []int{300, 400, 600} {
		if !originals[pid].ok || originals[pid].startSec == 0 {
			t.Fatalf("pid %d's original facts were not kept for the survivor check: %+v", pid, originals[pid])
		}
	}
	for _, pid := range []int{300, 400, 600} {
		if facts[pid].ok {
			t.Fatalf("pid %d kept proven facts although its ancestry is unresolved", pid)
		}
	}
	for _, pid := range []int{rootPid, 200, 500, 700, 800} {
		if !facts[pid].ok {
			t.Fatalf("pid %d lost its facts although its chain is decidable", pid)
		}
	}
}
