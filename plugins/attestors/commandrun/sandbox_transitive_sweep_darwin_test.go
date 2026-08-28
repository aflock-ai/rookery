//go:build darwin

package commandrun

import (
	"os/exec"
	"testing"
	"time"
)

// A descendant the sweep discovers is a descendant: its own children are
// this build's too. The single pass only admitted rows whose PARENT was
// already known, so a grandchild sitting behind an unobserved intermediate
// was never admitted — and the late scan then skipped it as "already seen".
func TestSweepAdmitsDescendantsTransitively(t *testing.T) {
	t.Parallel()
	const rootPid, rootPgid, rootSid = 100, 100, 7
	root := procFacts{ppid: 50, pgid: rootPgid, startSec: 1000, ok: true}
	facts := map[int]procFacts{rootPid: root}
	table := []kinfoFacts{
		{pid: rootPid, facts: root, uid: 501, comm: "sh"},
		// Never reported: a child in the root's group.
		{pid: 300, facts: procFacts{ppid: rootPid, pgid: rootPgid, startSec: 1001, ok: true}, uid: 501, comm: "sh"},
		// Its child, in its OWN group, so only the parent edge can reach it.
		{pid: 400, facts: procFacts{ppid: 300, pgid: 400, startSec: 1002, ok: true}, uid: 501, comm: "sh"},
		// And one more level down.
		{pid: 500, facts: procFacts{ppid: 400, pgid: 500, startSec: 1003, ok: true}, uid: 501, comm: "sh"},
	}
	sid := func(int) (int, error) { return rootSid, nil }
	got := sweepUnobservedDescendants(rootPid, rootPgid, rootSid, 501, root, facts, map[int]string{rootPid: "sh"}, table, sid)
	for _, pid := range []int{300, 400, 500} {
		if _, ok := got[pid]; !ok {
			t.Errorf("pid %d was not swept in; a grandchild behind an unobserved intermediate stays invisible to the tree and to the late scan", pid)
		}
	}
}

// argv[0] the wrapper cannot preserve must be refused, and an explicitly
// EMPTY argv[0] is the clearest such case — the child would see "" without
// the wrapper and the resolved path with it.
func TestEmptyArgv0IsRefused(t *testing.T) {
	t.Parallel()
	if err := argv0Preserved(&exec.Cmd{Path: "/usr/bin/tool", Args: []string{""}}); err == nil {
		t.Error("an explicitly empty argv[0] was accepted; the traced process runs with a different argv[0] than the caller asked for")
	}
	// No Args at all is fine: os/exec uses Path, which is exactly what the
	// wrapper supplies.
	if err := argv0Preserved(&exec.Cmd{Path: "/usr/bin/tool"}); err != nil {
		t.Errorf("an absent Args was refused: %v", err)
	}
	// The ordinary shape — exec.Command("tool") gives Args[0]="tool",
	// Path="/usr/bin/tool" — is accepted but NORMALIZED, and a verifier is
	// told so.
	if err := argv0Preserved(&exec.Cmd{Path: "/usr/bin/tool", Args: []string{"tool", "-x"}}); err != nil {
		t.Errorf("the ordinary invocation shape was refused: %v", err)
	}
	if !argv0Normalized(&exec.Cmd{Path: "/usr/bin/tool", Args: []string{"tool"}}) {
		t.Error(`argv[0] "tool" against path "/usr/bin/tool" is rewritten by the wrapper and must be reported as normalized`)
	}
	if argv0Normalized(&exec.Cmd{Path: "/usr/bin/tool", Args: []string{"/usr/bin/tool"}}) {
		t.Error("an argv[0] identical to the resolved path is not normalized")
	}
	// A different name entirely is still refused outright.
	if err := argv0Preserved(&exec.Cmd{Path: "/bin/busybox", Args: []string{"ls"}}); err == nil {
		t.Error("a multi-call alias was accepted; the traced run would not be the command the attestation names")
	}
}

// The drain must not be held open by a process this build provably did not
// start. Refreshing the clock for EVERY post-root pid meant that on a busy
// machine — the log stream is machine-wide — an unrelated app launched
// mid-build could keep the quiet window from ever closing and fail an
// honest attestation. A chain that reaches something older than the root is
// proof of non-descent; anything unresolved still holds the drain open.
func TestDrainClockIgnoresProvenStrangers(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.rootPid = 100
	s.rootFacts = procFacts{ppid: 50, pgid: 100, startSec: 1000, ok: true}
	// 800 started after the root, but its parent 700 predates the root: a
	// pre-existing app's new child, provably not ours.
	s.facts[700] = procFacts{ppid: 1, pgid: 700, startSec: 900, ok: true}
	s.facts[800] = procFacts{ppid: 700, pgid: 800, startSec: 1001, ok: true}
	// 900 started after the root and its parent cannot be read: undecidable,
	// so it must still hold the drain open.
	s.facts[900] = procFacts{ppid: 950, pgid: 900, startSec: 1002, ok: true}

	stale := time.Now().Add(-time.Hour)
	s.lastInTree = stale
	s.noteActivity(800)
	if s.lastInTree != stale {
		t.Error("a process whose ancestry predates the root held the drain open; a busy machine would fail honest builds")
	}
	s.lastInTree = stale
	s.noteActivity(900)
	if s.lastInTree == stale {
		t.Error("a post-root pid with unreadable ancestry did not hold the drain open; its late exec could be lost")
	}
}
