//go:build darwin

package commandrun

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The root's facts and its uid must come from ONE kernel snapshot. Two reads
// let a fast root exit between them: the facts land, the uid read fails, and
// rootUID silently stays 0 — after which the exit sweep filters launchd
// orphans by uid 0 and misses the user's own detached descendant.
func TestRootFactsAndUIDComeFromOneSnapshot(t *testing.T) {
	saved := readKinfo
	t.Cleanup(func() { readKinfo = saved })

	// Exactly one read may reach the kernel, and both the facts and the uid
	// must come out of it. A second read is a second instant, and the root
	// can be gone by then.
	real := saved
	calls := 0
	readKinfo = func(pid int) (*unix.KinfoProc, error) {
		calls++
		if calls > 1 {
			return nil, errors.New("the root exited between the two reads")
		}
		return real(pid)
	}
	s := drainSession()
	s.noteRoot(os.Getpid())
	if calls != 1 {
		t.Fatalf("noteRoot made %d kernel reads for the root; the facts and the uid must come from one snapshot", calls)
	}
	if !s.rootFacts.ok {
		t.Fatal("the root's facts were not recorded from the snapshot")
	}
	if s.rootUID != uint32(os.Getuid()) {
		t.Fatalf("rootUID = %d, want %d — a uid of 0 makes the exit sweep filter the user's own orphans by root", s.rootUID, os.Getuid())
	}
}

// A shared POSIX session is not ancestry. The traced root gets a new process
// GROUP but keeps the session it was started in, so an unrelated process the
// same runner (or shell) starts during the command shares rootSid — and was
// swept in as ours, then refused the whole attestation for being alive at
// exit. Legitimate concurrent work would fail every macOS trace. The session
// only speaks for a process the root's own lineage lost: one launchd already
// adopted.
func TestSharedSessionAloneIsNotOurs(t *testing.T) {
	t.Parallel()
	const rootPid, rootPgid, rootSid = 100, 100, 7
	root := procFacts{ppid: 50, pgid: rootPgid, startSec: 1000, ok: true}
	facts := map[int]procFacts{rootPid: root}
	shell := 60
	table := []kinfoFacts{
		{pid: rootPid, facts: root, uid: 501, comm: "sh"},
		// A sibling the same shell started while the command ran: same
		// session, live unrelated parent, its own group. Not ours.
		{pid: 800, facts: procFacts{ppid: shell, pgid: 800, startSec: 1001, ok: true}, uid: 501, comm: "vim"},
		// Our orphan: parent already gone, so launchd adopted it, and it
		// still carries the session it inherited from the root.
		{pid: 900, facts: procFacts{ppid: launchdPid, pgid: 900, startSec: 1002, ok: true}, uid: 501, noTTY: true, comm: "sh"},
	}
	sid := func(int) (int, error) { return rootSid, nil }
	got := sweepUnobservedDescendants(rootPid, rootPgid, rootSid, 501, root, facts, map[int]string{rootPid: "sh"}, table, sid)
	if _, ok := got[800]; ok {
		t.Error("a sibling with a live unrelated parent was swept in on session id alone; concurrent work on the same runner would refuse every trace")
	}
	if _, ok := got[900]; !ok {
		t.Error("the root's own launchd-adopted orphan was dropped; the double-fork it exists to catch would escape")
	}
}
