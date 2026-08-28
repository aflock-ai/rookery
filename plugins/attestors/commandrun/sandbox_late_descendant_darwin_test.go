//go:build darwin

package commandrun

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Liveness was asked BEFORE the images were hashed, and hashing a large tree
// is not instant. In that window a member could fork a successor and exit:
// the member then reads as gone, and the successor is in neither the exit
// snapshot nor any report-derived map, so the trace signed as complete while
// a process of this build's was still able to touch the artifacts. The
// question is now asked again after the evidence is built.
func TestLateForkedSuccessorRefusesTheTrace(t *testing.T) {
	const rootPid, rootPgid, rootSid = 100, 100, 7
	const successor = 4242
	root := procFacts{ppid: 50, pgid: rootPgid, startSec: 1000, ok: true}
	sess := &sandboxSession{
		facts:      map[int]procFacts{rootPid: root},
		pinned:     map[imageIdentity]pinnedImage{},
		canaryPIDs: map[int]procFacts{},
		ourPids:    map[int]bool{},
		rootPid:    rootPid,
		rootFacts:  root,
		rootUID:    501,
	}
	// The late check re-resolves membership from the session's own facts, so
	// the caller no longer supplies a set — that staleness was the bug.
	successorFacts := procFacts{ppid: launchdPid, pgid: 900, startSec: 1002, ok: true}

	// The table read at the END shows a process that was not there before:
	// parent already gone, but it still carries the root's session id.
	table := []kinfoFacts{
		{pid: rootPid, facts: root, uid: 501, comm: "sh"},
		{pid: successor, facts: successorFacts, uid: 501, noTTY: true, comm: "sh"},
	}
	list := func() ([]kinfoFacts, error) { return table, nil }
	sid := func(pid int) (int, error) { return rootSid, nil }

	saved := readKinfo
	t.Cleanup(func() { readKinfo = saved })
	readKinfo = func(pid int) (*unix.KinfoProc, error) {
		var kp unix.KinfoProc
		switch pid {
		case successor:
			kp.Proc.P_starttime.Sec = successorFacts.startSec
			return &kp, nil
		default:
			return nil, nil // gone
		}
	}

	err := refuseLateDescendants(rootPid, rootPgid, rootSid, sess, list, sid)
	if err == nil {
		t.Fatal("a successor forked after the exit snapshot was signed away; it can modify artifacts after the evidence exists")
	}
	if !strings.Contains(err.Error(), "4242") {
		t.Fatalf("the refusal does not name the process: %v", err)
	}

	// Nothing new: the same table it already swept, all of it gone. No refusal.
	readKinfo = func(int) (*unix.KinfoProc, error) { return nil, nil }
	if err := refuseLateDescendants(rootPid, rootPgid, rootSid, sess, list, sid); err != nil {
		t.Fatalf("a settled tree was refused: %v", err)
	}

	// A table that cannot be read is not proof of quiet.
	failing := func() ([]kinfoFacts, error) { return nil, errors.New("sysctl: out of memory") }
	if err := refuseLateDescendants(rootPid, rootPgid, rootSid, sess, failing, sid); err == nil {
		t.Fatal("an unreadable process table at the end was treated as an empty one")
	}
}
