//go:build darwin

package commandrun

import (
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The late check had a hole exactly where the two exclusions met.
//
// sweepUnobservedDescendants skips any pid the report channel mentioned, on
// the reasoning that a reported pid is already accounted for. resolveTreeMembers
// admits only pids whose parent chain reaches the root. A descendant that
// reported AND whose chain no longer reaches the root — it double-forked and
// was reparented to launchd, or its intermediate parent exited before its
// facts could be polled — satisfies neither: the sweep passes over it because
// it is in facts, and the member resolve passes over it because its ppid is 1.
// Nothing then asked the kernel whether it was still running, so a detached
// descendant could go on rewriting the artifacts while the attestation was
// signed over them.
//
// buildDarwinTree already treats both shapes as undecidable-therefore-ours
// (poisonReparented, poisonUnresolvedAncestry). The liveness check has to
// treat them the same way, or the tree calls them unproven while the trace
// calls the run complete.
func TestLateReportedDetachedDescendantRefusesTheTrace(t *testing.T) {
	const rootPid, rootPgid, rootSid = 100, 100, 7
	const reparented, behindGhost, ghostPpid = 4300, 4301, 999999
	root := procFacts{ppid: 50, pgid: rootPgid, startSec: 1000, ok: true}

	// Both reported, so the sweep will skip them. Neither chain reaches the
	// root, so the member resolve will skip them too.
	reparentedFacts := procFacts{ppid: launchdPid, pgid: 900, startSec: 1002, ok: true}
	behindGhostFacts := procFacts{ppid: ghostPpid, pgid: 901, startSec: 1003, ok: true}

	newSession := func() *sandboxSession {
		return &sandboxSession{
			facts: map[int]procFacts{
				rootPid:     root,
				reparented:  reparentedFacts,
				behindGhost: behindGhostFacts,
			},
			pinned:     map[imageIdentity]pinnedImage{},
			canaryPIDs: map[int]procFacts{},
			ourPids:    map[int]bool{},
			rootPid:    rootPid,
			rootFacts:  root,
			rootUID:    501,
		}
	}
	table := []kinfoFacts{
		{pid: rootPid, facts: root, uid: 501, comm: "sh"},
		{pid: reparented, facts: reparentedFacts, uid: 501, comm: "sh"},
		{pid: behindGhost, facts: behindGhostFacts, uid: 501, comm: "sh"},
	}
	list := func() ([]kinfoFacts, error) { return table, nil }
	sid := func(int) (int, error) { return rootSid, nil }

	saved := readKinfo
	t.Cleanup(func() { readKinfo = saved })

	alive := func(pid int, f procFacts) func(int) (*unix.KinfoProc, error) {
		return func(q int) (*unix.KinfoProc, error) {
			if q != pid {
				return nil, nil // gone
			}
			var kp unix.KinfoProc
			kp.Proc.P_starttime.Sec = f.startSec
			kp.Proc.P_starttime.Usec = f.startUsec
			return &kp, nil
		}
	}

	for _, tc := range []struct {
		name string
		pid  int
		f    procFacts
	}{
		{"reparented to launchd after the root started", reparented, reparentedFacts},
		{"chain runs through a pid nothing can be read about", behindGhost, behindGhostFacts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readKinfo = alive(tc.pid, tc.f)
			err := refuseLateDescendants(rootPid, rootPgid, rootSid, newSession(), list, sid)
			if err == nil {
				t.Fatalf("pid %d reported, lost its chain to the root, and was still running — the trace was signed anyway", tc.pid)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(tc.pid)) {
				t.Fatalf("the refusal does not name the live process %d: %v", tc.pid, err)
			}
		})
	}

	// The same two pids, both gone. Undecidable ancestry is not by itself a
	// refusal: the tree marks them unproven, and a run whose stragglers have
	// all exited is still attestable.
	t.Run("both exited", func(t *testing.T) {
		readKinfo = func(int) (*unix.KinfoProc, error) { return nil, nil }
		if err := refuseLateDescendants(rootPid, rootPgid, rootSid, newSession(), list, sid); err != nil {
			t.Fatalf("a settled tree with undecidable-but-dead descendants was refused: %v", err)
		}
	})
}
