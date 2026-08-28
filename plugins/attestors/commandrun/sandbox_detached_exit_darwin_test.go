//go:build darwin

package commandrun

import (
	"os/exec"
	"testing"
)

// os/exec treats a nil Args as "argv is just Path", and argv0Preserved
// accepts that shape — so wrap() must survive it. c.Args[1:] on a nil slice
// panics, and the panic lands inside enableTracing, before the command runs.
func TestWrapSurvivesNilArgs(t *testing.T) {
	t.Parallel()
	s := drainSession()
	c := &exec.Cmd{Path: "/usr/bin/true"}
	s.wrap(c) // must not panic
	if c.Path != sandboxExecPath {
		t.Fatalf("wrapped path = %q, want the sandbox wrapper", c.Path)
	}
	want := []string{sandboxExecPath, "-p", sandboxProfile, "--", "/usr/bin/true"}
	if len(c.Args) != len(want) {
		t.Fatalf("wrapped args = %q, want %q", c.Args, want)
	}
	for i := range want {
		if c.Args[i] != want[i] {
			t.Fatalf("wrapped args = %q, want %q", c.Args, want)
		}
	}
	// The ordinary shape still carries the caller's arguments through.
	c2 := &exec.Cmd{Path: "/usr/bin/true", Args: []string{"true", "-x", "-y"}}
	s.wrap(c2)
	if len(c2.Args) != 7 || c2.Args[5] != "-x" || c2.Args[6] != "-y" {
		t.Fatalf("wrapped args = %q, want the caller's arguments preserved", c2.Args)
	}
}

// A descendant that LEFT the process group before the command exited cannot
// be reached by the group reap. It can therefore keep working after the
// drain and exit before the survivor check, which then reads it as gone —
// so its post-drain execs and connections are missing from evidence that
// claims to be complete. The pre-reap snapshot is where it is still
// visible, and being seen there is enough to refuse.
func TestDetachedMemberAtExitRefuses(t *testing.T) {
	t.Parallel()
	const rootPid, rootPgid = 100, 100
	preReap := []kinfoFacts{
		{pid: rootPid, facts: procFacts{ppid: 50, pgid: rootPgid, startSec: 1000, ok: true}},
		// A well-behaved child: still in the root's group, the reap gets it.
		{pid: 200, facts: procFacts{ppid: rootPid, pgid: rootPgid, startSec: 1001, ok: true}},
		// This one called setsid/setpgid: the reap's kill(-pgid) misses it.
		{pid: 300, facts: procFacts{ppid: rootPid, pgid: 300, startSec: 1002, ok: true}},
	}
	members := map[int]bool{rootPid: true, 200: true, 300: true}
	got := detachedMembersAtExit(preReap, members, rootPid, rootPgid)
	if len(got) != 1 || got[0] != 300 {
		t.Fatalf("detachedMembersAtExit = %v, want [300] — a member outside the reap's group can act after the drain and vanish before the survivor check", got)
	}

	// Nothing detached: no refusal, or every honest build fails.
	got = detachedMembersAtExit(preReap[:2], map[int]bool{rootPid: true, 200: true}, rootPid, rootPgid)
	if len(got) != 0 {
		t.Fatalf("detachedMembersAtExit = %v on a tree that stayed in its group, want none", got)
	}
}

// The pre-reap snapshot is one instant, and a descendant can leave the group
// AFTER it: the reap's kill(-pgid) then misses it, it keeps working past the
// drain, and if it exits before the liveness check the whole window is
// invisible. Detachment has to be judged on the post-drain table too, and
// the merged table cannot do it — merge keeps the FIRST row for a pid, which
// is the pre-reap incarnation still showing the old group.
func TestDetachmentIsJudgedOnBothSnapshots(t *testing.T) {
	t.Parallel()
	const rootPid, rootPgid = 100, 100
	root := procFacts{ppid: 50, pgid: rootPgid, startSec: 1000, ok: true}
	// At pre-reap the child is still IN the group: nothing to report.
	preReap := []kinfoFacts{
		{pid: rootPid, facts: root},
		{pid: 300, facts: procFacts{ppid: rootPid, pgid: rootPgid, startSec: 1001, ok: true}},
	}
	// By the post-drain read it has setpgid'd out of the group.
	postDrain := []kinfoFacts{
		{pid: rootPid, facts: root},
		{pid: 300, facts: procFacts{ppid: rootPid, pgid: 300, startSec: 1001, ok: true}},
	}
	members := map[int]bool{rootPid: true, 300: true}

	if got := detachedMembersAtExit(preReap, members, rootPid, rootPgid); len(got) != 0 {
		t.Fatalf("pre-reap alone = %v, want none — it had not left the group yet at that instant", got)
	}
	if got := detachedMembersAtExit(postDrain, members, rootPid, rootPgid); len(got) != 1 || got[0] != 300 {
		t.Fatalf("post-drain = %v, want [300]", got)
	}
	// The merged table hides it: merge keeps the first row, which still shows
	// the old group. This is why the check needs the snapshots, not the merge.
	if got := detachedMembersAtExit(mergeProcTables(preReap, postDrain), members, rootPid, rootPgid); len(got) != 0 {
		t.Fatalf("merged table = %v — if this ever reports, the merge order changed and this test's premise is stale", got)
	}
	// Both together is what trace() must ask.
	union := append(append([]kinfoFacts{}, preReap...), postDrain...)
	if got := detachedMembersAtExit(union, members, rootPid, rootPgid); len(got) != 1 || got[0] != 300 {
		t.Fatalf("both snapshots = %v, want [300] — a descendant that left the group after the pre-reap read must still refuse", got)
	}
}
