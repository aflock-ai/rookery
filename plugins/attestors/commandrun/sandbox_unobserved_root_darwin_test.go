//go:build darwin

package commandrun

import (
	"strings"
	"testing"
)

// Every other completeness check on this backend counts things that went
// WRONG. A report channel that delivered nothing for the root trips none of
// them — no unattributed reports, no unproven pids, no undigested execs, all
// zero because there was nothing to count — while the readiness and network
// canaries, being separate processes with their own reports, can still
// succeed. The result is a capture mode, networkObserved true, and an EMPTY
// tree, off which cilock reads an empty egress list and stamps an affirmative
// "no external egress observed" on a build it never watched.
//
// Silence has to read as a refusal, not as a clean bill of health.
func TestTraceWithNoRootReportRefuses(t *testing.T) {
	t.Parallel()
	const rootPid = 4242

	// Nothing at all came back.
	err := refuseUnobservedRoot(nil, rootPid)
	if err == nil {
		t.Fatal("an EMPTY tree was accepted: an attestation would be signed over a command nobody observed")
	}
	if !strings.Contains(err.Error(), "no report at all") {
		t.Errorf("refusal does not say the channel delivered nothing: %v", err)
	}

	// The root is present but carries no exec — its report arrived as
	// something else, or its exec could not be attributed. Still nothing
	// establishes that the command ran.
	noExec := []ProcessInfo{{ProcessID: rootPid, SyscallEvents: []SyscallEvent{{Syscall: "connect"}}}}
	if err := refuseUnobservedRoot(noExec, rootPid); err == nil {
		t.Fatal("a root with no exec event was accepted")
	}

	// A child exec'd but the root did not: the tree is not empty, which is
	// exactly why a non-empty check would not have caught this.
	childOnly := []ProcessInfo{{ProcessID: 99, SyscallEvents: []SyscallEvent{{Syscall: "execve"}}}}
	if err := refuseUnobservedRoot(childOnly, rootPid); err == nil {
		t.Fatal("a tree with someone else's exec but none for the root was accepted")
	}

	// The ordinary case: the root exec'd, and the trace proceeds.
	ok := []ProcessInfo{
		{ProcessID: rootPid, SyscallEvents: []SyscallEvent{{Syscall: "execve", Path: "/bin/sh"}}},
		{ProcessID: 99, SyscallEvents: []SyscallEvent{{Syscall: "execve"}}},
	}
	if err := refuseUnobservedRoot(ok, rootPid); err != nil {
		t.Fatalf("an observed root exec was refused: %v", err)
	}
}
