//go:build darwin

package commandrun

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The report grammar must bind the pid and decision to the KERNEL's header —
// the bounded comm followed by the first "(pid) decision known-op" — and
// treat everything after it as opaque detail. A greedy comm binds to the
// LAST such triple, which an executed path or socket name can supply.
func TestReportHeaderBindsToTheKernelsTriple(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line          string
		pid           int
		comm, op, det string
	}{
		{"Sandbox: sh(100) allow process-exec* /tmp/tool(200) allow process-fork", 100, "sh", opExecStar, "/tmp/tool(200) allow process-fork"},
		{"Sandbox: cilock-catalog-planner(50366) deny(1) network-outbound remote:*:80", 50366, "cilock-catalog-planner", opNetworkOutbound, "remote:*:80"},
		{"Sandbox: curl(38711) allow network-outbound /tmp/x.sock(7) allow network-bind", 38711, "curl", opNetworkOutbound, "/tmp/x.sock(7) allow network-bind"},
		{"3 duplicate reports for Sandbox: sh(100) allow process-exec* /tmp/t(9) deny(1) process-exec", 100, "sh", opExecStar, "/tmp/t(9) deny(1) process-exec"},
		{"Sandbox: my(app)(55) allow process-fork", 55, "my(app)", opFork, ""},
	}
	for _, c := range cases {
		ev, ok := parseSandboxReport(c.line)
		if !ok {
			t.Errorf("%q: did not parse", c.line)
			continue
		}
		if ev.pid != c.pid || ev.comm != c.comm || ev.op != c.op || ev.detail != c.det {
			t.Errorf("%q:\n got pid=%d comm=%q op=%q detail=%q\nwant pid=%d comm=%q op=%q detail=%q",
				c.line, ev.pid, ev.comm, ev.op, ev.detail, c.pid, c.comm, c.op, c.det)
		}
	}
}

// A readable pid that started AFTER the root and is not yet linked to the
// tree — its parent's report has not arrived, or its parent already exited —
// may be this build's. Its reports must keep the drain from going quiet;
// only a process that predates the root is provably not ours.
func TestPostRootUnlinkedPidRefreshesTheDrainClock(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.rootPid = 100
	s.rootFacts = procFacts{ppid: 1, pgid: 100, startSec: 1000, startUsec: 500, ok: true}
	s.facts[300] = procFacts{ppid: 900, pgid: 300, startSec: 1001, ok: true}               // parent unknown to us, started after the root
	s.facts[301] = procFacts{ppid: 1, pgid: 301, startSec: 1000, startUsec: 900, ok: true} // reparented, same second, later usec
	s.facts[400] = procFacts{ppid: 1, pgid: 400, startSec: 900, ok: true}                  // Safari: predates the root

	stale := time.Now().Add(-time.Hour)
	for _, pid := range []int{300, 301} {
		s.lastInTree = stale
		s.noteActivity(pid)
		if s.lastInTree == stale {
			t.Errorf("pid %d started after the root with an unlinked parent; its report did not refresh the drain clock, so the drain could finish while its exec was in flight", pid)
		}
	}
	s.lastInTree = stale
	s.noteActivity(400)
	if s.lastInTree != stale {
		t.Error("a process that predates the root refreshed the drain clock; the drain would never go quiet on a busy Mac")
	}
}

// The survivor check must distinguish "gone" (a definitive zero-length
// kernel answer) from "could not ask". Only the former lets the trace sign.
func TestSurvivorCheckRefusesWhenLivenessIsIndeterminate(t *testing.T) {
	saved := readKinfo
	t.Cleanup(func() { readKinfo = saved })

	rootPid := os.Getpid()
	facts := map[int]procFacts{rootPid: pollProcFacts(rootPid), 4242: {ppid: rootPid, startSec: 1000, ok: true}}
	members := map[int]bool{rootPid: true, 4242: true}

	readKinfo = func(int) (*unix.KinfoProc, error) { return nil, errors.New("sysctl: resource temporarily unavailable") }
	if _, err := survivingDarwinMembers(rootPid, members, facts); err == nil {
		t.Fatal("an indeterminate liveness check signed the trace; a known descendant may still be running")
	}

	readKinfo = func(int) (*unix.KinfoProc, error) { return nil, nil } // definitive: no such pid
	survivors, err := survivingDarwinMembers(rootPid, members, facts)
	if err != nil || len(survivors) != 0 {
		t.Fatalf("a definitively absent pid: survivors=%v err=%v, want none and no error", survivors, err)
	}
}

// The real kernel: a missing pid is a definitive zero-length answer, not an
// error, and the live process reads back with its start time.
func TestKinfoOfDistinguishesAbsentFromFailed(t *testing.T) {
	t.Parallel()
	if kp, err := kinfoOf(999_999); err != nil || kp != nil {
		t.Fatalf("missing pid: kp=%v err=%v, want nil,nil", kp, err)
	}
	kp, err := kinfoOf(os.Getpid())
	if err != nil || kp == nil || int(kp.Proc.P_pid) != os.Getpid() {
		t.Fatalf("self: kp=%v err=%v", kp, err)
	}
}

// A process whose own NAME contains a well-formed header puts two readings
// on one line. Neither may be signed and neither may be dropped: the line is
// counted and harvest refuses.
func TestAmbiguousHeaderRefusesRatherThanPickingAReading(t *testing.T) {
	t.Parallel()
	// The name carries a COMPLETE header, trailing space included — a
	// filename may contain spaces, so this is buildable.
	for _, msg := range []string{
		"Sandbox: x(1) allow process-fork (4242) allow process-exec* /tmp/evil",
		"3 duplicate reports for Sandbox: a(9) allow network-bind (77) allow network-outbound remote:*:443",
	} {
		if !ambiguousHeader(msg) {
			t.Errorf("%q: two readings of the header were not detected; one of them would be signed as fact", msg)
		}
	}
	// One reading only: an ordinary report, a report whose DETAIL contains a
	// triple (no comm short enough to reach it), a parenthesised comm, and a
	// name carrying a triple whose operation this backend does not trace.
	for _, msg := range []string{
		"Sandbox: sh(100) allow process-exec* /bin/bash",
		"Sandbox: sh(100) allow process-exec* /tmp/tool(200) allow process-fork",
		"Sandbox: my(app)(55) allow process-fork",
		"Sandbox: cilock-catalog-planner(50366) deny(1) network-outbound remote:*:80",
		"Sandbox: x(1) allow zz sh(4242) allow process-exec* /tmp/evil",
		// No trailing space after the planted op, so the anchored grammar
		// can only read the kernel's own triple: one reading, not two.
		"Sandbox: x(1) allow process-fork(4242) allow process-exec* /tmp/evil",
	} {
		if ambiguousHeader(msg) {
			t.Errorf("%q: an unambiguous report was refused as ambiguous", msg)
		}
	}
}

// The refusal must reach the caller, not sit in a counter.
func TestAmbiguousReportFailsTheHarvest(t *testing.T) {
	t.Parallel()
	s := drainSession()
	s.ambiguous = 1
	if _, err := s.harvest(); err == nil {
		t.Fatal("a report with two readings was harvested; an exec hidden behind a crafted process name would be signed away")
	}
}
