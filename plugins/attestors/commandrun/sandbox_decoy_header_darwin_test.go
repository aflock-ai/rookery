//go:build darwin

package commandrun

import "testing"

// Comparing only the VALUES the two readings produce is not enough: a name
// can be chosen so both readings agree on pid, decision and operation while
// selecting DIFFERENT header positions. The strict parser then takes the
// first, and everything after it — including the kernel's own header and the
// real image path — becomes "detail", so the signed evidence names a decoy
// the attacker planted instead of the image that ran. The comm the two
// readings pick out is the position; it must agree too.
func TestIdenticalValuedDecoyHeaderIsAmbiguous(t *testing.T) {
	t.Parallel()
	// The name is "x(4242) allow process-exec* decoy" — 33 bytes, inside
	// p_name — so the line carries two headers with identical values.
	const decoy = "Sandbox: x(4242) allow process-exec* decoy(4242) allow process-exec* /tmp/real-image"
	if !ambiguousHeader(decoy) {
		t.Fatal("a decoy header with values identical to the kernel's was accepted; the attestation would name the decoy's bytes and never mention the image that ran")
	}
	for _, ok := range []string{
		"Sandbox: sh(100) allow process-exec* /bin/bash",
		"Sandbox: my(app)(55) allow process-fork",
		"Sandbox: cilock-catalog-planner(50366) deny(1) network-outbound remote:*:80",
		"Sandbox: sh(100) allow process-exec* /tmp/tool(200) allow process-fork",
	} {
		if ambiguousHeader(ok) {
			t.Errorf("%q: an unambiguous report was refused", ok)
		}
	}
}

// Fork accounting must be scoped to this build. Counting every pid in a
// MACHINE-WIDE stream let an unrelated process's report cancel a traced
// fork whose child vanished, so the completeness counter could read zero
// over a real hole.
func TestForkAccountingIgnoresStrangers(t *testing.T) {
	t.Parallel()
	const rootPid, stranger = 100, 900
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh", comm: "sh"},
			{pid: rootPid, op: opFork}, // our child: forked, acted, vanished
			// Safari, mid-build. Proven foreign, and it must not cancel anything.
			{pid: stranger, op: opExecStar, detail: "/Applications/Safari.app/Contents/MacOS/Safari"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts:    map[int]procFacts{rootPid: {ok: true}, stranger: {ppid: 1, pgid: 1, ok: true}},
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	// One fork reported, no child of ours observed: the counters DISAGREE,
	// which is what a completeness policy reads. The stranger's exec must not
	// appear as an observed child and mask it.
	if diag.ForkReports != 1 || diag.ObservedChildren != 0 {
		t.Fatalf("forkReports=%d observedChildren=%d, want 1 and 0 — a stranger's exec was counted as this build's child", diag.ForkReports, diag.ObservedChildren)
	}

	// A fork report from a STRANGER is not this build's fork and must not be
	// counted against it either.
	in.events = append(in.events, sandboxEvent{pid: stranger, op: opFork})
	diag = &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if diag.ForkReports != 1 || diag.ObservedChildren != 0 {
		t.Fatalf("forkReports=%d observedChildren=%d after a stranger's fork, want 1 and 0 — another process's forks are not this build's", diag.ForkReports, diag.ObservedChildren)
	}

	// A child the exit sweep found (no report of its own) accounts for a fork.
	in.events = in.events[:2]
	in.swept = map[int]procFacts{300: {ppid: rootPid, ok: true}}
	diag = &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if diag.ForkReports != 1 || diag.ObservedChildren != 1 {
		t.Fatalf("forkReports=%d observedChildren=%d, want 1 and 1 — a child the sweep found is an observed child", diag.ForkReports, diag.ObservedChildren)
	}
}

// The tracer's own probes must not account for the build's forks. A canary's
// kernel facts are unreadable by design, so the "could be ours" test admitted
// every probe as a child — and each one cancelled a real fork whose child had
// vanished, driving the completeness counter to zero over a genuine hole.
func TestCanariesDoNotAccountForForks(t *testing.T) {
	t.Parallel()
	const rootPid, canaryA, canaryB = 100, 777, 778
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh", comm: "sh"},
			{pid: rootPid, op: opFork}, // the child that vanished
			{pid: canaryA, op: opExecStar, detail: "/usr/bin/true", canary: true},
			{pid: canaryB, op: opExecStar, detail: "/usr/bin/true"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{canaryB: true},
		facts:    map[int]procFacts{rootPid: {ok: true}},
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if diag.ForkReports != 1 || diag.ObservedChildren != 0 {
		t.Fatalf("forkReports=%d observedChildren=%d, want 1 and 0 — the tracer's own probes were counted as the build's children", diag.ForkReports, diag.ObservedChildren)
	}
}
