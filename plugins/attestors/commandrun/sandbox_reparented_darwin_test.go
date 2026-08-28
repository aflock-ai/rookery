// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin

package commandrun

import (
	"crypto"
	"os/exec"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// A readable parent chain that does not reach the root is not proof of
// non-descent: a double-forked child whose parent exited hangs off launchd
// exactly like Safari does. The start time tells them apart — a launchd
// child that appeared AFTER the root started is undecidable, and undecidable
// is unproven, never foreign.
func TestReparentedAfterRootIsUnprovenNotForeign(t *testing.T) {
	t.Parallel()
	root := procFacts{ppid: 50, pgid: 100, startSec: 1000, startUsec: 500, ok: true}
	facts := map[int]procFacts{
		100: root,
		200: {ppid: 100, pgid: 100, startSec: 1001, ok: true},                        // ordinary child
		300: {ppid: launchdPid, pgid: 300, startSec: 1002, ok: true},                 // detached descendant (or a fresh app)
		301: {ppid: launchdPid, pgid: 301, startSec: 1000, startUsec: 500, ok: true}, // same instant as the root: undecidable
		400: {ppid: launchdPid, pgid: 400, startSec: 900, ok: true},                  // Safari: running before the build
		500: {},                                                                      // poll lost the race
	}
	reparented := poisonReparented(facts, root)
	for _, pid := range []int{300, 301} {
		if _, ok := reparented[pid]; !ok || facts[pid].ok {
			t.Fatalf("pid %d appeared after the root under launchd; want it poisoned to unproven, got facts=%+v listed=%v", pid, facts[pid], ok)
		}
	}
	for _, pid := range []int{100, 200, 400} {
		if _, ok := reparented[pid]; ok || !facts[pid].ok {
			t.Fatalf("pid %d must keep its proven facts (got %+v, listed=%v)", pid, facts[pid], ok)
		}
	}
	if _, ok := reparented[500]; ok {
		t.Fatal("an unreadable pid is already unproven and is not a reparented one")
	}

	// Its network is unproven egress on the root, its exec a listed one — and
	// Safari's stays a counted stranger.
	in := darwinTreeInput{
		rootPid: 100,
		events: []sandboxEvent{
			{pid: 100, op: opExecStar, detail: "/bin/sh"},
			{pid: 300, op: opNetworkOutbound, detail: "remote:*:443"},
			{pid: 300, op: opExecStar, detail: "/usr/bin/curl", pin: 7}, // the image was readable: identity is recorded
			{pid: 400, op: opNetworkOutbound, detail: "remote:*:443"},
		},
		members:  map[int]bool{100: true, 200: true},
		canaries: map[int]bool{},
		facts:    facts,
		digests:  map[pinID]cryptoutil.DigestSet{7: {cryptoutil.DigestValue{Hash: crypto.SHA256}: "aa"}},
	}
	diag := &DarwinTraceDiagnostics{ReparentedAfterRoot: uint64(len(reparented))}
	procs := buildDarwinTree(in, diag)
	rootProc := findProcess(procs, 100)
	if rootProc == nil || rootProc.Network == nil || len(rootProc.Network.Connections) != 1 {
		t.Fatalf("the detached descendant's connect must survive as unproven egress on the root; got %+v", rootProc)
	}
	if len(diag.UnprovenExecs) != 1 || diag.UnprovenExecs[0].PID != 300 {
		t.Fatalf("the detached descendant's exec must be listed unproven; got %+v", diag.UnprovenExecs)
	}
	if diag.NetworkReportsUnattributed != 1 {
		t.Fatalf("Safari's connect must stay a counted stranger, got %d", diag.NetworkReportsUnattributed)
	}
	if diag.ReparentedAfterRoot != 2 {
		t.Fatalf("reparentedAfterRoot = %d, want 2", diag.ReparentedAfterRoot)
	}
}

// End to end: an intermediate forks a sleeper that setsids into its own
// session (escaping the group reap) and exits at once; the shell waits until
// the sleeper says it is detached, then exits. The sleeper started after the
// root, hangs off launchd (or, if its exec report beat the intermediate's
// exit, off a proven member), and is still running when the evidence would
// be signed — either way the trace must refuse rather than sign a tree that
// omits a live process the command may have started.
func TestDetachedOrphanStillRunningRefusesTheTrace(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not available")
	}
	// The sleeper drops the root's stdio: a detached child holding the
	// tracer's stdout pipe keeps exec.Cmd.Wait blocked until it exits, which
	// would hide it from the survivor check by simply outliving the wait.
	script := writeScript(t, "#!/bin/sh\n"+
		"m=$(mktemp); rm -f \"$m\"\n"+
		"/usr/bin/perl -e 'use POSIX; my $m=$ARGV[0]; my $pid=fork(); "+
		"if ($pid==0) { POSIX::setsid(); open(F,\">\",$m); close F; exec \"/bin/sleep\",\"4\"; } exit 0' "+
		"\"$m\" </dev/null >/dev/null 2>&1\n"+
		"while [ ! -f \"$m\" ]; do /bin/sleep 0.01; done\n"+
		"exit 0\n")
	_, err := traceScript(t, []string{"/bin/sh", script})
	if err == nil {
		t.Fatal("a detached, still-running child was signed away")
	}
	// TWO refusal points cover this scenario, and which one fires is a race
	// with the child's own setsid: if it had already left the process group
	// when the pre-reap snapshot was taken, detachedMembersAtExit refuses
	// there (the group reap cannot reach it, so it could act after the drain
	// and be gone before any liveness check); otherwise the survivor check
	// catches it still running. Measured ~50/50 on a loaded machine. Both
	// are the same finding — a descendant escaped containment — and the test
	// exists to prove the trace is refused, not to pin which check noticed.
	// Matched on "process group", which BOTH refusals contain, so the test
	// survives a rewording of either. Pinning an exact phrase has broken this
	// test twice now for refusals that were entirely correct.
	if !strings.Contains(err.Error(), "still running") &&
		!strings.Contains(err.Error(), "process group") {
		t.Fatalf("the refusal must name the escaped descendant: %v", err)
	}
}

// Without the root's own incarnation the start-time rules decide nothing, and
// a detached descendant would read as a stranger. That is a refusal, not a
// quiet downgrade.
func TestMissingRootFactsDisableNothingSilently(t *testing.T) {
	t.Parallel()
	if reparentedAfterRoot(procFacts{ppid: launchdPid, startSec: 5000, ok: true}, procFacts{}) {
		t.Fatal("reparentedAfterRoot decided with no root facts")
	}
	facts := map[int]procFacts{300: {ppid: launchdPid, startSec: 5000, ok: true}}
	if n := poisonReparented(facts, procFacts{}); len(n) != 0 {
		t.Fatal("poisonReparented decided with no root facts")
	}
	// trace() refuses outright when the root's facts are missing; the unit
	// contract here is that the rules never claim a verdict they cannot make.
}
