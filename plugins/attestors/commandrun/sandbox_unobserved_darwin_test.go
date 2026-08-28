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
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A forked child that never execs and never touches the network produces no
// report: the collector cannot see it, but the kernel process table can, for
// as long as it hangs off a tree member or shares the root's group. The sweep
// runs before the reap and lists exactly those.
func TestSweepFindsDescendantsThatNeverReported(t *testing.T) {
	t.Parallel()
	const rootPid, rootPgid = 100, 100
	root := procFacts{ppid: 50, pgid: rootPgid, startSec: 1000, ok: true}
	facts := map[int]procFacts{
		rootPid: root,
		200:     {ppid: rootPid, pgid: rootPgid, startSec: 1001, ok: true}, // reported member
	}
	table := []kinfoFacts{
		{pid: rootPid, facts: root},
		{pid: 200, facts: facts[200]},
		{pid: 300, facts: procFacts{ppid: 200, pgid: 300, startSec: 1002, ok: true}},      // fork-only child of a member, own group
		{pid: 400, facts: procFacts{ppid: 900, pgid: rootPgid, startSec: 1003, ok: true}}, // in the root's group
		{pid: 500, facts: procFacts{ppid: 1, pgid: 500, startSec: 1004, ok: true}},        // launchd child: undecidable, stated residual
		{pid: 600, facts: procFacts{ppid: 200, pgid: 600, startSec: 900, ok: true}},       // predates the root: not ours
		{pid: os.Getpid(), facts: procFacts{ppid: 1, pgid: 1, startSec: 1005, ok: true}},  // cilock itself
		{pid: 700, facts: procFacts{ppid: 1, pgid: 700, startSec: 1006, ok: true}},        // parent reaped, kept the root's session
		{pid: 800, facts: procFacts{ppid: launchdPid, pgid: 800, startSec: 1007, ok: true}, uid: 501, noTTY: true, comm: "perl"},
		{pid: 900, facts: procFacts{ppid: launchdPid, pgid: 900, startSec: 1008, ok: true}, uid: 501, noTTY: false, comm: "perl"}, // a terminal perl the user ran
	}
	const rootSid = 7
	// Fill in what the process table also carries: everyone here is this
	// user; the root and the members have a terminal; the launchd children
	// do not. 500 is a user-launched app (comm "Slack"); 800 is the
	// double-fork — same image as the member that forked it (perl), setsid'd,
	// parent gone.
	for i := range table {
		table[i].uid = 501
		table[i].noTTY = table[i].facts.ppid == launchdPid
		table[i].comm = "perl"
	}
	table[4].comm = "Slack"           // pid 500
	table[len(table)-1].noTTY = false // pid 900: a terminal perl the user ran
	sids := map[int]int{rootPid: rootSid, 200: rootSid, 300: rootSid, 400: rootSid, 500: 500, 600: rootSid, 700: rootSid, 800: 800, 900: 900}
	commOf := map[int]string{rootPid: "sh", 200: "perl", 500: "Slack"}
	got := sweepUnobservedDescendants(rootPid, rootPgid, rootSid, 501, root, facts, commOf, table, func(pid int) (int, error) { return sids[pid], nil })
	if len(got) != 4 || !got[300].ok || !got[400].ok || !got[700].ok || !got[800].ok {
		t.Fatalf("sweep = %v, want exactly pids 300, 400, 700 (same session, parent gone) and 800 (the double-fork)", got)
	}
}

// An invocation whose argv[0] is an alias the sandbox wrapper cannot keep is
// refused before any session starts; the ordinary shapes pass.
func TestAliasedArgv0IsRefused(t *testing.T) {
	t.Parallel()
	c := exec.Command("/bin/echo", "hi")
	if err := argv0Preserved(c); err != nil {
		t.Fatalf("plain invocation refused: %v", err)
	}
	c.Args[0] = "echo"
	if err := argv0Preserved(c); err != nil {
		t.Fatalf("basename argv[0] refused: %v", err)
	}
	c.Args[0] = "busybox-applet"
	if err := argv0Preserved(c); err == nil || !strings.Contains(err.Error(), "argv[0]") {
		t.Fatalf("an aliased argv[0] was not refused: %v", err)
	}
	c.Args[0] = "busybox-applet"
	enableTracing(c)
	if c.Err == nil {
		t.Fatal("enableTracing did not carry the refusal onto the command")
	}
}

// End to end: a member forks a child that never execs, moves it to its own
// process group (escaping the reap) and both outlive the shell. Nothing about
// the child ever reached the report channel; the sweep sees it hanging off
// the live member, and the trace refuses rather than sign around it.
func TestForkOnlyDescendantStillRunningRefusesTheTrace(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not available")
	}
	// The root stays alive long enough for the fork to happen — a real build
	// is still working when its helper forks; a shell that exits in a
	// millisecond has its whole group reaped before perl even starts.
	script := writeScript(t, "#!/bin/sh\n"+
		"/usr/bin/perl -e 'use POSIX; my $p=fork(); if ($p==0) { POSIX::setpgid(0,0); sleep 4; exit 0 } sleep 4' "+
		"</dev/null >/dev/null 2>&1 &\n"+
		"/bin/sleep 0.5\n"+
		"exit 0\n")
	_, err := traceScript(t, []string{"/bin/sh", script})
	if err == nil {
		t.Fatal("a fork-only descendant that outlived the command was signed away")
	}
	// EITHER refusal is the right one, and which fires is a race with the
	// orphan's own setsid. The detached-at-exit check asks "was it seen
	// outside the reaped group", the survivor check asks "is it still
	// running"; both are this finding, and pinning the test to one wording
	// makes it fail on a correct refusal. What it exists to prove is that the
	// trace is REFUSED rather than signed with the orphan absent.
	if !strings.Contains(err.Error(), "still running") && !strings.Contains(err.Error(), "process group") {
		t.Fatalf("the refusal names neither liveness nor detachment: %v", err)
	}
}

// The double-fork: a member forks a child that setsids and forks again, then
// every ancestor exits; the grandchild hangs off launchd in a fresh session
// and produced no report. It still runs the tree's image, has no terminal
// and is this user — the sweep's last signal — and the trace refuses.
func TestDoubleForkedSetsidOrphanRefusesTheTrace(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not available")
	}
	script := writeScript(t, "#!/bin/sh\n"+
		"/usr/bin/perl -e 'use POSIX; if (fork()==0) { POSIX::setsid(); if (fork()==0) { sleep 4; exit 0 } exit 0 } exit 0' "+
		"</dev/null >/dev/null 2>&1\n"+
		"/bin/sleep 0.5\n"+
		"exit 0\n")
	_, err := traceScript(t, []string{"/bin/sh", script})
	if err == nil {
		t.Fatal("a double-forked, setsid'd orphan that outlived the command was signed away")
	}
	// EITHER refusal is the right one, and which fires is a race with the
	// orphan's own setsid. The detached-at-exit check asks "was it seen
	// outside the reaped group", the survivor check asks "is it still
	// running"; both are this finding, and pinning the test to one wording
	// makes it fail on a correct refusal. What it exists to prove is that the
	// trace is REFUSED rather than signed with the orphan absent.
	if !strings.Contains(err.Error(), "still running") && !strings.Contains(err.Error(), "process group") {
		t.Fatalf("the refusal names neither liveness nor detachment: %v", err)
	}
}
