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
	"strings"
	"testing"
)

// A kernel sandbox report the grammar cannot read is not silently gone. A
// newline inside an exec'd path defeats the anchored regex (`.` stops at a
// newline); so would a report format this version does not know. The pid is
// still readable, and that decides whose loss it is.
func TestUnparseableReportKeepsItsPid(t *testing.T) {
	t.Parallel()
	msg := "Sandbox: sh(4242) allow process-exec* /tmp/evil\nname/tool"
	if _, ok := parseSandboxReport(msg); ok {
		t.Fatal("the grammar accepted a path with a newline; this test has lost its subject")
	}
	pid, isReport := unparseableReportPid(msg)
	if !isReport || pid != 4242 {
		t.Fatalf("unparseableReportPid = (%d, %v), want (4242, true)", pid, isReport)
	}
	// The comm is the process's to choose. One that spells a fake
	// "(1) allow foo" ahead of the kernel's real "(4242) allow process-exec*"
	// must not steal the pid: the pid is bound to the decision AND a known
	// operation, and a 16-byte comm cannot hold that triple.
	forged := "Sandbox: x(1) allow foo(4242) allow process-exec* /tmp/evil\nname/tool"
	if pid, ok := unparseableReportPid(forged); !ok || pid != 4242 {
		t.Fatalf("a forged comm stole the pid: got (%d, %v), want (4242, true)", pid, ok)
	}
	if _, isReport := unparseableReportPid("Filtering the log data using ..."); isReport {
		t.Fatal("a non-report line was taken for an unparseable report")
	}
	// An operation the profile never asked for is readable and irrelevant,
	// not unparseable.
	if _, ok := parseSandboxReport("Sandbox: Safari(77) deny(1) file-read-data /private/etc/hosts"); ok {
		t.Fatal("an irrelevant op was admitted as an event")
	}
}

// Whose loss it is: a member's or an undecidable pid's unreadable report
// refuses the trace; a proven stranger's is only counted.
func TestUnparseableOwnReportFailsClosed(t *testing.T) {
	t.Parallel()
	const rootPid, member, unknown, stranger = 100, 200, 300, 400
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: member, op: opUnparseable},
			{pid: unknown, op: opUnparseable},
			{pid: stranger, op: opUnparseable},
		},
		members:  map[int]bool{rootPid: true, member: true},
		canaries: map[int]bool{},
		facts: map[int]procFacts{
			rootPid:  {ok: true},
			member:   {ppid: rootPid, ok: true},
			unknown:  {}, // poll lost the race
			stranger: {ppid: 1, pgid: 1, startSec: 1, ok: true},
		},
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if diag.UnparseableOwnReports != 2 {
		t.Fatalf("unparseableOwnReports = %d, want 2 (the member's and the undecidable pid's)", diag.UnparseableOwnReports)
	}
	if diag.UnparsedRecords != 1 {
		t.Fatalf("unparsedRecords = %d, want 1 (the stranger's)", diag.UnparsedRecords)
	}
}

// End to end: an image whose path contains a newline is exec'd by the traced
// command; the trace must refuse rather than sign a tree without it.
func TestNewlineInExecPathRefusesTheTrace(t *testing.T) {
	dir := t.TempDir()
	tool := dir + "/odd\nname"
	// Executable, or bash fails the exec with EACCES before the sandbox ever
	// sees it and no report is emitted at all.
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := writeScript(t, "#!/bin/sh\n'"+tool+"'\nexit 0\n")
	_, err := traceScript(t, []string{"/bin/sh", script})
	if err == nil {
		t.Fatal("an exec whose report the grammar cannot read was signed away")
	}
	if !strings.Contains(err.Error(), "could not be interpreted") {
		t.Fatalf("the refusal must say why: %v", err)
	}
}

// The signed predicate says what an exec digest is bound to on this backend.
func TestExecDigestBindingIsStated(t *testing.T) {
	rc, err := traceScript(t, []string{"/bin/sh", "-c", "exit 0"})
	if err != nil {
		t.Fatal(err)
	}
	if rc.darwinTraceDiag.ExecDigestBinding != "path-at-collector-open-time" {
		t.Fatalf("execDigestBinding = %q, want path-at-collector-open-time", rc.darwinTraceDiag.ExecDigestBinding)
	}
}

// A kernel report neither grammar can read a pid out of (a comm with a
// newline in it defeats both) is undecidable, and undecidable refuses at
// harvest rather than being counted and forgotten.
func TestUnattributableKernelReportRefusesTheHarvest(t *testing.T) {
	t.Parallel()
	msg := "Sandbox: odd\nname(4242) allow process-exec* /usr/bin/true"
	if _, ok := parseSandboxReport(msg); ok {
		t.Fatal("the grammar accepted a comm with a newline; this test has lost its subject")
	}
	if pid, isReport := unparseableReportPid(msg); isReport {
		t.Fatalf("the loose grammar recovered pid %d across a newline; this test has lost its subject", pid)
	}
	s := drainSession()
	s.mu.Lock()
	s.unattributable++
	s.mu.Unlock()
	if _, err := s.harvest(); err == nil || !strings.Contains(err.Error(), "could not be attributed") {
		t.Fatalf("an unattributable kernel report did not refuse the harvest: %v", err)
	}
}

// forgedRecords is an accusation — "something wrote sandbox-shaped messages
// from outside the kernel" — and only a line SHAPED like a report can earn
// it. An ordinary framework log line from a user process is not a report.
func TestOnlyReportShapedLinesCanBeForged(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"Sandbox: curl(1) allow network-outbound remote:*:443", "3 duplicate reports for Sandbox: sh(2) allow process-fork"} {
		if !looksLikeSandboxReport(m) {
			t.Errorf("%q is a report and was not recognised as one", m)
		}
	}
	for _, m := range []string{"sandbox_check failed for pid 4", "filecache_entry_invalidate: invalidating <private>", "", "Sandboxed process started"} {
		if looksLikeSandboxReport(m) {
			t.Errorf("%q is not a report and would be counted as a forgery", m)
		}
	}
}

// A record the collector could not decode AT ALL is a different fact from a
// record that was decoded and proved to be a stranger's, and folding the two
// into one counter described the first as the second.
//
// `log stream` NDJSON that fails json.Unmarshal yields nothing: not the pid,
// not the sender, not even whether the line was a sandbox report. Ownership is
// UNKNOWN — and unknown fails toward ours everywhere else in this backend,
// because a build's own exec or connect may be inside the record nobody could
// read. A malformed record usually also means the stream was truncated, which
// is data loss whoever it belonged to. It was previously added to
// UnparsedRecords, whose contract is "provably a stranger's", so the gap was
// reported as somebody else's problem and refused nothing.
func TestUndecodableCollectorRecordRefusesTheTrace(t *testing.T) {
	t.Parallel()
	if err := refuseIncompleteTree(&DarwinTraceDiagnostics{CollectorRecordsUnreadable: 1}); err == nil {
		t.Fatal("a record the collector could not decode at all was accepted: this build's exec or connection " +
			"may be inside it, and the stream may have been truncated")
	}
	// A PROVEN stranger's unreadable report still does not refuse. That is the
	// distinction the split exists to preserve: the report was decoded, its
	// pid read, and its chain shown to reach something that predates this
	// build. Refusing on it would make every trace on a busy Mac unattestable.
	if err := refuseIncompleteTree(&DarwinTraceDiagnostics{UnparsedRecords: 3}); err != nil {
		t.Fatalf("a proven stranger's unreadable report refused the trace: %v", err)
	}
}
