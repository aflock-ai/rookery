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

import "testing"

// The kext reports the sandbox DECISION, and a deny(N) report is an operation
// the sandbox REFUSED — the exec never ran, the connect never reached the
// network. A parser that discards the decision records denied attempts as
// executed images, which lets a no-op build imitate an expected process tree
// by running a deny-everything nested sandbox: every "exec" in the signed
// evidence would be an attempt that never happened.
func TestDeniedReportCarriesItsDecision(t *testing.T) {
	t.Parallel()
	ev, ok := parseSandboxReport(`Sandbox: passd(98302) deny(1) process-exec* /usr/bin/true`)
	if !ok {
		t.Fatal("a deny report failed to parse; it must be parsed AND marked denied, not dropped or recorded as allowed")
	}
	if !ev.denied {
		t.Fatalf("parseSandboxReport discarded the deny decision: %+v", ev)
	}
	allowed, ok := parseSandboxReport(`Sandbox: bash(16171) allow process-exec* /usr/bin/true`)
	if !ok {
		t.Fatal("an allow report failed to parse")
	}
	if allowed.denied {
		t.Fatalf("an allow report was marked denied: %+v", allowed)
	}
}

// A denied exec by an in-tree pid must not become a tree node's executed
// image, and a denied outbound must not become egress — the operation did not
// happen. Both are counted so a verifier sees that something tried.
func TestDeniedOperationsAreCountedNotRecorded(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: rootPid, op: opExecStar, detail: "/usr/bin/never-ran", denied: true},
			{pid: rootPid, op: opNetworkOutbound, detail: "remote:*:443", denied: true},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts:    map[int]procFacts{rootPid: {ppid: 1, pgid: rootPid, ok: true}},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	root := findProcess(procs, rootPid)
	if root == nil {
		t.Fatal("root missing from tree")
	}
	for _, ev := range root.SyscallEvents {
		if ev.Path == "/usr/bin/never-ran" {
			t.Errorf("a DENIED exec was recorded as an executed image: %+v", ev)
		}
	}
	if root.Network != nil {
		for _, c := range root.Network.Connections {
			if c.Port == 443 {
				t.Errorf("a DENIED outbound was recorded as a connection: %+v", c)
			}
		}
	}
	if diag.DeniedReports != 2 {
		t.Errorf("DeniedReports = %d, want 2 — refused operations are counted, not silently dropped", diag.DeniedReports)
	}
	if diag.ExecReports != 1 {
		t.Errorf("ExecReports = %d, want 1 (only the allowed exec)", diag.ExecReports)
	}
}
