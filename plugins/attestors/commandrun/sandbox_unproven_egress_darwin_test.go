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

// A short-lived child can connect and exit before its kernel facts are
// polled. Its ownership is then UNPROVEN — it might be this build's, it might
// be a stranger's — and dropping its network reports with only a diagnostic
// counter turns "we could not attribute this egress" into an empty egress
// list that downstream logic signs as hermetic. Unprovable ownership must
// fail toward NON-hermetic: the outbound operation is recorded against the
// root as egress nobody could describe (FamilyNotObservable), which cilock's
// filter counts.
func TestUnprovenPidOutboundFailsTowardNonHermetic(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			// The racing child: reported a connect, gone before the poll.
			{pid: 999, op: opNetworkOutbound, detail: "remote:*:443"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts: map[int]procFacts{
			rootPid: {ppid: 1, pgid: rootPid, ok: true},
			999:     {}, // poll failed: ownership unproven
		},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	root := findProcess(procs, rootPid)
	if root == nil {
		t.Fatal("root process missing from tree")
	}
	if root.Network == nil || len(root.Network.Connections) == 0 {
		t.Fatalf("the unproven pid's outbound operation vanished: root has no network connections; diag=%+v", *diag)
	}
	conn := root.Network.Connections[0]
	if conn.Family != FamilyNotObservable {
		t.Errorf("unproven-ownership egress recorded with family %q, want %q — it must classify as egress a consumer counts", conn.Family, FamilyNotObservable)
	}
	if conn.Syscall != "connect" {
		t.Errorf("unproven-ownership outbound recorded as syscall %q, want %q so the hermeticity filter counts it", conn.Syscall, "connect")
	}
	if ClassifySocketFamily(conn.Family) != FamilyClassUnobservable {
		t.Errorf("family %q classifies as %v, not FamilyClassUnobservable", conn.Family, ClassifySocketFamily(conn.Family))
	}
	if diag.NetworkReportsUnprovenOwnership != 1 {
		t.Errorf("NetworkReportsUnprovenOwnership = %d, want 1", diag.NetworkReportsUnprovenOwnership)
	}
	if diag.NetworkReportsUnattributed != 0 {
		t.Errorf("NetworkReportsUnattributed = %d, want 0 — unproven is a different fact from proven-foreign", diag.NetworkReportsUnattributed)
	}
}

// A PROVEN stranger's connection stays out: its kernel facts were read and its
// parent chain does not reach the root, so counting it would blame this build
// for a neighbor's traffic. The distinction being tested is proven-foreign
// (dropped, counted) versus unproven (fails closed, above).
func TestProvenForeignOutboundStaysUnattributed(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: 777, op: opNetworkOutbound, detail: "remote:*:443"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts: map[int]procFacts{
			rootPid: {ppid: 1, pgid: rootPid, ok: true},
			777:     {ppid: 1, pgid: 777, ok: true}, // read, and provably not ours
		},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	if root := findProcess(procs, rootPid); root != nil && root.Network != nil && len(root.Network.Connections) != 0 {
		t.Errorf("a proven stranger's connection was attributed to the root: %+v", root.Network.Connections)
	}
	if diag.NetworkReportsUnattributed != 1 {
		t.Errorf("NetworkReportsUnattributed = %d, want 1", diag.NetworkReportsUnattributed)
	}
	if diag.NetworkReportsUnprovenOwnership != 0 {
		t.Errorf("NetworkReportsUnprovenOwnership = %d, want 0", diag.NetworkReportsUnprovenOwnership)
	}
}

// A canary pid performing NETWORK activity is not a canary: the probes are
// sandboxed /usr/bin/true runs that never touch the network, so a network
// report under a canary pid means the pid was recycled by some process whose
// ownership nobody can prove. Excluding it by pid would hand an attacker a
// blessed pid to hide egress under (fork until the pid space wraps onto a
// canary pid, then fetch). It must take the unproven-ownership path.
func TestRecycledCanaryPidCannotHideEgress(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	const canaryPid = 555
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: canaryPid, op: opNetworkOutbound, detail: "remote:*:443"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{canaryPid: true},
		facts: map[int]procFacts{
			rootPid: {ppid: 1, pgid: rootPid, ok: true},
		},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	root := findProcess(procs, rootPid)
	if root == nil || root.Network == nil || len(root.Network.Connections) == 0 {
		t.Fatalf("network activity under a canary pid vanished from the evidence; diag=%+v", *diag)
	}
	if got := root.Network.Connections[0].Family; got != FamilyNotObservable {
		t.Errorf("canary-pid egress recorded with family %q, want %q", got, FamilyNotObservable)
	}
	if diag.NetworkReportsUnprovenOwnership != 1 {
		t.Errorf("NetworkReportsUnprovenOwnership = %d, want 1", diag.NetworkReportsUnprovenOwnership)
	}
}

// The same hole, one direction over, and it survived the round that fixed the
// outbound one because `recordUnprovenNetwork` returned early on anything that
// was not `opNetworkOutbound`.
//
// cilock treats an ACCEPTED inbound connection as an undeclared input channel
// (egressEndpoint labels it "inbound:"), on the reasoning that the peer was
// already running so its own outbound report is a stranger's and is dropped —
// if the build's inbound is ignored too, a helper outside the tree can feed
// the build and the run still reads hermetic. That reasoning applies with
// MORE force to an inbound whose owner could not be proven: a short-lived
// child can accept external input and exit before its facts are polled, and
// counting it only in a diagnostic leaves an empty egress list that gets
// signed as hermetic.
func TestUnprovenPidInboundFailsTowardNonHermetic(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			// Accepted a connection, then gone before the poll.
			{pid: 999, op: opNetworkInbound, detail: "remote:*:8080"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts: map[int]procFacts{
			rootPid: {ppid: 1, pgid: rootPid, ok: true},
			999:     {}, // poll failed: ownership unproven
		},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	root := findProcess(procs, rootPid)
	if root == nil {
		t.Fatal("root process missing from tree")
	}
	if root.Network == nil || len(root.Network.Connections) == 0 {
		t.Fatalf("the unproven pid's inbound operation vanished: root has no network connections — a helper "+
			"outside the tree could feed this build and it would still sign hermetic; diag=%+v", *diag)
	}
	conn := root.Network.Connections[0]
	if conn.Syscall != "accept" {
		t.Errorf("unproven-ownership inbound recorded as syscall %q, want %q — that is the name cilock's "+
			"filter keys the undeclared-input-channel rule on", conn.Syscall, "accept")
	}
	if conn.Family != FamilyNotObservable {
		t.Errorf("unproven-ownership inbound recorded with family %q, want %q", conn.Family, FamilyNotObservable)
	}
	if diag.NetworkReportsUnprovenOwnership != 1 {
		t.Errorf("NetworkReportsUnprovenOwnership = %d, want 1", diag.NetworkReportsUnprovenOwnership)
	}
}

// A bind is NOT recorded against the root, and the asymmetry is deliberate
// rather than an oversight repeated. Recording an unproven operation on the
// root is a FALSE ATTRIBUTION accepted because it fails the verdict toward
// non-hermetic — it buys safety. cilock ignores bind outright ("bind()/listen()
// is serving, not fetching"), so a bind entry would buy no safety and would
// claim the root opened a listener nobody proved it opened. It stays counted.
func TestUnprovenPidBindIsCountedNotAttributed(t *testing.T) {
	t.Parallel()
	const rootPid = 100
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: 999, op: opNetworkBind, detail: "local:*:8080"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts: map[int]procFacts{
			rootPid: {ppid: 1, pgid: rootPid, ok: true},
			999:     {},
		},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	if root := findProcess(procs, rootPid); root != nil && root.Network != nil && len(root.Network.Connections) > 0 {
		t.Errorf("an unproven BIND was attributed to the root (%+v) — that is a claim nobody proved, and it "+
			"changes no verdict, so it buys nothing", root.Network.Connections)
	}
	if diag.NetworkReportsUnprovenOwnership != 1 {
		t.Errorf("NetworkReportsUnprovenOwnership = %d, want 1 — it still has to be visible", diag.NetworkReportsUnprovenOwnership)
	}
}
