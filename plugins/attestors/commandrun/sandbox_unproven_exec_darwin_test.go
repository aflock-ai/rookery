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
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// A child that execs and exits before its kernel facts can be read has no
// provable parent edge, and it is NOT rare: measured 2026-08-27 under load at
// 25–38% of the children of a 1,500-way fork storm. Dropping those reports
// would let a fast child make its exec vanish from the signed evidence. The
// exec must be listed — image, pid, the digest pinned at report time — with
// no parent edge and outside the tree, so a policy that forbids an image can
// fail closed on it while nothing is attributed that was not proven.
func TestUnprovenExecIsListedNotDropped(t *testing.T) {
	t.Parallel()
	const rootPid, fastChild, stranger = 100, 555, 777
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: fastChild, comm: "sh", op: opExecStar, detail: "/usr/bin/curl", pin: 7, timestamp: "t1"},
			{pid: fastChild, op: opFork},
			{pid: stranger, op: opExecStar, detail: "/usr/bin/ssh"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts: map[int]procFacts{
			rootPid:   {ok: true},
			fastChild: {},                           // poll lost the race: unproven
			stranger:  {ppid: 1, pgid: 1, ok: true}, // proven foreign
		},
		digests: map[pinID]cryptoutil.DigestSet{7: {cryptoutil.DigestValue{Hash: crypto.SHA256}: "aa"}},
	}
	diag := &DarwinTraceDiagnostics{}
	procs := buildDarwinTree(in, diag)

	if findProcess(procs, fastChild) != nil {
		t.Fatal("an unproven pid was admitted to the tree — nothing proved it is this build's")
	}
	if len(diag.UnprovenExecs) != 1 {
		t.Fatalf("unprovenExecs = %+v, want exactly the fast child's exec", diag.UnprovenExecs)
	}
	got := diag.UnprovenExecs[0]
	if got.PID != fastChild || got.Timestamp != "t1" {
		t.Fatalf("listed exec = %+v, want pid %d at t1", got, fastChild)
	}
	// Never the path or the command name: the stream is machine-wide and the
	// process may be another user's, whose executable names are not ours to
	// publish. The path hash still lets a policy forbid a known image.
	if b, _ := json.Marshal(got); strings.Contains(string(b), "/usr/bin/curl") || strings.Contains(string(b), "\"sh\"") {
		t.Fatalf("an unproven exec serialized a path or comm: %s", b)
	}
	if b, _ := json.Marshal(got); strings.Contains(string(b), "digest") || strings.Contains(string(b), "sha") {
		t.Fatalf("an unproven exec published image identity for a process whose owner is unknown: %s", b)
	}
	// The stranger's facts were read and its chain leads elsewhere: it stays
	// a count, never a listing that could be read as possibly-ours.
	if diag.UnattributedReports != 2 { // stranger's exec + the fast child's fork
		t.Fatalf("unattributedReports = %d, want 2 (a proven-foreign exec and an unproven fork)", diag.UnattributedReports)
	}
}

// The list is bounded and says so.
func TestUnprovenExecListIsCappedAndCounted(t *testing.T) {
	t.Parallel()
	in := darwinTreeInput{rootPid: 1, members: map[int]bool{1: true}, canaries: map[int]bool{}, facts: map[int]procFacts{1: {ok: true}}}
	for i := 0; i < maxUnprovenExecs+3; i++ {
		in.events = append(in.events, sandboxEvent{pid: 1000 + i, op: opExecStar, detail: "/usr/bin/true"})
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if len(diag.UnprovenExecs) != maxUnprovenExecs || diag.UnprovenExecsOmitted != 3 {
		t.Fatalf("listed=%d omitted=%d, want %d listed and 3 omitted", len(diag.UnprovenExecs), diag.UnprovenExecsOmitted, maxUnprovenExecs)
	}
	// And an overflowed list refuses the trace: a policy reading it would be
	// reading an incomplete account.
	if err := refuseIncompleteTree(diag); err == nil || !strings.Contains(err.Error(), "beyond the") {
		t.Fatalf("an overflowed unproven-exec list did not refuse: %v", err)
	}
	diag.UnprovenExecsOmitted = 0
	if err := refuseIncompleteTree(diag); err != nil {
		t.Fatalf("a complete list refused: %v", err)
	}
}
