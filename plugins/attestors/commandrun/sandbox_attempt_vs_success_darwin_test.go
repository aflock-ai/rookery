//go:build darwin

package commandrun

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// Ambiguity is about which reading is the KERNEL's, and the decision field
// is part of that reading. A name carrying "(pid) deny(1) op " puts a denied
// reading of the same pid and op ahead of the kernel's allowed one, and a
// check that compares only pid and op calls the line unambiguous — after
// which the real egress or exec is discarded as denied.
func TestAmbiguityCoversTheAllowDenyDecision(t *testing.T) {
	t.Parallel()
	const msg = "Sandbox: x(4242) deny(1) network-outbound (4242) allow network-outbound remote:*:443"
	if !ambiguousHeader(msg) {
		t.Fatal("two readings differing only in allow/deny were called unambiguous; the build's egress would be filed as refused")
	}
	if ambiguousHeader("Sandbox: curl(4242) allow network-outbound remote:*:443") {
		t.Fatal("an ordinary report was refused as ambiguous")
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// The exit sweep must look at the table BEFORE the group reap kills it.
// A fork-only child (never exec'd, never touched the network, so no report
// names it) is visible to the kernel until reapDarwinProcessGroup SIGKILLs
// the group — and the sweep ran after that, so the one process the sweep
// exists to find was destroyed by this code first. mergeProcTables keeps the
// pre-reap rows so such a child is listed and counted.
func TestPreReapRowsSurviveIntoTheSweep(t *testing.T) {
	t.Parallel()
	root := procFacts{ppid: 50, pgid: 100, startSec: 1000, ok: true}
	before := []kinfoFacts{
		{pid: 100, facts: root, uid: 501, comm: "sh"},
		{pid: 300, facts: procFacts{ppid: 100, pgid: 100, startSec: 1001, ok: true}, uid: 501, comm: "sh"}, // reaped by us
	}
	after := []kinfoFacts{
		{pid: 100, facts: root, uid: 501, comm: "sh"},
		{pid: 400, facts: procFacts{ppid: 100, pgid: 100, startSec: 1002, ok: true}, uid: 501, comm: "sh"}, // seen only after
	}
	merged := mergeProcTables(before, after)
	got := map[int]bool{}
	for _, row := range merged {
		if got[row.pid] {
			t.Fatalf("pid %d appears twice in the merged table", row.pid)
		}
		got[row.pid] = true
	}
	for _, pid := range []int{100, 300, 400} {
		if !got[pid] {
			t.Fatalf("pid %d is missing from the merged table; a child the reap killed would never be counted", pid)
		}
	}
}

// Being able to READ another user's world-readable binary is not permission
// to publish that they ran it. An unproven pid's ownership is unknown by
// construction — that is what unproven means — so the entry carries no
// image identity at all.
func TestUnprovenExecCarriesNoImageIdentity(t *testing.T) {
	t.Parallel()
	const rootPid, fast = 100, 555
	in := darwinTreeInput{
		rootPid: rootPid,
		events: []sandboxEvent{
			{pid: rootPid, op: opExecStar, detail: "/bin/sh"},
			{pid: fast, op: opExecStar, detail: "/usr/local/bin/someones-tool", pin: 1, timestamp: "t1"},
		},
		members:  map[int]bool{rootPid: true},
		canaries: map[int]bool{},
		facts:    map[int]procFacts{rootPid: {ok: true}, fast: {}},
		digests:  map[pinID]cryptoutil.DigestSet{1: {cryptoutil.DigestValue{Hash: crypto.SHA256}: "aa"}},
	}
	diag := &DarwinTraceDiagnostics{}
	buildDarwinTree(in, diag)
	if len(diag.UnprovenExecs) != 1 {
		t.Fatalf("unprovenExecs = %+v, want the gap listed", diag.UnprovenExecs)
	}
	if b, _ := json.Marshal(diag.UnprovenExecs[0]); strings.Contains(string(b), "aa") || strings.Contains(string(b), "sha") {
		t.Fatalf("an unproven exec published image identity for a process whose owner is unknown: %s", b)
	}
}
