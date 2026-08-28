//go:build darwin

package commandrun

import "testing"

// PROVING ONE OPERATION CLASS SAYS NOTHING ABOUT THE OTHER.
//
// cilock's verdict counts an outbound connect as a fetch AND an accepted
// inbound connection as an undeclared input channel. An outbound-only proof
// therefore lets "the network channel works" be true while inbound reports
// never arrive at all — and a build being fed from outside publishes an empty
// egress list under an affirmative no-egress claim.
//
// This is the end-to-end guard on that: a real trace must come back with the
// capability PROVEN, which the paired listener/connector probe only achieves
// by observing network-inbound from the listener AND network-outbound from
// the connector. It is written as a live assertion rather than a unit test
// because the failure it exists to catch is exactly a probe that quietly
// proves nothing: an earlier revision looped in the shell, forked nc as a
// child, and reported outbound against a pid that was never registered —
// which measured 0/8 while every unit test still passed.
func TestNetworkCapabilityProvesBothOperationClasses(t *testing.T) {
	rc, err := traceScript(t, []string{"/bin/sh", "-c", "exit 0"})
	if err != nil {
		t.Fatalf("trace refused: %v", err)
	}
	if rc.Summary == nil || rc.Summary.Diagnostics.Darwin == nil {
		t.Fatal("no darwin diagnostics on a traced run")
	}
	if !rc.Summary.Diagnostics.Darwin.NetworkObserved {
		t.Fatal("networkObserved is FALSE on a healthy run: the capability probe proves nothing, so cilock " +
			"will withhold the hermeticity verdict on every macOS build. Check that BOTH probes exec rather " +
			"than fork — a shell loop reports against an unregistered child pid.")
	}
}

// sawNetworkOpFromPID must discriminate BY OPERATION, not merely by "some
// network report arrived". Matching any op is what let an outbound-only probe
// stand in for a capability the verdict also keys on inbound.
func TestSawNetworkOpDiscriminatesByOperation(t *testing.T) {
	t.Parallel()
	const pid = 4242
	s := &sandboxSession{
		facts:      map[int]procFacts{},
		pinned:     map[imageIdentity]pinnedImage{},
		canaryPIDs: map[int]procFacts{},
		ourPids:    map[int]bool{},
		events: []sandboxEvent{
			{pid: pid, op: opNetworkOutbound},
		},
	}
	if !s.sawNetworkOpFromPID(pid, opNetworkOutbound) {
		t.Error("an outbound report from the pid was not seen")
	}
	if s.sawNetworkOpFromPID(pid, opNetworkInbound) {
		t.Error("an INBOUND report was claimed from a pid that only sent outbound — this is the exact " +
			"conflation that let a half-proven channel read as fully proven")
	}
	if s.sawNetworkOpFromPID(pid+1, opNetworkOutbound) {
		t.Error("a report was attributed to the wrong pid")
	}
}
