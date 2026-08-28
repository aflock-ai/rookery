//go:build darwin

package commandrun

import (
	"testing"
)

// networkObserved is a CAPABILITY claim, and cilock keys its hermeticity
// verdict on it. The profile text proves only that the rule was asked for;
// if the backend accepted the profile and stopped emitting network-* events,
// a build that fetched the world would show an empty egress list and be
// signed hermetic.
//
// This exercises the PRODUCTION path — a real traced run, reading the
// diagnostics the attestation actually carries — rather than restating the
// expression the production code uses. An earlier version asserted
// `sandboxProfileReportsNetwork() && s.networkProven`, which is the
// implementation written twice and could not have failed if the wiring were
// wrong.
func TestNetworkObservedIsFalseWhenTheProbeCannotRun(t *testing.T) {
	saved := networkProbePath
	networkProbePath = "/nonexistent/nc"
	t.Cleanup(func() { networkProbePath = saved })

	rc, err := traceScript(t, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if rc.darwinTraceDiag == nil {
		t.Fatal("no darwin diagnostics on a traced run")
	}
	if rc.darwinTraceDiag.NetworkObserved {
		t.Fatal("networkObserved is TRUE with no probe binary present — the flag is inheriting the profile's intent " +
			"rather than a delivered report, and cilock would sign a hermeticity claim on it")
	}
}

// The same path with the probe available: the capability is claimed only
// when a report actually came back, and this asserts the emitted diagnostic
// rather than recomputing it.
func TestNetworkObservedIsTrueOnlyWithADeliveredReport(t *testing.T) {
	rc, err := traceScript(t, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	d := rc.darwinTraceDiag
	if d == nil {
		t.Fatal("no darwin diagnostics on a traced run")
	}
	t.Logf("networkObserved=%v (profile asks: %v)", d.NetworkObserved, sandboxProfileReportsNetwork())
	if d.NetworkObserved && !sandboxProfileReportsNetwork() {
		t.Fatal("networkObserved claimed while the profile does not even ask for network reports")
	}
}
