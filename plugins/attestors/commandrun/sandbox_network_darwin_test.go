//go:build darwin

package commandrun

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// listenLoopback starts a real listener and returns its port. Loopback rather
// than an internet host so the test is deterministic and needs no egress of its
// own: the kernel reports a loopback connect as `remote:*:<port>`, the SAME
// shape it reports for an external one, so this exercises the real path.
func listenLoopback(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func darwinConnections(rc *CommandRun) []NetworkConnection {
	var out []NetworkConnection
	for i := range rc.Processes {
		if rc.Processes[i].Network == nil {
			continue
		}
		out = append(out, rc.Processes[i].Network.Connections...)
	}
	return out
}

// Egress observed by the kernel has to reach the attestation, or cilock computes
// `Hermetic = len(NetworkEgress) == 0` over an empty set and certifies a build
// that reached the network.
//
// The port is the assertion that matters: it is the ONE thing about an IP
// destination this backend can actually name, so it is the only part worth
// checking, and checking it proves the report was parsed rather than merely
// counted.
func TestDarwinTraceRecordsRealEgress(t *testing.T) {
	port := listenLoopback(t)
	script := writeScript(t, fmt.Sprintf(
		"#!/bin/sh\n/usr/bin/nc -z -w 2 127.0.0.1 %d\n", port))

	rc, err := traceScript(t, []string{"/bin/sh", script})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	conns := darwinConnections(rc)
	if len(conns) == 0 {
		t.Fatal("no network connections recorded for a build that connected out; " +
			"cilock would read this as a hermetic build")
	}

	var found *NetworkConnection
	for i := range conns {
		if conns[i].Syscall == "connect" && conns[i].Port == port {
			found = &conns[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no connect to port %d in %+v", port, conns)
	}

	// The host is NOT observable here, and the recorded address must say so
	// rather than inventing one — a fabricated host would be worse than none,
	// because a verifier would believe it.
	if found.Address != HostNotObservable {
		t.Errorf("address = %q, want %q — this backend cannot name the host and must not claim to",
			found.Address, HostNotObservable)
	}
	if found.Family != FamilyInetUnspecified {
		t.Errorf("family = %q, want %q — IPv4 vs IPv6 is not observable from a sandbox report",
			found.Family, FamilyInetUnspecified)
	}
	// Hostname means "TLS SNI read from the ClientHello". This backend never
	// sees one, and putting the not-observable marker there would manufacture
	// exactly the resolved-host claim the address is avoiding.
	if found.Hostname != "" {
		t.Errorf("hostname = %q, want empty — no SNI is ever observed here", found.Hostname)
	}

	if rc.Summary == nil || rc.Summary.Diagnostics.Darwin == nil {
		t.Fatal("summary carries no darwin diagnostics")
	}
	if !rc.Summary.Diagnostics.Darwin.NetworkObserved {
		t.Error("networkObserved = false while the profile carried the network rule")
	}
}

// The profile comment claims networkReportRule is what makes hermeticity
// claimable at all. This deletes the rule and watches the evidence disappear,
// which is the only way to know the line is load-bearing rather than decorative.
//
// The direction that matters is the SECOND assertion. Losing the egress records
// is not itself dangerous; losing them while still reporting networkObserved
// would be, because cilock would then compute hermeticity over an empty set and
// hand back "hermetic" for a build it never watched.
func TestDarwinNetworkRuleIsLoadBearing(t *testing.T) {
	port := listenLoopback(t)

	original := sandboxProfile
	stripped := strings.ReplaceAll(original, networkReportRule, "")
	if stripped == original {
		t.Fatalf("networkReportRule %q is not present in the profile; this test is testing nothing",
			networkReportRule)
	}
	sandboxProfile = stripped
	t.Cleanup(func() { sandboxProfile = original })

	if sandboxProfileReportsNetwork() {
		t.Fatal("sandboxProfileReportsNetwork() is true after the rule was removed — " +
			"the flag is not derived from the profile actually applied")
	}

	script := writeScript(t, fmt.Sprintf(
		"#!/bin/sh\n/usr/bin/nc -z -w 2 127.0.0.1 %d\n", port))
	rc, err := traceScript(t, []string{"/bin/sh", script})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	if conns := darwinConnections(rc); len(conns) != 0 {
		t.Errorf("recorded %d connections with the network rule removed: %+v", len(conns), conns)
	}
	if rc.Summary == nil || rc.Summary.Diagnostics.Darwin == nil {
		t.Fatal("summary carries no darwin diagnostics")
	}
	if rc.Summary.Diagnostics.Darwin.NetworkObserved {
		t.Error("networkObserved = true while the profile had no network rule — " +
			"cilock would claim hermeticity for a build nothing watched")
	}

	// The tree itself must survive: dropping the network rule may not cost us
	// the exec reports, or this test would pass for the wrong reason.
	if rc.Summary.Diagnostics.Darwin.ExecReports == 0 {
		t.Error("exec reports vanished along with the network rule; the profile edit broke more than it should")
	}
}
