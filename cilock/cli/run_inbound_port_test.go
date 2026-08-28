package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// The inbound label is a waiver, so it has to name the channel. macOS often
// cannot observe the peer host but DOES report the port: collapsing every
// accept onto "inbound:(host-not-observable)" meant a waiver written for one
// intended test listener waived every inbound channel on the box.
func TestInboundEndpointKeepsThePort(t *testing.T) {
	t.Parallel()
	accept := func(port int) commandrun.NetworkConnection {
		return commandrun.NetworkConnection{
			Syscall: "accept", Family: commandrun.FamilyInetUnspecified,
			Address: commandrun.HostNotObservable, Port: port, FD: commandrun.FDNotObservable,
		}
	}
	a, _ := egressEndpoint(accept(8080))
	b, _ := egressEndpoint(accept(9999))
	if a == b {
		t.Fatalf("accepts on different ports collapsed to %q; one waiver would cover every inbound channel", a)
	}
	if want := "inbound:" + commandrun.FamilyInetUnspecified + ":" + commandrun.HostNotObservable + ":8080"; a != want {
		t.Fatalf("endpoint = %q, want %q", a, want)
	}
	// No port observed: the label still says what the channel was.
	if ep, counts := egressEndpoint(commandrun.NetworkConnection{Syscall: "accept", Family: commandrun.FamilyUnix, Address: "/tmp/x.sock"}); !counts || ep != "inbound:"+commandrun.FamilyUnix+":/tmp/x.sock" {
		t.Fatalf("portless inbound = %q counts=%v", ep, counts)
	}
}
