package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// An accepted INBOUND connection is an undeclared input channel: a process
// that was already running connects into the traced build and feeds it. Its
// own outbound report is a stranger's and is dropped, so if the build's
// inbound is ignored too the run reads hermetic while consuming input from
// outside. The peer is not observable here, so the operation itself is the
// evidence — labelled so a policy can waive exactly this channel, the way
// the resolver channel is waived.
func TestInboundConnectionBreaksHermeticity(t *testing.T) {
	t.Parallel()
	in := commandrun.NetworkConnection{
		Syscall: "accept",
		Family:  commandrun.FamilyInetUnspecified,
		Address: commandrun.HostNotObservable,
		FD:      commandrun.FDNotObservable,
	}
	ep, counts := egressEndpoint(in)
	if !counts {
		t.Fatalf("an accepted inbound connection did not count (%q); a helper outside the tree can feed the build and it still reads hermetic", ep)
	}
	// FAMILY-QUALIFIED: without it, an AF_UNIX accept on a socket created at
	// the path "127.0.0.1:8080" renders identically to an AF_INET accept on
	// 127.0.0.1:8080, and a waiver for one silently exempts the other.
	if got := "inbound:" + commandrun.FamilyInetUnspecified + ":" + commandrun.HostNotObservable; ep != got {
		t.Fatalf("endpoint = %q, want %q — the label is what lets a policy waive this channel alone", ep, got)
	}
	// Serving is still not fetching: a bind/listen with nobody connecting is
	// not an input channel.
	if ep, counts := egressEndpoint(commandrun.NetworkConnection{Syscall: "bind", Family: "AF_INET", Address: "0.0.0.0", Port: 8080}); counts {
		t.Errorf("bind counted as an input channel (%q)", ep)
	}
}
