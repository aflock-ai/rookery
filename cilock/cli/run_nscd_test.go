package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// nscd is not a DNS resolver: one socket multiplexes host, passwd, group,
// services and netgroup lookups, and nothing in this channel says which was
// asked for. Labelling it "resolver:" would let a DNS waiver accept an
// unrelated undeclared input. It counts as ordinary unix egress.
func TestNscdIsNotWaivableAsDNS(t *testing.T) {
	t.Parallel()
	connect := func(path string) commandrun.NetworkConnection {
		return commandrun.NetworkConnection{Syscall: "connect", Family: commandrun.FamilyUnix, Address: path, FD: commandrun.FDNotObservable}
	}
	for _, path := range []string{"/var/run/nscd/socket", "/run/nscd/socket", "/var/run/nscd.sock"} {
		ep, counts := egressEndpoint(connect(path))
		if !counts || ep != "unix:"+path {
			t.Errorf("nscd at %q: ep=%q counts=%v, want unix:%s — one socket carries passwd and group lookups too", path, ep, counts, path)
		}
	}
	// And the macOS resolver gets no special label either — same reason:
	// the label was a waiver and the pathname cannot authenticate the peer.
	// Resolution still COUNTS, which is the property that matters; it is
	// just named by its path like every other unix peer.
	for _, path := range []string{"/var/run/mDNSResponder", "/private/var/run/mDNSResponder"} {
		ep, counts := egressEndpoint(connect(path))
		if !counts || ep != "unix:"+path {
			t.Errorf("mDNSResponder at %q: ep=%q counts=%v, want unix:%s", path, ep, counts, path)
		}
	}
}
