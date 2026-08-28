package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// A UNIX socket is a channel. A build can fetch undeclared inputs through a
// local proxy at /tmp/build-input.sock exactly as it could over TCP, and a
// rule that counted only docker.sock and the resolver signed such a build
// hermetic. Sockets outside the OS's own IPC directories count, labelled
// unix:<path>; the OS's endpoints do not; a socket the traced tree bound
// itself is the build's own server and never counts.
func TestUnixPeerOutsideSystemIPCCountsAsEgress(t *testing.T) {
	t.Parallel()
	connect := func(path string) commandrun.NetworkConnection {
		return commandrun.NetworkConnection{Syscall: "connect", Family: commandrun.FamilyUnix, Address: path, FD: commandrun.FDNotObservable}
	}
	for _, path := range []string{"/tmp/build-input.sock", "/Users/dev/.cache/proxy.sock", "./relay.sock", "/home/ci/work/agent.sock",
		"/run/user/501/input.sock", "/usr/local/var/proxy.sock", "/var/lib/agent/input.sock", "@cilock-input", "",
		// Beneath the OS's directories is not the OS: a database, an agent, a
		// device mux or the system bus broker there is a peer with inputs.
		"/var/run/postgresql/.s.PGSQL.5432", "/var/run/mysqld/mysqld.sock", "/var/run/usbmuxd", "/run/dbus/system_bus_socket",
		"/run/systemd/private", "/var/run/syslog/", "/var/run/../run/syslog", "/private/var/run/mDNSResponder.evil"} {
		ep, counts := egressEndpoint(connect(path))
		if !counts || ep != "unix:"+path {
			t.Errorf("connect to %q: counts=%v ep=%q, want unix:%s — a local proxy is a channel for undeclared inputs", path, counts, ep, path)
		}
	}
	// NOTHING is exempt by path any more: the channel reports a NAME, not a
	// peer, so the OS's own socket paths are claims a privileged build or a
	// pre-arranged helper can forge. They count like any other peer, and the
	// endpoint names the socket so a policy can waive exactly one.
	for _, path := range []string{"/var/run/syslog", "/private/var/run/syslog", "/dev/log",
		"/run/systemd/journal/socket", "/var/run/mDNSResponder"} {
		ep, counts := egressEndpoint(connect(path))
		if !counts {
			t.Errorf("the OS's own %q did not count; a replaced socket at that path is an undeclared input channel", path)
		}
		// NOTHING carries a special label any more, the resolver included:
		// a label is a waiver, and a waiver resting on a pathname this
		// channel cannot authenticate is a waiver an attacker inherits by
		// replacing the path.
		if ep != "unix:"+path {
			t.Errorf("%q: ep=%q, want unix:%s", path, ep, path)
		}
	}
	// The tree's own server counts too: the report channel carries no unlink
	// and no socket identity, so an earlier bind cannot prove the listener a
	// later connect reached was still the tree's.
	own := "/tmp/build-own.sock"
	procs := []commandrun.ProcessInfo{
		{ProcessID: 1, Network: &commandrun.NetworkActivity{Connections: []commandrun.NetworkConnection{
			{Syscall: "bind", Family: commandrun.FamilyUnix, Address: own, FD: commandrun.FDNotObservable, Timestamp: "2026-08-27T10:00:05Z"},
		}}},
		{ProcessID: 2, Network: &commandrun.NetworkActivity{Connections: []commandrun.NetworkConnection{
			connect(own), connect("/tmp/build-input.sock"),
		}}},
	}
	got := externalEgress(procs)
	want := []string{"unix:/tmp/build-input.sock", "unix:/tmp/build-own.sock"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("externalEgress = %v, want %v: a bind cannot prove who answered a later connect", got, want)
	}
}
