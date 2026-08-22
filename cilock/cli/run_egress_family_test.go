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

// The consumer half of the socket-family coverage gate.
//
// commandrun's own gate proves every family it can emit is CLASSIFIED. This one
// proves the classification is OBEYED here, at the only place where getting it
// wrong becomes a signed claim. The two together are what make the vocabulary
// closed: neither alone would have caught an IP family that the attestor
// emitted and this filter dropped.
//
// NO BUILD TAG, so it runs on the Linux CI runners. What it checks is the wire
// contract rather than any one platform's tracer, and a family only some
// platform can emit still has to be counted correctly here.

package cli

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// TestEveryIPFamilyCountsAsEgress walks commandrun's classification table and
// requires this filter to count a connect() on EVERY family classified as IP.
//
// Table-driven off the attestor's own table rather than off a list written
// here, so a family added there is exercised here with no edit: a hand-written
// list is precisely what let AF_INET_UNSPECIFIED reach a filter that knew only
// AF_INET and AF_INET6.
func TestEveryIPFamilyCountsAsEgress(t *testing.T) {
	table := commandrun.SocketFamilyClassifications()
	if len(table) == 0 {
		t.Fatal("commandrun published an empty family table, so this gate checks nothing")
	}
	var ipFamilies int
	for family, class := range table {
		if class != commandrun.FamilyClassIP {
			continue
		}
		ipFamilies++
		t.Run(family, func(t *testing.T) {
			// An external host, named. Every IP family must count.
			ep, ok := egressEndpoint(commandrun.NetworkConnection{
				Syscall: "connect", Family: family, Address: "140.82.112.3", Port: 443,
			})
			if !ok {
				t.Fatalf("egressEndpoint dropped a connect() on IP family %q; a build that "+
					"fetched over it would be signed hermetic with an empty egress list", family)
			}
			if ep != "140.82.112.3:443" {
				t.Errorf("endpoint = %q, want 140.82.112.3:443", ep)
			}

			// A host the observer could not name still has to count: that is
			// the case the family exists for.
			ep, ok = egressEndpoint(commandrun.NetworkConnection{
				Syscall: "connect", Family: family,
				Address: commandrun.HostNotObservable, Port: 443, FD: commandrun.FDNotObservable,
			})
			if !ok {
				t.Fatalf("egressEndpoint dropped an un-named endpoint on IP family %q — "+
					"'the observer could not look' was read as 'there was nothing there'", family)
			}
			if ep != commandrun.HostNotObservable+":443" {
				t.Errorf("endpoint = %q, want %q", ep, commandrun.HostNotObservable+":443")
			}
		})
	}
	if ipFamilies < 3 {
		t.Errorf("only %d IP families in the table; expected at least AF_INET, AF_INET6 and "+
			"AF_INET_UNSPECIFIED, so this gate is not covering what it claims to", ipFamilies)
	}
}

// TestEveryRemoteCapableFamilyCountsAsEgress is the same gate widened past IP.
//
// A family does not have to be IP to reach another machine: AF_VSOCK carries a
// guest to its hypervisor host. Driving off the published table rather than a
// list written here means a remote-capable family added to the vocabulary is
// exercised in this filter with no edit — the failure mode that let
// AF_INET_UNSPECIFIED reach a filter that knew only AF_INET and AF_INET6.
func TestEveryRemoteCapableFamilyCountsAsEgress(t *testing.T) {
	var remote int
	for family, class := range commandrun.SocketFamilyClassifications() {
		if class != commandrun.FamilyClassRemoteNonIP {
			continue
		}
		remote++
		t.Run(family, func(t *testing.T) {
			ep, ok := egressEndpoint(commandrun.NetworkConnection{
				Syscall: "connect", Family: family, Address: "2", Port: 1024,
			})
			if !ok {
				t.Fatalf("egressEndpoint dropped a connect() on remote-capable family %q; a "+
					"build that fetched over it would be signed hermetic with an empty egress list", family)
			}
			if !strings.Contains(ep, family) {
				t.Errorf("endpoint %q does not name the family, so the signed summary does not "+
					"say what channel broke hermeticity", ep)
			}
		})
	}
	if remote == 0 {
		t.Error("no remote-capable non-IP family in the table; AF_VSOCK is one, so either it was " +
			"dropped from the vocabulary or reclassified and this gate now checks nothing")
	}
}

// TestUnclassifiedRuntimeFamilyBreaksHermeticity is the gate the compile-time
// one cannot be.
//
// commandrun's TestEverySocketFamilyConstantIsClassified proves every family
// CONSTANT is classified — by scanning the sources with go/parser. It is
// blind by construction to the families that only exist at RUNTIME: the Linux
// tracer writes fmt.Sprintf("AF_%d", domain) for any domain it has no name for,
// and no constant declares "AF_42". Such a string was in no table, so
// egressEndpoint dropped the connection, externalEgress returned empty, and
// `Hermetic = len(NetworkEgress) == 0` signed "this build reached nothing" over
// a build that reached the network. AF_VSOCK arriving as "AF_40" is that hole
// with a remote-capable family in it.
//
// Asserted end-to-end on the summary cilock signs, not on the classifier: the
// claim under test is about what gets SIGNED.
func TestUnclassifiedRuntimeFamilyBreaksHermeticity(t *testing.T) {
	cases := []struct {
		name   string
		family string
		want   string
	}{
		{
			name:   "numeric fallback for a domain the tracer cannot name",
			family: "AF_42",
			want:   "unclassified-family:AF_42:raw:2a00:1024",
		},
		{
			name:   "AF_VSOCK arriving before the vocabulary named it",
			family: "AF_40",
			want:   "unclassified-family:AF_40:raw:2a00:1024",
		},
		{
			name:   "an observer that recorded no family at all",
			family: "",
			want:   "unclassified-family:(family-not-observable):raw:2a00:1024",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Keep the case honest: if the vocabulary later classifies this
			// string, it is no longer testing the unclassified path.
			if got := commandrun.ClassifySocketFamily(tc.family); got != commandrun.FamilyClassUndefined {
				t.Fatalf("family %q now classifies as %v; this case no longer exercises the "+
					"unclassified path — pick a family the vocabulary still does not define", tc.family, got)
			}

			cr := commandrun.New(commandrun.WithTracing(true))
			cr.Summary = &commandrun.TraceSummary{CaptureMode: "trace"}
			cr.Processes = connectsTo(commandrun.NetworkConnection{
				Syscall: "connect", Family: tc.family, Address: "raw:2a00", Port: 1024,
			})

			s := &options.RunSummary{}
			stampHermeticity(s, []attestation.Attestor{cr})

			if s.Tracing == "" {
				t.Fatal("a captured trace must publish a capture mode, or the verdict below is vacuous")
			}
			if s.Hermetic {
				t.Errorf("a build that connect()ed on family %q — which nothing classifies, so "+
					"nobody can say it is not remote-capable — was signed HERMETIC; egress=%#v",
					tc.family, s.NetworkEgress)
			}
			if len(s.NetworkEgress) != 1 || s.NetworkEgress[0] != tc.want {
				t.Errorf("NetworkEgress = %#v, want [%q] — the reason hermeticity broke has to be "+
					"legible in the signed summary, not silent", s.NetworkEgress, tc.want)
			}
		})
	}
}

// TestVSockConnectBreaksHermeticity pins the concrete case, on the name the
// tracer emits now that the vocabulary has learned it. AF_VSOCK is
// remote-capable — guest to hypervisor host and back — so counting it is right
// on the merits, not merely as a conservative default.
func TestVSockConnectBreaksHermeticity(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "trace"}
	cr.Processes = connectsTo(commandrun.NetworkConnection{
		Syscall: "connect", Family: commandrun.FamilyVSock, Address: "2", Port: 1024,
	})

	s := &options.RunSummary{}
	stampHermeticity(s, []attestation.Attestor{cr})

	want := commandrun.FamilyVSock + ":2:1024"
	if len(s.NetworkEgress) != 1 || s.NetworkEgress[0] != want {
		t.Errorf("NetworkEgress = %#v, want [%q]", s.NetworkEgress, want)
	}
	if s.Hermetic {
		t.Error("a build that connect()ed to its hypervisor host over AF_VSOCK was signed HERMETIC")
	}
}

// TestNonRemoteFamiliesAreNotEgress is the other pole. A family the observer
// DESCRIBED and which cannot name a remote host must not be counted, or
// hermeticity becomes unreachable: AF_NETLINK appears on every Linux build, and
// AF_UNSPEC on every build that resolves a hostname.
func TestNonRemoteFamiliesAreNotEgress(t *testing.T) {
	for family, class := range commandrun.SocketFamilyClassifications() {
		if class != commandrun.FamilyClassNonRemote {
			continue
		}
		if _, ok := egressEndpoint(commandrun.NetworkConnection{
			Syscall: "connect", Family: family, Address: commandrun.HostNotObservable, Port: 443,
		}); ok {
			t.Errorf("family %q is classified non-remote but counted as egress", family)
		}
	}
}

// TestUnnamedIPEndpointBreaksHermeticity is the end of the chain, asserted on
// the summary cilock signs.
//
// The connection is the shape a report-based observer produces — an IP socket
// whose version and host the kernel never named — and the requirement is that
// it lands in NetworkEgress and drives Hermetic to false. The unit tests above
// cover the classifier; this one covers the two lines that turn a classifier
// result into an SLSA L3 hermeticity assertion.
func TestUnnamedIPEndpointBreaksHermeticity(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "trace"}
	cr.Processes = connectsTo(commandrun.NetworkConnection{
		Syscall: "connect",
		Family:  commandrun.FamilyInetUnspecified,
		Address: commandrun.HostNotObservable,
		Port:    8080,
		FD:      commandrun.FDNotObservable,
	})

	s := &options.RunSummary{}
	stampHermeticity(s, []attestation.Attestor{cr})

	if s.Tracing == "" {
		t.Fatal("a captured trace must publish a capture mode, or the verdict below is vacuous")
	}
	want := commandrun.HostNotObservable + ":8080"
	if len(s.NetworkEgress) != 1 || s.NetworkEgress[0] != want {
		t.Errorf("NetworkEgress = %#v, want [%q]", s.NetworkEgress, want)
	}
	if s.Hermetic {
		t.Error("a build that opened a TCP connection to an endpoint the observer " +
			"could not name was signed HERMETIC — the SLSA L3 hermeticity assertion is inverted")
	}
}

// TestResolverNoiseStaysHermetic guards the direction that makes the gate worth
// having, on the one case that earns it.
//
// glibc's resolver dissolves its UDP socket's association with
// connect(fd, {sa_family = AF_UNSPEC}, …) on every hostname lookup. A ptrace
// census of `getent hosts` + `curl https://` counts exactly one such event per
// run. It is a FULLY DESCRIBED operation — the observer read sa_family — and
// what it describes reaches nothing, so counting it would put every build that
// resolves a name over the line and make SLSA L3 unreachable while teaching
// nobody anything.
//
// The scope here is exactly that: a family the observer READ. An operation the
// observer could NOT read carries FamilyNotObservable instead and must break
// hermeticity — TestUnobservedConnectBreaksHermeticity is that half, and the
// two together are the split this test does not get to blur.
func TestResolverNoiseStaysHermetic(t *testing.T) {
	if got := commandrun.ClassifySocketFamily(commandrun.FamilyUnspecified); got != commandrun.FamilyClassNonRemote {
		t.Fatalf("AF_UNSPEC classifies as %v, not FamilyClassNonRemote; this test no longer "+
			"describes the resolver-disconnect case it exists to protect", got)
	}
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "trace"}
	cr.Processes = connectsTo(
		commandrun.NetworkConnection{Syscall: "connect", Family: commandrun.FamilyUnspecified, FD: commandrun.FDNotObservable},
		commandrun.NetworkConnection{Syscall: "connect", Family: commandrun.FamilyUnix, Address: "/var/run/mDNSResponder"},
	)

	s := &options.RunSummary{}
	stampHermeticity(s, []attestation.Attestor{cr})

	if !s.Hermetic {
		t.Errorf("name resolution alone made the build non-hermetic; egress=%v", s.NetworkEgress)
	}
}

// TestUnobservedConnectBreaksHermeticity is the sibling of the test above and
// the reason the two cases cannot share one family value.
//
// A backend that saw a connect() and could not read its sockaddr reports
// FamilyNotObservable. The build reached SOMETHING; the attestor is the only
// witness and it did not see what. Signing Hermetic over that publishes "we did
// not look" as "there was none" — absence projected as an authoritative value,
// which is the single failure this whole filter exists to prevent.
//
// Asserted on the summary cilock signs, not on the classifier, because the
// claim under test is about what gets SIGNED.
func TestUnobservedConnectBreaksHermeticity(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "trace"}
	cr.Processes = connectsTo(
		commandrun.UnobservedConnection("connect", commandrun.FDNotObservable),
	)

	s := &options.RunSummary{}
	stampHermeticity(s, []attestation.Attestor{cr})

	if s.Tracing == "" {
		t.Fatal("a captured trace must publish a capture mode, or the verdict below is vacuous")
	}
	if s.Hermetic {
		t.Errorf("a build that made a connect() the observer could not describe was signed "+
			"HERMETIC; egress=%#v — 'I could not look' was published as 'there was nothing there'",
			s.NetworkEgress)
	}
	want := "unclassified-family:(family-not-observable):" + commandrun.HostNotObservable
	if len(s.NetworkEgress) != 1 || s.NetworkEgress[0] != want {
		t.Errorf("NetworkEgress = %#v, want [%q] — the reason hermeticity broke has to be legible "+
			"in the signed summary, not silent", s.NetworkEgress, want)
	}
}

// TestEveryUnobservableFamilyCountsAsEgress walks the published table the same
// way the IP and remote-capable gates do, so a family later classified
// unobservable is exercised here without this file being edited.
func TestEveryUnobservableFamilyCountsAsEgress(t *testing.T) {
	var unobservable int
	for family, class := range commandrun.SocketFamilyClassifications() {
		if class != commandrun.FamilyClassUnobservable {
			continue
		}
		unobservable++
		t.Run(family, func(t *testing.T) {
			ep, ok := egressEndpoint(commandrun.NetworkConnection{
				Syscall: "connect", Family: family,
				Address: commandrun.HostNotObservable, Port: 443, FD: commandrun.FDNotObservable,
			})
			if !ok {
				t.Fatalf("egressEndpoint dropped a connect() on unobservable family %q; a build "+
					"that fetched through it would be signed hermetic with an empty egress list", family)
			}
			want := "unclassified-family:(family-not-observable):" + commandrun.HostNotObservable + ":443"
			if ep != want {
				t.Errorf("endpoint = %q, want %q", ep, want)
			}
		})
	}
	if unobservable == 0 {
		t.Error("no unobservable family in the table; commandrun.FamilyNotObservable is one, so " +
			"either it was dropped from the vocabulary or reclassified and this gate now checks nothing")
	}
}
