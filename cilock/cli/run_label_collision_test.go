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

package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// AN ENDPOINT LABEL IS A POLICY WAIVER, so two different channels must never
// render as the same string.
//
// Every variable part of a label is attacker-influenced: a unix socket PATH is
// chosen by whoever creates the socket, a hostname comes off the wire, and an
// IPv6 address contains ':' — which is the separator. Unescaped, a socket
// created at the path "127.0.0.1:8080" produces exactly the label an AF_INET
// accept on 127.0.0.1:8080 produces, and an operator's waiver for their own
// test listener silently exempts a channel someone else built. That is the
// same defect as the pathname-based exemptions this change removed, one layer
// further down, in the encoding rather than in the policy.
func TestEndpointLabelsCannotCollide(t *testing.T) {
	t.Parallel()

	// The pair the sweep named: a crafted AF_UNIX path against a real inet
	// endpoint. Before the family was included and the fields escaped, both of
	// these produced "inbound:127.0.0.1:8080".
	unixAccept := commandrun.NetworkConnection{
		Syscall: "accept",
		Family:  "AF_UNIX",
		Address: "127.0.0.1:8080",
	}
	inetAccept := commandrun.NetworkConnection{
		Syscall: "accept",
		Family:  "AF_INET",
		Address: "127.0.0.1",
		Port:    8080,
	}
	uLabel, ok := egressEndpoint(unixAccept)
	if !ok {
		t.Fatal("a unix accept produced no label at all")
	}
	iLabel, ok := egressEndpoint(inetAccept)
	if !ok {
		t.Fatal("an inet accept produced no label at all")
	}
	if uLabel == iLabel {
		t.Fatalf("two different inbound channels render identically as %q — a waiver for one exempts the other", uLabel)
	}

	// The same hazard on the outbound side, which the sweep did not name: a
	// unix socket path that impersonates a labelled endpoint.
	pairs := []struct {
		name string
		a, b commandrun.NetworkConnection
	}{
		{
			"unix path impersonating a loopback endpoint",
			commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/tmp/x:443"},
			commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/tmp/x", Port: 443},
		},
		{
			"IPv6 address running into the port",
			commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET6", Address: "fd00::1", Port: 443},
			commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET6", Address: "fd00::1:443"},
		},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			la, oka := egressEndpoint(p.a)
			lb, okb := egressEndpoint(p.b)
			if !oka || !okb {
				t.Skipf("one side is not classified as egress (%v/%v); nothing to collide", oka, okb)
			}
			if la == lb {
				t.Errorf("distinct endpoints share the label %q", la)
			}
		})
	}
}

// The host/port join is where ambiguity could still enter, so it is pinned
// directly: a host containing ':' MUST be bracketed, or it runs into the port
// and two different endpoints share one waiver.
func TestHostPortJoinIsUnambiguous(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		host string
		port int
		want string
	}{
		{"127.0.0.1", 8080, "127.0.0.1:8080"},
		{"fd00::1", 443, "[fd00::1]:443"},
		{"::1", 8080, "[::1]:8080"},
	} {
		if got := joinHostPort(c.host, c.port); got != c.want {
			t.Errorf("joinHostPort(%q,%d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
	// The property that matters: an address that already looks like host:port
	// cannot impersonate a real host:port pair.
	if joinHostPort("fd00::1", 443) == joinHostPort("fd00::1:443", 0) {
		t.Error("an address containing the port separator collides with a real host/port pair")
	}
}
