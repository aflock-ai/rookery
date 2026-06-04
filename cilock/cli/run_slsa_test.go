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
	"reflect"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// connectsTo builds a single-process trace whose network connections are the
// given list, so the egress classifier can be exercised over realistic shapes.
func connectsTo(conns ...commandrun.NetworkConnection) []commandrun.ProcessInfo {
	return []commandrun.ProcessInfo{{Network: &commandrun.NetworkActivity{Connections: conns}}}
}

// TestExternalEgress is the security-critical classifier behind the SLSA L2→L3
// hermeticity gate: only a genuine EXTERNAL connect() may count as egress. A
// false negative here would let a non-hermetic build claim L3.
func TestExternalEgress(t *testing.T) {
	cases := []struct {
		name  string
		procs []commandrun.ProcessInfo
		want  []string
	}{
		{
			name:  "public IPv4 connect is egress",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443}),
			want:  []string{"140.82.112.3:443"},
		},
		{
			name:  "TLS SNI hostname is preferred over the raw address",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443, Hostname: "github.com"}),
			want:  []string{"github.com:443"},
		},
		{
			name:  "loopback IPv4 connect breaks hermeticity (localhost proxy/service can fetch inputs)",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "127.0.0.1", Port: 8080}),
			want:  []string{"loopback:127.0.0.1:8080"},
		},
		{
			name:  "loopback IPv6 connect breaks hermeticity",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET6", Address: "::1", Port: 8080}),
			want:  []string{"loopback:::1:8080"},
		},
		{
			name:  "public IPv6 connect is egress",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET6", Address: "2606:4700:4700::1111", Port: 443}),
			want:  []string{"2606:4700:4700::1111:443"},
		},
		{
			name:  "AF_UNIX docker.sock connect breaks hermeticity (can pull images/inputs)",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/var/run/docker.sock"}),
			want:  []string{"unix:/var/run/docker.sock"},
		},
		{
			name:  "ordinary AF_UNIX IPC (dbus) is NOT counted — keeps L3 reachable",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/run/dbus/system_bus_socket"}),
			want:  nil,
		},
		{
			name:  "bind/listen is serving, not egress",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "bind", Family: "AF_INET", Address: "0.0.0.0", Port: 8080}),
			want:  nil,
		},
		{
			name:  "private-range egress still breaks hermeticity (undeclared network input)",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "10.0.0.5", Port: 443}),
			want:  []string{"10.0.0.5:443"},
		},
		{
			name: "duplicate connects collapse to one endpoint, sorted",
			procs: connectsTo(
				commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443, Hostname: "proxy.golang.org"},
				commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443, Hostname: "proxy.golang.org"},
				commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "1.1.1.1", Port: 53},
			),
			want: []string{"1.1.1.1:53", "proxy.golang.org:443"},
		},
		{
			name:  "address-less, hostname-less connect is skipped (no nameable endpoint)",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "", Port: 443}),
			want:  nil,
		},
		{
			name:  "nil network is harmless",
			procs: []commandrun.ProcessInfo{{Network: nil}},
			want:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := externalEgress(tc.procs)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("externalEgress() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestStampHermeticity_UntracedMakesNoClaim proves that without an active trace
// cilock makes NO hermeticity claim (Tracing == "") — so ComputeSLSA holds the
// run at L2 rather than assuming a hermetic build it never observed.
func TestStampHermeticity_UntracedMakesNoClaim(t *testing.T) {
	cr := commandrun.New() // tracing OFF
	cr.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443})
	s := &options.RunSummary{}
	stampHermeticity(s, []attestation.Attestor{cr})
	if s.Tracing != "" {
		t.Errorf("untraced run must leave Tracing empty (unknown), got %q", s.Tracing)
	}
	if s.Hermetic {
		t.Errorf("untraced run must not claim Hermetic=true")
	}
}

// TestStampHermeticity_RequestedButNoCaptureMakesNoClaim proves that when
// tracing was REQUESTED but the attestor captured nothing — an unsupported
// platform or a failed trace backend, so Summary is nil or carries no capture
// mode — cilock makes NO hermeticity claim. Without this, a build whose trace
// silently captured zero connections would falsely read as hermetic (caught by
// an end-to-end run on a platform without tracing support).
func TestStampHermeticity_RequestedButNoCaptureMakesNoClaim(t *testing.T) {
	// Tracing on, but no Summary at all (trace never produced a result).
	crNil := commandrun.New(commandrun.WithTracing(true))
	sNil := &options.RunSummary{}
	stampHermeticity(sNil, []attestation.Attestor{crNil})
	if sNil.Tracing != "" || sNil.Hermetic {
		t.Errorf("nil-summary trace must make no claim, got Tracing=%q Hermetic=%v", sNil.Tracing, sNil.Hermetic)
	}

	// Tracing on, Summary present but no capture mode recorded.
	crEmpty := commandrun.New(commandrun.WithTracing(true))
	crEmpty.Summary = &commandrun.TraceSummary{CaptureMode: ""}
	crEmpty.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443})
	sEmpty := &options.RunSummary{}
	stampHermeticity(sEmpty, []attestation.Attestor{crEmpty})
	if sEmpty.Tracing != "" || sEmpty.Hermetic {
		t.Errorf("empty-capture-mode trace must make no claim, got Tracing=%q Hermetic=%v", sEmpty.Tracing, sEmpty.Hermetic)
	}
}

// TestStampHermeticity_TracedHermetic proves a traced build with no external
// egress is recorded hermetic, with the capture-mode label surfaced.
func TestStampHermeticity_TracedHermetic(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "ebpf-readtap"}
	cr.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/var/run/nscd.sock"})
	s := &options.RunSummary{}
	stampHermeticity(s, []attestation.Attestor{cr})
	if s.Tracing != "ebpf" {
		t.Errorf("Tracing label = %q, want ebpf", s.Tracing)
	}
	if !s.Hermetic {
		t.Errorf("local-only traced build should be hermetic; egress=%v", s.NetworkEgress)
	}
}

// TestStampHermeticity_TracedEgressBreaksHermetic proves a traced build that
// reached the network is recorded NOT hermetic, with the egress endpoint kept as
// evidence for the verdict.
func TestStampHermeticity_TracedEgressBreaksHermetic(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "ptrace"}
	cr.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443, Hostname: "github.com"})
	s := &options.RunSummary{}
	stampHermeticity(s, []attestation.Attestor{cr})
	if s.Tracing != "ptrace" {
		t.Errorf("Tracing label = %q, want ptrace", s.Tracing)
	}
	if s.Hermetic {
		t.Errorf("build with external egress must not be hermetic")
	}
	if len(s.NetworkEgress) != 1 || s.NetworkEgress[0] != "github.com:443" {
		t.Errorf("NetworkEgress = %#v, want [github.com:443]", s.NetworkEgress)
	}
}
