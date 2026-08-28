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

// TestExternalEgress pins the classifier behind the network observation. A
// false negative would let the summary say no external egress was observed when
// the trace recorded an external-input channel.
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
			name:  "loopback IPv4 connect counts as egress because a localhost service can fetch inputs",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "127.0.0.1", Port: 8080}),
			want:  []string{"loopback:127.0.0.1:8080"},
		},
		{
			name:  "loopback IPv6 connect counts as egress",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET6", Address: "::1", Port: 8080}),
			want:  []string{"loopback:[::1]:8080"},
		},
		{
			name:  "public IPv6 connect is egress",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET6", Address: "2606:4700:4700::1111", Port: 443}),
			want:  []string{"[2606:4700:4700::1111]:443"},
		},
		{
			name:  "AF_UNIX docker.sock connect counts as egress because it can pull images",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/var/run/docker.sock"}),
			want:  []string{"unix:/var/run/docker.sock"},
		},
		{
			name:  "the system D-Bus broker is a peer with inputs (PackageKit, NetworkManager…), and counts",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/run/dbus/system_bus_socket"}),
			want:  []string{"unix:/run/dbus/system_bus_socket"},
		},
		{
			name:  "even the OS's own logging socket counts — the channel names a path, not a peer",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_UNIX", Address: "/dev/log"}),
			want:  []string{"unix:/dev/log"},
		},
		{
			name:  "bind/listen is serving, not egress",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "bind", Family: "AF_INET", Address: "0.0.0.0", Port: 8080}),
			want:  nil,
		},
		{
			name:  "private-range connection still counts as external egress",
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
			// An IP connect() whose destination the observer could not name is
			// still an OBSERVED IP connect(). It used to be skipped, which made
			// "we could not look" indistinguishable from "there was nothing
			// there" — the same projection of absence the family default now
			// closes. HostNotObservable is the name that cannot be misread as
			// a host, so there is no longer a reason to drop it.
			name:  "address-less, hostname-less IP connect is named, not skipped",
			procs: connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "", Port: 443}),
			want:  []string{commandrun.HostNotObservable + ":443"},
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

// TestStampNetworkObservation_UntracedMakesNoClaim proves that without an
// active trace cilock reports no network observation.
func TestStampNetworkObservation_UntracedMakesNoClaim(t *testing.T) {
	cr := commandrun.New() // tracing OFF
	cr.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443})
	s := &options.RunSummary{}
	stampNetworkObservation(s, []attestation.Attestor{cr})
	if s.Tracing != "" {
		t.Errorf("untraced run must leave Tracing empty (unknown), got %q", s.Tracing)
	}
	if s.NoExternalNetworkEgressObserved {
		t.Errorf("untraced run must not claim no external egress was observed")
	}
}

// TestStampNetworkObservation_RequestedButNoCaptureMakesNoClaim proves that when
// tracing was REQUESTED but the attestor captured nothing — an unsupported
// platform or a failed trace backend, so Summary is nil or carries no capture
// mode — cilock makes no network claim. Without this, a failed trace would read
// as an affirmative observation of zero connections.
func TestStampNetworkObservation_RequestedButNoCaptureMakesNoClaim(t *testing.T) {
	// Tracing on, but no Summary at all (trace never produced a result).
	crNil := commandrun.New(commandrun.WithTracing(true))
	sNil := &options.RunSummary{}
	stampNetworkObservation(sNil, []attestation.Attestor{crNil})
	if sNil.Tracing != "" || sNil.NoExternalNetworkEgressObserved {
		t.Errorf("nil-summary trace must make no claim, got Tracing=%q NoExternalNetworkEgressObserved=%v", sNil.Tracing, sNil.NoExternalNetworkEgressObserved)
	}

	// Tracing on, Summary present but no capture mode recorded.
	crEmpty := commandrun.New(commandrun.WithTracing(true))
	crEmpty.Summary = &commandrun.TraceSummary{CaptureMode: ""}
	crEmpty.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443})
	sEmpty := &options.RunSummary{}
	stampNetworkObservation(sEmpty, []attestation.Attestor{crEmpty})
	if sEmpty.Tracing != "" || sEmpty.NoExternalNetworkEgressObserved {
		t.Errorf("empty-capture-mode trace must make no claim, got Tracing=%q NoExternalNetworkEgressObserved=%v", sEmpty.Tracing, sEmpty.NoExternalNetworkEgressObserved)
	}
}

// TestStampNetworkObservation_TracedNoEgress proves a traced build with no
// external egress records that narrow fact with the capture-mode label.
func TestStampNetworkObservation_TracedNoEgress(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "ebpf-readtap"}
	// Nothing is exempt by PATH any more, and loopback is reported as its own
	// endpoint class, so the build that reads hermetic is the one that made
	// no outbound connection at all — it still binds and serves, which is
	// not fetching.
	cr.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "bind", Family: "AF_INET", Address: "0.0.0.0", Port: 8080})
	s := &options.RunSummary{}
	stampNetworkObservation(s, []attestation.Attestor{cr})
	if s.Tracing != "ebpf" {
		t.Errorf("Tracing label = %q, want ebpf", s.Tracing)
	}
	if !s.NoExternalNetworkEgressObserved {
		t.Errorf("local-only traced build should report no observed external egress; egress=%v", s.NetworkEgress)
	}
}

// TestStampNetworkObservation_TracedEgress proves a traced build that reached
// the network retains the endpoint as evidence.
func TestStampNetworkObservation_TracedEgress(t *testing.T) {
	cr := commandrun.New(commandrun.WithTracing(true))
	cr.Summary = &commandrun.TraceSummary{CaptureMode: "ptrace"}
	cr.Processes = connectsTo(commandrun.NetworkConnection{Syscall: "connect", Family: "AF_INET", Address: "140.82.112.3", Port: 443, Hostname: "github.com"})
	s := &options.RunSummary{}
	stampNetworkObservation(s, []attestation.Attestor{cr})
	if s.Tracing != "ptrace" {
		t.Errorf("Tracing label = %q, want ptrace", s.Tracing)
	}
	if s.NoExternalNetworkEgressObserved {
		t.Errorf("build with external egress must not claim no observed egress")
	}
	if len(s.NetworkEgress) != 1 || s.NetworkEgress[0] != "github.com:443" {
		t.Errorf("NetworkEgress = %#v, want [github.com:443]", s.NetworkEgress)
	}
}
