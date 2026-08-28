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

//go:build darwin

// Tests for the network half of the macOS sandbox-report tracer.
//
// Everything here runs against the real sandbox, the real unified log and the
// real kernel. The one thing NOT used is the public internet: the egress cases
// connect to a listener this test process opens on 127.0.0.1, because the
// kernel reports a loopback connection as `remote:*:<port>` — byte-identical to
// an external one — so a local socket exercises the exact code path a download
// would, without making the suite depend on a network it cannot control.

package commandrun

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// localHTTPServer opens a listener on 127.0.0.1 and answers one-line HTTP so a
// traced curl exits 0. Returns the port.
func localHTTPServer(t *testing.T) int {
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
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// traceLocalFetch traces a curl to the given loopback port and returns the run.
func traceLocalFetch(t *testing.T, port int) *CommandRun {
	t.Helper()
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/"
	rc, err := traceScript(t, []string{"/usr/bin/curl", "-s", "-o", "/dev/null", "--max-time", "10", url})
	if err != nil {
		t.Fatalf("Attest of a loopback fetch: %v", err)
	}
	return rc
}

// connections flattens every recorded connection across the traced tree.
func connections(rc *CommandRun) []NetworkConnection {
	var out []NetworkConnection
	for i := range rc.Processes {
		if rc.Processes[i].Network == nil {
			continue
		}
		out = append(out, rc.Processes[i].Network.Connections...)
	}
	return out
}

// inetConnects is the subset that cilock's hermeticity filter counts: an
// outbound connection on an IP socket.
func inetConnects(conns []NetworkConnection) []NetworkConnection {
	var out []NetworkConnection
	for _, c := range conns {
		if c.Syscall == "connect" && c.Family == FamilyInetUnspecified {
			out = append(out, c)
		}
	}
	return out
}

// TestDarwinTraceObservesOutboundConnection is the core claim of this change:
// a traced command that reaches the network leaves evidence that it did.
//
// Before it, the darwin backend reported no network at all, so cilock's
// `Hermetic = len(NetworkEgress) == 0` would have called this build hermetic —
// absence of observation projected as an authoritative value, under exactly the
// claim SLSA L3 asks for.
func TestDarwinTraceObservesOutboundConnection(t *testing.T) {
	port := localHTTPServer(t)
	rc := traceLocalFetch(t, port)

	conns := connections(rc)
	if len(conns) == 0 {
		t.Fatal("a command that opened a TCP connection recorded NO network activity — " +
			"this is the shape that would come back hermetic")
	}
	inet := inetConnects(conns)
	if len(inet) == 0 {
		t.Fatalf("no IP connection recorded; got %+v", conns)
	}

	var matched *NetworkConnection
	for i := range inet {
		if inet[i].Port == port {
			matched = &inet[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("no connection to the listener's port %d; recorded %+v", port, inet)
	}

	// THE REPRESENTATION. The port is real and the host is not, and the record
	// must say both without ever reading as a resolved host.
	if matched.Address != HostNotObservable {
		t.Errorf("address = %q, want the not-observable marker %q", matched.Address, HostNotObservable)
	}
	if ip := net.ParseIP(matched.Address); ip != nil {
		t.Errorf("address %q parses as the IP %v — it would be mistaken for an observed host",
			matched.Address, ip)
	}
	if !strings.ContainsAny(matched.Address, "()") {
		t.Errorf("address %q contains only characters legal in a hostname, so a reader "+
			"(or a policy allowlist) can mistake it for one", matched.Address)
	}
	if matched.Hostname != "" {
		t.Errorf("hostname = %q, want empty: this backend never reads a TLS ClientHello, "+
			"and a marker there would manufacture a resolved-host claim", matched.Hostname)
	}
	if matched.FD != FDNotObservable {
		t.Errorf("fd = %d, want %d — 0 is a real descriptor and must not stand in for 'unknown'",
			matched.FD, FDNotObservable)
	}
	if matched.Timestamp == "" {
		t.Error("connection carries no timestamp")
	}

	d := rc.Summary.Diagnostics.Darwin
	if d == nil {
		t.Fatal("no darwin diagnostics")
	}
	if !d.NetworkObserved {
		t.Error("networkObserved is false on a run whose profile carries the report rule")
	}
	if d.NetworkHostsObservable {
		t.Error("networkHostsObservable is TRUE — this backend cannot name hosts and must not claim to")
	}
	if d.NetworkReports == 0 {
		t.Error("networkReports is 0 while connections were recorded")
	}
	t.Logf("connections: %+v", conns)
	t.Logf("diagnostics: %+v", d)
}

// TestDarwinTraceHermeticCommandRecordsNoEgress is the opposite pole. A command
// that touches nothing must produce an empty connection set — otherwise the
// egress signal is noise and every build reads as non-hermetic, which teaches a
// verifier nothing.
func TestDarwinTraceHermeticCommandRecordsNoEgress(t *testing.T) {
	rc, err := traceScript(t, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if conns := connections(rc); len(conns) != 0 {
		t.Errorf("/usr/bin/true recorded %d network connections: %+v", len(conns), conns)
	}
	d := rc.Summary.Diagnostics.Darwin
	if d == nil {
		t.Fatal("no darwin diagnostics")
	}
	// The distinction that makes the empty list mean something: the backend
	// WAS watching. An empty list from an observer that never looked is not
	// evidence of hermeticity, and cilock keys on this flag to tell them apart.
	if !d.NetworkObserved {
		t.Error("an empty egress list is only evidence if the backend watched; networkObserved is false")
	}
	if d.NetworkReports != 0 {
		t.Errorf("networkReports = %d for a command that made no network calls", d.NetworkReports)
	}
}

// TestDarwinResolverNoiseIsNotEgress covers the case that decides whether this
// feature is usable at all.
//
// The DNS resolver socket (/var/run/mDNSResponder) appears on essentially every
// real build. It must be RECORDED — it is a real observed connection — and must
// not by itself count as fetching an undeclared input, or hermeticity becomes
// unreachable on macOS and the gate stops meaning anything.
//
// Nothing here special-cases mDNSResponder. The connection is recorded verbatim
// as an AF_UNIX path and cilock's existing rule — only container-runtime
// control sockets are an input-fetch vector — does the judging. The proof that
// the rule is still narrow is the sibling assertion: the same channel reports a
// docker.sock connect with its path in full, so a real UNIX fetch vector is
// caught by that rule rather than waved through by a blanket exemption.
func TestDarwinResolverNoiseIsNotEgress(t *testing.T) {
	// Resolves a name that cannot resolve, then exits 0 — so the resolver is
	// exercised and no data connection is ever made. Works with no internet.
	rc, err := traceScript(t, []string{"/bin/sh", "-c",
		"/usr/bin/curl -s -o /dev/null --max-time 5 http://cilock-does-not-resolve.invalid/ ; exit 0"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	conns := connections(rc)
	if len(conns) == 0 {
		t.Skip("this machine's resolver produced no sandbox report for an unresolvable name; " +
			"nothing to assert about resolver noise here")
	}

	sawResolver := false
	for _, c := range conns {
		if c.Family == "AF_UNIX" && strings.Contains(c.Address, "mDNSResponder") {
			sawResolver = true
		}
	}
	if !sawResolver {
		t.Logf("no mDNSResponder socket in %+v (resolver path may be cached)", conns)
	}
	// The load-bearing assertion: name resolution alone produced no IP endpoint,
	// so cilock has nothing to count and the build stays hermetic.
	if inet := inetConnects(conns); len(inet) != 0 {
		t.Errorf("resolving a name produced IP endpoints %+v — every build that resolves a "+
			"hostname would be non-hermetic", inet)
	}
	t.Logf("resolver-only connections: %+v", conns)
}

// TestDarwinUnixFetchVectorKeepsItsPath is the other half of the resolver rule:
// the exemption that lets mDNSResponder through must be cilock's narrow
// container-runtime rule, not "AF_UNIX is fine". This proves the backend hands
// that rule what it needs — the socket's full path — for a socket that IS a
// fetch vector.
func TestDarwinUnixFetchVectorKeepsItsPath(t *testing.T) {
	// NOT t.TempDir(): sockaddr_un caps a path at 104 bytes and the per-test
	// temp path blows past it, which turned this into a permanent skip — a
	// load-bearing test that quietly stopped running.
	dir, err := os.MkdirTemp("/tmp", "cilock-sock")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("cannot bind a unix socket at %s: %v", sock, err)
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

	// nc speaks unix sockets and ships with macOS; -U selects the unix domain.
	rc, err := traceScript(t, []string{"/bin/sh", "-c", "/usr/bin/nc -U " + sock + " </dev/null ; exit 0"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	var got []string
	for _, c := range connections(rc) {
		if c.Family == "AF_UNIX" {
			got = append(got, c.Address)
		}
	}
	found := false
	for _, a := range got {
		// The path is reported through /private/var symlink resolution, so
		// match the basename cilock's isContainerRuntimeSocket() matches on.
		if strings.HasSuffix(a, "/docker.sock") {
			found = true
		}
	}
	if !found {
		t.Errorf("a connect to %s left no unix path for the container-runtime rule to match; got %v",
			sock, got)
	}
	t.Logf("unix connections: %v", got)
}

// TestDarwinNetworkRuleGreenThenRed runs the SAME egress assertion twice in one
// run — once with the profile's network report rule, once without — and
// requires it to hold and then FAIL. A test that only ever runs against the
// fixed code cannot tell a working observer from a lucky one, and asserting
// both directions back to back rules out a machine where the assertion would
// have failed either way.
//
// (sandbox_network_darwin_test.go asserts the stripped direction on its own;
// this one is the paired red/green, so a green baseline is proven in the same
// process, on the same machine, seconds apart.)
func TestDarwinNetworkRuleGreenThenRed(t *testing.T) {
	port := localHTTPServer(t)

	withRule := traceLocalFetch(t, port)
	if got := len(inetConnects(connections(withRule))); got == 0 {
		t.Fatalf("baseline: the profile carries %s and still recorded no IP connection", networkReportRule)
	}
	if d := withRule.Summary.Diagnostics.Darwin; d == nil || !d.NetworkObserved {
		t.Fatalf("baseline: networkObserved is not true with the rule present (%+v)", d)
	}

	restore := sandboxProfile
	sandboxProfile = strings.ReplaceAll(sandboxProfile, networkReportRule, "")
	t.Cleanup(func() { sandboxProfile = restore })
	if strings.Contains(sandboxProfile, networkReportRule) {
		t.Fatalf("failed to remove the rule from the profile: %s", sandboxProfile)
	}

	withoutRule := traceLocalFetch(t, port)
	if got := inetConnects(connections(withoutRule)); len(got) != 0 {
		t.Errorf("with the report rule removed the tracer still produced %+v — the rule is not "+
			"what is doing the observing, so this test proves nothing about it", got)
	}
	d := withoutRule.Summary.Diagnostics.Darwin
	if d == nil {
		t.Fatal("no darwin diagnostics")
	}
	if d.NetworkObserved {
		t.Error("with the rule removed the attestation STILL claims networkObserved — cilock would " +
			"read the empty egress list as proof of hermeticity for a build that fetched over TCP")
	}
	if d.ExecReports == 0 {
		t.Error("removing the network rule also killed exec reporting; the two must be independent")
	}
	t.Logf("without the rule: %+v", d)
}

// TestDarwinNetworkReportsUseKernelAttribution is the reason attribution is not
// optional here. The report stream is machine-wide: every other sandboxed
// process on this Mac narrates its own traffic into it. A tracer that took the
// stream at face value would mark a build non-hermetic because a browser was
// open — and, worse, an agent could point at someone else's connections as
// evidence of work, or drown a real fetch in noise.
//
// This test generates genuinely foreign sandboxed egress — different process
// group, different parent — while tracing a command that touches nothing, and
// requires those reports to be DROPPED and COUNTED.
func TestDarwinNetworkReportsUseKernelAttribution(t *testing.T) {
	// The stranger must be ALIVE when its report is polled, or the test
	// measures the poll race instead of attribution: a connect to a closed
	// port is refused in microseconds and curl is gone before its report
	// arrives, at which point ownership is undecidable and the doctrine
	// (correctly) records unproven egress on the root. A listener that
	// accepts and never answers keeps each curl alive for its --max-time.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c) // hold it open until curl gives up
			}(conn)
		}
	}()
	target := "http://" + ln.Addr().String() + "/"
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Foreign: started by this test process directly, in its own
			// process group, never a descendant of the traced root.
			// #nosec G204 -- fixed binary, fixed profile, fixed argument.
			c := exec.Command(sandboxExecPath, "-p", sandboxProfile, "--",
				"/usr/bin/curl", "-s", "-o", "/dev/null", "--max-time", "2", target)
			_ = c.Run()
		}
	}()
	defer func() { close(stop); wg.Wait() }()

	var injected uint64
	for attempt := 0; attempt < 4; attempt++ {
		rc, err := traceScript(t, []string{"/usr/bin/true"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if conns := connections(rc); len(conns) != 0 {
			t.Fatalf("a stranger's network activity entered this build's tree: %+v", conns)
		}
		d := rc.Summary.Diagnostics.Darwin
		if d == nil {
			t.Fatal("no darwin diagnostics")
		}
		injected = d.NetworkReportsUnattributed
		if injected > 0 {
			t.Logf("dropped %d foreign network reports; in-tree connections: 0", injected)
			return
		}
	}
	t.Fatalf("never managed to put a foreign network report in front of the tracer in 4 attempts, " +
		"so this test did not exercise attribution at all")
}

// TestDarwinSignedBytesCarryNetworkEvidence checks the SIGNED BYTES.
//
// v2_marshal.go emits only the sections in its specs list, and a populated
// struct field whose section is missing is silently dropped from what gets
// signed — that already cost a production outage once with exitcode. Recording
// egress in memory is worth nothing if MarshalJSON drops it, so this asserts on
// the wire form and on the round-trip a verifier performs.
func TestDarwinSignedBytesCarryNetworkEvidence(t *testing.T) {
	port := localHTTPServer(t)
	rc := traceLocalFetch(t, port)

	signed, err := rc.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(signed, &body); err != nil {
		t.Fatalf("signed body is not an object: %v", err)
	}

	// The blind-spot statement must be IN the signed summary section. It is a
	// false bool with no omitempty precisely so its key cannot go missing —
	// an absent "networkHostsObservable" would read as "hosts were observable".
	summary, ok := body["summary"]
	if !ok {
		t.Fatal("signed body has no summary section")
	}
	if !strings.Contains(string(summary), `"networkHostsObservable":false`) {
		t.Errorf("the signed summary does not state that hosts are unobservable; a verifier "+
			"cannot tell the endpoint list is port-only by construction. summary=%s", truncateForLog(string(summary)))
	}
	if !strings.Contains(string(summary), `"networkObserved":true`) {
		t.Errorf("the signed summary does not state that the backend watched the network: %s",
			truncateForLog(string(summary)))
	}

	var v02 V02Predicate
	if err := json.Unmarshal(signed, &v02); err != nil {
		t.Fatalf("decode signed body: %v", err)
	}
	if v02.Summary == nil || v02.Summary.Diagnostics.Darwin == nil {
		t.Fatal("signed body dropped the darwin diagnostics")
	}
	d := v02.Summary.Diagnostics.Darwin
	if !d.NetworkObserved || d.NetworkHostsObservable {
		t.Errorf("signed diagnostics: networkObserved=%v networkHostsObservable=%v, want true/false",
			d.NetworkObserved, d.NetworkHostsObservable)
	}
	if !strings.Contains(d.Note, "HOST IS NOT OBSERVABLE") {
		t.Errorf("the signed note does not state the host blind spot: %q", d.Note)
	}

	// The connection itself must survive interning into the signed processes[].
	found := false
	for _, p := range v02.Processes {
		if p.Network == nil {
			continue
		}
		for _, c := range p.Network.Connections {
			if c.Syscall == "connect" && c.Family == FamilyInetUnspecified && c.Port == port {
				found = true
				if c.Address != HostNotObservable {
					t.Errorf("signed address = %q, want %q", c.Address, HostNotObservable)
				}
			}
		}
	}
	if !found {
		t.Fatalf("the signed body carries NO connection to port %d — the egress evidence was "+
			"collected and then dropped by the marshaller, and every macOS build would sign as hermetic",
			port)
	}

	// What a verifier reads back must be what the producer recorded.
	var decoded CommandRun
	if err := decoded.UnmarshalJSON(signed); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if len(inetConnects(connections(&decoded))) == 0 {
		t.Error("verifier-side decode lost the egress the producer recorded")
	}
}

func truncateForLog(s string) string {
	if len(s) > 600 {
		return s[:600] + "…"
	}
	return s
}

// TestParseDarwinEndpoint pins the parser against the shapes MEASURED on
// macOS 15.7.7/arm64. Every input below was copied from a real report line
// captured while running the probe programs described in each case.
func TestParseDarwinEndpoint(t *testing.T) {
	cases := []struct {
		name   string
		detail string
		want   darwinEndpoint
	}{
		{
			// curl https://example.com — a name that WAS resolved.
			name:   "outbound to a resolved name is still port-only",
			detail: "remote:*:443",
			want: darwinEndpoint{family: FamilyInetUnspecified, address: HostNotObservable,
				port: 443, kind: endpointPortOnly},
		},
		{
			// curl https://93.184.215.14/ — a LITERAL IP, no DNS in the path.
			// Reports identically, which is the measurement that proves the
			// host is not observable rather than merely not looked up.
			name:   "outbound to a literal IP reports the same shape",
			detail: "remote:*:443",
			want: darwinEndpoint{family: FamilyInetUnspecified, address: HostNotObservable,
				port: 443, kind: endpointPortOnly},
		},
		{
			// A loopback connect. Indistinguishable from an external one, so
			// locality is not observable either — conservative, since cilock
			// counts loopback against hermeticity anyway.
			name:   "loopback is indistinguishable from external",
			detail: "remote:*:57793",
			want: darwinEndpoint{family: FamilyInetUnspecified, address: HostNotObservable,
				port: 57793, kind: endpointPortOnly},
		},
		{
			name:   "the serving side is named the same way",
			detail: "local:*:57793",
			want: darwinEndpoint{family: FamilyInetUnspecified, address: HostNotObservable,
				port: 57793, kind: endpointPortOnly},
		},
		{
			name:   "a bind to an ephemeral port",
			detail: "local:*:0",
			want: darwinEndpoint{family: FamilyInetUnspecified, address: HostNotObservable,
				port: 0, kind: endpointPortOnly},
		},
		{
			// The DNS resolver. Named in full — the one shape this backend
			// observes completely.
			name:   "a unix socket is named in full",
			detail: "/private/var/run/mDNSResponder",
			want: darwinEndpoint{family: "AF_UNIX", address: "/private/var/run/mDNSResponder",
				kind: endpointUnixPath},
		},
		{
			name:   "a container runtime socket keeps its path for cilock to match",
			detail: "/private/tmp/docker.sock",
			want: darwinEndpoint{family: "AF_UNIX", address: "/private/tmp/docker.sock",
				kind: endpointUnixPath},
		},
		{
			// Measured: a process that called getaddrinfo() and never
			// connected produced exactly this plus the mDNSResponder socket.
			// The report proves an outbound operation happened and names
			// NOTHING about it — that is the not-observable family, which
			// classifies as egress. Mapping it to any non-remote family would
			// let a build consume attacker-controlled DNS answers (or encode
			// data in the names it queries) and still be signed hermetic.
			name:   "a bare outbound is an observed operation nobody could describe, and counts",
			detail: "",
			want: darwinEndpoint{family: FamilyNotObservable, address: HostNotObservable,
				kind: endpointUnnamed},
		},
		{
			// Not measured — which is the point. An unknown shape is where
			// "we did not understand" must not become "there was no egress",
			// so it is given an unnameable IP endpoint and COUNTS.
			name:   "an unrecognized destination fails closed",
			detail: "something-new-from-a-future-macos",
			want: darwinEndpoint{family: FamilyInetUnspecified, address: HostNotObservable,
				kind: endpointUnrecognized},
		},
		{
			// Forward compatibility: if a future macOS starts naming hosts,
			// use the name instead of the marker rather than discarding it.
			name:   "a named host is used when the kernel provides one",
			detail: "remote:93.184.215.14:443",
			want: darwinEndpoint{family: FamilyInetUnspecified, address: "93.184.215.14",
				port: 443, kind: endpointPortOnly},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDarwinEndpoint(tc.detail)
			if got != tc.want {
				t.Errorf("parseDarwinEndpoint(%q) = %+v, want %+v", tc.detail, got, tc.want)
			}
		})
	}
}

// TestParseSandboxReportAcceptsNetworkOps pins the report-line parsing for the
// network operations, verbatim from lines captured on this machine.
func TestParseSandboxReportAcceptsNetworkOps(t *testing.T) {
	cases := []struct {
		msg  string
		want sandboxEvent
	}{
		{
			msg:  "Sandbox: curl(38711) allow network-outbound remote:*:443",
			want: sandboxEvent{pid: 38711, comm: "curl", op: opNetworkOutbound, detail: "remote:*:443"},
		},
		{
			msg: "Sandbox: curl(38711) allow network-outbound /private/var/run/mDNSResponder",
			want: sandboxEvent{pid: 38711, comm: "curl", op: opNetworkOutbound,
				detail: "/private/var/run/mDNSResponder"},
		},
		{
			msg:  "Sandbox: curl(38711) allow network-outbound",
			want: sandboxEvent{pid: 38711, comm: "curl", op: opNetworkOutbound},
		},
		{
			msg:  "Sandbox: Python(44431) allow network-bind local:*:0",
			want: sandboxEvent{pid: 44431, comm: "Python", op: opNetworkBind, detail: "local:*:0"},
		},
		{
			msg:  "Sandbox: Python(44431) allow network-inbound local:*:57793",
			want: sandboxEvent{pid: 44431, comm: "Python", op: opNetworkInbound, detail: "local:*:57793"},
		},
		{
			// A DENIED outbound parses the same way — dropping it at the
			// parser would lose the observation — but it carries its decision:
			// the sandbox refused the operation, so it reached nothing and
			// must not be recorded as egress. This backend's own profile
			// denies nothing; a deny comes from another process's profile.
			msg: "Sandbox: cilock-catalog-planner(50366) deny(1) network-outbound remote:*:80",
			want: sandboxEvent{pid: 50366, comm: "cilock-catalog-planner", op: opNetworkOutbound,
				detail: "remote:*:80", denied: true},
		},
		{
			msg: "2 duplicate reports for Sandbox: curl(38711) allow network-outbound remote:*:443",
			want: sandboxEvent{pid: 38711, comm: "curl", op: opNetworkOutbound,
				detail: "remote:*:443", duplicates: 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			got, ok := parseSandboxReport(tc.msg)
			if !ok {
				t.Fatalf("parseSandboxReport(%q) refused the line", tc.msg)
			}
			if got != tc.want {
				t.Errorf("event = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestDarwinNetworkSyscallMapping pins which operations reach cilock's egress
// filter. Only "connect" is counted there, so mislabelling a bind would make a
// build that merely SERVES read as one that FETCHED.
func TestDarwinNetworkSyscallMapping(t *testing.T) {
	for op, want := range map[string]string{
		opNetworkOutbound: "connect",
		opNetworkBind:     "bind",
		opNetworkInbound:  "accept",
		opExecStar:        "",
		opFork:            "",
	} {
		if got := darwinNetworkSyscall(op); got != want {
			t.Errorf("darwinNetworkSyscall(%q) = %q, want %q", op, got, want)
		}
	}
}

// TestSandboxProfileReportsNetwork proves the capability flag is READ from the
// applied profile rather than asserted. This is what makes the flag
// self-correcting: an edit that drops the rule cannot leave behind an
// attestation still claiming the network was watched.
func TestSandboxProfileReportsNetwork(t *testing.T) {
	if !sandboxProfileReportsNetwork() {
		t.Fatalf("the shipped profile does not carry %s: %s", networkReportRule, sandboxProfile)
	}
	restore := sandboxProfile
	t.Cleanup(func() { sandboxProfile = restore })
	sandboxProfile = strings.ReplaceAll(sandboxProfile, networkReportRule, "")
	if sandboxProfileReportsNetwork() {
		t.Error("the flag still reports true after the rule was removed from the profile")
	}
}
