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

// The end-to-end hermeticity verdict on macOS.
//
// WHY THIS DRIVES A BINARY INSTEAD OF CALLING A FUNCTION. The verdict this
// change exists to fix — RunSummary.Hermetic and RunSummary.NetworkEgress — is
// computed in cilock (cli/run.go: stampHermeticity → traceBackendObservesNetwork
// → externalEgress → egressEndpoint). cilock imports this package, so this
// package cannot import cilock back, and a Go re-implementation of that
// classification here would be a test double asserting its own conclusion: it
// would keep passing after the real filter stopped counting anything.
//
// So the test runs the REAL `cilock run --json` and reads the REAL verdict off
// its stdout. It is slower than a unit test and it is the only version of this
// test that can fail for the right reason.

package commandrun

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// cilockVerdict is the hermeticity slice of `cilock run --json`.
type cilockVerdict struct {
	Tracing string `json:"tracing"`
	// main renamed this on the wire in #8390's series: the summary now
	// reports the NARROW fact it can actually establish — no external
	// network egress was OBSERVED — rather than the word "hermetic", which
	// claims more than the observation supports.
	Hermetic      bool     `json:"no_external_network_egress_observed"`
	NetworkEgress []string `json:"network_egress"`
}

var (
	cilockBuildOnce sync.Once
	cilockBinPath   string
	cilockBuildErr  error
)

// cilockModuleDir is the sibling module that owns the hermeticity verdict.
const cilockModuleDir = "../../../cilock"

// buildCilock compiles the CLI once per test binary.
//
// A missing module or toolchain SKIPS (this package is also consumed standalone,
// where cilock is simply not present). A module that is present and fails to
// build FAILS — a load-bearing test must not quietly disappear because the thing
// it tests stopped compiling.
func buildCilock(t *testing.T) string {
	t.Helper()
	cilockBuildOnce.Do(func() {
		if _, err := os.Stat(filepath.Join(cilockModuleDir, "go.mod")); err != nil {
			cilockBuildErr = errSkip
			return
		}
		if _, err := exec.LookPath("go"); err != nil {
			cilockBuildErr = errSkip
			return
		}
		out := filepath.Join(os.TempDir(), "cilock-hermeticity-test-"+strconv.Itoa(os.Getpid()))
		// #nosec G204 -- fixed arguments; the only variable is a temp path we chose.
		cmd := exec.Command("go", "build", "-o", out, "./cmd/...")
		cmd.Dir = cilockModuleDir
		if b, err := cmd.CombinedOutput(); err != nil {
			cilockBuildErr = errors.New("building cilock: " + err.Error() + "\n" + string(b))
			return
		}
		cilockBinPath = out
	})
	if errors.Is(cilockBuildErr, errSkip) {
		t.Skip("cilock module or Go toolchain unavailable; the end-to-end hermeticity verdict cannot be exercised")
	}
	if cilockBuildErr != nil {
		t.Fatal(cilockBuildErr)
	}
	return cilockBinPath
}

var errSkip = errors.New("skip")

// runCilockTraced wraps a command in `cilock run --trace` and returns the
// verdict cilock published.
//
// Deliberately minimal flags: --offline with a local key so nothing contacts a
// platform, `--workload manual -a environment` so the git attestor does not fail
// the run in a temp dir, and cmd.Dir set to a scratch directory so the material
// walk does not crawl the repository.
func runCilockTraced(t *testing.T, args ...string) cilockVerdict {
	t.Helper()
	bin := buildCilock(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	writeEd25519Key(t, key)

	full := append([]string{
		"run", "--offline", "-k", key, "--trace", "--json",
		"--workload", "manual", "-a", "environment",
		"-s", "hermeticity-test", "-o", filepath.Join(dir, "att.json"), "--",
	}, args...)
	// #nosec G204 -- the binary is one we just built and the arguments are fixed
	// by the caller inside this test file.
	cmd := exec.Command(bin, full...)
	cmd.Dir = dir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cilock run failed: %v\nstdout:\n%s\nstderr tail:\n%s", err, stdout.String(), tail(stderr.String()))
	}
	var v cilockVerdict
	if err := json.Unmarshal([]byte(stdout.String()), &v); err != nil {
		t.Fatalf("decoding cilock's run summary: %v\nstdout:\n%s", err, stdout.String())
	}
	if v.Tracing == "" {
		t.Fatalf("cilock reports no trace at all, so its hermeticity verdict is vacuous:\n%s", stdout.String())
	}
	return v
}

func writeEd25519Key(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 25 {
		lines = lines[len(lines)-25:]
	}
	return strings.Join(lines, "\n")
}

// TestCilockCallsAMacOSFetchNonHermetic is the whole point of the change,
// asserted where a consumer actually reads it.
//
// Before this, a macOS build reached the network and cilock published no egress
// at all, because the darwin backend never watched. The gate in run.go then
// withheld the hermeticity claim to avoid publishing a lie — correct, but it
// also meant macOS could never reach SLSA L3. Now the backend genuinely
// observes, so the verdict is earned in both directions.
func TestCilockCallsAMacOSFetchNonHermetic(t *testing.T) {
	port := localHTTPServer(t)
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/"

	v := runCilockTraced(t, "/usr/bin/curl", "-s", "-o", "/dev/null", "--max-time", "10", url)

	if v.Hermetic {
		t.Errorf("a build that opened a TCP connection was called HERMETIC; egress=%v", v.NetworkEgress)
	}
	if len(v.NetworkEgress) == 0 {
		t.Fatal("cilock published an EMPTY network_egress for a build that fetched over TCP — " +
			"the evidence never reached the verdict")
	}
	want := HostNotObservable + ":" + strconv.Itoa(port)
	found := false
	for _, e := range v.NetworkEgress {
		if e == want {
			found = true
		}
		// The endpoint an operator reads must not look like a resolved host.
		host := e
		if i := strings.LastIndexByte(e, ':'); i >= 0 {
			host = e[:i]
		}
		if ip := net.ParseIP(host); ip != nil {
			t.Errorf("egress entry %q names %v as though the host had been observed", e, ip)
		}
	}
	if !found {
		t.Errorf("network_egress = %v, want it to contain %q", v.NetworkEgress, want)
	}
	t.Logf("verdict: hermetic=%v egress=%v", v.Hermetic, v.NetworkEgress)
}

// TestCilockCallsAMacOSNoOpHermetic is the opposite pole, and the one that
// makes the feature worth having: a build that touches nothing must reach the
// hermetic verdict. If the resolver socket or any other pervasive noise counted
// as egress, this would fail and no macOS build could ever be hermetic.
func TestCilockCallsAMacOSNoOpHermetic(t *testing.T) {
	v := runCilockTraced(t, "/usr/bin/true")
	if !v.Hermetic {
		t.Errorf("a command that touched nothing was called NON-hermetic; egress=%v", v.NetworkEgress)
	}
	if len(v.NetworkEgress) != 0 {
		t.Errorf("network_egress = %v for /usr/bin/true, want empty", v.NetworkEgress)
	}
}

// TestCilockCountsResolutionAsUnobservedEgress pins the verdict for a build
// that RESOLVES a name and connects to nothing: NON-hermetic, with the reason
// legible in the egress list.
//
// The resolution path surfaces as a bare `network-outbound` report — an
// observed operation the kernel named nothing about. An earlier revision
// excluded that shape from egress on the measurement that a getaddrinfo-only
// process produces it; but the measurement characterizes one benign program,
// not the channel, and name resolution itself moves data both ways (queried
// names leave the machine; answers arrive as undeclared inputs a build can act
// on). So the verdict is withheld in the only direction an attestation may
// err: the build is non-hermetic, the entry says WHY, and a policy that
// accepts resolution can waive that labelled entry with its eyes open.
func TestCilockCountsResolutionAsUnobservedEgress(t *testing.T) {
	v := runCilockTraced(t, "/bin/sh", "-c",
		"/usr/bin/curl -s -o /dev/null --max-time 5 http://cilock-does-not-resolve.invalid/ ; exit 0")
	if v.Hermetic {
		t.Errorf("a build that performed name resolution was called HERMETIC; egress=%v. "+
			"An observed outbound operation with no describable destination must count, or "+
			"a build can consume attacker-controlled DNS answers and still be signed hermetic", v.NetworkEgress)
	}
	found := false
	for _, e := range v.NetworkEgress {
		// The resolution channel surfaces as the resolver daemon's socket
		// (counted with the "resolver:" label), and on OS builds that also
		// emit a bare destination-less outbound report, as an entry labelled
		// family-not-observable. Either way the entry must say what it was
		// rather than imitate a resolved host.
		// The "resolver:" label is gone: it was a WAIVER resting on a
		// pathname this channel cannot authenticate, so the resolver socket
		// is now ordinary unix egress named by its path. The entry still
		// says what the channel was — the path IS mDNSResponder — it just
		// no longer carries a label a policy can accept wholesale.
		if strings.Contains(e, "mDNSResponder") || strings.Contains(e, "family-not-observable") {
			found = true
		}
	}
	if !found {
		t.Errorf("network_egress = %v, want an entry naming the resolver socket or family-not-observable "+
			"so the reader can see WHY hermeticity broke", v.NetworkEgress)
	}
}
