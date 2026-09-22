// jade:ring local
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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// H18: `cilock attest` and `cilock attest vex` are sugar over runRun, but
// they went straight to it and skipped preRunGates, the fail-closed start
// gates `cilock run` applies (PreflightIdentity, EnforceEvidenceStorage,
// EnforcePlatformBinding). A platform-authenticated attest could therefore
// sign evidence the platform cannot link to a product, or sign as a stored
// principal and store nothing, and exit as if the evidence existed: the
// incident-2026-09-02 class, on a second verb. These tests drive the real
// commands so the assertion is on what the verb does, not on a helper.

// bindingRefusingPlatform answers resolve-binding with a 401 (a deterministic
// auth failure the binding gate must fail closed on) and counts every request
// that would carry evidence off the machine.
func bindingRefusingPlatform(t *testing.T) (srv *httptest.Server, bindingCalls, otherCalls *atomic.Int32) {
	t.Helper()
	bindingCalls, otherCalls = &atomic.Int32{}, &atomic.Int32{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/resolve-binding" {
			bindingCalls.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		otherCalls.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, bindingCalls, otherCalls
}

// attestBindingCases are the two command-less verbs, each with the argv that
// reaches signing on an unmodified tree.
func attestBindingCases(platformURL, key, out, vexOut string) map[string]struct {
	cmd  func() *cobra.Command
	args []string
} {
	common := []string{"--platform-url", platformURL, "--step", "attest-gate", "-k", key, "-o", out}
	return map[string]struct {
		cmd  func() *cobra.Command
		args []string
	}{
		"attest": {cmd: AttestCmd, args: append([]string{"-a", "environment"}, common...)},
		"attest vex": {cmd: AttestVexCmd, args: append([]string{
			"--product", "pkg:golang/example.com/mod@v1.2.3", "--vuln", "CVE-2024-12345",
			"--status", "fixed", "--vex-out", vexOut,
		}, common...)},
	}
}

// TestAttestRunsProductBindingGateBeforeSigning: a logged-in session whose
// product binding is refused must stop attest before anything is signed,
// written or uploaded, exactly as it stops `cilock run` before the command.
func TestAttestRunsProductBindingGateBeforeSigning(t *testing.T) {
	isolateAgentConfig(t)
	_, _, key := inventoryRunFixture(t)
	srv, bindingCalls, otherCalls := bindingRefusingPlatform(t)
	require.NoError(t, auth.Save(auth.Credential{PlatformURL: srv.URL, Token: "test-only", AuthMode: auth.AuthModeBrowser, ExpiresAt: time.Now().Add(time.Hour)}))

	for name, tc := range attestBindingCases(srv.URL, key, filepath.Join(t.TempDir(), "attest.json"), filepath.Join(t.TempDir(), "doc.openvex.json")) {
		t.Run(name, func(t *testing.T) {
			bindingCalls.Store(0)
			otherCalls.Store(0)
			out := tc.args[len(tc.args)-1]
			cmd := tc.cmd()
			cmd.SetArgs(tc.args)
			_, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })

			require.Error(t, err, "a refused product binding must fail attest")
			require.Positive(t, bindingCalls.Load(), "attest must run the product-binding gate (err: %v)", err)
			require.Zero(t, otherCalls.Load(), "nothing may be uploaded or timestamped after the binding gate refused (err: %v)", err)
			require.NoFileExists(t, out, "no evidence may be written after the binding gate refused")
		})
	}
}

// TestAttestVexRefusesBeforeWritingTheDocument: the gate runs after the
// document is validated but before --vex-out is written, so a refused run
// leaves no unsigned document behind for something else to pick up.
func TestAttestVexRefusesBeforeWritingTheDocument(t *testing.T) {
	isolateAgentConfig(t)
	_, _, key := inventoryRunFixture(t)
	srv, _, _ := bindingRefusingPlatform(t)
	require.NoError(t, auth.Save(auth.Credential{PlatformURL: srv.URL, Token: "test-only", AuthMode: auth.AuthModeBrowser, ExpiresAt: time.Now().Add(time.Hour)}))
	vexOut := filepath.Join(t.TempDir(), "doc.openvex.json")
	tc := attestBindingCases(srv.URL, key, filepath.Join(t.TempDir(), "attest.json"), vexOut)["attest vex"]
	cmd := tc.cmd()
	cmd.SetArgs(tc.args)
	_, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })
	require.Error(t, err)
	require.NoFileExists(t, vexOut)
}

// TestAttestRunsEvidenceGate drives the one evidence-gate cell a current
// credential path reaches (the refusing cell is unreachable since #8732; see
// TestRunEvidenceGateRunsBeforeTheCommand): an enrolled agent with an explicit
// --enable-archivista=false. Only the gate emits the "NO evidence stored"
// warning, so its presence proves attest ran the gate.
func TestAttestRunsEvidenceGate(t *testing.T) {
	for name, build := range map[string]func() *cobra.Command{"attest": AttestCmd, "attest vex": AttestVexCmd} {
		t.Run(name, func(t *testing.T) {
			isolateAgentConfig(t)
			platform := agentExchangePlatform(t)
			require.NoError(t, auth.SaveAgent(auth.AgentCredential{
				PlatformURL:       platform.URL,
				TenantID:          "t-1",
				AgentID:           "a-1",
				RefreshCredential: agentTestSecret,
			}))
			logs := &captureLogger{}
			log.SetLogger(logs)
			t.Cleanup(func() { log.SetLogger(log.SilentLogger{}) })

			args := []string{"--platform-url", platform.URL, "--step", "attest-gate", "-a", "environment",
				"--enable-archivista=false", "-o", filepath.Join(t.TempDir(), "attest.json")}
			if name == "attest vex" {
				args = append(args, "--product", "pkg:golang/example.com/mod@v1.2.3", "--vuln", "CVE-2024-12345",
					"--status", "fixed", "--vex-out", filepath.Join(t.TempDir(), "doc.openvex.json"))
			}
			cmd := build()
			cmd.SetArgs(args)
			_ = cmd.Execute() // the fixture has no Fulcio; only the gate's warning is asserted

			warned := strings.Join(logs.warns, "\n")
			require.Contains(t, warned, "NO evidence stored", "attest must run the evidence gate; warnings:\n%s", warned)
			require.Contains(t, warned, agentTestSPIFFEID)
			require.NotContains(t, warned, agentTestSecret)
		})
	}
}

// TestAttestPreflightsIdentity: with a platform, no stored session, no local
// key and no CI identity, attest must say 'cilock login' up front, as run
// does, instead of failing somewhere inside signer construction.
func TestAttestPreflightsIdentity(t *testing.T) {
	isolateAgentConfig(t)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	srv, _, _ := bindingRefusingPlatform(t)
	out := filepath.Join(t.TempDir(), "attest.json")
	cmd := AttestCmd()
	cmd.SetArgs([]string{"--platform-url", srv.URL, "--step", "attest-gate", "-a", "environment", "-o", out})
	_, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })
	require.ErrorContains(t, err, "not signed in to")
	require.ErrorContains(t, err, "cilock login")
	_, statErr := os.Stat(out)
	require.True(t, os.IsNotExist(statErr))
}
