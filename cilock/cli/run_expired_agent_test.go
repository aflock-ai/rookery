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
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingPlatform is agentExchangePlatform plus a request counter, so a test
// can prove a refusal was reached WITHOUT a round trip. A local fact must be
// read locally: the expiry is recorded on the credential this machine holds.
func countingPlatform(t *testing.T, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRunRefusesAnExpiredAgentCredentialBeforeTheCommand is the defect
// (observed three times on 2026-09-02): a stored agent credential past its own
// recorded ceiling was only discovered when the collection was signed — AFTER
// the wrapped test run — so a full gate cycle was spent to produce a refusal
// that was knowable before the first attestor ran.
//
// The refusal itself is correct; its TIMING was the bug. So this pins three
// things at once: the run exits non-zero, the wrapped command never executed
// (the sentinel it would have created is absent), and the message names BOTH
// remedies — a new ceremony, or dropping the agent identity — because falling
// back to the human session silently is exactly what the agent principal
// exists to prevent.
func TestRunRefusesAnExpiredAgentCredentialBeforeTheCommand(t *testing.T) {
	isolateAgentConfig(t)
	var hits atomic.Int64
	platform := countingPlatform(t, &hits)
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platform.URL,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
		TrustDomain:       "platform.example.com",
		ExpiresAt:         time.Now().Add(-2 * time.Hour),
	}))

	marker := filepath.Join(t.TempDir(), "wrapped-command-ran")
	cmd := RunCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--platform-url", platform.URL, "--step", "push-tests", "-a", "environment",
		"--", "touch", marker,
	})
	err := cmd.Execute()

	require.Error(t, err, "an expired agent credential must end the run")
	_, statErr := os.Stat(marker)
	require.True(t, os.IsNotExist(statErr),
		"the wrapped command must NOT have run: the whole point is not to spend the build on a refusal")

	assert.Contains(t, err.Error(), "expired")
	assert.Contains(t, err.Error(), "a-1", "the refusal names the principal that is dead")
	assert.Contains(t, err.Error(), "cilock enroll agent",
		"remedy one: mint a new agent principal")
	assert.Contains(t, err.Error(), "cilock agent logout",
		"remedy two: drop the agent identity and sign as your own session — cilock will not do that silently")
	assert.NotContains(t, err.Error(), agentTestSecret, "the refresh credential is never printed")
	assert.Zero(t, hits.Load(), "the expiry is recorded locally; refusing must cost no round trip")
}

// An agent credential that is still within its ceiling is untouched by the new
// gate: the run resolves the agent principal and the wrapped command executes.
// A gate that refuses a live identity would be a worse defect than the one it
// fixes.
func TestRunStillRunsWithAnUnexpiredAgentCredential(t *testing.T) {
	isolateAgentConfig(t)
	platform := agentExchangePlatform(t)
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platform.URL,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
		ExpiresAt:         time.Now().Add(4 * time.Hour),
	}))

	marker := filepath.Join(t.TempDir(), "wrapped-command-ran")
	cmd := RunCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--platform-url", platform.URL, "--step", "push-tests", "-a", "environment",
		"--enable-archivista=false", "--", "touch", marker,
	})
	_ = cmd.Execute() // the fixture platform has no Fulcio; the signature failing later is not this test's subject.

	_, statErr := os.Stat(marker)
	require.NoError(t, statErr, "a live agent credential must let the wrapped command run")
}

// No agent credential at all: the human session path is unchanged. The gate
// added for the agent credential must not become a gate on `cilock login`.
//
// This one is pinned at option resolution rather than end-to-end because the
// fixture platform serves no Fulcio, so a human-session run cannot reach its
// wrapped command for reasons that have nothing to do with this change. What
// must hold is that the enrolled-agent path reports NOTHING for a machine with
// no enrollment.
func TestRunWithNoAgentCredentialLeavesTheHumanPathAlone(t *testing.T) {
	isolateAgentConfig(t)
	platform := agentExchangePlatform(t)
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: platform.URL,
		Token:       "stored-human-session",
		Email:       "cole@example.com",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	cmd := &cobra.Command{Use: "run"}
	ro := &options.RunOptions{}
	ro.AddFlags(cmd)
	require.NoError(t, cmd.ParseFlags([]string{"--platform-url", platform.URL}))

	ro.ResolvePlatformDefaults(cmd)
	require.NoError(t, ro.AgentIdentityError(),
		"a machine with no enrolled agent must not be refused by the agent gate")
	require.Empty(t, ro.ResolvedAgentPrincipal(), "no agent signed, so none is claimed")
}

// THE TWO PATHS CANNOT DISAGREE. `cilock agent status` is what an operator
// reads to decide whether their machine can sign; `cilock run` is what
// enforces it. If status says the identity is fine and the run refuses (or the
// reverse), the operator has no way to tell which is lying — so both read the
// SAME predicate, and this test drives both over the same stored credential.
//
// It also pins the exit code: a script gating on `cilock agent status` needs a
// non-zero exit for a dead identity, not prose on stdout with exit 0.
func TestAgentStatusAndRunAgreeOnExpiry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires time.Time
		expired bool
	}{
		{name: "past its ceiling", expires: time.Now().Add(-time.Minute), expired: true},
		{name: "within its ceiling", expires: time.Now().Add(time.Hour)},
		{name: "no recorded ceiling", expires: time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAgentConfig(t)
			var hits atomic.Int64
			platform := countingPlatform(t, &hits)
			require.NoError(t, auth.SaveAgent(auth.AgentCredential{
				PlatformURL:       platform.URL,
				TenantID:          "t-1",
				AgentID:           "a-1",
				RefreshCredential: agentTestSecret,
				TrustDomain:       "platform.example.com",
				ExpiresAt:         tc.expires,
			}))

			status := AgentStatusCmd()
			var statusOut bytes.Buffer
			status.SetOut(&statusOut)
			status.SetErr(&statusOut)
			status.SetArgs([]string{"--platform-url", platform.URL})
			statusErr := status.Execute()

			// The run's verdict is read as the TYPED refusal, not as "the
			// command did not run": the fixture platform refuses every exchange,
			// so a live credential fails too — just later, and for a different
			// reason. Only identity distinguishes the two.
			runCmd := &cobra.Command{Use: "run"}
			ro := &options.RunOptions{}
			ro.AddFlags(runCmd)
			require.NoError(t, runCmd.ParseFlags([]string{"--platform-url", platform.URL}))
			ro.ResolvePlatformDefaults(runCmd)
			var expiredRefusal *auth.ExpiredAgentCredentialError
			runSaysExpired := errors.As(ro.AgentIdentityError(), &expiredRefusal)

			assert.Equal(t, tc.expired, statusErr != nil,
				"`agent status` must exit non-zero exactly when the identity is dead (output: %s)", statusOut.String())
			assert.Equal(t, tc.expired, runSaysExpired,
				"`cilock run` must refuse for expiry exactly when `agent status` calls the identity dead (got %v)", ro.AgentIdentityError())
			if tc.expired {
				assert.Contains(t, statusOut.String(), "EXPIRED")
				assert.Contains(t, statusOut.String(), "cilock enroll agent")
				assert.Contains(t, statusOut.String(), "cilock agent logout")
				assert.Zero(t, hits.Load(), "neither path may ask the platform about a fact it already holds")
			}
			assert.NotContains(t, statusOut.String(), agentTestSecret)
		})
	}
}
