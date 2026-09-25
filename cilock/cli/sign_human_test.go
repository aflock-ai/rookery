// jade:ring local

// Copyright 2026 The Aflock Authors
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
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const signHumanPlatform = "https://platform.example.com"

func signHumanEnrollAgent(t *testing.T) string {
	t.Helper()
	isolateAgentConfig(t)
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       signHumanPlatform,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
	}))
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"expires":"2030-01-01T00:00:00Z","steps":{}}`), 0o600))
	return policyPath
}

// A human told "humans sign policies" must be handed the one command that does
// it, not left to assemble five Fulcio flags (what happened on 2026-09-25).
func TestSignHumanRefusalNamesTheHumanCommand(t *testing.T) {
	policyPath := signHumanEnrollAgent(t)
	cmd := SignCmd()
	cmd.SetArgs([]string{"--platform-url", signHumanPlatform, "-f", policyPath, "-o", policyPath + ".signed"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "humans sign policies, agents sign attestations")
	assert.Contains(t, err.Error(), "cilock sign --human")
}

// A bare --signer-fulcio-url selects the fulcio signer but no token source, so
// the keyless exchange would fill the token from the stored credential, which is
// the enrolled agent. It must not count as an explicit human choice.
func TestSignHumanBareFulcioURLDoesNotEscapeTheAgentRefusal(t *testing.T) {
	policyPath := signHumanEnrollAgent(t)
	out := policyPath + ".signed"
	cmd := SignCmd()
	cmd.SetArgs([]string{"--platform-url", signHumanPlatform, "--signer-fulcio-url", signHumanPlatform + "/fulcio",
		"-f", policyPath, "-o", out})
	err := cmd.Execute()
	require.Error(t, err, "a fulcio URL alone would sign with the agent's exchanged token")
	assert.Contains(t, err.Error(), "humans sign policies, agents sign attestations")
	assert.NoFileExists(t, out)
}

// --human derives the whole interactive (browser) Fulcio flow from the platform
// URL and never takes a stored credential, so it passes the agent refusal.
func TestSignHumanSelectsThePlatformBrowserFlow(t *testing.T) {
	policyPath := signHumanEnrollAgent(t)
	cmd, so := newSignCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--platform-url", signHumanPlatform, "--human", "-f", policyPath}))

	require.NoError(t, selectHumanBrowserSigner(cmd, so))

	assert.Equal(t, signHumanPlatform+"/fulcio", cmd.Flags().Lookup("signer-fulcio-url").Value.String())
	assert.Equal(t, signHumanPlatform+"/fulcio/oidc", cmd.Flags().Lookup("signer-fulcio-oidc-issuer").Value.String())
	assert.Equal(t, "sigstore", cmd.Flags().Lookup("signer-fulcio-oidc-client-id").Value.String())
	assert.Empty(t, cmd.Flags().Lookup("signer-fulcio-token").Value.String(), "the human flow never takes a stored token")
	assert.Equal(t, []string{signHumanPlatform + "/api/v1/timestamp"}, so.TimestampServers,
		"the certificate is short-lived; the signature needs the platform TSA to verify later")
	assert.NoError(t, refuseAgentPolicySigning(cmd, *so, []byte(`{"expires":"2030-01-01T00:00:00Z","steps":{}}`)))
}

func TestSignHumanRefusesAConflictingSigner(t *testing.T) {
	for name, args := range map[string][]string{
		"file key":     {"--human", "-k", "/tmp/k.pem"},
		"offline":      {"--human", "--offline"},
		"fulcio token": {"--human", "--signer-fulcio-token", "tok"},
		"no platform":  {"--human", "--platform-url", ""},
	} {
		t.Run(name, func(t *testing.T) {
			policyPath := signHumanEnrollAgent(t)
			cmd, so := newSignCmd()
			full := append([]string{"--platform-url", signHumanPlatform, "-f", policyPath}, args...)
			require.NoError(t, cmd.ParseFlags(full))
			err := selectHumanBrowserSigner(cmd, so)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "--human")
		})
	}
}
