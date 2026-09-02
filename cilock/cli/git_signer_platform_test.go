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
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateStores points both credential stores (human + agent) at a scratch
// HOME so these tests never read the developer's real enrollment state.
// os.UserConfigDir derives from $HOME on darwin and $XDG_CONFIG_HOME/$HOME on
// linux, so setting both covers CI and dev machines.
func isolateStores(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
}

func enrollTestAgent(t *testing.T, platformURL string) {
	t.Helper()
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platformURL,
		TenantID:          "11111111-1111-1111-1111-111111111111",
		AgentID:           "22222222-2222-2222-2222-222222222222",
		RefreshCredential: "test-refresh-credential",
	}))
}

// Regression for judge#8738: the signer used to resolve its platform from the
// env var alone, so with the env unset it consulted the compiled DEFAULT
// platform's agent store, found nothing, and fell through to the human
// session — a valid signature under the wrong principal. Resolution is now
// agent-first: the enrolled platform wins when the env var does not name one.
func TestGitSignerPlatformURL_EnrolledAgentWinsWhenEnvUnset(t *testing.T) {
	isolateStores(t)
	enrollTestAgent(t, "http://127.0.0.1:9")

	got, err := gitSignerPlatformURL("")
	require.NoError(t, err)
	assert.Equal(t, auth.NormalizeURL("http://127.0.0.1:9"), got,
		"with one enrolled agent and no env override, the signature must target the ENROLLED platform, not the compiled default")
}

func TestGitSignerPlatformURL_EnvNamingAnotherPlatformIsRefused(t *testing.T) {
	isolateStores(t)
	enrollTestAgent(t, "http://127.0.0.1:9")

	_, err := gitSignerPlatformURL("https://other.example")
	require.Error(t, err,
		"an enrolled machine told to sign against a platform with no agent must refuse, never fall through to the human session")
	assert.Contains(t, err.Error(), "127.0.0.1:9",
		"the refusal must name where the agent IS enrolled so the operator can fix the mismatch")
}

func TestGitSignerPlatformURL_EnvMatchingTheEnrolledPlatformProceeds(t *testing.T) {
	isolateStores(t)
	enrollTestAgent(t, "http://127.0.0.1:9")

	got, err := gitSignerPlatformURL("http://127.0.0.1:9")
	require.NoError(t, err)
	assert.Equal(t, auth.NormalizeURL("http://127.0.0.1:9"), got)
}

func TestGitSignerPlatformURL_NoAgentsFallsBackToActiveThenDefault(t *testing.T) {
	isolateStores(t)

	// No agent store, no human session: empty resolution, caller derives the
	// compiled default — the pre-fix behavior, preserved for un-enrolled
	// machines.
	got, err := gitSignerPlatformURL("")
	require.NoError(t, err)
	assert.Equal(t, "", got)

	// Env still wins outright on an un-enrolled machine.
	got, err = gitSignerPlatformURL("https://explicit.example")
	require.NoError(t, err)
	assert.Equal(t, "https://explicit.example", got)
}

func TestGitSignerPlatformURL_MultipleAgentsWithoutEnvIsRefused(t *testing.T) {
	isolateStores(t)
	enrollTestAgent(t, "http://127.0.0.1:9")
	enrollTestAgent(t, "http://127.0.0.1:19")

	_, err := gitSignerPlatformURL("")
	require.Error(t, err, "two enrolled platforms and no selector is ambiguous; guessing could sign under the wrong principal")
	assert.Contains(t, err.Error(), platformconfig.PlatformURLEnv,
		"the refusal must tell the operator which knob selects the platform")
}
