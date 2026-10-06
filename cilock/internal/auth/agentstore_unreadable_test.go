// jade:ring local
package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 2026-09-30 23:58Z: while the store was in a format the installed cilock could
// not read as agents, signing fell through to the human login and minted
// evidence under colek42@gmail.com. An agent store that EXISTS but cannot be
// read, or carries a version this binary does not know, must refuse every
// signing path. Only an absent store, or a readable one with no agent for the
// platform, lets the human sign.

func writeAgentStoreBytes(t *testing.T, data []byte, mode os.FileMode) {
	t.Helper()
	path, err := AgentStorePath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, 0o600))
	require.NoError(t, os.Chmod(path, mode))
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
}

func TestSigningRefusesAnAgentStoreItCannotRead(t *testing.T) {
	for name, tc := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		"malformed":       {[]byte(`{"agents": {`), 0o600},
		"unknown version": {[]byte(`{"version": 3, "agents": {}}`), 0o600},
		"wrong shape":     {[]byte(`{"agents": "x"}`), 0o600},
		"unreadable":      {[]byte(`{"agents": {}}`), 0o000},
	} {
		t.Run(name, func(t *testing.T) {
			isolateConfig(t)
			if tc.mode == 0 && os.Geteuid() == 0 {
				t.Skip("root reads a 0000 file")
			}
			srv, humanExchanged := agentAndHumanPlatform(t, "spiffe://p/tenant/t-1/agent/a-1", true)
			seedHumanSession(t, srv.URL)
			writeAgentStoreBytes(t, tc.data, tc.mode)

			_, err := ResolveAgentCredential(srv.URL)
			require.Error(t, err, "the run path must refuse")
			got, err := ResolveSigningToken(srv.URL, "sigstore")
			require.Error(t, err, "the git signing path must refuse")
			assert.Empty(t, got.Token)
			assert.False(t, *humanExchanged, "fell through to the human sign-token endpoint")
		})
	}
}

func TestSigningUsesTheHumanOnlyWhenNoAgentIsStored(t *testing.T) {
	for name, data := range map[string][]byte{
		"absent":      nil,
		"empty v1":    []byte(`{"agents": {}}`),
		"empty v2":    []byte(`{"version": 2, "agents": []}`),
		"null agents": []byte(`{"agents": null}`),
	} {
		t.Run(name, func(t *testing.T) {
			isolateConfig(t)
			srv, humanExchanged := agentAndHumanPlatform(t, "spiffe://p/tenant/t-1/agent/a-1", true)
			seedHumanSession(t, srv.URL)
			if data != nil {
				writeAgentStoreBytes(t, data, 0o600)
			}
			agent, err := ResolveAgentCredential(srv.URL)
			require.NoError(t, err)
			assert.Nil(t, agent)
			_, err = ResolveSigningToken(srv.URL, "sigstore")
			require.NoError(t, err)
			assert.True(t, *humanExchanged)
		})
	}
}

// An older cilock must fail CLOSED on a version 2 file, never see "no agent".
// Version 1 binaries decode the store into platform-keyed maps and do not
// check a version; a v2 file whose slots were maps would decode cleanly with
// no entry under the platform URL, which is the human fallback above.
func TestOlderReadersCannotDecodeAVersion2Store(t *testing.T) {
	useV2Store(t)
	require.NoError(t, SaveAgent(v2Credential("a")))
	require.NoError(t, SavePendingAgent(v2Credential("p")))
	path, err := AgentStorePath()
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var v1 struct {
		Agents  map[string]AgentCredential `json:"agents"`
		Pending map[string]AgentCredential `json:"pending,omitempty"`
	}
	require.Error(t, json.Unmarshal(data, &v1))
}
