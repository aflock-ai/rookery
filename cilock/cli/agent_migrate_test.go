// jade:ring local
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storeVersion(t *testing.T) int {
	t.Helper()
	path, err := auth.AgentStorePath()
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		Version int `json:"version"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc.Version
}

func TestAgentMigrateIsTheOnlyWayToVersion2(t *testing.T) {
	isolateAgentConfig(t)
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: "a-1", RefreshCredential: agentTestSecret}))
	assert.Equal(t, 0, storeVersion(t), "enrollment keeps the version 1 format older callers read")

	run := func() string {
		cmd := AgentCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"migrate"})
		require.NoError(t, cmd.Execute())
		return out.String()
	}
	first := run()
	assert.Contains(t, first, "version 2")
	assert.Contains(t, first, "older cilock")
	assert.NotContains(t, first, agentTestSecret)
	assert.Equal(t, 2, storeVersion(t))
	assert.Contains(t, run(), "already version 2")
}

// Rule from 2026-09-30 23:58Z: an agent store git's signer cannot read must
// refuse the signature, never resolve to the human's platform session.
func TestGitSignerRefusesAnUnreadableAgentStore(t *testing.T) {
	for name, data := range map[string]string{
		"malformed":       `{"agents": {`,
		"unknown version": `{"version": 3, "agents": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			isolateAgentConfig(t)
			path, err := auth.AgentStorePath()
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
			_, err = gitSignerPlatformURL("")
			require.Error(t, err)
			_, err = gitSignerPlatformURL("https://p.example.com")
			require.Error(t, err)
		})
	}
}
