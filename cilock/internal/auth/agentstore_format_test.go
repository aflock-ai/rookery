// jade:ring local
package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The 2026-09-30 incident: a v2 binary read the real v1 store and rewrote it as
// v2, and the installed v1 cilock (git's signing program) could no longer parse
// it. These tests pin the rule: the format version changes only through an
// explicit MigrateAgentStore.

func v2Credential(id string) AgentCredential {
	return AgentCredential{PlatformURL: "https://p.example.com", TenantID: "t-1", AgentID: id,
		RefreshCredential: "secret-" + id, TrustDomain: "p.example.com", TrustBundleSPKI: "pin",
		ExpiresAt: time.Now().Add(time.Hour).UTC(), Scope: &AgentScope{Mode: AgentScopeAll}}
}

// useV2Store isolates the config and explicitly migrates the empty store, for
// tests of version 2 behaviour (several agents on one platform).
func useV2Store(t *testing.T) {
	t.Helper()
	isolateConfig(t)
	_, err := MigrateAgentStore()
	require.NoError(t, err)
}

func writeV1Store(t *testing.T, active, pending []AgentCredential) (string, []byte) {
	t.Helper()
	path, err := AgentStorePath()
	require.NoError(t, err)
	agents := map[string]AgentCredential{}
	for _, c := range active {
		agents[c.PlatformURL] = c
	}
	doc := map[string]any{"agents": agents}
	if len(pending) > 0 {
		p := map[string]AgentCredential{}
		for _, c := range pending {
			p[c.PlatformURL] = c
		}
		doc["pending"] = p
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path, data
}

// diskVersion is what an older binary sees: absent (v1) or the number written.
func diskVersion(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		Version int             `json:"version"`
		Agents  json.RawMessage `json:"agents"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	if doc.Version < 2 {
		// A v1 reader keys by platform URL; every key must parse as one.
		var keyed map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(doc.Agents, &keyed))
		for key := range keyed {
			assert.Equal(t, NormalizeURL(key), key, "v1 key must be a platform URL")
		}
	}
	return doc.Version
}

func TestV1StoreIsNeverMigratedByReadsOrWrites(t *testing.T) {
	isolateConfig(t)
	a := v2Credential("a")
	path, before := writeV1Store(t, []AgentCredential{a}, nil)

	got, err := LookupAgent(a.PlatformURL)
	require.NoError(t, err)
	require.NotNil(t, got)
	_, err = ListAgents(a.PlatformURL, false)
	require.NoError(t, err)
	_, err = EnrolledAgentPlatforms()
	require.NoError(t, err)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a read must leave a v1 store byte-identical")

	// Exchange-derived writes and same-ID re-enrollment keep v1.
	require.NoError(t, RecordAgentExpiry(a, a.ExpiresAt.Add(time.Minute)))
	require.NoError(t, RecordAgentScope(a, &AgentScope{Mode: AgentScopeListed, Repositories: []ScopedRepository{{ID: "7"}}}))
	again := a
	again.RefreshCredential = "rotated"
	require.NoError(t, SaveAgent(again))
	assert.Equal(t, 0, diskVersion(t, path))
	got, err = LookupAgent(a.PlatformURL)
	require.NoError(t, err)
	assert.Equal(t, "rotated", got.RefreshCredential)
}

func TestV1RefusesASecondLiveAgentAndLeavesTheFileUnchanged(t *testing.T) {
	isolateConfig(t)
	a, b := v2Credential("a"), v2Credential("b")
	path, before := writeV1Store(t, []AgentCredential{a}, nil)

	for name, write := range map[string]func() error{
		"save":    func() error { return SaveAgent(b) },
		"pending": func() error { return SavePendingAgent(b) },
	} {
		err := write()
		require.ErrorIs(t, err, ErrAgentStoreNeedsMigration, name)
		assert.Contains(t, err.Error(), "cilock agent migrate")
		assert.Contains(t, err.Error(), "cilock agent remove")
		after, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		assert.Equal(t, before, after, name)
	}
}

// On v1 a login supersedes ANY pending credential for the platform (#10823).
func TestV1LoginClearsAnotherIDsPendingCredential(t *testing.T) {
	isolateConfig(t)
	b, c := v2Credential("b"), v2Credential("c")
	path, _ := writeV1Store(t, nil, []AgentCredential{b})
	require.NoError(t, SaveAgent(c))
	assert.Equal(t, 0, diskVersion(t, path))
	pending, err := LookupPendingAgent(b.PlatformURL)
	require.NoError(t, err)
	assert.Nil(t, pending, "a v1 login must not leave another ID pending")
}
