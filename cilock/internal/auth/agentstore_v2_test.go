// jade:ring local
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreAddsConcurrentEnrollmentsWithoutEviction(t *testing.T) {
	useV2Store(t)
	const count = 12
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := v2Credential(fmt.Sprint(i))
			if err := SavePendingAgent(c); err != nil {
				errs <- err
				return
			}
			errs <- PromotePendingAgentIf(c)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	s, err := loadAgents()
	require.NoError(t, err)
	require.Len(t, s.Agents, count)
	assert.Empty(t, s.Pending)
	for _, c := range s.Agents {
		assert.False(t, c.EnrolledAt.IsZero())
		assert.Equal(t, "pin", c.TrustBundleSPKI)
		require.NotNil(t, c.Scope)
	}
}

func TestStoreMigratesBothV1SlotsWithoutChangingCredentials(t *testing.T) {
	isolateConfig(t)
	a, p := v2Credential("active"), v2Credential("pending")
	path, err := AgentStorePath()
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"agents": map[string]AgentCredential{a.PlatformURL: a}, "pending": map[string]AgentCredential{p.PlatformURL: p}})
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, data, 0600))
	migrated, err := MigrateAgentStore()
	require.NoError(t, err)
	require.True(t, migrated)
	s, err := loadAgents()
	require.NoError(t, err)
	require.Len(t, s.Agents, 1)
	require.Len(t, s.Pending, 1)
	for _, got := range s.Agents {
		assert.Equal(t, a, got)
	}
	for _, got := range s.Pending {
		assert.Equal(t, p, got)
	}
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	var disk map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &disk))
	assert.JSONEq(t, "2", string(disk["version"]))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.NoError(t, SaveAgent(v2Credential("third")))
	s, err = loadAgents()
	require.NoError(t, err)
	assert.Len(t, s.Agents, 2)
	assert.Len(t, s.Pending, 1)
}

func TestStoreRejectsUnknownVersionWithoutRewriting(t *testing.T) {
	useV2Store(t)
	path, err := AgentStorePath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	before := []byte(`{"version":99,"agents":{}}`)
	require.NoError(t, os.WriteFile(path, before, 0600))
	_, err = LookupAgent("https://p.example.com")
	require.Error(t, err)
	require.Error(t, SaveAgent(v2Credential("new")))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestStoreUpdatesOnlyTheExchangedIdentity(t *testing.T) {
	useV2Store(t)
	a, b := v2Credential("a"), v2Credential("b")
	require.NoError(t, SaveAgent(a))
	require.NoError(t, SaveAgent(b))
	require.NoError(t, RecordAgentScope(a, &AgentScope{Mode: AgentScopeListed, Repositories: []ScopedRepository{{ID: "7"}}}))
	s, err := loadAgents()
	require.NoError(t, err)
	require.Len(t, s.Agents, 2)
	for _, c := range s.Agents {
		if c.AgentID == "a" {
			assert.Equal(t, AgentScopeListed, c.Scope.Mode)
		} else {
			assert.Equal(t, AgentScopeAll, c.Scope.Mode)
		}
	}
	replacement := a
	replacement.RefreshCredential = "rotated"
	require.NoError(t, SaveAgent(replacement))
	require.ErrorIs(t, RecordAgentExpiry(a, time.Now()), ErrAgentCredentialReplaced)
	removed, err := DeleteAgentIf(b)
	require.NoError(t, err)
	assert.True(t, removed)
	s, err = loadAgents()
	require.NoError(t, err)
	require.Len(t, s.Agents, 1)
	for _, c := range s.Agents {
		assert.Equal(t, "a", c.AgentID)
		assert.Equal(t, "rotated", c.RefreshCredential)
	}
}

func TestRemoveAgentPreservesOtherIDsAndPlatforms(t *testing.T) {
	useV2Store(t)
	a, b := v2Credential("a"), v2Credential("b")
	other := a
	other.PlatformURL = "https://other.example.com"
	for _, c := range []AgentCredential{a, b, other} {
		require.NoError(t, SaveAgent(c))
		require.NoError(t, SavePendingAgent(c))
	}
	removed, err := RemoveAgent(a.PlatformURL+"/", a.AgentID)
	require.NoError(t, err)
	require.True(t, removed)
	for _, pending := range []bool{false, true} {
		got, err := ListAgents(a.PlatformURL, pending)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, b.AgentID, got[0].AgentID)
		got, err = ListAgents(other.PlatformURL, pending)
		require.NoError(t, err)
		require.Len(t, got, 1)
	}
	removed, err = DeleteAgent(b.PlatformURL)
	require.NoError(t, err)
	assert.True(t, removed)
	platforms, err := EnrolledAgentPlatforms()
	require.NoError(t, err)
	assert.Equal(t, []string{other.PlatformURL}, platforms)
}

func TestActivationFindsItsOwnPendingIDBesideANewerEnrollment(t *testing.T) {
	useV2Store(t)
	srv := agentExchangeStub(t, "spiffe://p.example.com/tenant/t-1/agent/a", nil)
	defer srv.Close()
	a, b := v2Credential("a"), v2Credential("b")
	a.PlatformURL = srv.URL
	b.PlatformURL = srv.URL
	require.NoError(t, SavePendingAgent(a))
	require.NoError(t, SavePendingAgent(b))
	_, err := ActivateEnrolledAgent(srv.URL, AgentCredential{TenantID: a.TenantID, AgentID: a.AgentID})
	require.NoError(t, err)
	active, err := LookupAgentID(srv.URL, a.AgentID, false)
	require.NoError(t, err)
	require.NotNil(t, active)
	pending, err := LookupAgentID(srv.URL, b.AgentID, true)
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.Equal(t, b.RefreshCredential, pending.RefreshCredential)
}
