// jade:ring local
package cli

import (
	"bytes"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func listCredential(id string) auth.AgentCredential {
	return auth.AgentCredential{PlatformURL: "https://p.example.com", TenantID: "tenant", AgentID: id, RefreshCredential: "secret-" + id, EnrolledAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Now().Add(time.Hour), Scope: &auth.AgentScope{Mode: auth.AgentScopeAll, AnsweredAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}}
}

func TestAgentListShowsEveryLocalEnrollmentWithoutBearers(t *testing.T) {
	isolateAgentConfig(t)
	a, b := listCredential("agent-a"), listCredential("agent-b")
	a.ExpiresAt = time.Now().Add(-time.Hour)
	b.Scope = nil
	other := listCredential("agent-other")
	other.PlatformURL = "https://other.example.com"
	require.NoError(t, auth.SaveAgent(a))
	require.NoError(t, auth.SavePendingAgent(b))
	require.NoError(t, auth.SaveAgent(other))
	var out bytes.Buffer
	cmd := AgentCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"list", "--platform-url", a.PlatformURL})
	require.NoError(t, cmd.Execute())
	for _, want := range []string{"agent-a", "agent-b", "tenant", "expired", "pending", "2026-01-02", "unknown", "platform not checked"} {
		assert.Contains(t, out.String(), want)
	}
	for _, secret := range []string{a.RefreshCredential, b.RefreshCredential, other.RefreshCredential, "agent-other"} {
		assert.NotContains(t, out.String(), secret)
	}
}

func TestAgentRemoveTargetsOnlyOneIDOnOnePlatform(t *testing.T) {
	isolateAgentConfig(t)
	_, err := auth.MigrateAgentStore()
	require.NoError(t, err)
	a, b := listCredential("agent-a"), listCredential("agent-b")
	other := a
	other.PlatformURL = "https://other.example.com"
	for _, c := range []auth.AgentCredential{a, b, other} {
		require.NoError(t, auth.SaveAgent(c))
		require.NoError(t, auth.SavePendingAgent(c))
	}
	var out bytes.Buffer
	cmd := AgentCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"remove", a.AgentID, "--platform-url", a.PlatformURL})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "not revoked")
	assert.NotContains(t, out.String(), a.RefreshCredential)
	for _, pending := range []bool{false, true} {
		got, err := auth.LookupAgentID(a.PlatformURL, a.AgentID, pending)
		require.NoError(t, err)
		assert.Nil(t, got)
		got, err = auth.LookupAgentID(b.PlatformURL, b.AgentID, pending)
		require.NoError(t, err)
		assert.NotNil(t, got)
		got, err = auth.LookupAgentID(other.PlatformURL, other.AgentID, pending)
		require.NoError(t, err)
		assert.NotNil(t, got)
	}
}

func TestAgentListAndRemoveEmptyStoreAndHelp(t *testing.T) {
	isolateAgentConfig(t)
	for _, args := range [][]string{{"list"}, {"remove", "missing"}} {
		cmd := AgentCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		require.NoError(t, cmd.Execute())
		assert.Contains(t, out.String(), "No local agent")
	}
	cmd := AgentCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"logout", "--help"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "all local")
	cmd = AgentCmd()
	cmd.SetArgs([]string{"remove"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	require.Error(t, cmd.Execute())
}

// On a version 1 store, removing the live agent is the documented remedy for
// enrolling a different one; it must make room without touching other platforms.
func TestAgentRemoveMakesRoomOnAVersion1Store(t *testing.T) {
	isolateAgentConfig(t)
	a, b := listCredential("agent-a"), listCredential("agent-b")
	other := listCredential("agent-other")
	other.PlatformURL = "https://other.example.com"
	require.NoError(t, auth.SaveAgent(a))
	require.NoError(t, auth.SaveAgent(other))
	require.ErrorIs(t, auth.SaveAgent(b), auth.ErrAgentStoreNeedsMigration)
	cmd := AgentCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"remove", a.AgentID, "--platform-url", a.PlatformURL})
	require.NoError(t, cmd.Execute())
	require.NoError(t, auth.SaveAgent(b))
	got, err := auth.LookupAgentID(other.PlatformURL, other.AgentID, false)
	require.NoError(t, err)
	assert.NotNil(t, got)
}
