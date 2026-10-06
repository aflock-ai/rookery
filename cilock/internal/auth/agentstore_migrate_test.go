// jade:ring local
package auth

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV1PromotionOfADifferentIDIsRefusedWhileTheActiveAgentLives(t *testing.T) {
	isolateConfig(t)
	a, b := v2Credential("a"), v2Credential("b")
	// A pending credential written by an older binary beside a live agent.
	path, before := writeV1Store(t, []AgentCredential{a}, []AgentCredential{b})
	require.ErrorIs(t, PromotePendingAgentIf(b), ErrAgentStoreNeedsMigration)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestV1KeepsAgentsOnOtherPlatforms(t *testing.T) {
	isolateConfig(t)
	a, other := v2Credential("a"), v2Credential("o")
	other.PlatformURL = "https://other.example.com"
	path, _ := writeV1Store(t, []AgentCredential{a}, nil)
	require.NoError(t, SaveAgent(other))
	assert.Equal(t, 0, diskVersion(t, path))
	platforms, err := EnrolledAgentPlatforms()
	require.NoError(t, err)
	assert.Equal(t, []string{other.PlatformURL, a.PlatformURL}, platforms)
}

func TestMigrateIsExplicitAndIdempotent(t *testing.T) {
	isolateConfig(t)
	a, p := v2Credential("a"), v2Credential("p")
	path, _ := writeV1Store(t, []AgentCredential{a}, []AgentCredential{p})
	migrated, err := MigrateAgentStore()
	require.NoError(t, err)
	assert.True(t, migrated)
	assert.Equal(t, 2, diskVersion(t, path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	migrated, err = MigrateAgentStore()
	require.NoError(t, err)
	assert.False(t, migrated)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "migrate on v2 is a no-op")

	// v2 adds without evicting, and stays v2.
	require.NoError(t, SaveAgent(v2Credential("b")))
	assert.Equal(t, 2, diskVersion(t, path))
	got, err := ListAgents(a.PlatformURL, false)
	require.NoError(t, err)
	require.Len(t, got, 2)
	pending, err := LookupAgentID(a.PlatformURL, "p", true)
	require.NoError(t, err)
	require.NotNil(t, pending)
}

func TestMigrateCreatesAnEmptyV2Store(t *testing.T) {
	isolateConfig(t)
	migrated, err := MigrateAgentStore()
	require.NoError(t, err)
	assert.True(t, migrated)
	path, err := AgentStorePath()
	require.NoError(t, err)
	assert.Equal(t, 2, diskVersion(t, path))
}

func TestEnrollmentPreflightRefusesBeforeTheCeremonyOnALiveV1Store(t *testing.T) {
	isolateConfig(t)
	a := v2Credential("a")
	require.NoError(t, AgentStoreAdmitsNewAgent(a.PlatformURL), "an empty store admits")
	path, before := writeV1Store(t, []AgentCredential{a}, nil)
	require.ErrorIs(t, AgentStoreAdmitsNewAgent(a.PlatformURL+"/"), ErrAgentStoreNeedsMigration)
	require.NoError(t, AgentStoreAdmitsNewAgent("https://other.example.com"))
	_, err := BrowserEnroll(a.PlatformURL, EnrollParams{})
	require.ErrorIs(t, err, ErrAgentStoreNeedsMigration, "refused before any browser or platform call")
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	_, err = MigrateAgentStore()
	require.NoError(t, err)
	require.NoError(t, AgentStoreAdmitsNewAgent(a.PlatformURL))
}

func TestFreshStoreIsWrittenAsV1(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, SaveAgent(v2Credential("a")))
	path, err := AgentStorePath()
	require.NoError(t, err)
	assert.Equal(t, 0, diskVersion(t, path))
}

func TestV1ReplacesAnExpiredAgent(t *testing.T) {
	isolateConfig(t)
	a, b := v2Credential("a"), v2Credential("b")
	a.ExpiresAt = time.Now().Add(-time.Minute).UTC()
	path, _ := writeV1Store(t, []AgentCredential{a}, nil)
	require.NoError(t, SaveAgent(b))
	assert.Equal(t, 0, diskVersion(t, path))
	got, err := ListAgents(a.PlatformURL, false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "b", got[0].AgentID)
}

// Codex #10823: legacy entries carry no enrollment time. After migrating a v1
// store holding active a and pending z, promoting z must make z the identity
// that signs, not lose a zero-time tie to a's smaller ID.
func TestPromotionAfterMigrationSignsWithThePromotedAgent(t *testing.T) {
	isolateConfig(t)
	a, z := v2Credential("a"), v2Credential("z")
	writeV1Store(t, []AgentCredential{a}, []AgentCredential{z})
	_, err := MigrateAgentStore()
	require.NoError(t, err)
	require.NoError(t, PromotePendingAgentIf(z))
	got, err := LookupAgent(z.PlatformURL)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "z", got.AgentID)
}
