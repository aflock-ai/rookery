package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateConfig points os.UserConfigDir at a temp dir (HOME on macOS,
// XDG_CONFIG_HOME on Linux) so the test never touches the real store.
func isolateConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
}

func TestNormalizeURL(t *testing.T) {
	assert.Equal(t, "https://p.example.com", NormalizeURL("https://p.example.com/"))
	assert.Equal(t, "https://p.example.com", NormalizeURL("  https://p.example.com  "))
}

func TestStoreRoundTrip(t *testing.T) {
	isolateConfig(t)

	// Trailing slash must normalize to the same key on save and lookup.
	require.NoError(t, Save(Credential{
		PlatformURL: "https://p.example.com/",
		Token:       "jwt-abc",
		TenantName:  "acme",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "jwt-abc", got.Token)
	assert.Equal(t, "acme", got.TenantName)

	// Stored file must be 0600.
	path, err := StorePath()
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	removed, err := Delete("https://p.example.com/")
	require.NoError(t, err)
	assert.True(t, removed)

	got, err = Lookup("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got, "lookup after delete must be nil")
}

func TestExpiredCredentialNotReturned(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "stale",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}))
	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got, "an expired credential must not be returned")
}

func TestLookupMissingIsNil(t *testing.T) {
	isolateConfig(t)
	got, err := Lookup("https://none.example.com")
	require.NoError(t, err)
	assert.Nil(t, got)
}
