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

// TestLookupAnyIncludingExpired_SurfacesExpired proves the diagnostic lookup
// returns an expired credential where LookupAny collapses it to nil. This is
// the seam `cilock doctor` relies on to tell an EXPIRED session apart from a
// MISSING one; without it, an expired login is mislabeled "not logged in" and
// preflight passes.
func TestLookupAnyIncludingExpired_SurfacesExpired(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "stale",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}))

	// LookupAny hides the expired credential (the bug's data source).
	hidden, err := LookupAny("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, hidden, "LookupAny must keep filtering expired creds")

	// LookupAnyIncludingExpired surfaces it so the doctor can fail on expiry.
	got, err := LookupAnyIncludingExpired("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got, "diagnostic lookup must return the expired credential")
	assert.True(t, got.Expired(), "returned credential should report Expired()")
	assert.Equal(t, "stale", got.Token)
}

func TestLookupAnyIncludingExpired_MissingIsNil(t *testing.T) {
	isolateConfig(t)
	got, err := LookupAnyIncludingExpired("https://none.example.com")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// writeJctlConfig writes a minimal ~/.jctl/config.yaml under the isolated HOME
// so lookupJctl's read-through fires in tests.
func writeJctlConfig(t *testing.T, judgeURL, token string) {
	t.Helper()
	dir := filepath.Join(os.Getenv("HOME"), ".jctl")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	body := "contexts:\n  default:\n    judgeURL: " + judgeURL + "\n    token: " + token + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600))
}

// TestLookupAnyIncludingExpired_PrefersValidJctlOverExpiredCilock proves the
// diagnostic lookup matches what `cilock run` actually does: when the cilock
// store holds an EXPIRED cred but a VALID jctl token exists for the same
// platform, it returns the jctl token (not the stale cilock entry). Otherwise
// the doctor would over-report FAIL on an environment a real run handles fine —
// the doctor/run divergence this precedence fix closes.
func TestLookupAnyIncludingExpired_PrefersValidJctlOverExpiredCilock(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "expired-cilock",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}))
	writeJctlConfig(t, "https://p.example.com", "fresh-jctl-token")

	got, err := LookupAnyIncludingExpired("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "fresh-jctl-token", got.Token, "must prefer the valid jctl token, not the stale cilock entry")
	assert.False(t, got.Expired())

	// The doctor lookup must agree with the run-time lookup (LookupAny).
	la, err := LookupAny("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, la)
	assert.Equal(t, "fresh-jctl-token", la.Token, "doctor and run must resolve the same credential")
}
