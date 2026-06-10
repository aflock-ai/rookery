package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
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

// TestSetScope_UpdatesBindingPreservesToken is the core of `cilock use`: rebinding
// the working product must change only the scope fields and leave token / auth
// mode / tenant / expiry untouched.
func TestSetScope_UpdatesBindingPreservesToken(t *testing.T) {
	isolateConfig(t)

	exp := time.Now().Add(time.Hour)
	require.NoError(t, Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "jwt-abc",
		AuthMode:    AuthModeBrowser,
		TenantID:    "t-1",
		TenantName:  "acme",
		ExpiresAt:   exp,
	}))

	// Rebind product only (tenant args empty) — tenant/token/expiry must survive.
	require.NoError(t, SetScope("https://p.example.com/", "", "", "prod-9", "Widget"))

	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "jwt-abc", got.Token, "token preserved")
	assert.Equal(t, AuthModeBrowser, got.AuthMode, "auth mode preserved")
	assert.Equal(t, "t-1", got.TenantID, "tenant id preserved")
	assert.Equal(t, "acme", got.TenantName, "tenant name preserved")
	assert.Equal(t, "prod-9", got.ProductID, "product id bound")
	assert.Equal(t, "Widget", got.ProductName, "product name bound")
	assert.WithinDuration(t, exp, got.ExpiresAt, time.Second, "expiry preserved")
}

// TestSetScope_RequiresExistingCredential confirms you must `cilock login` first.
func TestSetScope_RequiresExistingCredential(t *testing.T) {
	isolateConfig(t)
	err := SetScope("https://nope.example.com", "", "", "p", "P")
	require.Error(t, err, "SetScope with no stored credential must error")
}

// TestLookupJctl_InheritsProduct confirms a prior `jctl config set-product` is
// inherited by cilock's read-through (product_id/product_name were dropped before).
func TestLookupJctl_InheritsProduct(t *testing.T) {
	isolateConfig(t) // HOME -> temp dir
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".jctl"), 0o700))
	cfgYAML := `current_context: p
contexts:
  p:
    judgeURL: https://p.example.com
    token: jctl-jwt
    tenant_id: t-1
    tenant_name: acme
    product_id: prod-7
    product_name: Gadget
`
	require.NoError(t, os.WriteFile(filepath.Join(home, ".jctl", "config.yaml"), []byte(cfgYAML), 0o600))

	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got, "jctl fallback should resolve")
	assert.Equal(t, "jctl-jwt", got.Token)
	assert.Equal(t, "prod-7", got.ProductID, "product_id inherited from jctl config")
	assert.Equal(t, "Gadget", got.ProductName, "product_name inherited from jctl config")
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

// writeJctlScrubbedConfig writes a ~/.jctl/config.yaml in jctl's KEYCHAIN-mode
// shape: full context metadata but an empty token, because jctl scrubbed the
// token into the OS keychain (service "jctl", account = the context NAME).
// This is what jctl actually writes on macOS and desktop Linux.
func writeJctlScrubbedConfig(t *testing.T, contextName, judgeURL string) {
	t.Helper()
	dir := filepath.Join(os.Getenv("HOME"), ".jctl")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	body := "current_context: " + contextName + "\n" +
		"contexts:\n" +
		"  " + contextName + ":\n" +
		"    judgeURL: " + judgeURL + "\n" +
		"    token: \"\"\n" +
		"    tenant_id: t-1\n" +
		"    tenant_name: acme\n" +
		"    product_id: prod-7\n" +
		"    product_name: Gadget\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600))
}

// TestLookupJctl_KeychainScrubbedToken is the core interop fix: on macOS and
// desktop Linux jctl stores the token in the OS keychain and leaves token: ""
// in the YAML, which made the documented "jctl login works for cilock too"
// read-through silently dead. The fallback must fetch the token from the
// keychain under service "jctl" with account = the context NAME (the YAML map
// key, NOT a recomputed hostname — hence the context name "staging" here,
// which is deliberately not the URL's hostname).
func TestLookupJctl_KeychainScrubbedToken(t *testing.T) {
	isolateConfig(t)
	keyring.MockInit() // fresh in-memory keychain — never touches the real OS keychain
	writeJctlScrubbedConfig(t, "staging", "https://p.example.com")
	require.NoError(t, keyring.Set("jctl", "staging", "keychain-jwt"))

	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got, "keychain-scrubbed jctl context must resolve")
	assert.Equal(t, "keychain-jwt", got.Token, "token must come from the keychain")
	assert.Equal(t, "t-1", got.TenantID, "tenant metadata still inherited from YAML")
	assert.Equal(t, "acme", got.TenantName)
	assert.Equal(t, "prod-7", got.ProductID)
	assert.Equal(t, "Gadget", got.ProductName)
}

// TestLookupJctl_KeychainMiss pins the no-regression contract: an empty YAML
// token with no matching keychain entry behaves exactly as before the
// fallback existed — no credential from that context.
func TestLookupJctl_KeychainMiss(t *testing.T) {
	isolateConfig(t)
	keyring.MockInit() // fresh empty mock — Get returns ErrNotFound
	writeJctlScrubbedConfig(t, "default", "https://p.example.com")

	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got, "empty YAML token + keychain miss must mean no credential")
}

// TestLookupJctl_KeychainTimeout simulates a wedged secret-service daemon
// (broken GNOME Keyring, zombie session bus): the keychain read blocks
// forever. The bounded read must give up and report no credential instead of
// hanging every cilock command.
func TestLookupJctl_KeychainTimeout(t *testing.T) {
	isolateConfig(t)
	writeJctlScrubbedConfig(t, "default", "https://p.example.com")

	release := make(chan struct{})
	origGet, origTimeout := getJctlKeyringToken, jctlKeyringTimeout
	getJctlKeyringToken = func(string) (string, error) {
		<-release // wedged daemon: never answers until the test releases it
		return "", errors.New("wedged")
	}
	jctlKeyringTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		close(release) // unblock the abandoned goroutine so it exits
		getJctlKeyringToken, jctlKeyringTimeout = origGet, origTimeout
	})

	start := time.Now()
	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got, "wedged keychain must time out to no credential")
	assert.Less(t, time.Since(start), 5*time.Second, "lookup must be bounded, not hang")
}

// TestLookupJctl_FileTokenSkipsKeychain pins precedence: when the YAML token
// is present (jctl file mode / JCTL_DISABLE_KEYRING=1), the keychain must not
// be consulted at all — today's working path stays byte-for-byte identical
// and can't be slowed down by a wedged daemon.
func TestLookupJctl_FileTokenSkipsKeychain(t *testing.T) {
	isolateConfig(t)
	orig := getJctlKeyringToken
	getJctlKeyringToken = func(string) (string, error) {
		t.Error("keychain must not be consulted when the YAML token is present")
		return "", errors.New("unexpected keychain read")
	}
	t.Cleanup(func() { getJctlKeyringToken = orig })
	writeJctlConfig(t, "https://p.example.com", "file-token")

	got, err := Lookup("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "file-token", got.Token, "file token wins without touching the keychain")
}

// TestActivePlatformURL is the "default to the platform you logged into" behavior:
// the most recent login is active; logout falls back to the sole remaining one.
func TestActivePlatformURL(t *testing.T) {
	isolateConfig(t)

	// No credentials → empty (callers fall back to the compiled default).
	assert.Equal(t, "", ActivePlatformURL())

	// Login to staging → staging is the active platform.
	require.NoError(t, Save(Credential{PlatformURL: "https://staging.example.com", Token: "s", ExpiresAt: time.Now().Add(time.Hour)}))
	assert.Equal(t, "https://staging.example.com", ActivePlatformURL())

	// A later login to prod makes prod active (most recent write).
	require.NoError(t, Save(Credential{PlatformURL: "https://prod.example.com", Token: "p", ExpiresAt: time.Now().Add(time.Hour)}))
	assert.Equal(t, "https://prod.example.com", ActivePlatformURL())

	// Logging out of prod clears the dangling active platform and falls back to
	// the sole remaining credential (staging).
	removed, err := Delete("https://prod.example.com")
	require.NoError(t, err)
	require.True(t, removed)
	assert.Equal(t, "https://staging.example.com", ActivePlatformURL())
}
