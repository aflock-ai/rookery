// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// withKeyring points the store at a fresh in-memory OS keyring and re-arms the
// backend probe so selectStore picks the (now available) keyring. It also
// isolates HOME/XDG so the store never touches the real config dir.
func withKeyring(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv(disableEnvVar, "")
	keyring.MockInit()
	resetStoreForTest()
	t.Cleanup(resetStoreForTest)
	s, err := DefaultStore()
	require.NoError(t, err)
	return s
}

// withFileFallback forces the file-based fallback (keyring disabled), isolating
// HOME/XDG to a temp dir.
func withFileFallback(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv(disableEnvVar, "1")
	resetStoreForTest()
	t.Cleanup(resetStoreForTest)
	s, err := DefaultStore()
	require.NoError(t, err)
	return s
}

func TestNormalizeURL(t *testing.T) {
	assert.Equal(t, "https://p.example.com", NormalizeURL("https://p.example.com/"))
	assert.Equal(t, "https://p.example.com", NormalizeURL("  https://p.example.com  "))
}

func TestDefaultStore_XDGPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	s, err := DefaultStore()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "judge", "session.json"), s.Path())
}

func TestDefaultStore_HomeFallbackPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", dir)
	s, err := DefaultStore()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, ".config", "judge", "session.json"), s.Path())
}

func TestStoreRoundTrip_Keyring(t *testing.T) {
	s := withKeyring(t)

	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com/", // trailing slash must normalize
		Token:       "jwt-abc",
		TenantName:  "acme",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	got, err := s.Get("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "jwt-abc", got.Token)
	assert.Equal(t, "acme", got.TenantName)

	// File must be 0600.
	info, err := os.Stat(s.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	removed, err := s.Delete("https://p.example.com/")
	require.NoError(t, err)
	assert.True(t, removed)

	got, err = s.Get("https://p.example.com")
	require.NoError(t, err)
	assert.Nil(t, got, "get after delete must be nil")
}

// TestSecretNeverCleartextWhenKeyringAvailable is the at-rest-posture gate: when
// the keyring is the active backend, the metadata file must contain NO token —
// the secret lives only in the keyring.
func TestSecretNeverCleartextWhenKeyringAvailable(t *testing.T) {
	s := withKeyring(t)
	const secret = "super-secret-bearer-jwt-value"
	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       secret,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	raw, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secret, "metadata file must not contain the token in keyring mode")

	// The token must still resolve (it's in the keyring).
	got, err := s.Get("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, secret, got.Token, "token must round-trip via the keyring")

	// And the keyring holds it under service "judge" / account = normalized URL.
	ring, err := keyring.Get(keyringService, "https://p.example.com")
	require.NoError(t, err)
	assert.Equal(t, secret, ring)

	// Metadata file must carry the schema version.
	var m metadata
	require.NoError(t, json.Unmarshal(raw, &m))
	assert.Equal(t, metadataSchemaVersion, m.Version)
}

// TestFileFallback_StoresTokenInline is the headless/CI gate: with the keyring
// disabled, the token falls back into the 0600 file and still round-trips.
func TestFileFallback_StoresTokenInline(t *testing.T) {
	s := withFileFallback(t)
	const secret = "fallback-bearer-jwt"
	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       secret,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	raw, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	assert.Contains(t, string(raw), secret, "fallback mode keeps the token inline in the 0600 file")
	info, err := os.Stat(s.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	got, err := s.Get("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, secret, got.Token)
}

func TestSetScope_PreservesToken(t *testing.T) {
	s := withKeyring(t)
	exp := time.Now().Add(time.Hour)
	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "jwt-abc",
		AuthMode:    AuthModeBrowser,
		TenantID:    "t-1",
		TenantName:  "acme",
		ExpiresAt:   exp,
	}))

	require.NoError(t, s.SetScope("https://p.example.com/", "", "", "prod-9", "Widget"))

	got, err := s.Get("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "jwt-abc", got.Token, "token preserved")
	assert.Equal(t, AuthModeBrowser, got.AuthMode, "auth mode preserved")
	assert.Equal(t, "t-1", got.TenantID, "tenant id preserved")
	assert.Equal(t, "prod-9", got.ProductID, "product id bound")
	assert.Equal(t, "Widget", got.ProductName, "product name bound")
	assert.WithinDuration(t, exp, got.ExpiresAt, time.Second, "expiry preserved")
}

func TestSetScope_RequiresExistingCredential(t *testing.T) {
	s := withKeyring(t)
	err := s.SetScope("https://nope.example.com", "", "", "p", "P")
	require.Error(t, err)
}

func TestActivePlatformURL(t *testing.T) {
	s := withKeyring(t)
	assert.Equal(t, "", s.ActivePlatformURL())

	require.NoError(t, s.Save(Credential{PlatformURL: "https://staging.example.com", Token: "s", ExpiresAt: time.Now().Add(time.Hour)}))
	assert.Equal(t, "https://staging.example.com", s.ActivePlatformURL())

	require.NoError(t, s.Save(Credential{PlatformURL: "https://prod.example.com", Token: "p", ExpiresAt: time.Now().Add(time.Hour)}))
	assert.Equal(t, "https://prod.example.com", s.ActivePlatformURL())

	removed, err := s.Delete("https://prod.example.com")
	require.NoError(t, err)
	require.True(t, removed)
	assert.Equal(t, "https://staging.example.com", s.ActivePlatformURL())
}

// TestSetTrustBundleSPKI_PinsAndIsUnpinnableWhenMissing covers the GHSA #5988
// pin mechanics: a pin writes onto an existing credential and is un-pinnable
// (persisted=false, nil err) when no credential exists for the platform.
func TestSetTrustBundleSPKI_PinsAndIsUnpinnableWhenMissing(t *testing.T) {
	s := withKeyring(t)

	// No credential yet → un-pinnable.
	persisted, err := s.SetTrustBundleSPKI("https://p.example.com", "deadbeef")
	require.NoError(t, err)
	assert.False(t, persisted, "no credential to pin onto must report un-pinnable, not error")

	require.NoError(t, s.Save(Credential{PlatformURL: "https://p.example.com", Token: "t", ExpiresAt: time.Now().Add(time.Hour)}))
	persisted, err = s.SetTrustBundleSPKI("https://p.example.com", "deadbeef")
	require.NoError(t, err)
	assert.True(t, persisted, "pin must persist onto an existing credential")

	got, err := s.Get("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "deadbeef", got.TrustBundleSPKI)
	assert.Equal(t, "t", got.Token, "pin write preserves the token")
}

// TestVersionedSchema_ReadsAndRewrites confirms the metadata file carries a
// version and that a version-0 (unversioned) file loads and is rewritten with
// the current version — the forward-compatibility hook.
func TestVersionedSchema_ReadsAndRewrites(t *testing.T) {
	s := withFileFallback(t)
	// Hand-write an unversioned file (version omitted == 0).
	body := `{"credentials":{"https://p.example.com":{"platform_url":"https://p.example.com","token":"legacy-inline"}}}`
	require.NoError(t, os.MkdirAll(filepath.Dir(s.Path()), 0o700))
	require.NoError(t, os.WriteFile(s.Path(), []byte(body), 0o600))

	got, err := s.Get("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "legacy-inline", got.Token)

	// A save stamps the current version.
	require.NoError(t, s.Save(Credential{PlatformURL: "https://q.example.com", Token: "x", ExpiresAt: time.Now().Add(time.Hour)}))
	raw, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(raw), `"version": 1`), "rewritten file carries the schema version")
}

// TestForceActivePlatform covers the deterministic active-platform primitive the
// cilock migration relies on: it sets an exact target regardless of credential
// presence, clears the pointer on an empty target, and is a no-op rewrite when
// already at the target.
func TestForceActivePlatform(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, s.Save(Credential{PlatformURL: "https://a.example.com", Token: "ta", ExpiresAt: time.Now().Add(time.Hour)}))
	require.NoError(t, s.Save(Credential{PlatformURL: "https://b.example.com", Token: "tb", ExpiresAt: time.Now().Add(time.Hour)}))
	// The last Save stamped b as active.
	require.Equal(t, "https://b.example.com", s.ActivePlatformURL())

	// Force it back to a (a present credential).
	require.NoError(t, s.forceActivePlatform("https://a.example.com"))
	assert.Equal(t, "https://a.example.com", s.ActivePlatformURL())

	// An un-normalized target normalizes to the same key.
	require.NoError(t, s.forceActivePlatform("https://b.example.com/"))
	assert.Equal(t, "https://b.example.com", s.ActivePlatformURL())

	// An empty target clears the pointer; ActivePlatformURL then has no single
	// credential to fall back to (two are stored) and returns empty.
	require.NoError(t, s.forceActivePlatform(""))
	assert.Empty(t, s.ActivePlatformURL())
}
