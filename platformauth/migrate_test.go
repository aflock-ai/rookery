// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// seedLegacyCilock writes a cilock-style cleartext credential file at the legacy
// path under the isolated config dir.
func seedLegacyCilock(t *testing.T, creds map[string]Credential, current string) string {
	t.Helper()
	dir, err := os.UserConfigDir()
	require.NoError(t, err)
	cilockDir := filepath.Join(dir, "cilock")
	require.NoError(t, os.MkdirAll(cilockDir, 0o700))
	path := filepath.Join(cilockDir, "credentials.json")
	legacy := legacyCilockStore{Credentials: creds, CurrentPlatform: current}
	data, err := json.MarshalIndent(legacy, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// TestMigrateLegacyCilock_Transparent is the headline gate: a logged-in cilock
// user upgrading must not be logged out. Seed a legacy cleartext store, migrate,
// and assert the session resolves through the shared store, the token landed in
// the keyring, and the metadata file holds NO cleartext token.
func TestMigrateLegacyCilock_Transparent(t *testing.T) {
	s := withKeyring(t)
	const secret = "legacy-cilock-session-jwt"
	seedLegacyCilock(t, map[string]Credential{
		"https://p.example.com": {
			PlatformURL: "https://p.example.com",
			Token:       secret,
			AuthMode:    AuthModeBrowser,
			TenantID:    "t-1",
			TenantName:  "acme",
			ProductID:   "prod-7",
			ProductName: "Gadget",
			Email:       "user@acme.example",
			ExpiresAt:   time.Now().Add(time.Hour),
		},
	}, "https://p.example.com")

	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "one legacy session must migrate")

	// The session still works — resolved through the shared store as a bearer.
	r, err := NewResolver(s)
	require.NoError(t, err)
	resolved, err := r.Resolve("https://p.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, resolved, "migrated session must resolve (no re-login)")
	assert.Equal(t, secret, resolved.Token)
	assert.Equal(t, "prod-7", resolved.ProductID, "scope metadata survives the migration")
	assert.Equal(t, "user@acme.example", resolved.Email)
	assert.Equal(t, SourceSharedStore, resolved.Source)
	assert.True(t, resolved.Has(CapCanPinTrust), "migrated session is pinnable")

	// Token is in the keyring, not cleartext in the metadata file.
	ring, err := keyring.Get(keyringService, "https://p.example.com")
	require.NoError(t, err)
	assert.Equal(t, secret, ring)
	raw, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secret, "migrated token must not be cleartext in the metadata file")
}

// TestMigrateLegacyCilock_Idempotent confirms re-running migration does not
// clobber a fresh login: a platform already in the shared store wins over the
// legacy file.
func TestMigrateLegacyCilock_Idempotent(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "fresh-login",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	seedLegacyCilock(t, map[string]Credential{
		"https://p.example.com": {PlatformURL: "https://p.example.com", Token: "stale-legacy", ExpiresAt: time.Now().Add(time.Hour)},
	}, "https://p.example.com")

	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "an already-present platform must not be re-migrated")

	got, err := s.Get("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "fresh-login", got.Token, "fresh login must win over the stale legacy entry")
}

// TestMigrateLegacyCilock_PreservesActivePlatform is the determinism gate. With
// MULTIPLE legacy sessions, the post-migration active platform must equal the
// legacy CurrentPlatform — NOT whichever credential happened to iterate last in
// Go's randomized map order. Save() stamps CurrentPlatform on every write, so the
// migration must restore the legacy pointer explicitly; otherwise a bare
// run/sign/verify/trust would target the wrong platform after the cutover.
func TestMigrateLegacyCilock_PreservesActivePlatform(t *testing.T) {
	s := withKeyring(t)
	const active = "https://b.example.com"
	seedLegacyCilock(t, map[string]Credential{
		"https://a.example.com": {PlatformURL: "https://a.example.com", Token: "tok-a", ExpiresAt: time.Now().Add(time.Hour)},
		"https://b.example.com": {PlatformURL: "https://b.example.com", Token: "tok-b", ExpiresAt: time.Now().Add(time.Hour)},
		"https://c.example.com": {PlatformURL: "https://c.example.com", Token: "tok-c", ExpiresAt: time.Now().Add(time.Hour)},
		"https://d.example.com": {PlatformURL: "https://d.example.com", Token: "tok-d", ExpiresAt: time.Now().Add(time.Hour)},
	}, active)

	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err)
	assert.Equal(t, 4, n, "all legacy sessions must migrate")

	assert.Equal(t, active, s.ActivePlatformURL(),
		"the active platform must follow the legacy CurrentPlatform, not Go's map-iteration order")
}

// TestMigrateLegacyCilock_NoActiveWhenLegacyCurrentEmpty confirms that when the
// legacy store has no CurrentPlatform, the migration does not invent one: with
// multiple migrated credentials and no pointer, the active platform stays empty
// (callers fall back to the compiled default) rather than picking a random one.
func TestMigrateLegacyCilock_NoActiveWhenLegacyCurrentEmpty(t *testing.T) {
	s := withKeyring(t)
	seedLegacyCilock(t, map[string]Credential{
		"https://a.example.com": {PlatformURL: "https://a.example.com", Token: "tok-a", ExpiresAt: time.Now().Add(time.Hour)},
		"https://b.example.com": {PlatformURL: "https://b.example.com", Token: "tok-b", ExpiresAt: time.Now().Add(time.Hour)},
	}, "") // no active platform recorded in the legacy store

	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	assert.Empty(t, s.ActivePlatformURL(),
		"with no legacy CurrentPlatform and multiple credentials, no active platform may be invented")
}

// TestMigrateLegacyCilock_PreservesActiveAcrossExistingFresh confirms the active
// pointer follows the legacy CurrentPlatform even when an already-present (fresh)
// shared-store login is skipped by the idempotent guard, and the legacy active
// platform is one of the newly-migrated ones.
func TestMigrateLegacyCilock_PreservesActiveAcrossExistingFresh(t *testing.T) {
	s := withKeyring(t)
	// A fresh login already owns one platform (and is the current active one).
	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://fresh.example.com",
		Token:       "fresh-login",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	const active = "https://a.example.com"
	seedLegacyCilock(t, map[string]Credential{
		"https://a.example.com":     {PlatformURL: "https://a.example.com", Token: "tok-a", ExpiresAt: time.Now().Add(time.Hour)},
		"https://b.example.com":     {PlatformURL: "https://b.example.com", Token: "tok-b", ExpiresAt: time.Now().Add(time.Hour)},
		"https://fresh.example.com": {PlatformURL: "https://fresh.example.com", Token: "stale-legacy", ExpiresAt: time.Now().Add(time.Hour)},
	}, active)

	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "only the two new legacy sessions migrate; the fresh login is skipped")

	assert.Equal(t, active, s.ActivePlatformURL(),
		"the legacy active platform must win over the pre-migration fresh login's active stamp")

	got, err := s.Get("https://fresh.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "fresh-login", got.Token, "fresh login token must survive the migration")
}

// TestMigrateLegacyCilock_MissingFileIsNoError confirms a clean install (no
// legacy file) migrates zero sessions without error.
func TestMigrateLegacyCilock_MissingFileIsNoError(t *testing.T) {
	s := withKeyring(t)
	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// TestMigrateLegacyCilock_FallbackKeyringUnavailable proves migration also works
// on the headless/CI path: with the keyring disabled the migrated token lands in
// the 0600 fallback file and still resolves — no re-login required there either.
func TestMigrateLegacyCilock_FallbackKeyringUnavailable(t *testing.T) {
	s := withFileFallback(t)
	const secret = "headless-legacy-jwt"
	seedLegacyCilock(t, map[string]Credential{
		"https://p.example.com": {PlatformURL: "https://p.example.com", Token: secret, ExpiresAt: time.Now().Add(time.Hour)},
	}, "https://p.example.com")

	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	r, err := NewResolver(s)
	require.NoError(t, err)
	resolved, err := r.Resolve("https://p.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, resolved, "migrated session must resolve under fallback too")
	assert.Equal(t, secret, resolved.Token)
}

// failingTokenStore is an in-memory keyring backend that errors on Save for a
// chosen set of accounts (normalized platform URLs) and behaves normally for the
// rest. It is the surgical failing-Save injection: a per-credential keyring write
// fails while reads and the metadata file stay fully functional, so a test can
// observe the store's post-migration state (which credential persisted, what the
// active platform is) rather than a globally-broken store.
type failingTokenStore struct {
	tokens   map[string]string // account -> token (successful saves)
	failOn   map[string]bool   // accounts whose Save must fail
	saveErrs int
}

func (f *failingTokenStore) Save(account, token string) error {
	if f.failOn[account] {
		f.saveErrs++
		return fmt.Errorf("injected keyring save failure for %q", account)
	}
	if f.tokens == nil {
		f.tokens = map[string]string{}
	}
	f.tokens[account] = token
	return nil
}

func (f *failingTokenStore) Load(account string) (string, error) { return f.tokens[account], nil }

func (f *failingTokenStore) Delete(account string) error {
	delete(f.tokens, account)
	return nil
}

// clearFailures makes all subsequent Saves succeed, simulating a transient
// keyring outage recovering before the migration retry.
func (f *failingTokenStore) clearFailures() { f.failOn = map[string]bool{} }

// withFailingKeyring arms a keyring-mode Store whose backend fails Save for the
// given accounts (normalized URLs). Reads/Get/ActivePlatformURL work normally, so
// the test can assert post-failure state. It isolates HOME/XDG and forces the
// injected backend by pre-completing the once-guarded probe.
func withFailingKeyring(t *testing.T, failOn ...string) (*Store, *failingTokenStore) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv(disableEnvVar, "")
	resetStoreForTest()
	fail := map[string]bool{}
	for _, a := range failOn {
		fail[NormalizeURL(a)] = true
	}
	fts := &failingTokenStore{tokens: map[string]string{}, failOn: fail}
	// Pin the injected backend by completing the probe deterministically.
	storeOnce.Do(func() {})
	resolvedStore = fts
	usingKeyring = true
	t.Cleanup(resetStoreForTest)
	s, err := DefaultStore()
	require.NoError(t, err)
	return s, fts
}

// TestMigrateLegacyCilock_FailedSaveDoesNotPersistPhantom is the failure-atomicity
// gate for the per-credential Save. When the shared store's Save fails, the
// migration must NOT leave a credential that was never persisted, must NOT count it
// as migrated, and must surface the failure — while a sibling whose Save SUCCEEDED
// must persist normally. The local map must only ever hold what actually reached
// disk, otherwise a phantom (unsaved) credential can drive the active-platform
// restore below.
func TestMigrateLegacyCilock_FailedSaveDoesNotPersistPhantom(t *testing.T) {
	const okURL = "https://ok.example.com"
	const failURL = "https://fails.example.com"
	s, _ := withFailingKeyring(t, failURL)
	seedLegacyCilock(t, map[string]Credential{
		okURL:   {PlatformURL: okURL, Token: "tok-ok", ExpiresAt: time.Now().Add(time.Hour)},
		failURL: {PlatformURL: failURL, Token: "tok-fail", ExpiresAt: time.Now().Add(time.Hour)},
	}, okURL)

	n, err := MigrateLegacyCilock(s)
	require.Error(t, err, "a Save that fails must surface an error, not silently succeed")
	assert.Equal(t, 1, n, "only the successfully-saved credential is counted as migrated")

	// The successful one persisted.
	gotOK, err := s.Get(okURL)
	require.NoError(t, err)
	require.NotNil(t, gotOK, "the credential whose Save succeeded must persist")
	assert.Equal(t, "tok-ok", gotOK.Token)

	// The failed one did NOT persist — no phantom.
	gotFail, err := s.Get(failURL)
	require.NoError(t, err)
	assert.Nil(t, gotFail, "a credential whose Save failed must not appear in the store")
}

// TestMigrateLegacyCilock_FailedSaveDoesNotBecomeActive is the active-platform leg
// of the same atomicity property: a credential whose Save failed must NEVER be
// restored as the active platform, even when the legacy CurrentPlatform points at
// it. A phantom in the local map must not satisfy the active-platform presence
// gate; the restore must trust only successfully-saved credentials. Here the
// legacy active points at the FAILING credential while a sibling saves fine, so a
// buggy restore would either pick the phantom or wrongly fall through.
func TestMigrateLegacyCilock_FailedSaveDoesNotBecomeActive(t *testing.T) {
	const okURL = "https://ok.example.com"
	const activeFail = "https://active-fails.example.com"
	s, _ := withFailingKeyring(t, activeFail)
	seedLegacyCilock(t, map[string]Credential{
		okURL:      {PlatformURL: okURL, Token: "tok-ok", ExpiresAt: time.Now().Add(time.Hour)},
		activeFail: {PlatformURL: activeFail, Token: "tok-x", ExpiresAt: time.Now().Add(time.Hour)},
	}, activeFail) // legacy active platform is the one whose Save fails

	_, err := MigrateLegacyCilock(s)
	require.Error(t, err)

	assert.NotEqual(t, activeFail, s.ActivePlatformURL(),
		"a credential whose Save failed must not be restored as the active platform")
}

// TestMigrateLegacyCilock_RestoresOnlySuccessfullySavedActive confirms the
// positive side: when the legacy active platform's Save SUCCEEDS (even if a
// DIFFERENT credential's Save fails), the active platform is restored to that
// successfully-saved credential.
func TestMigrateLegacyCilock_RestoresOnlySuccessfullySavedActive(t *testing.T) {
	const activeOK = "https://active-ok.example.com"
	const otherFail = "https://other-fails.example.com"
	s, _ := withFailingKeyring(t, otherFail)
	seedLegacyCilock(t, map[string]Credential{
		activeOK:  {PlatformURL: activeOK, Token: "tok-a", ExpiresAt: time.Now().Add(time.Hour)},
		otherFail: {PlatformURL: otherFail, Token: "tok-b", ExpiresAt: time.Now().Add(time.Hour)},
	}, activeOK) // legacy active platform saves fine; a sibling fails

	_, err := MigrateLegacyCilock(s)
	require.Error(t, err, "the sibling's Save failure is still surfaced")

	assert.Equal(t, activeOK, s.ActivePlatformURL(),
		"the active platform is restored to the successfully-saved legacy active credential")
}

// TestMigrateLegacyCilock_RetrySelfHealsActivePlatform is the compose gate for
// the two fixes: when the legacy ACTIVE platform's Save fails on the first pass
// (so it is not restored as active), a retry after the transient failure clears
// must migrate the remaining credential AND restore the correct active platform —
// proving the failure is recoverable, not permanently lost. This mirrors what the
// cilock retry guard does across reads, exercised here directly on the migration.
func TestMigrateLegacyCilock_RetrySelfHealsActivePlatform(t *testing.T) {
	const okURL = "https://ok.example.com"
	const activeFail = "https://active.example.com"
	s, fts := withFailingKeyring(t, activeFail)
	seedLegacyCilock(t, map[string]Credential{
		okURL:      {PlatformURL: okURL, Token: "tok-ok", ExpiresAt: time.Now().Add(time.Hour)},
		activeFail: {PlatformURL: activeFail, Token: "tok-active", ExpiresAt: time.Now().Add(time.Hour)},
	}, activeFail)

	// First pass: the active platform's Save fails → it is not restored as active.
	_, err := MigrateLegacyCilock(s)
	require.Error(t, err)
	assert.NotEqual(t, activeFail, s.ActivePlatformURL(),
		"the failed active credential must not be active after the failing pass")

	// The transient keyring failure clears; the retry runs the whole migration
	// again (idempotent for the already-saved cred, retrying the failed one).
	fts.clearFailures()
	n, err := MigrateLegacyCilock(s)
	require.NoError(t, err, "the retry succeeds once the transient failure clears")
	assert.Equal(t, 1, n, "only the previously-failed credential needs migrating on retry")

	got, err := s.Get(activeFail)
	require.NoError(t, err)
	require.NotNil(t, got, "the previously-failed credential is now persisted")
	assert.Equal(t, activeFail, s.ActivePlatformURL(),
		"the retry restores the correct active platform — the failure was recoverable, not permanent")
}
