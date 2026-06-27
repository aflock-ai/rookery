// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forceFailingMigration enables the shared-session flag with a mocked keyring but
// stubs the legacy→keyring migration to ALWAYS fail, so useShared() stays false
// and every store op must consistently route to the legacy cilock store. It
// returns nothing; the migration body just keeps failing for the test's lifetime.
func forceFailingMigration(t *testing.T) {
	t.Helper()
	enableSharedSession(t) // flag on + mocked keyring + re-armed once-guard
	orig := doMigrateLegacy
	doMigrateLegacy = func() error { return errors.New("forced migration failure") }
	resetMigrateOnceForTest()
	t.Cleanup(func() {
		doMigrateLegacy = orig
		resetMigrateOnceForTest()
	})
}

// TestMigrationFailure_AllOpsUseLegacyConsistently is the FINDING 1 regression
// gate: with the shared-session flag ON but the migration FAILING, a valid legacy
// credential must remain fully usable through EVERY operation — not just Resolve.
// Before the single-predicate fix, Resolve fell back to the legacy provider
// (reads worked, advertising CapCanPinTrust) while SetTrustBundleSPKI / SetScope /
// ActivePlatformURL / Delete hit the empty shared store: the active platform was
// lost and the trust-pin returned "unpinnable" despite the read claiming it was
// pinnable. The fix routes all of them through useShared(), which is false on a
// migration failure, so they ALL operate on the legacy store together.
func TestMigrationFailure_AllOpsUseLegacyConsistently(t *testing.T) {
	forceFailingMigration(t)
	const (
		platform = "https://p.example.com"
		secret   = "legacy-session-jwt"
	)
	writeLegacyCilockStore(t, Credential{
		PlatformURL: platform,
		Token:       secret,
		AuthMode:    AuthModeBrowser,
		TenantID:    "t-1",
		ProductID:   "prod-7",
		Email:       "u@acme.example",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	// Sanity: the migration really is failing, so we are exercising the
	// migration-FAILURE path (useShared must be false).
	require.False(t, useShared(), "migration is forced to fail, so useShared must be false")

	// 1) Resolve (read) — resolves the legacy credential with full capabilities.
	resolved, err := Resolve(platform, ForBearer)
	require.NoError(t, err)
	require.NotNil(t, resolved, "valid legacy credential must resolve under migration failure (no logout)")
	assert.Equal(t, secret, resolved.Token)
	assert.True(t, resolved.Has(CapCanPinTrust), "legacy resolve advertises CapCanPinTrust")

	// 2) ActivePlatformURL — the legacy active-platform pointer is honored, NOT the
	//    empty shared store (which would return "" and lose the active platform).
	assert.Equal(t, platform, ActivePlatformURL(),
		"bare commands must still target the legacy active platform under migration failure")

	// 3) SetScope — binds onto the legacy credential (requires an existing one; the
	//    empty shared store would have errored "not logged in").
	require.NoError(t, SetScope(platform, "t-2", "Acme Two", "prod-9", "Widget"),
		"SetScope must operate on the legacy store under migration failure")
	rescoped, err := Lookup(platform)
	require.NoError(t, err)
	require.NotNil(t, rescoped)
	assert.Equal(t, "t-2", rescoped.TenantID, "scope rebind landed on the legacy credential")
	assert.Equal(t, "prod-9", rescoped.ProductID)
	assert.Equal(t, secret, rescoped.Token, "scope rebind preserved the token")

	// 4) SetTrustBundleSPKI — THE key regression. The read advertised CapCanPinTrust,
	//    so the pin MUST actually persist (persisted=true), not return the false
	//    "unpinnable" the empty shared store produced.
	persisted, err := SetTrustBundleSPKI(platform, "abc123")
	require.NoError(t, err)
	assert.True(t, persisted, "trust-pin must persist onto the legacy credential, not report unpinnable")
	pinned, err := Lookup(platform)
	require.NoError(t, err)
	require.NotNil(t, pinned)
	assert.Equal(t, "abc123", pinned.TrustBundleSPKI, "pin durably written to the legacy store")

	// 5) Delete — removes from the legacy store (the shared store never held it).
	removed, err := Delete(platform)
	require.NoError(t, err)
	assert.True(t, removed, "delete must remove the legacy credential under migration failure")
	gone, err := Lookup(platform)
	require.NoError(t, err)
	assert.Nil(t, gone, "credential is gone after legacy delete")
}

// TestMigrationFailure_NoSourceMixAcrossOps locks the single-source invariant: the
// source that Resolve uses and the source that a write op uses must be the SAME
// under migration failure. We prove it by mutating via a write op and observing
// the change through Resolve — if the write had gone to a different (shared) store,
// the read would not see it.
func TestMigrationFailure_NoSourceMixAcrossOps(t *testing.T) {
	forceFailingMigration(t)
	const platform = "https://q.example.com"
	writeLegacyCilockStore(t, Credential{
		PlatformURL: platform,
		Token:       "tok",
		AuthMode:    AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	})
	require.False(t, useShared())

	// Write through SetScope, then read through Resolve. Same source ⇒ visible.
	require.NoError(t, SetScope(platform, "tenant-x", "", "", ""))
	resolved, err := Resolve(platform, ForBearer)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, "tenant-x", resolved.TenantID,
		"a write and a subsequent read under migration failure must hit the same (legacy) source")
}
