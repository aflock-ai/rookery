// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider is a test fallback provider that returns a fixed credential.
type fakeProvider struct {
	name string
	cred *Credential
	caps Capabilities
}

func (f fakeProvider) Name() string { return f.name }
func (f fakeProvider) Resolve(string, ResolveMode) (*Resolved, error) {
	if f.cred == nil {
		return nil, nil
	}
	return &Resolved{Credential: f.cred, Source: f.name, Capabilities: f.caps}, nil
}

func TestResolve_StoreTakesPrecedenceOverFallback(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, s.Save(Credential{PlatformURL: "https://p.example.com", Token: "store-token", ExpiresAt: time.Now().Add(time.Hour)}))

	fb := fakeProvider{name: "fallback", cred: &Credential{PlatformURL: "https://p.example.com", Token: "fallback-token"}}
	r, err := NewResolver(s, fb)
	require.NoError(t, err)

	resolved, err := r.Resolve("https://p.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, "store-token", resolved.Token, "shared store wins over the fallback")
	assert.Equal(t, SourceSharedStore, resolved.Source)
	assert.True(t, resolved.Has(CapCanPinTrust))
}

func TestResolve_FallsThroughToFallback(t *testing.T) {
	s := withKeyring(t) // empty store
	fb := fakeProvider{name: "fallback", cred: &Credential{PlatformURL: "https://p.example.com", Token: "fallback-token"}, caps: NewCapabilities()}
	r, err := NewResolver(s, fb)
	require.NoError(t, err)

	resolved, err := r.Resolve("https://p.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, "fallback-token", resolved.Token)
	assert.Equal(t, "fallback", resolved.Source)
	assert.False(t, resolved.Has(CapCanPinTrust), "a fallback declaring nothing is un-pinnable (fail-closed)")
}

func TestResolve_ForBearerFiltersExpiredAndTokenless(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, s.Save(Credential{PlatformURL: "https://exp.example.com", Token: "t", ExpiresAt: time.Now().Add(-time.Hour)}))
	require.NoError(t, s.Save(Credential{PlatformURL: "https://nokey.example.com", AuthMode: AuthModeWorkflowOIDC, ExpiresAt: time.Now().Add(time.Hour)}))

	r, err := NewResolver(s)
	require.NoError(t, err)

	exp, err := r.Resolve("https://exp.example.com", ForBearer)
	require.NoError(t, err)
	assert.Nil(t, exp, "ForBearer must not return an expired credential")

	nokey, err := r.Resolve("https://nokey.example.com", ForBearer)
	require.NoError(t, err)
	assert.Nil(t, nokey, "ForBearer must not return a token-less marker")
}

func TestResolve_ForDisplaySurfacesTokenless(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, s.Save(Credential{PlatformURL: "https://nokey.example.com", AuthMode: AuthModeWorkflowOIDC, ExpiresAt: time.Now().Add(time.Hour)}))

	r, err := NewResolver(s)
	require.NoError(t, err)
	got, err := r.Resolve("https://nokey.example.com", ForDisplay)
	require.NoError(t, err)
	require.NotNil(t, got, "ForDisplay surfaces a token-less workflow marker")
	assert.Empty(t, got.Token)
}

func TestResolve_IncludingExpiredSurfacesExpiredAfterFallbackMiss(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, s.Save(Credential{PlatformURL: "https://p.example.com", Token: "stale", ExpiresAt: time.Now().Add(-time.Hour)}))

	r, err := NewResolver(s) // no fallback
	require.NoError(t, err)

	display, err := r.Resolve("https://p.example.com", ForDisplay)
	require.NoError(t, err)
	assert.Nil(t, display, "ForDisplay hides the expired credential")

	got, err := r.Resolve("https://p.example.com", IncludingExpired)
	require.NoError(t, err)
	require.NotNil(t, got, "IncludingExpired surfaces the expired credential for diagnosis")
	assert.True(t, got.Expired())
	assert.Equal(t, "stale", got.Token)
}

// TestResolve_IncludingExpiredPrefersValidFallbackOverExpiredStore proves the
// expired last-resort runs AFTER fallbacks: a fresh fallback session must not be
// masked by a stale store entry.
func TestResolve_IncludingExpiredPrefersValidFallbackOverExpiredStore(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, s.Save(Credential{PlatformURL: "https://p.example.com", Token: "expired-store", ExpiresAt: time.Now().Add(-time.Hour)}))
	fb := fakeProvider{name: "fallback", cred: &Credential{PlatformURL: "https://p.example.com", Token: "fresh-fallback"}}

	r, err := NewResolver(s, fb)
	require.NoError(t, err)
	got, err := r.Resolve("https://p.example.com", IncludingExpired)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "fresh-fallback", got.Token, "valid fallback must win over the stale store entry")
}

func TestCapabilities_FailClosed(t *testing.T) {
	var nilCaps Capabilities
	assert.False(t, nilCaps.Has(CapCanPinTrust), "nil capability set must report false")
	empty := NewCapabilities()
	assert.False(t, empty.Has(CapCanPinTrust), "empty capability set must report false")

	// The store's unconditional capabilities are declared for every credential.
	base := storeCapabilitiesFor(&Credential{})
	assert.True(t, base.Has(CapCanPinTrust))
	assert.True(t, base.Has(CapCarriesIdentity))
	assert.True(t, base.Has(CapEnforcesExpiry))
	// CapAudienceValidated is per-credential: NOT declared for a credential whose
	// audience was never validated (a raw Save / migrated session), declared only
	// when the credential records that its audience was checked.
	assert.False(t, base.Has(CapAudienceValidated), "a non-validated credential must NOT carry audience-validated (fail-closed)")
	assert.False(t, storeCapabilitiesFor(nil).Has(CapAudienceValidated), "a nil credential is fail-closed")
	validated := storeCapabilitiesFor(&Credential{AudienceValidated: true})
	assert.True(t, validated.Has(CapAudienceValidated), "a token-validated credential carries audience-validated")
}

// TestResolve_AudienceValidatedIsPerCredential is the regression guard for the
// per-credential audience capability (Finding 1): a migrated/raw-Save session
// resolves WITHOUT CapAudienceValidated (its audience was never checked), while a
// session built on the validating TokenCredential path resolves WITH it. Before
// the fix the store declared CapAudienceValidated for EVERY credential, which
// overstated the security of a migrated device/browser session.
func TestResolve_AudienceValidatedIsPerCredential(t *testing.T) {
	s := withKeyring(t)
	// A raw Save — the path jctl migration and the browser/device flows use. No
	// audience check ran, so the resolved credential must NOT claim it.
	require.NoError(t, s.Save(Credential{PlatformURL: "https://migrated.example.com", Token: "raw", ExpiresAt: time.Now().Add(time.Hour)}))
	// A credential whose audience WAS validated (what TokenCredential stamps).
	require.NoError(t, s.Save(Credential{PlatformURL: "https://validated.example.com", Token: "checked", ExpiresAt: time.Now().Add(time.Hour), AudienceValidated: true}))

	r, err := NewResolver(s)
	require.NoError(t, err)

	migrated, err := r.Resolve("https://migrated.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, migrated)
	assert.False(t, migrated.Has(CapAudienceValidated), "a raw-Save/migrated session must not be vouched audience-validated")
	assert.True(t, migrated.Has(CapCanPinTrust), "other store capabilities are unchanged")

	validated, err := r.Resolve("https://validated.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, validated)
	assert.True(t, validated.Has(CapAudienceValidated), "a TokenCredential-validated session carries the capability")
}

// TestResolve_TokenCredentialEndToEndCarriesAudience proves the only construction
// path that checks the audience (TokenCredential) yields, once stored and
// resolved, a credential that surfaces CapAudienceValidated — the end-to-end
// version of the per-credential guard.
func TestResolve_TokenCredentialEndToEndCarriesAudience(t *testing.T) {
	tok := mintJWT(t, map[string]any{"aud": "https://p.example.com/login", "exp": time.Now().Add(time.Hour).Unix()})
	cred, err := TokenCredential("https://p.example.com", tok, "https://p.example.com/login")
	require.NoError(t, err)
	require.True(t, cred.AudienceValidated, "the validating --token path stamps audience-validated")

	s := withKeyring(t)
	require.NoError(t, s.Save(*cred))
	r, err := NewResolver(s)
	require.NoError(t, err)
	got, err := r.Resolve("https://p.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Has(CapAudienceValidated), "a stored TokenCredential resolves with the audience capability")
}
