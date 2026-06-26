// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCapabilitiesHas_FailClosed is the core safety property of the seam: an
// undeclared capability — including on a nil/empty set — is always false. A trust
// branch gating on Has can therefore only proceed when a source affirmatively
// vouched for the property.
func TestCapabilitiesHas_FailClosed(t *testing.T) {
	// nil set: every capability is false.
	var nilSet Capabilities
	assert.False(t, nilSet.Has(CapCanPinTrust), "nil set must not declare CapCanPinTrust")
	assert.False(t, nilSet.Has(CapCarriesIdentity))
	assert.False(t, nilSet.Has(CapEnforcesExpiry))
	assert.False(t, nilSet.Has(CapAudienceValidated))

	// empty (but non-nil) set: still false for everything.
	empty := NewCapabilities()
	assert.False(t, empty.Has(CapCanPinTrust), "empty set must not declare CapCanPinTrust")

	// a partial set declares only what was added; everything else is false.
	partial := NewCapabilities(CapCarriesIdentity)
	assert.True(t, partial.Has(CapCarriesIdentity), "declared cap is true")
	assert.False(t, partial.Has(CapCanPinTrust), "undeclared cap is false")
	assert.False(t, partial.Has(Capability("totally-unknown")), "unknown cap is false")
}

// TestProviderCapabilityDeclarations pins the per-provider declarations the whole
// design hinges on: cilock declares ALL capabilities (it owns the pin); jctl
// declares NONE (so Phase 2's trust branch fails closed on a jctl session without
// any source-string compare).
func TestProviderCapabilityDeclarations(t *testing.T) {
	cl := cilockCapabilities()
	for _, c := range []Capability{CapCanPinTrust, CapCarriesIdentity, CapEnforcesExpiry, CapAudienceValidated} {
		assert.True(t, cl.Has(c), "cilock must declare %s", c)
	}

	jc := jctlCapabilities()
	assert.False(t, jc.Has(CapCanPinTrust), "jctl must NOT declare CapCanPinTrust (un-pinnable — the #5988/#6014 gate)")
	assert.False(t, jc.Has(CapCarriesIdentity))
	assert.False(t, jc.Has(CapEnforcesExpiry))
	assert.False(t, jc.Has(CapAudienceValidated))
}

// TestResolvePrecedence_CilockBeatsJctl proves the provider walk preserves today's
// precedence: when BOTH the cilock store and a jctl context hold a usable
// credential for the same platform, the cilock one wins and carries the cilock
// capability set (including CapCanPinTrust).
func TestResolvePrecedence_CilockBeatsJctl(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "cilock-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	writeJctlConfig(t, "https://p.example.com", "jctl-token")

	res, err := Resolve("https://p.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "cilock-token", res.Token, "cilock store must win over jctl")
	assert.Equal(t, "cilock", res.Source)
	assert.True(t, res.Capabilities.Has(CapCanPinTrust), "cilock source declares pin capability")
}

// TestResolveFallsBackToJctl proves the second provider is consulted only when the
// first misses, and the jctl-sourced result declares NO capabilities.
func TestResolveFallsBackToJctl(t *testing.T) {
	isolateConfig(t)
	writeJctlConfig(t, "https://p.example.com", "jctl-token") // no cilock store entry

	res, err := Resolve("https://p.example.com", ForBearer)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "jctl-token", res.Token)
	assert.Equal(t, "jctl", res.Source)
	assert.False(t, res.Capabilities.Has(CapCanPinTrust), "jctl-sourced credential must declare no pin capability")
}

// TestForBearer_MatchesLookup runs the ForBearer mode and the legacy Lookup over
// the SAME fixtures and asserts byte-identical results, including the
// token-empty/expired filtering that distinguishes ForBearer from ForDisplay.
func TestForBearer_MatchesLookup(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
		url   string
	}{
		{
			name: "live token in cilock store",
			setup: func(t *testing.T) {
				require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "t", ExpiresAt: time.Now().Add(time.Hour)}))
			},
			url: "https://p.example.com",
		},
		{
			name: "expired cilock cred — ForBearer must miss",
			setup: func(t *testing.T) {
				require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "t", ExpiresAt: time.Now().Add(-time.Hour)}))
			},
			url: "https://p.example.com",
		},
		{
			name: "token-less cilock marker — ForBearer must miss (no bearer)",
			setup: func(t *testing.T) {
				require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "", AuthMode: AuthModeWorkflowOIDC, ExpiresAt: time.Now().Add(time.Hour)}))
			},
			url: "https://p.example.com",
		},
		{
			name:  "jctl fallback",
			setup: func(t *testing.T) { writeJctlConfig(t, "https://p.example.com", "jctl") },
			url:   "https://p.example.com",
		},
		{
			name:  "missing",
			setup: func(t *testing.T) {},
			url:   "https://none.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			tc.setup(t)

			old, errOld := lookupForBearerOld(tc.url)
			res, errNew := Resolve(tc.url, ForBearer)
			require.NoError(t, errOld)
			require.NoError(t, errNew)
			assertCredEqual(t, old, resolvedCred(res))

			// And the shim itself must agree with both.
			shim, errShim := Lookup(tc.url)
			require.NoError(t, errShim)
			assertCredEqual(t, old, shim)
		})
	}
}

// TestForDisplay_MatchesLookupAny mirrors the LookupAny contract: a token-less but
// non-expired cilock marker MATCHES (unlike ForBearer), expired still misses.
func TestForDisplay_MatchesLookupAny(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
		url   string
	}{
		{
			name: "token-less marker matches (display)",
			setup: func(t *testing.T) {
				require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "", AuthMode: AuthModeWorkflowOIDC, ExpiresAt: time.Now().Add(time.Hour)}))
			},
			url: "https://p.example.com",
		},
		{
			name: "expired still misses",
			setup: func(t *testing.T) {
				require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "t", ExpiresAt: time.Now().Add(-time.Hour)}))
			},
			url: "https://p.example.com",
		},
		{
			name:  "jctl fallback",
			setup: func(t *testing.T) { writeJctlConfig(t, "https://p.example.com", "jctl") },
			url:   "https://p.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			tc.setup(t)

			old, errOld := lookupForDisplayOld(tc.url)
			res, errNew := Resolve(tc.url, ForDisplay)
			require.NoError(t, errOld)
			require.NoError(t, errNew)
			assertCredEqual(t, old, resolvedCred(res))

			shim, errShim := LookupAny(tc.url)
			require.NoError(t, errShim)
			assertCredEqual(t, old, shim)
		})
	}
}

// TestIncludingExpired_MatchesLookupAnyIncludingExpired covers the tricky ordering:
// an expired cilock entry must be surfaced ONLY after the jctl fallback also
// misses — a valid jctl token must never be masked by a stale cilock entry.
func TestIncludingExpired_MatchesLookupAnyIncludingExpired(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
		url   string
	}{
		{
			name: "expired cilock surfaced as last resort",
			setup: func(t *testing.T) {
				require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "stale", ExpiresAt: time.Now().Add(-time.Hour)}))
			},
			url: "https://p.example.com",
		},
		{
			name: "valid jctl preferred over expired cilock (no masking)",
			setup: func(t *testing.T) {
				require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "stale", ExpiresAt: time.Now().Add(-time.Hour)}))
				writeJctlConfig(t, "https://p.example.com", "fresh-jctl")
			},
			url: "https://p.example.com",
		},
		{
			name:  "missing is nil",
			setup: func(t *testing.T) {},
			url:   "https://none.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			tc.setup(t)

			old, errOld := lookupIncludingExpiredOld(tc.url)
			res, errNew := Resolve(tc.url, IncludingExpired)
			require.NoError(t, errOld)
			require.NoError(t, errNew)
			assertCredEqual(t, old, resolvedCred(res))

			shim, errShim := LookupAnyIncludingExpired(tc.url)
			require.NoError(t, errShim)
			assertCredEqual(t, old, shim)
		})
	}
}

// --- pre-refactor reference implementations -------------------------------
//
// These are byte-for-byte copies of the ORIGINAL Lookup / LookupAny /
// LookupAnyIncludingExpired bodies (before the shim refactor), kept here so the
// tests above can prove the seam returns identical results to the code it
// replaced. They read the same load()/lookupJctl() the real path uses.

func lookupForBearerOld(platformURL string) (*Credential, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := s.Credentials[key]; ok && c.Token != "" && !c.Expired() {
		return &c, nil
	}
	if c, ok := lookupJctl(key); ok {
		return c, nil
	}
	return nil, nil
}

func lookupForDisplayOld(platformURL string) (*Credential, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := s.Credentials[key]; ok && !c.Expired() {
		return &c, nil
	}
	if c, ok := lookupJctl(key); ok {
		return c, nil
	}
	return nil, nil
}

func lookupIncludingExpiredOld(platformURL string) (*Credential, error) {
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := s.Credentials[key]; ok && !c.Expired() {
		return &c, nil
	}
	if c, ok := lookupJctl(key); ok {
		return c, nil
	}
	if c, ok := s.Credentials[key]; ok {
		return &c, nil
	}
	return nil, nil
}

// resolvedCred unwraps the embedded *Credential from a *Resolved, tolerating nil.
func resolvedCred(r *Resolved) *Credential {
	if r == nil {
		return nil
	}
	return r.Credential
}

// assertCredEqual asserts two *Credential pointers carry identical values (or are
// both nil) — the "byte-identical shim" proof.
func assertCredEqual(t *testing.T, want, got *Credential) {
	t.Helper()
	if want == nil {
		assert.Nil(t, got, "expected nil credential")
		return
	}
	require.NotNil(t, got, "expected a credential, got nil")
	assert.Equal(t, *want, *got, "credential must be byte-identical to the pre-refactor result")
}

// TestResolveExpiredCilock_OnlyAfterMiss is a direct unit test of the
// IncludingExpired last-resort helper: it must NOT fire when a usable credential
// exists at the provider level, and must return the cilock capability set when it
// does surface an expired entry (the entry still came from the cilock store).
func TestResolveExpiredCilock_DeclaresCilockCaps(t *testing.T) {
	isolateConfig(t)
	require.NoError(t, Save(Credential{PlatformURL: "https://p.example.com", Token: "stale", ExpiresAt: time.Now().Add(-time.Hour)}))

	res, err := resolveExpiredCilock("https://p.example.com")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "cilock", res.Source)
	assert.True(t, res.Expired(), "surfaced entry is the expired one")
	assert.True(t, res.Capabilities.Has(CapCanPinTrust), "an expired cilock entry still came from the cilock store")
}

// TestProviderError_Propagates proves resolveWith surfaces a provider's I/O error
// rather than treating it as a miss. We force load() to fail by planting a regular
// FILE where the "cilock" credential DIRECTORY is expected, so reading
// credentials.json under it errors with ENOTDIR (a non-IsNotExist error) — works
// regardless of where StorePath resolves on this platform.
func TestProviderError_Propagates(t *testing.T) {
	isolateConfig(t)

	path, err := StorePath()
	require.NoError(t, err)
	cilockDir := filepath.Dir(path) // .../cilock — make it a FILE, not a dir.
	require.NoError(t, os.MkdirAll(filepath.Dir(cilockDir), 0o700))
	require.NoError(t, os.WriteFile(cilockDir, []byte("x"), 0o600))

	res, err := Resolve("https://p.example.com", ForBearer)
	require.Error(t, err, "a real store I/O error must propagate, not be swallowed as a miss")
	assert.Nil(t, res)
}
