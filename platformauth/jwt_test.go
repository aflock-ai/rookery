// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintJWT builds an unsigned (alg=none-style) three-segment token whose payload
// carries the given claims. Signature verification is never done client-side, so
// a dummy signature segment is fine.
func mintJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(body)
	return header + "." + payload + ".sig"
}

func TestTokenCredential_RejectsWrongAudience(t *testing.T) {
	tok := mintJWT(t, map[string]any{"aud": "https://p.example.com/upload"})
	_, err := TokenCredential("https://p.example.com", tok, "https://p.example.com/login")
	require.Error(t, err, "a token minted for a different audience must be rejected as a login session")
}

func TestTokenCredential_AcceptsMatchingAudience(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).Unix()
	tok := mintJWT(t, map[string]any{"aud": "https://p.example.com/login", "exp": exp})
	cred, err := TokenCredential("https://p.example.com", tok, "https://p.example.com/login")
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, AuthModeToken, cred.AuthMode)
	assert.WithinDuration(t, time.Unix(exp, 0), cred.ExpiresAt, time.Second, "expiry comes from the token's exp claim")
}

func TestTokenCredential_NoDecodableAudFailsOpen(t *testing.T) {
	// A non-JWT string carries no decodable aud → fails open (server is authority).
	_, err := TokenCredential("https://p.example.com", "opaque-not-a-jwt", "https://p.example.com/login")
	require.NoError(t, err, "a token with no decodable aud must fail open")
}

func TestTokenCredential_EmptyTokenRejected(t *testing.T) {
	_, err := TokenCredential("https://p.example.com", "   ", "aud")
	require.Error(t, err)
}

func TestTokenExp_FallbackTTLWhenNoExp(t *testing.T) {
	tok := mintJWT(t, map[string]any{"aud": "https://p.example.com/login"})
	cred, err := TokenCredential("https://p.example.com", tok, "https://p.example.com/login")
	require.NoError(t, err)
	// No exp claim → bounded default TTL window (not non-expiring).
	assert.WithinDuration(t, time.Now().Add(defaultSessionTTL), cred.ExpiresAt, time.Minute)
	assert.False(t, cred.Expired())
}
