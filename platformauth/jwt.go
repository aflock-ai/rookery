// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// defaultSessionTTL bounds a session credential whose JWT carries no decodable
// `exp` claim. A token with a real `exp` is gated on its own expiry; only a
// token with no usable expiry falls back to this window, so a missing claim
// never yields a non-expiring credential.
const defaultSessionTTL = 30 * 24 * time.Hour

// sessionTTLEnvVar lets an operator TIGHTEN the fallback session window for
// tokens with no decodable `exp` (e.g. a compliance regime that mandates a
// shorter maximum session lifetime). It accepts a Go duration string
// (time.ParseDuration), e.g. "8h".
const sessionTTLEnvVar = "JUDGE_SESSION_TTL"

// sessionTTL resolves the fallback window applied to a session credential whose
// JWT carries no decodable `exp` claim. It honors JUDGE_SESSION_TTL ONLY as a
// tighten-only override: the env value is used solely when it parses and is
// strictly positive AND no greater than defaultSessionTTL. defaultSessionTTL is
// a SECURITY ceiling for a token whose real expiry can't be read — operators may
// shorten it for compliance, but must never be able to extend it (which would
// keep an un-revocable credential live longer than the platform intends). Any
// absent, unparseable, zero/negative, or out-of-range (longer) value silently
// falls back to defaultSessionTTL.
func sessionTTL() time.Duration {
	raw := os.Getenv(sessionTTLEnvVar)
	if raw == "" {
		return defaultSessionTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > defaultSessionTTL {
		return defaultSessionTTL
	}
	return d
}

// TokenCredential builds a session credential from an explicit --token (the
// CI/headless login path), validating the JWT client-side before it is stored
// (GHSA #5991):
//
//   - ExpiresAt is taken from the token's own `exp` claim so a server-expired
//     token is recognized as expired rather than replayed for a synthetic
//     now+TTL window; a token with no decodable `exp` falls back to the bounded
//     defaultSessionTTL.
//   - The `aud` claim must include loginAudience (the platform's dedicated login
//     audience). A token minted for a different audience — e.g. the Archivista
//     upload audience — is REJECTED rather than silently stored as a session
//     bearer, closing the confused-deputy gap. A token carrying no decodable
//     `aud` fails open (the server stays the authority).
//
// The token is decoded WITHOUT signature verification — this is a pre-flight;
// the platform remains the authority on signature and issuer.
func TokenCredential(platformURL, token, loginAudience string) (*Credential, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	if !tokenHasAudience(token, loginAudience) {
		return nil, fmt.Errorf("token audience does not match the platform login audience %q "+
			"(a token minted for a different audience — e.g. attestation upload — must not be "+
			"used as a login session); obtain a session token via an interactive login", loginAudience)
	}
	expiresAt := time.Now().Add(sessionTTL())
	if exp, ok := tokenExp(token); ok {
		expiresAt = exp
	}
	return &Credential{
		PlatformURL: platformURL,
		Token:       token,
		AuthMode:    AuthModeToken,
		ExpiresAt:   expiresAt,
		// This is the only construction path that checks the token's `aud` against
		// the platform login audience (the tokenHasAudience guard above), so it is
		// the only one that may vouch for the audience. Every other write path
		// (browser/device flows, legacy migration) leaves this false — fail-closed.
		AudienceValidated: true,
	}, nil
}

// decodeClaims decodes a JWT payload WITHOUT verifying the signature into the raw
// claim map. ok is false when the token isn't a decodable three-segment JWT whose
// payload is a JSON object. This is a pre-flight only — the platform remains the
// authority on signature/issuer.
func decodeClaims(token string) (claims map[string]json.RawMessage, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c map[string]json.RawMessage
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, false
	}
	return c, true
}

// tokenExp extracts the `exp` claim (NumericDate — seconds since the Unix epoch)
// from a JWT payload without verifying the signature. ok is false when the token
// can't be decoded or carries no numeric `exp`. The returned time is the real
// server-side expiry, so a credential can be gated on it rather than a synthetic
// client-side window that ignores when the platform actually revokes the session.
func tokenExp(token string) (exp time.Time, ok bool) {
	claims, decoded := decodeClaims(token)
	if !decoded {
		return time.Time{}, false
	}
	raw, present := claims["exp"]
	if !present {
		return time.Time{}, false
	}
	var secs float64
	if err := json.Unmarshal(raw, &secs); err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0), true
}

// tokenAud extracts the `aud` claim from a JWT payload without verifying the
// signature. Per RFC 7519 `aud` may be a single string or an array of strings;
// both shapes are returned as a slice. ok is false when the token can't be
// decoded or carries no `aud`.
func tokenAud(token string) (aud []string, ok bool) {
	claims, decoded := decodeClaims(token)
	if !decoded {
		return nil, false
	}
	raw, present := claims["aud"]
	if !present {
		return nil, false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, true
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, true
	}
	return nil, false
}

// tokenHasAudience reports whether the token's `aud` claim contains want. When
// the token carries no decodable `aud` it fails OPEN (returns true) — a parsing
// quirk must not block a token the server would accept; the server remains the
// authority. Only a token that DOES declare an audience set NOT containing want
// is rejected, which is the confused-deputy case this gate exists to catch.
func tokenHasAudience(token, want string) bool {
	auds, ok := tokenAud(token)
	if !ok {
		return true // no decodable aud — let the server decide
	}
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}
