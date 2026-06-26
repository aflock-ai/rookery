// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// makeClaimsJWT builds an unsigned JWT-shaped string carrying the given claims
// so the client-side pre-flight decoder can be tested without real crypto. The
// signature segment is irrelevant — the pre-flight never verifies it.
func makeClaimsJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

// TestSecurity_Issue5991_ExpiredJWTReadsAsValid pins that a session JWT whose
// `exp` is already in the past produces an EXPIRED credential on BOTH the
// browser flow and the --token flow — instead of a synthetic now+30d expiry
// that ignores the real `exp` and replays a server-expired token for 30 days.
func TestSecurity_Issue5991_ExpiredJWTReadsAsValid(t *testing.T) {
	const platformURL = "https://platform.testifysec.com"
	loginAud := platformURL + "/login"

	// exp 1h in the past; aud is the correct login audience so the audience
	// gate (exercised separately) does not interfere with the expiry assertion.
	expired := makeClaimsJWT(t, map[string]any{
		"sub": "cred-1",
		"aud": loginAud,
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	// Browser flow: the credential the loopback callback builds must honor the
	// token's own `exp`, not a synthetic now+30d.
	browserCred := newBrowserCredential(platformURL, expired, map[string]string{})
	if !browserCred.Expired() {
		t.Fatalf("browser-flow credential with past exp must report Expired()==true; ExpiresAt=%s", browserCred.ExpiresAt)
	}

	// --token flow: the headless credential must likewise honor `exp`.
	tokenCred, err := TokenCredential(platformURL, expired, loginAud)
	if err != nil {
		t.Fatalf("TokenCredential returned error for expired-but-correct-aud token: %v", err)
	}
	if !tokenCred.Expired() {
		t.Fatalf("--token credential with past exp must report Expired()==true; ExpiresAt=%s", tokenCred.ExpiresAt)
	}
}

// TestSecurity_Issue5991_WrongAudienceTokenAccepted pins that a --token JWT
// minted for the Archivista UPLOAD audience is not silently stored as a live
// session bearer (confused deputy). An audience gate must reject it (or, at
// minimum, refuse to mint a usable session) so the stored credential never
// carries the wrong-audience token.
func TestSecurity_Issue5991_WrongAudienceTokenAccepted(t *testing.T) {
	const platformURL = "https://platform.testifysec.com"
	loginAud := platformURL + "/login"
	uploadAud := platformURL + "/archivista"

	wrongAud := makeClaimsJWT(t, map[string]any{
		"sub": "cred-1",
		"aud": uploadAud, // upload audience, NOT the login audience
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	cred, err := TokenCredential(platformURL, wrongAud, loginAud)
	// The aud gate must keep an upload-audience token from becoming a usable
	// session: either a hard error, or a credential that does not carry the
	// wrong-audience token as a live bearer.
	if err == nil && cred != nil && cred.Token == wrongAud {
		t.Fatalf("upload-audience token was accepted and stored as a session bearer (confused deputy)")
	}
}
