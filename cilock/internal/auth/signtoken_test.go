// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestExchangeSignToken_PersistsEmail proves identity is passed along: the
// server resolves the signing email and returns it; ExchangeSignToken persists
// it onto the stored session when it has none, so a headless `cilock login
// --token` (which can't resolve identity) later lets `cilock verify` default
// the expected signer to it.
func TestExchangeSignToken_PersistsEmail(t *testing.T) {
	isolateConfig(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":           "minted.oidc.token",
			"email":           "alice@acme-corp.com",
			"assurance_level": "aal1",
		})
	}))
	defer srv.Close()

	// A headless login stored a credential with NO email.
	if err := Save(Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		AuthMode:    AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	tok, err := ExchangeSignToken(srv.URL, "stored-session-credential")
	if err != nil {
		t.Fatalf("ExchangeSignToken: %v", err)
	}
	if tok != "minted.oidc.token" {
		t.Fatalf("token = %q, want the minted token", tok)
	}

	cred, err := Lookup(srv.URL)
	if err != nil || cred == nil {
		t.Fatalf("lookup after exchange: cred=%v err=%v", cred, err)
	}
	if cred.Email != "alice@acme-corp.com" {
		t.Fatalf("email = %q, want it persisted from the exchange response", cred.Email)
	}
}

// TestExchangeSignToken_DoesNotClobberEmail ensures an existing (browser-login)
// email is never overwritten by the exchange.
func TestExchangeSignToken_DoesNotClobberEmail(t *testing.T) {
	isolateConfig(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "t", "email": "server@acme.com"})
	}))
	defer srv.Close()

	if err := Save(Credential{
		PlatformURL: srv.URL,
		Token:       "cred",
		Email:       "browser@acme.com",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	if _, err := ExchangeSignToken(srv.URL, "cred"); err != nil {
		t.Fatalf("ExchangeSignToken: %v", err)
	}

	cred, _ := Lookup(srv.URL)
	if cred == nil || cred.Email != "browser@acme.com" {
		t.Fatalf("existing email must not be clobbered, got %v", cred)
	}
}
