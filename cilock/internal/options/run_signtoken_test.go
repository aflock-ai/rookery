// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"

	// Register the fulcio signer provider so AddFlags wires up the
	// --signer-fulcio-* flags the keyless exchange targets.
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// isolateCredentialStore points cilock's credential store at a throwaway dir so
// the test never reads or writes the developer's real ~/.config/cilock store.
func isolateCredentialStore(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	// auth.StorePath derives from os.UserConfigDir, which honors XDG_CONFIG_HOME
	// on Linux and $HOME (Application Support) on macOS — set both so the
	// isolation holds on either CI host.
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
}

// fakeSignToken is a syntactically-valid JWT the stub sign-token endpoint hands
// back. ResolvePlatformDefaults only ferries it to the --signer-fulcio-token
// flag; it never parses it, so any non-empty value proves the wiring.
const fakeSignToken = "eyJhbGciOiJFUzI1NiJ9.eyJlbWFpbCI6ImFsaWNlQGFjbWUuY29tIn0.sig"

// TestResolvePlatformDefaults_ExchangesSignToken pins GAP A: after `cilock
// login`, a minimal-flag `cilock run` must exchange its stored platform
// credential at <platform>/oauth/sign-token and feed the returned OIDC
// token to the Fulcio signer (the --signer-fulcio-token flag). Before this the
// flag stayed empty and the signer failed with "no token provided".
func TestResolvePlatformDefaults_ExchangesSignToken(t *testing.T) {
	isolateCredentialStore(t)

	var gotAuth atomic.Value // string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/oauth/sign-token" {
			gotAuth.Store(r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": fakeSignToken, "token_type": "oidc"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// Simulate a prior `cilock login` to this platform: a stored, sign-scoped
	// API credential keyed by the platform URL.
	require := func(err error, msg string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", msg, err)
		}
	}
	require(auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}), "seed credential")

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	f := cmd.Flags().Lookup("signer-fulcio-token")
	if f == nil {
		t.Fatal("signer-fulcio-token flag not registered")
	}
	if got := f.Value.String(); got != fakeSignToken {
		t.Fatalf("signer-fulcio-token = %q, want %q (the exchanged OIDC token)", got, fakeSignToken)
	}

	// The stored credential — not the OIDC token — must be the bearer presented
	// to the exchange endpoint.
	if got, _ := gotAuth.Load().(string); got != "Bearer stored-session-credential" {
		t.Fatalf("exchange Authorization header = %q, want %q", got, "Bearer stored-session-credential")
	}
}

// TestResolvePlatformDefaults_ExplicitFulcioTokenWins ensures an operator who
// passes --signer-fulcio-token keeps full control: the login-exchange must not
// clobber an explicit token.
func TestResolvePlatformDefaults_ExplicitFulcioTokenWins(t *testing.T) {
	isolateCredentialStore(t)

	exchanged := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/sign-token" {
			atomic.AddInt32(&exchanged, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": fakeSignToken})
	}))
	defer srv.Close()

	if err := auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--signer-fulcio-token", "operator-supplied-token",
	}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "operator-supplied-token" {
		t.Fatalf("explicit --signer-fulcio-token should win, got %q", got)
	}
	if atomic.LoadInt32(&exchanged) != 0 {
		t.Fatal("must not call the sign-token exchange when an explicit token is set")
	}
}

// signTokenStub returns an httptest server that answers the sign-token exchange,
// so ResolvePlatformDefaults's logged-in branch runs end to end.
func signTokenStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": fakeSignToken})
	}))
}

func seedLoginCredential(t *testing.T, platformURL string) {
	t.Helper()
	if err := auth.Save(auth.Credential{
		PlatformURL: platformURL,
		Token:       "stored-session-credential",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

// TestResolvePlatformDefaults_ArchivistaOnWhenLoggedIn pins the "stored
// attestation is the point of logging in" UX: a logged-in minimal-flag run
// enables Archivista without --enable-archivista.
func TestResolvePlatformDefaults_ArchivistaOnWhenLoggedIn(t *testing.T) {
	isolateCredentialStore(t)
	srv := signTokenStub(t)
	defer srv.Close()
	seedLoginCredential(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if !ro.ArchivistaOptions.Enable {
		t.Fatal("Archivista should be enabled by default when logged in")
	}
}

// TestResolvePlatformDefaults_ArchivistaExplicitFalseWins ensures a logged-in
// user can still opt out of storage with --enable-archivista=false.
func TestResolvePlatformDefaults_ArchivistaExplicitFalseWins(t *testing.T) {
	isolateCredentialStore(t)
	srv := signTokenStub(t)
	defer srv.Close()
	seedLoginCredential(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL, "--enable-archivista=false"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if ro.ArchivistaOptions.Enable {
		t.Fatal("explicit --enable-archivista=false must win over the logged-in default")
	}
}

// TestResolvePlatformDefaults_ArchivistaOffWhenLoggedOut preserves the
// offline/no-platform default: without a session, Archivista stays off.
func TestResolvePlatformDefaults_ArchivistaOffWhenLoggedOut(t *testing.T) {
	isolateCredentialStore(t)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if ro.ArchivistaOptions.Enable {
		t.Fatal("Archivista must stay off when there is no login session")
	}
}
