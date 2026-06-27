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
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"

	"github.com/spf13/cobra"
)

// newSignCmd builds a cobra command with the sign options' flags registered,
// mirroring how SignCmd wires them, so ResolvePlatformDefaults sees the same
// flag set at runtime.
func newSignCmd(t *testing.T) (*cobra.Command, *SignOptions) {
	t.Helper()
	so := &SignOptions{}
	cmd := &cobra.Command{Use: "sign"}
	so.AddFlags(cmd)
	return cmd, so
}

// TestSignResolvePlatformDefaults_ExchangesSignToken proves `cilock sign` signs
// keyless after `cilock login`: a minimal-flag sign against the platform must
// exchange the stored session credential at <platform>/oauth/sign-token and feed
// the returned OIDC token to the Fulcio signer (--signer-fulcio-token), and
// derive the platform TSA.
func TestSignResolvePlatformDefaults_ExchangesSignToken(t *testing.T) {
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

	if err := auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != fakeSignToken {
		t.Fatalf("signer-fulcio-token = %q, want %q (the exchanged OIDC token)", got, fakeSignToken)
	}
	if got, _ := gotAuth.Load().(string); got != "Bearer stored-session-credential" {
		t.Fatalf("exchange Authorization header = %q, want %q", got, "Bearer stored-session-credential")
	}
	// The platform TSA must be derived so the keyless policy signature is timestamped.
	if len(so.TimestampServers) != 1 || so.TimestampServers[0] != srv.URL+"/api/v1/timestamp" {
		t.Fatalf("timestamp servers = %v, want [%s/api/v1/timestamp]", so.TimestampServers, srv.URL)
	}
}

// TestSignResolvePlatformDefaults_ExplicitFulcioTokenWins ensures an operator who
// passes --signer-fulcio-token keeps control: the login exchange must not clobber
// it, and no exchange call is made.
func TestSignResolvePlatformDefaults_ExplicitFulcioTokenWins(t *testing.T) {
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

	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--signer-fulcio-token", "operator-supplied-token",
	}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "operator-supplied-token" {
		t.Fatalf("explicit --signer-fulcio-token should win, got %q", got)
	}
	if atomic.LoadInt32(&exchanged) != 0 {
		t.Fatal("must not call the sign-token exchange when an explicit token is set")
	}
}

// TestSignResolvePlatformDefaults_FileSignerSuppressesLoggedInKeyless pins the
// offline/local-key tutorial path: after `cilock login`, an explicit file signer
// still wins. The stored session must not auto-select Fulcio or add a platform
// TSA to this local signature; users can opt into platform signing by omitting
// -k, or opt out explicitly with --platform-url "".
func TestSignResolvePlatformDefaults_FileSignerSuppressesLoggedInKeyless(t *testing.T) {
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

	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--signer-file-key-path", "/tmp/local-key.pem",
	}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "" {
		t.Fatalf("file signer must suppress logged-in Fulcio token, got %q", got)
	}
	if cmd.Flags().Changed("signer-fulcio-token") || cmd.Flags().Changed("signer-fulcio-url") {
		t.Fatal("file signer must not mark any signer-fulcio-* flag changed")
	}
	if atomic.LoadInt32(&exchanged) != 0 {
		t.Fatal("must not call the sign-token exchange when a file signer is explicit")
	}
	if len(so.TimestampServers) != 0 {
		t.Fatalf("file signer path must not derive a platform TSA, got %v", so.TimestampServers)
	}
}

// TestSignResolvePlatformDefaults_NotLoggedInDoesNotSelectFulcio is the
// regression test for the critical Codex finding on #5326: a `cilock sign`
// while NOT logged in must not touch any signer-fulcio-* flag, or it implicitly
// selects the fulcio signer (selection keys off changed signer-* flags) and
// breaks local/KMS signing with "no token provided".
func TestSignResolvePlatformDefaults_NotLoggedInDoesNotSelectFulcio(t *testing.T) {
	isolateCredentialStore(t) // no stored session

	cmd, so := newSignCmd(t)
	// default platform url (prod), simulating `cilock sign -k key.pem` with no login
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if cmd.Flags().Changed("signer-fulcio-url") {
		t.Fatal("not-logged-in sign must NOT mark signer-fulcio-url changed (would select the fulcio signer)")
	}
	if cmd.Flags().Changed("signer-fulcio-token") {
		t.Fatal("not-logged-in sign must NOT set signer-fulcio-token")
	}
	if got := cmd.Flags().Lookup("signer-fulcio-url").Value.String(); got != "" {
		t.Fatalf("not-logged-in sign must leave fulcio url empty, got %q", got)
	}
	// And it must NOT append a platform TSA to a purely local sign.
	if len(so.TimestampServers) != 0 {
		t.Fatalf("not-logged-in sign must not derive a platform TSA, got %v", so.TimestampServers)
	}
}

// TestSignResolvePlatformDefaults_ExplicitTokenNotLoggedInDerivesURL is the
// regression test for Codex finding #2: an explicit --signer-fulcio-token selects
// the fulcio signer, so `cilock sign --platform-url X --signer-fulcio-token T`
// (no login) must still get the platform Fulcio URL, or signer construction fails
// with "fulcio URL must include a host".
func TestSignResolvePlatformDefaults_ExplicitTokenNotLoggedInDerivesURL(t *testing.T) {
	isolateCredentialStore(t) // no login — purely the explicit-token path

	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", "https://platform.example",
		"--signer-fulcio-token", "ci-oidc-token",
	}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got, want := cmd.Flags().Lookup("signer-fulcio-url").Value.String(), "https://platform.example"; got != want {
		t.Fatalf("explicit-token sign must derive fulcio url from the platform, got %q want %q", got, want)
	}
	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "ci-oidc-token" {
		t.Fatalf("explicit --signer-fulcio-token must be preserved, got %q", got)
	}
}

// TestSignResolvePlatformDefaults_OptOut verifies --platform-url "" disables all
// platform derivation: no fulcio URL, no TSA, no exchange.
func TestSignResolvePlatformDefaults_OptOut(t *testing.T) {
	isolateCredentialStore(t)

	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", ""}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-url").Value.String(); got != "" {
		t.Fatalf("opt-out must not derive a fulcio url, got %q", got)
	}
	if len(so.TimestampServers) != 0 {
		t.Fatalf("opt-out must not derive a TSA, got %v", so.TimestampServers)
	}
}
