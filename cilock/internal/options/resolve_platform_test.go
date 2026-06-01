// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/spf13/cobra"

	// Register the fulcio signer provider so AddFlags wires up --signer-fulcio-url,
	// the flag the keyless exchange targets.
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

func newRunCmd(t *testing.T) (*cobra.Command, *RunOptions) {
	t.Helper()
	ro := &RunOptions{}
	cmd := &cobra.Command{Use: "run"}
	ro.AddFlags(cmd)
	return cmd, ro
}

func fulcioURL(t *testing.T, cmd *cobra.Command) string {
	t.Helper()
	f := cmd.Flags().Lookup("signer-fulcio-url")
	if f == nil {
		t.Fatal("signer-fulcio-url flag not registered")
	}
	return f.Value.String()
}

// resolveSignTokenStub answers the /oauth/sign-token exchange so the keyless
// path runs end-to-end against an in-process server.
func resolveSignTokenStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/oauth/sign-token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": fakeSignToken, "token_type": "oidc"})
			return
		}
		http.NotFound(w, r)
	}))
}

// resolveSeedCredential simulates a prior `cilock login` to platformURL.
func resolveSeedCredential(t *testing.T, platformURL string) {
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

// TestResolvePlatformDefaults_FulcioURLDerivedOnlyWhenSelected pins both halves
// of the Codex findings on #5326. Deriving --signer-fulcio-url marks that flag
// "changed", which SELECTS the fulcio signer (selection keys off changed
// signer-* flags, see cli.providersFromFlags). So the invariant is:
//
//   - fulcio NOT selected (local/KMS, no login)  → leave the URL empty, or we'd
//     implicitly select fulcio and break local/KMS signing with "no token
//     provided" (Codex finding #1).
//   - fulcio SELECTED (keyless exchange OR an explicit --signer-fulcio-token)  →
//     supply the platform URL, or signer construction fails with "fulcio URL
//     must include a host" (Codex finding #2 — the explicit-token regression).
func TestResolvePlatformDefaults_FulcioURLDerivedOnlyWhenSelected(t *testing.T) {
	t.Run("NOT logged in, no fulcio flag: url stays empty (local/KMS signing preserved)", func(t *testing.T) {
		isolateCredentialStore(t) // no stored session
		cmd, ro := newRunCmd(t)
		// default platform url (prod), simulating `cilock run -k key.pem` with no login
		if err := cmd.ParseFlags(nil); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got := fulcioURL(t, cmd); got != "" {
			t.Fatalf("not-logged-in run must NOT derive a fulcio url (would select the fulcio signer), got %q", got)
		}
		if cmd.Flags().Changed("signer-fulcio-url") {
			t.Fatal("not-logged-in run must NOT mark signer-fulcio-url changed (would select fulcio + fail 'no token provided')")
		}
	})

	t.Run("explicit --signer-fulcio-token, NOT logged in: platform still supplies the url", func(t *testing.T) {
		// Codex finding #2: an explicit token selects fulcio; without URL derivation
		// the signer is built with an empty host and fails "fulcio URL must include
		// a host". A CI run `cilock run --platform-url X --signer-fulcio-token T`
		// must work without also passing --signer-fulcio-url.
		isolateCredentialStore(t) // no login — purely the explicit-token path
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{
			"--platform-url", "https://platform.example",
			"--signer-fulcio-token", "ci-oidc-token",
		}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got, want := fulcioURL(t, cmd), "https://platform.example"; got != want {
			t.Fatalf("explicit-token run must derive fulcio url from the platform, got %q want %q", got, want)
		}
		if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "ci-oidc-token" {
			t.Fatalf("explicit --signer-fulcio-token must be preserved, got %q", got)
		}
	})

	t.Run("logged in: keyless exchange derives fulcio url + token together", func(t *testing.T) {
		isolateCredentialStore(t)
		srv := resolveSignTokenStub(t)
		defer srv.Close()
		resolveSeedCredential(t, srv.URL)

		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got, want := fulcioURL(t, cmd), srv.URL; got != want {
			t.Fatalf("logged-in keyless run should derive fulcio url %q, got %q", want, got)
		}
		if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != fakeSignToken {
			t.Fatalf("logged-in keyless run should set the exchanged token, got %q", got)
		}
	})

	t.Run("explicit signer-fulcio-url is never clobbered", func(t *testing.T) {
		isolateCredentialStore(t)
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{
			"--platform-url", "http://localhost:8083",
			"--signer-fulcio-url", "https://custom.example/fulcio",
		}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got, want := fulcioURL(t, cmd), "https://custom.example/fulcio"; got != want {
			t.Fatalf("explicit --signer-fulcio-url should win, got %q want %q", got, want)
		}
	})

	t.Run("offline platform-url empty does not derive fulcio url", func(t *testing.T) {
		isolateCredentialStore(t)
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", ""}); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if got := fulcioURL(t, cmd); got != "" {
			t.Fatalf("offline (--platform-url \"\") must leave fulcio url empty, got %q", got)
		}
	})
}
