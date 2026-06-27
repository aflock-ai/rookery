// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"

	// Register both providers so AddFlags wires --signer-fulcio-* AND
	// --signer-file-* — the exact flag set that triggers the "only one signer is
	// supported" collision this test guards against.
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// signerProvidersFromChanged derives the distinct signer providers that
// cli.providersFromFlags would compute from the command's CHANGED signer-* flags.
// cli/sign.go feeds exactly this set to loadSigners, and runSign aborts with
// "only one signer is supported" when it holds more than one. The classifier lives
// in package cli (importing it here would be a cycle), so we reproduce its one rule:
// a provider is the second '-'-delimited segment of any changed "signer-*" flag.
// Asserting against this set ties the test to the real failure condition rather
// than a proxy.
func signerProvidersFromChanged(cmd *cobra.Command) map[string]struct{} {
	providers := make(map[string]struct{})
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if !strings.HasPrefix(f.Name, "signer-") {
			return
		}
		parts := strings.Split(f.Name, "-")
		if len(parts) < 2 {
			return
		}
		providers[parts[1]] = struct{}{}
	})
	return providers
}

// TestSignResolvePlatformDefaults_ExplicitFileSignerWinsEveryLoginPath is the
// end-to-end pin for the #6028 regression: a logged-in / ambient-CI `cilock sign
// -k key.pem` must resolve EXACTLY ONE signer (the file signer), so runSign never
// hits "only one signer is supported". It exercises every path that could attach
// an ambient/stored Fulcio token alongside the explicit file key:
//
//   - stored browser session  (auth.LookupAny ⇒ session exchange branch)
//   - workflow-identity marker (AuthModeWorkflowOIDC ⇒ ambient mint branch)
//   - ambient CI env only      (no stored credential, ACTIONS_ID_TOKEN_* present)
//
// On each, the keyless wiring must stand down: no signer-fulcio-* flag changed,
// no platform TSA appended, no network exchange attempted. The keyless-still-works
// cases live alongside in sign_signtoken_test.go and sign_workflow_keyless_test.go.
func TestSignResolvePlatformDefaults_ExplicitFileSignerWinsEveryLoginPath(t *testing.T) {
	const platform = "https://platform.example.com"

	t.Run("stored browser session", func(t *testing.T) {
		isolateCredentialStore(t)
		exchanged := int32(0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/sign-token" {
				atomic.AddInt32(&exchanged, 1)
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
		if err := cmd.ParseFlags([]string{
			"--platform-url", srv.URL,
			"--signer-file-key-path", "/tmp/local-key.pem",
		}); err != nil {
			t.Fatal(err)
		}
		so.ResolvePlatformDefaults(cmd)

		assertSingleFileSigner(t, cmd, so)
		if atomic.LoadInt32(&exchanged) != 0 {
			t.Fatal("file signer must suppress the stored-session sign-token exchange")
		}
	})

	t.Run("workflow-identity marker", func(t *testing.T) {
		isolateCredentialStore(t)
		stubGitHubOIDC(t)
		if err := auth.Save(auth.Credential{
			PlatformURL: platform,
			AuthMode:    auth.AuthModeWorkflowOIDC,
			ExpiresAt:   time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed workflow-identity credential: %v", err)
		}

		cmd, so := newSignCmd(t)
		if err := cmd.ParseFlags([]string{
			"--platform-url", platform,
			"--signer-file-key-path", "/tmp/local-key.pem",
		}); err != nil {
			t.Fatal(err)
		}
		so.ResolvePlatformDefaults(cmd)

		assertSingleFileSigner(t, cmd, so)
	})

	t.Run("ambient CI env only", func(t *testing.T) {
		isolateCredentialStore(t) // no stored credential — pure ambient identity
		stubGitHubOIDC(t)

		cmd, so := newSignCmd(t)
		if err := cmd.ParseFlags([]string{
			"--platform-url", platform,
			"--signer-file-key-path", "/tmp/local-key.pem",
		}); err != nil {
			t.Fatal(err)
		}
		so.ResolvePlatformDefaults(cmd)

		assertSingleFileSigner(t, cmd, so)
	})
}

// assertSingleFileSigner asserts the post-resolve flag state yields exactly one
// signer provider — {file} — with no Fulcio wiring and no platform TSA, the exact
// invariant runSign needs to avoid "only one signer is supported".
func assertSingleFileSigner(t *testing.T, cmd *cobra.Command, so *SignOptions) {
	t.Helper()
	providers := signerProvidersFromChanged(cmd)
	if len(providers) != 1 {
		t.Fatalf("resolved signer providers = %v, want exactly {file} (explicit signer must win, one signer only)", providers)
	}
	if _, ok := providers["file"]; !ok {
		t.Fatalf("resolved signer providers = %v, want {file}", providers)
	}
	if cmd.Flags().Changed("signer-fulcio-token") || cmd.Flags().Changed("signer-fulcio-url") {
		t.Fatal("explicit file signer must not mark any signer-fulcio-* flag changed")
	}
	if len(so.TimestampServers) != 0 {
		t.Fatalf("explicit file signer must not derive a platform TSA, got %v", so.TimestampServers)
	}
}
