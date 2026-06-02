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
	// --signer-fulcio-* flags the keyless wiring targets.
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// stubGitHubOIDC stands up a fake GitHub Actions OIDC token endpoint and points
// the ambient env vars at it, returning the token it will hand back plus an
// accessor for the audience the caller requested.
func stubGitHubOIDC(t *testing.T) (token string, audience func() string) {
	t.Helper()
	const minted = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3b3JrZmxvdyJ9.sig"
	var gotAudience atomic.Value // string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience.Store(r.URL.Query().Get("audience"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": minted})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ghs-fake-bearer")
	return minted, func() string { s, _ := gotAudience.Load().(string); return s }
}

// TestSignResolvePlatformDefaults_BareAmbientKeyless is the regression test for
// the v2.0.0-rc1 release failure. The release pipeline runs `cilock sign
// --platform-url <staging>` with NO `cilock login` step — it relies purely on
// the ambient GitHub Actions OIDC identity (permissions: id-token: write). Before
// the fix, ResolvePlatformDefaults only consulted the stored session via
// auth.Lookup and applied a token solely `if loggedIn`, so with no stored
// credential it wired no signer and signing died with
// "failed to load signer: failed to load any signers" (mirroring the bug that
// `cilock run` already fixed). After the fix it mints a fresh ambient OIDC token
// (Fulcio audience) and feeds it to the fulcio signer — no manual flags.
func TestSignResolvePlatformDefaults_BareAmbientKeyless(t *testing.T) {
	isolateCredentialStore(t) // no stored credential — pure ambient CI identity
	minted, audience := stubGitHubOIDC(t)

	const platform = "https://platform.aws-sandbox-staging.testifysec.dev"
	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", platform}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != minted {
		t.Fatalf("signer-fulcio-token = %q, want the minted ambient GHA OIDC token %q", got, minted)
	}
	if got := cmd.Flags().Lookup("signer-fulcio-url").Value.String(); got != platform {
		t.Fatalf("signer-fulcio-url = %q, want platform root %q", got, platform)
	}
	if got := audience(); got != "sigstore" {
		t.Fatalf("minted OIDC audience = %q, want %q (Fulcio signing audience)", got, "sigstore")
	}
	if len(so.TimestampServers) == 0 {
		t.Fatal("keyless platform signing must derive the platform TSA, got none")
	}
}

// TestSignResolvePlatformDefaults_WorkflowIdentityKeyless covers the same ambient
// minting after an explicit `cilock login --workflow-identity` (a stored marker
// carrying AuthModeWorkflowOIDC and an empty token): LookupAny returns it, and
// the workflow-identity branch must mint rather than fall into the session
// exchange (which has no token to trade).
func TestSignResolvePlatformDefaults_WorkflowIdentityKeyless(t *testing.T) {
	isolateCredentialStore(t)
	minted, audience := stubGitHubOIDC(t)

	const platform = "https://platform.sandbox.example.com"
	if err := auth.Save(auth.Credential{
		PlatformURL: platform,
		AuthMode:    auth.AuthModeWorkflowOIDC,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed workflow-identity credential: %v", err)
	}

	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", platform}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != minted {
		t.Fatalf("signer-fulcio-token = %q, want the minted GHA OIDC token %q", got, minted)
	}
	if got := cmd.Flags().Lookup("signer-fulcio-url").Value.String(); got != platform {
		t.Fatalf("signer-fulcio-url = %q, want platform root %q", got, platform)
	}
	if got := audience(); got != "sigstore" {
		t.Fatalf("minted OIDC audience = %q, want %q", got, "sigstore")
	}
}

// TestSignResolvePlatformDefaults_PlatformDisabledNoMint proves --platform-url ""
// opts out entirely: even with an ambient OIDC identity available, no token is
// minted and no fulcio signer is wired (a local `cilock sign -k key.pem` path).
func TestSignResolvePlatformDefaults_PlatformDisabledNoMint(t *testing.T) {
	isolateCredentialStore(t)
	stubGitHubOIDC(t)

	cmd, so := newSignCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", ""}); err != nil {
		t.Fatal(err)
	}
	so.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "" {
		t.Fatalf("signer-fulcio-token = %q, want empty (platform disabled)", got)
	}
	if len(so.TimestampServers) != 0 {
		t.Fatalf("TimestampServers = %v, want none (platform disabled)", so.TimestampServers)
	}
}
