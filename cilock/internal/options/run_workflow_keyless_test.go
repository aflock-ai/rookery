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

// fakeWorkflowOIDC is the token the stub GitHub Actions OIDC endpoint hands back.
const fakeWorkflowOIDC = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3b3JrZmxvdyJ9.sig"

// TestResolvePlatformDefaults_WorkflowIdentityKeyless pins the keyless UX for
// ambient CI identity: after `cilock login --workflow-identity` against a
// non-default platform, a minimal-flag `cilock run` must mint a GitHub Actions
// OIDC token (Fulcio signing audience) and feed it to the fulcio signer — with
// NO manual --signer-fulcio-* flags. Before this, a workflow-identity credential
// (empty stored token) fell into the session-exchange path, set no token, and
// `cilock run` failed with "failed to load any signers".
func TestResolvePlatformDefaults_WorkflowIdentityKeyless(t *testing.T) {
	isolateCredentialStore(t)

	var gotAudience atomic.Value // string
	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience.Store(r.URL.Query().Get("audience"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": fakeWorkflowOIDC})
	}))
	defer oidcSrv.Close()
	// Simulate the GitHub Actions OIDC environment (permissions: id-token: write).
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidcSrv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ghs-fake-bearer")

	// A prior `cilock login --workflow-identity` to a NON-default platform:
	// a workflow-OIDC credential intentionally carries no stored token.
	const platform = "https://platform.sandbox.example.com"
	if err := auth.Save(auth.Credential{
		PlatformURL: platform,
		AuthMode:    auth.AuthModeWorkflowOIDC,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed workflow-identity credential: %v", err)
	}

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", platform}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != fakeWorkflowOIDC {
		t.Fatalf("signer-fulcio-token = %q, want the minted GHA OIDC token %q", got, fakeWorkflowOIDC)
	}
	// The signer needs the platform's Fulcio URL (platform root) or it fails with
	// "fulcio URL must include a host".
	if got := cmd.Flags().Lookup("signer-fulcio-url").Value.String(); got != platform {
		t.Fatalf("signer-fulcio-url = %q, want platform root %q", got, platform)
	}
	// The OIDC token must carry the Fulcio signing audience, not the archivista or
	// login audience (confused-deputy hazard).
	if got, _ := gotAudience.Load().(string); got != "sigstore" {
		t.Fatalf("minted OIDC audience = %q, want %q", got, "sigstore")
	}
	// A workflow-identity marker maps to no platform tenant, so Archivista upload
	// would 401 and `cilock run` treats that as fatal. Auto-enabling it would break
	// the minimal-flag ambient UX, so a workflow login must NOT default it on.
	if ro.ArchivistaOptions.Enable {
		t.Fatal("workflow-identity must NOT auto-enable Archivista (no tenant; upload would 401 and is fatal)")
	}
}

// TestResolvePlatformDefaults_WorkflowIdentityKeylessNoLogin pins the CI UX: a
// bare `cilock run --platform-url X` must sign keyless when the ambient GitHub
// OIDC tokens exist (id-token: write), with NO prior `cilock login` step and no
// stored credential — mint the OIDC token and wire the fulcio signer directly.
func TestResolvePlatformDefaults_WorkflowIdentityKeylessNoLogin(t *testing.T) {
	isolateCredentialStore(t) // deliberately NO stored credential

	var gotAudience atomic.Value // string
	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience.Store(r.URL.Query().Get("audience"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": fakeWorkflowOIDC})
	}))
	defer oidcSrv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidcSrv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ghs-fake-bearer")

	const platform = "https://platform.sandbox.example.com"
	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", platform}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != fakeWorkflowOIDC {
		t.Fatalf("signer-fulcio-token = %q, want the minted GHA OIDC token (bare run, no login)", got)
	}
	if got := cmd.Flags().Lookup("signer-fulcio-url").Value.String(); got != platform {
		t.Fatalf("signer-fulcio-url = %q, want platform root %q", got, platform)
	}
	if got, _ := gotAudience.Load().(string); got != "sigstore" {
		t.Fatalf("minted OIDC audience = %q, want sigstore", got)
	}
}

// TestResolvePlatformDefaults_NoLoginNoAmbientNoSigner ensures the local/offline
// path is untouched: no login + no ambient OIDC ⇒ no fulcio signer is forced
// (local/KMS signing must keep working).
func TestResolvePlatformDefaults_NoLoginNoAmbientNoSigner(t *testing.T) {
	isolateCredentialStore(t)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.sandbox.example.com"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "" {
		t.Fatalf("signer-fulcio-token = %q, want empty (no login, no ambient ⇒ no keyless signer)", got)
	}
}

// TestResolvePlatformDefaults_WorkflowIdentityExplicitTokenWins ensures an
// operator who passes --signer-fulcio-token keeps control even with a stored
// workflow-identity credential: no ambient OIDC token is minted.
func TestResolvePlatformDefaults_WorkflowIdentityExplicitTokenWins(t *testing.T) {
	isolateCredentialStore(t)

	minted := int32(0)
	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&minted, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": fakeWorkflowOIDC})
	}))
	defer oidcSrv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidcSrv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ghs-fake-bearer")

	const platform = "https://platform.sandbox.example.com"
	if err := auth.Save(auth.Credential{
		PlatformURL: platform,
		AuthMode:    auth.AuthModeWorkflowOIDC,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed workflow-identity credential: %v", err)
	}

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", platform,
		"--signer-fulcio-token", "operator-supplied-token",
	}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "operator-supplied-token" {
		t.Fatalf("explicit --signer-fulcio-token should win, got %q", got)
	}
	if atomic.LoadInt32(&minted) != 0 {
		t.Fatal("must not mint an ambient OIDC token when an explicit token is set")
	}
}
