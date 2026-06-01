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
)

const testTrustBundlePEM = "-----BEGIN CERTIFICATE-----\nMIITESTROOT\n-----END CERTIFICATE-----\n"

// discoveryStub serves /.well-known/judge-configuration with a signing block.
func discoveryStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/judge-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"archivista_url": r.Host,
			"signing": map[string]any{
				"fulcio_url":         "https://platform.example.com",
				"fulcio_oidc_issuer": "https://platform.example.com/fulcio/oidc",
				"oidc_audience":      "sigstore",
				"trust_bundle_pem":   testTrustBundlePEM,
				"assurance_level":    "aal1",
			},
		})
	}))
}

func newVerifyCmd(t *testing.T) (*cobra.Command, *VerifyOptions) {
	t.Helper()
	vo := &VerifyOptions{}
	cmd := &cobra.Command{Use: "verify"}
	vo.AddFlags(cmd)
	return cmd, vo
}

// TestVerifyResolvePlatformDefaults_DerivesTrustFromDiscovery proves a logged-in
// `cilock verify` needs no CA file or issuer flag: discovery supplies the CA
// roots PEM and the Fulcio OIDC issuer, and the session supplies the email.
func TestVerifyResolvePlatformDefaults_DerivesTrustFromDiscovery(t *testing.T) {
	isolateCredentialStore(t)
	srv := discoveryStub(t)
	defer srv.Close()

	if err := auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		Email:       "alice@acme-corp.com",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	vo.ResolvePlatformDefaults(cmd)

	if string(vo.PolicyCARootsPEM) != testTrustBundlePEM {
		t.Fatalf("PolicyCARootsPEM = %q, want the discovered trust bundle", string(vo.PolicyCARootsPEM))
	}
	if vo.PolicyFulcioCertExtensions.Issuer != "https://platform.example.com/fulcio/oidc" {
		t.Fatalf("issuer = %q, want the discovered issuer", vo.PolicyFulcioCertExtensions.Issuer)
	}
	if len(vo.PolicyEmails) != 1 || vo.PolicyEmails[0] != "alice@acme-corp.com" {
		t.Fatalf("PolicyEmails = %v, want [alice@acme-corp.com] from the session", vo.PolicyEmails)
	}
}

// TestVerifyResolvePlatformDefaults_ExplicitFlagsWin ensures operator-supplied
// trust always overrides discovery — even for a logged-in session where
// discovery would otherwise supply the roots/issuer/email.
func TestVerifyResolvePlatformDefaults_ExplicitFlagsWin(t *testing.T) {
	isolateCredentialStore(t)
	srv := discoveryStub(t)
	defer srv.Close()

	// Logged in, so discovery actually runs — the point is that explicit flags
	// still beat it.
	if err := auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		Email:       "alice@acme-corp.com",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--policy-ca-roots", "/path/to/my-root.pem",
		"--policy-fulcio-oidc-issuer", "https://my-issuer.example.com",
		"--policy-emails", "explicit@acme-corp.com",
	}); err != nil {
		t.Fatal(err)
	}
	vo.ResolvePlatformDefaults(cmd)

	if len(vo.PolicyCARootsPEM) != 0 {
		t.Fatal("explicit --policy-ca-roots must suppress the discovered trust bundle")
	}
	if vo.PolicyFulcioCertExtensions.Issuer != "https://my-issuer.example.com" {
		t.Fatalf("explicit issuer should win, got %q", vo.PolicyFulcioCertExtensions.Issuer)
	}
	if len(vo.PolicyEmails) != 1 || vo.PolicyEmails[0] != "explicit@acme-corp.com" {
		t.Fatalf("explicit --policy-emails should win, got %v", vo.PolicyEmails)
	}
}

// TestVerifyResolvePlatformDefaults_NotLoggedInDoesNotSourceNetworkTrust pins the
// security fix: an UNAUTHENTICATED `cilock verify` must NOT adopt verification
// trust (CA roots, OIDC issuer) from a network discovery document. Otherwise a
// verify pointed at an attacker-influenced --platform-url would trust whatever
// the attacker advertises and PASS against forged evidence. With no session, the
// operator must supply explicit --policy-ca-roots.
func TestVerifyResolvePlatformDefaults_NotLoggedInDoesNotSourceNetworkTrust(t *testing.T) {
	isolateCredentialStore(t) // NO stored session
	srv := discoveryStub(t)   // discovery WOULD serve a trust bundle
	defer srv.Close()

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	vo.ResolvePlatformDefaults(cmd)

	// The CA roots are the trust anchor — these MUST stay empty (no network trust).
	if len(vo.PolicyCARootsPEM) != 0 {
		t.Fatalf("not-logged-in verify must NOT adopt network-sourced CA roots, got %q", string(vo.PolicyCARootsPEM))
	}
	// The issuer must not be overridden by the DISCOVERED value; it keeps whatever
	// default/flag the operator has (AddFlags defaults it to the GitHub Actions
	// OIDC issuer), never the platform's network-advertised issuer.
	if vo.PolicyFulcioCertExtensions.Issuer == "https://platform.example.com/fulcio/oidc" {
		t.Fatalf("not-logged-in verify must NOT adopt the discovered OIDC issuer, got %q", vo.PolicyFulcioCertExtensions.Issuer)
	}
	if len(vo.PolicyEmails) != 0 {
		t.Fatalf("not-logged-in verify must not default an expected signer, got %v", vo.PolicyEmails)
	}
}

// TestVerifyResolvePlatformDefaults_DiscoversArchivista proves a logged-in
// `cilock verify` pulls evidence from the platform without -a: Archivista is
// enabled by default and the session bearer is attached for authenticated reads.
func TestVerifyResolvePlatformDefaults_DiscoversArchivista(t *testing.T) {
	isolateCredentialStore(t)
	srv := discoveryStub(t)
	defer srv.Close()

	if err := auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		Email:       "alice@acme-corp.com",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	vo.ResolvePlatformDefaults(cmd)

	if !vo.ArchivistaOptions.Enable {
		t.Fatal("Archivista should be enabled by default when logged in, so verify can discover evidence")
	}
	var hasBearer bool
	for _, h := range vo.ArchivistaOptions.Headers {
		if h == "Authorization: Bearer stored-session-credential" {
			hasBearer = true
		}
	}
	if !hasBearer {
		t.Fatalf("session bearer must be attached for authenticated Archivista reads, headers=%v", vo.ArchivistaOptions.Headers)
	}
}

// TestVerifyResolvePlatformDefaults_OptOut ensures --platform-url "" disables
// discovery entirely (offline verify).
func TestVerifyResolvePlatformDefaults_OptOut(t *testing.T) {
	isolateCredentialStore(t)

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", ""}); err != nil {
		t.Fatal(err)
	}
	vo.ResolvePlatformDefaults(cmd)

	if len(vo.PolicyCARootsPEM) != 0 {
		t.Fatal("opt-out must not derive any trust bundle")
	}
	// Opt-out must not touch the issuer — it stays at the flag's compiled
	// default (GitHub Actions), NOT a discovery-derived value.
	if vo.PolicyFulcioCertExtensions.Issuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("opt-out must leave the issuer at its default, got %q", vo.PolicyFulcioCertExtensions.Issuer)
	}
}
