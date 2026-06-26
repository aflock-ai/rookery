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
)

const (
	honestTrustBundlePEM   = "-----BEGIN CERTIFICATE-----\nMIIHONESTROOT\n-----END CERTIFICATE-----\n"
	attackerTrustBundlePEM = "-----BEGIN CERTIFICATE-----\nMIIATTACKERROOT\n-----END CERTIFICATE-----\n"
)

// flipDiscoveryStub serves /.well-known/judge-configuration whose
// trust_bundle_pem is whatever the *bundle atomic currently holds, so a test can
// flip the served trust anchor mid-flight (honest → attacker) to simulate a
// compromised / malicious platform changing its advertised policy-signer CA.
func flipDiscoveryStub(t *testing.T, bundle *atomic.Value) *httptest.Server {
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
				"trust_bundle_pem":   bundle.Load().(string),
				"assurance_level":    "aal1",
			},
		})
	}))
}

// TestSecurity_Issue5988_ChangedDiscoveryBundleSilentlyAdopted is the security
// regression for GHSA #5988: a logged-in `cilock verify` TOFU-trusts the
// platform's network-served discovery trust_bundle_pem as the policy-signature
// CA roots. Once a platform's trust anchor is known (first successful resolve),
// a SILENTLY CHANGED bundle on a later resolve must NOT be adopted — otherwise a
// compromised/malicious platform can swap in an attacker CA and make verify PASS
// against attacker-signed policies, with no operator opt-in.
//
// Flow: log in to a loopback platform, resolve once with the honest bundle
// (pins it), flip the served bundle to the attacker's CA, resolve again. SECURE
// behavior: the second resolve does NOT adopt the attacker bundle (it errors
// and/or keeps the pinned honest bundle). Before the fix this test FAILS because
// the attacker bundle is silently adopted.
func TestSecurity_Issue5988_ChangedDiscoveryBundleSilentlyAdopted(t *testing.T) {
	isolateCredentialStore(t)

	var served atomic.Value
	served.Store(honestTrustBundlePEM)
	srv := flipDiscoveryStub(t, &served)
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

	// First resolve with the honest bundle — establishes the pin.
	cmd1, vo1 := newVerifyCmd(t)
	if err := cmd1.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := vo1.ResolvePlatformDefaults(cmd1); err != nil {
		t.Fatalf("first resolve (honest bundle) must succeed: %v", err)
	}
	if string(vo1.PolicyCARootsPEM) != honestTrustBundlePEM {
		t.Fatalf("first resolve should adopt the honest bundle, got %q", string(vo1.PolicyCARootsPEM))
	}

	// The platform is now compromised: it serves an ATTACKER CA as its trust anchor.
	served.Store(attackerTrustBundlePEM)

	// Second resolve with the SAME logged-in platform but a changed bundle.
	cmd2, vo2 := newVerifyCmd(t)
	if err := cmd2.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	err := vo2.ResolvePlatformDefaults(cmd2)

	// SECURE: the attacker bundle must NOT be silently adopted. Acceptable secure
	// outcomes are (a) a hard error, and/or (b) the resolved CA roots are NOT the
	// attacker bundle. The vulnerable behavior adopts it silently with no error.
	if string(vo2.PolicyCARootsPEM) == attackerTrustBundlePEM {
		t.Fatalf("SECURITY: changed discovery trust bundle was silently adopted as policy CA roots (TOFU, #5988)")
	}
	if err == nil {
		t.Fatalf("SECURITY: a changed discovery trust bundle for a known platform must be a hard error (#5988); got nil")
	}
}

// TestSecurity_Issue5988_ExplicitPolicyCARootsOverridesDiscovery is a regression
// guard: an out-of-band --policy-ca-roots always wins, fully suppressing the
// discovered bundle even on a logged-in session. This already passes; it must
// keep passing after the TOFU-pin fix.
func TestSecurity_Issue5988_ExplicitPolicyCARootsOverridesDiscovery(t *testing.T) {
	isolateCredentialStore(t)

	var served atomic.Value
	served.Store(honestTrustBundlePEM)
	srv := flipDiscoveryStub(t, &served)
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
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--policy-ca-roots", "/path/to/my-root.pem",
	}); err != nil {
		t.Fatal(err)
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		t.Fatalf("explicit --policy-ca-roots resolve must succeed: %v", err)
	}

	if len(vo.PolicyCARootsPEM) != 0 {
		t.Fatal("explicit --policy-ca-roots must suppress the discovered trust bundle")
	}
}
