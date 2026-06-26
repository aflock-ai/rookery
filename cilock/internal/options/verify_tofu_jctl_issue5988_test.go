// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// seedJctlSession writes a ~/.jctl/config.yaml under the test's isolated $HOME
// with a single context whose judgeURL matches platformURL and an INLINE token.
// This produces a credential that auth.Lookup resolves via lookupJctl (jctl
// fallback) — NOT cilock's own credential store. Such a session has no cilock
// store entry, so auth.SetTrustBundleSPKI cannot persist a trust-on-first-use
// pin onto it: it is "un-pinnable". This is the exact session shape that left
// GHSA #5988 open for jctl-login users even after the #6014 TOFU pin landed
// (the pin write silently no-ops, so every resolve re-takes the first-use
// branch and re-adopts whatever bundle the platform currently serves).
func seedJctlSession(t *testing.T, platformURL string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolve isolated HOME: %v", err)
	}
	jctlDir := filepath.Join(home, ".jctl")
	if err := os.MkdirAll(jctlDir, 0o700); err != nil {
		t.Fatalf("create jctl config dir: %v", err)
	}
	// Inline token so lookupJctl resolves it from the YAML (no OS keychain).
	cfg := "" +
		"contexts:\n" +
		"  default:\n" +
		"    judgeURL: " + platformURL + "\n" +
		"    token: jctl-session-token\n" +
		"    tenant_id: tenant-123\n" +
		"    tenant_name: Acme\n"
	if err := os.WriteFile(filepath.Join(jctlDir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write jctl config: %v", err)
	}
}

// TestSecurity_Issue5988_JctlSessionUnpinnableFailsClosed is the core #5988
// regression for jctl-login sessions. A jctl-sourced credential carries no
// cilock store entry, so the trust-on-first-use pin can never be persisted onto
// it. Before this fix, that made SetTrustBundleSPKI a silent no-op: every
// resolve saw TrustBundleSPKI=="" → first-use branch → adopted whatever bundle
// the platform served. An attacker who swaps the served bundle on a later
// resolve is silently trusted — the #6014 pin protected only cilock-store
// sessions.
//
// SECURE contract: when the session is un-pinnable AND the operator did not
// explicitly opt in (--trust-discovery / out-of-band --policy-ca-roots), verify
// must REFUSE to adopt the discovery bundle (fail closed), on the FIRST resolve
// and every later one.
func TestSecurity_Issue5988_JctlSessionUnpinnableFailsClosed(t *testing.T) {
	isolateCredentialStore(t)

	var served atomic.Value
	served.Store(honestTrustBundlePEM)
	srv := flipDiscoveryStub(t, &served)
	defer srv.Close()

	// jctl session only — NOT auth.Save (which would create a pinnable cilock
	// store entry). This session is un-pinnable.
	seedJctlSession(t, srv.URL)

	// Sanity: the session really is jctl-sourced (un-pinnable). It must resolve
	// (so Discover/adoption is reached) yet carry no pin.
	cred, err := auth.Lookup(srv.URL)
	if err != nil {
		t.Fatalf("lookup jctl session: %v", err)
	}
	if cred == nil || cred.Token == "" {
		t.Fatalf("expected a jctl-sourced credential, got %#v", cred)
	}
	if cred.TrustBundleSPKI != "" {
		t.Fatalf("jctl session must carry no trust pin, got %q", cred.TrustBundleSPKI)
	}

	// First resolve, no opt-in: must FAIL CLOSED rather than adopt the bundle.
	cmd1, vo1 := newVerifyCmd(t)
	if err := cmd1.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	err1 := vo1.ResolvePlatformDefaults(cmd1)
	if err1 == nil {
		t.Fatalf("SECURITY: un-pinnable (jctl) session with no opt-in must refuse silent first-use trust adoption (#5988); got nil")
	}
	if string(vo1.PolicyCARootsPEM) == honestTrustBundlePEM {
		t.Fatalf("SECURITY: un-pinnable session adopted the discovery bundle despite refusing (#5988): %q", string(vo1.PolicyCARootsPEM))
	}

	// The attacker now swaps the served bundle. A SECOND resolve must STILL fail
	// closed — it must never silently adopt the attacker bundle.
	served.Store(attackerTrustBundlePEM)
	cmd2, vo2 := newVerifyCmd(t)
	if err := cmd2.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	err2 := vo2.ResolvePlatformDefaults(cmd2)
	if err2 == nil {
		t.Fatalf("SECURITY: un-pinnable session must fail closed on every resolve, not just the first (#5988); got nil")
	}
	if string(vo2.PolicyCARootsPEM) == attackerTrustBundlePEM {
		t.Fatalf("SECURITY: un-pinnable session silently adopted the ATTACKER bundle on repeat resolve (#5988)")
	}
}

// TestSecurity_Issue5988_JctlSessionExplicitTrustDiscoveryAllows proves the
// fail-closed guard honors an explicit operator opt-in: with --trust-discovery,
// the operator has acknowledged that this un-pinnable session is trusting the
// served bundle, so adoption is allowed (no fail-closed error).
func TestSecurity_Issue5988_JctlSessionExplicitTrustDiscoveryAllows(t *testing.T) {
	isolateCredentialStore(t)

	var served atomic.Value
	served.Store(honestTrustBundlePEM)
	srv := flipDiscoveryStub(t, &served)
	defer srv.Close()

	seedJctlSession(t, srv.URL)

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--trust-discovery",
	}); err != nil {
		t.Fatal(err)
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		t.Fatalf("explicit --trust-discovery opt-in must allow adoption on an un-pinnable session: %v", err)
	}
	if string(vo.PolicyCARootsPEM) != honestTrustBundlePEM {
		t.Fatalf("with --trust-discovery the un-pinnable session should adopt the served bundle, got %q", string(vo.PolicyCARootsPEM))
	}
}

// TestSecurity_Issue5988_JctlSessionExplicitPolicyCARootsAllows proves the
// other explicit opt-out — out-of-band --policy-ca-roots — still suppresses
// discovery entirely on an un-pinnable session (never reaches the gate). This
// guards against the fail-closed guard accidentally firing when the operator
// already supplied trust out-of-band.
func TestSecurity_Issue5988_JctlSessionExplicitPolicyCARootsAllows(t *testing.T) {
	isolateCredentialStore(t)

	var served atomic.Value
	served.Store(honestTrustBundlePEM)
	srv := flipDiscoveryStub(t, &served)
	defer srv.Close()

	seedJctlSession(t, srv.URL)

	cmd, vo := newVerifyCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--policy-ca-roots", "/path/to/my-root.pem",
	}); err != nil {
		t.Fatal(err)
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		t.Fatalf("explicit --policy-ca-roots on an un-pinnable session must succeed (discovery suppressed): %v", err)
	}
	if len(vo.PolicyCARootsPEM) != 0 {
		t.Fatal("explicit --policy-ca-roots must suppress the discovered bundle even for a jctl session")
	}
}

// TestSecurity_Issue5988_CilockStoreSessionStillPinsNoRegression is the
// regression guard for #6014: a pinnable cilock-store session must keep working
// exactly as before — adopt + pin on first resolve, and a SECOND resolve uses
// the persisted pin (no re-adoption decision, unchanged bundle trusted; changed
// bundle refused). The fail-closed jctl guard must not perturb this path.
func TestSecurity_Issue5988_CilockStoreSessionStillPinsNoRegression(t *testing.T) {
	isolateCredentialStore(t)

	var served atomic.Value
	served.Store(honestTrustBundlePEM)
	srv := flipDiscoveryStub(t, &served)
	defer srv.Close()

	// Pinnable: a real cilock-store credential.
	if err := auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		Email:       "alice@acme-corp.com",
		AuthMode:    auth.AuthModeBrowser,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	// First resolve: adopt the honest bundle and persist the pin.
	cmd1, vo1 := newVerifyCmd(t)
	if err := cmd1.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := vo1.ResolvePlatformDefaults(cmd1); err != nil {
		t.Fatalf("cilock-store first resolve must succeed: %v", err)
	}
	if string(vo1.PolicyCARootsPEM) != honestTrustBundlePEM {
		t.Fatalf("cilock-store first resolve should adopt the honest bundle, got %q", string(vo1.PolicyCARootsPEM))
	}

	// The pin must now be persisted onto the cilock-store credential.
	pinned, err := auth.Lookup(srv.URL)
	if err != nil {
		t.Fatalf("re-lookup after pin: %v", err)
	}
	if pinned == nil || pinned.TrustBundleSPKI == "" {
		t.Fatalf("cilock-store session must persist a trust pin after first adoption, got %#v", pinned)
	}

	// Second resolve, UNCHANGED bundle: the persisted pin is used and the bundle
	// is trusted again (no re-adoption error).
	cmd2, vo2 := newVerifyCmd(t)
	if err := cmd2.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	if err := vo2.ResolvePlatformDefaults(cmd2); err != nil {
		t.Fatalf("cilock-store second resolve (unchanged bundle) must succeed via the pin: %v", err)
	}
	if string(vo2.PolicyCARootsPEM) != honestTrustBundlePEM {
		t.Fatalf("cilock-store second resolve should keep trusting the pinned bundle, got %q", string(vo2.PolicyCARootsPEM))
	}

	// Third resolve, CHANGED bundle with no opt-in: the #6014 pin must refuse it.
	served.Store(attackerTrustBundlePEM)
	cmd3, vo3 := newVerifyCmd(t)
	if err := cmd3.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	err3 := vo3.ResolvePlatformDefaults(cmd3)
	if err3 == nil {
		t.Fatalf("cilock-store changed-bundle resolve must refuse (#6014 pin); got nil")
	}
	if string(vo3.PolicyCARootsPEM) == attackerTrustBundlePEM {
		t.Fatalf("cilock-store session must not adopt a changed bundle (#6014 regression)")
	}
}
