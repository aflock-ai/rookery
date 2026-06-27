// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// TestVerifyTrustGate_KeysOnCanPinTrustCapability proves the discovery-trust
// adoption gate branches on the resolving source's DECLARED CapCanPinTrust
// capability (Phase 2), not on a re-derived persisted-bool. The two sessions are
// distinguished ONLY by which provider resolves them:
//
//   - a cilock-store session declares CapCanPinTrust → adopt + pin on first use;
//   - a jctl session declares NO capabilities → fail closed on first use with no
//     operator opt-in.
//
// This is the same fail-open/fail-closed split the #5988 suite asserts, but here
// the assertion is explicitly tied to the capability so a future change that
// breaks the capability→trust wiring (e.g. a source that should not be able to
// pin but accidentally declares CapCanPinTrust, or the gate keying on Source
// string instead of Has) is caught.
func TestVerifyTrustGate_KeysOnCanPinTrustCapability(t *testing.T) {
	// Guard the test's own premise: the gate's two outcomes must correspond to
	// the two providers' capability declarations. If this invariant ever breaks,
	// the behavioral assertions below would be testing the wrong thing.
	if !auth.NewCapabilities(auth.CapCanPinTrust).Has(auth.CapCanPinTrust) {
		t.Fatal("precondition: cilock capability set must declare CapCanPinTrust")
	}
	if auth.NewCapabilities().Has(auth.CapCanPinTrust) {
		t.Fatal("precondition: jctl (empty) capability set must NOT declare CapCanPinTrust")
	}

	t.Run("cilock_session_can_pin_adopts", func(t *testing.T) {
		isolateCredentialStore(t)
		var served atomic.Value
		served.Store(honestTrustBundlePEM)
		srv := flipDiscoveryStub(t, &served)
		defer srv.Close()

		// A cilock-store session — resolved by cilockProvider, which declares
		// CapCanPinTrust. The resolved session must carry the capability.
		if err := auth.Save(auth.Credential{
			PlatformURL: srv.URL,
			Token:       "stored-session-credential",
			Email:       "alice@acme-corp.com",
			AuthMode:    auth.AuthModeBrowser,
			ExpiresAt:   time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed cilock credential: %v", err)
		}
		resolved, err := auth.Resolve(srv.URL, auth.ForBearer)
		if err != nil || resolved == nil {
			t.Fatalf("resolve cilock session: %v (resolved=%v)", err, resolved)
		}
		if !resolved.Has(auth.CapCanPinTrust) {
			t.Fatalf("cilock session must declare CapCanPinTrust, posture=%q", resolved.Posture())
		}

		cmd, vo := newVerifyCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
			t.Fatal(err)
		}
		if err := vo.ResolvePlatformDefaults(cmd); err != nil {
			t.Fatalf("can-pin (cilock) session must adopt on first use: %v", err)
		}
		if string(vo.PolicyCARootsPEM) != honestTrustBundlePEM {
			t.Fatalf("can-pin session should adopt the honest bundle, got %q", string(vo.PolicyCARootsPEM))
		}
	})

	t.Run("jctl_session_cannot_pin_fails_closed", func(t *testing.T) {
		isolateCredentialStore(t)
		var served atomic.Value
		served.Store(honestTrustBundlePEM)
		srv := flipDiscoveryStub(t, &served)
		defer srv.Close()

		// A jctl session — resolved by jctlProvider, which declares NOTHING.
		seedJctlSession(t, srv.URL)
		resolved, err := auth.Resolve(srv.URL, auth.ForBearer)
		if err != nil || resolved == nil {
			t.Fatalf("resolve jctl session: %v (resolved=%v)", err, resolved)
		}
		if resolved.Has(auth.CapCanPinTrust) {
			t.Fatalf("jctl session must NOT declare CapCanPinTrust, posture=%q", resolved.Posture())
		}

		cmd, vo := newVerifyCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
			t.Fatal(err)
		}
		if err := vo.ResolvePlatformDefaults(cmd); err == nil {
			t.Fatal("cannot-pin (jctl) session with no opt-in must fail closed on first use")
		}
		if string(vo.PolicyCARootsPEM) == honestTrustBundlePEM {
			t.Fatalf("cannot-pin session must not adopt the bundle when failing closed, got %q", string(vo.PolicyCARootsPEM))
		}
	})
}
