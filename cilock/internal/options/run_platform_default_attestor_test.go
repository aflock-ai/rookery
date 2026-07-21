// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"testing"
)

// The platform attestor binds a run to a logged-in platform tenant. It is one of
// the auto DefaultAttestors ([environment, git, platform]), but with no session
// it has nothing to record — and a preset binary (cilock-all) may not even
// register it, so demanding it dead-ends an offline run with
// "attestor not found: platform". ResolvePlatformDefaults now trims "platform"
// from the AUTO defaults whenever there is no platform identity, while leaving an
// explicit -a set untouched. These tests pin that behavior.

func attestorsHave(attestations []string, name string) bool {
	for _, a := range attestations {
		if a == name {
			return true
		}
	}
	return false
}

// TestPlatformDefault_DroppedWhenLoggedOut: a bare run (no --platform-url, no
// session, no CI OIDC) must NOT carry the platform attestor in its auto defaults.
func TestPlatformDefault_DroppedWhenLoggedOut(t *testing.T) {
	isolateCredentialStore(t)
	// No ambient GitHub Actions OIDC identity.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if attestorsHave(ro.Attestations, "platform") {
		t.Fatalf("platform attestor must be dropped when logged out, got %v", ro.Attestations)
	}
	// The rest of the defaults are untouched.
	if !attestorsHave(ro.Attestations, "environment") || !attestorsHave(ro.Attestations, "git") {
		t.Fatalf("environment+git must survive, got %v", ro.Attestations)
	}
}

// TestPlatformDefault_DroppedWhenPlatformDisabled: --platform-url "" opts out of
// the platform entirely, so the platform attestor must be dropped from the auto
// defaults (the explicit-disable early-return path).
func TestPlatformDefault_DroppedWhenPlatformDisabled(t *testing.T) {
	isolateCredentialStore(t)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", ""}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if attestorsHave(ro.Attestations, "platform") {
		t.Fatalf("platform attestor must be dropped when platform is disabled, got %v", ro.Attestations)
	}
}

// TestPlatformDefault_KeptWhenLoggedIn: a stored session means the operator is
// logged in, so the platform attestor stays in the auto defaults to bind the run
// to the tenant.
func TestPlatformDefault_KeptWhenLoggedIn(t *testing.T) {
	isolateCredentialStore(t)
	srv := signTokenStub(t)
	defer srv.Close()
	seedLoginCredential(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if !attestorsHave(ro.Attestations, "platform") {
		t.Fatalf("platform attestor must be kept when logged in, got %v", ro.Attestations)
	}
}

// TestPlatformDefault_ExplicitSetHonored: an explicit `-a platform` while logged
// out must be honored verbatim — the trim only touches the AUTO defaults.
func TestPlatformDefault_ExplicitSetHonored(t *testing.T) {
	isolateCredentialStore(t)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"-a", "platform"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if !attestorsHave(ro.Attestations, "platform") {
		t.Fatalf("explicit -a platform must be honored even when logged out, got %v", ro.Attestations)
	}
}
