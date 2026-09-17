// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"slices"
	"testing"
)

// The platform attestor binds a run to a logged-in platform tenant. It is one of
// the auto DefaultAttestors ([environment, git, platform]), and there are two
// independent reasons a run cannot produce it: no platform identity to bind to,
// and no registration in this binary. ResolvePlatformDefaults trims "platform"
// from the AUTO defaults for either reason, while leaving an explicit -a set
// untouched. These tests pin both halves.
//
// The two reasons are genuinely independent, which is why the second one needs
// its own coverage: a logged-in operator running a preset binary satisfies the
// identity check and still reaches the factory with a name nothing can build.

func attestorsHave(attestations []string, name string) bool {
	return slices.Contains(attestations, name)
}

// withPlatformAttestorRegistered forces the registration answer for one test.
//
// This package's test binary registers no attestors at all — only
// cmd/cilock/main.go imports the internal adapter that registers "platform" —
// so the unstubbed answer here is always false, which is exactly the cilock-all
// case. A test that wants the full-cilock case has to say so.
func withPlatformAttestorRegistered(t *testing.T, registered bool) {
	t.Helper()
	prev := platformAttestorRegistered
	platformAttestorRegistered = func() bool { return registered }
	t.Cleanup(func() { platformAttestorRegistered = prev })
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
// to the tenant — provided the binary can actually build it, which is the full
// cilock binary's case and is stated explicitly here.
func TestPlatformDefault_KeptWhenLoggedIn(t *testing.T) {
	isolateCredentialStore(t)
	withPlatformAttestorRegistered(t, true)
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

// TestPlatformDefault_DroppedWhenAttestorUnregistered is the cilock-all case: a
// logged-in operator, so the identity check passes, running a binary that never
// registered the attestor. Before this trim the run died at
// "failed to create attestor: attestor not found: platform" — fatal, on a
// default nobody asked for.
//
// Deliberately NOT stubbed: this package's test binary registers no attestors,
// so the real registry lookup answers the question, and the test would stop
// proving anything the day that lookup silently started answering true.
func TestPlatformDefault_DroppedWhenAttestorUnregistered(t *testing.T) {
	isolateCredentialStore(t)
	srv := signTokenStub(t)
	defer srv.Close()
	seedLoginCredential(t, srv.URL)

	if platformAttestorRegistered() {
		t.Fatal("precondition: this test binary must not register the platform attestor")
	}

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if attestorsHave(ro.Attestations, "platform") {
		t.Fatalf("platform attestor must be dropped when the binary cannot build it, got %v", ro.Attestations)
	}
	// The trim is surgical: the other defaults are not collateral.
	if !attestorsHave(ro.Attestations, "environment") || !attestorsHave(ro.Attestations, "git") {
		t.Fatalf("environment+git must survive, got %v", ro.Attestations)
	}
}

// TestPlatformDefault_ExplicitSetHonoredWhenUnregistered: asking for evidence
// the binary cannot produce must stay an error, not become a silent no-op. The
// trim only ever touches the auto defaults, so `-a platform` survives here and
// fails downstream at the factory, where the operator can see why.
func TestPlatformDefault_ExplicitSetHonoredWhenUnregistered(t *testing.T) {
	isolateCredentialStore(t)
	withPlatformAttestorRegistered(t, false)
	srv := signTokenStub(t)
	defer srv.Close()
	seedLoginCredential(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL, "-a", "platform"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if !attestorsHave(ro.Attestations, "platform") {
		t.Fatalf("explicit -a platform must be honored even when unregistered, got %v", ro.Attestations)
	}
}

// TestDropDefaultPlatformAttestor_ReportsWhetherItDropped pins the signal the
// caller logs on.
//
// An end-to-end run caught this: the warning was emitted unconditionally, so
// `-a platform` against a binary without the attestor announced "dropping it
// from the default attestor set" and then failed at the factory anyway — a log
// line describing the opposite of what the operator was about to see. The
// return value exists so the reason is only announced for a drop that happened.
func TestDropDefaultPlatformAttestor_ReportsWhetherItDropped(t *testing.T) {
	t.Run("auto defaults", func(t *testing.T) {
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags(nil); err != nil {
			t.Fatal(err)
		}
		if !ro.dropDefaultPlatformAttestor(cmd) {
			t.Fatal("must report a drop when platform was in the auto defaults")
		}
		if ro.dropDefaultPlatformAttestor(cmd) {
			t.Fatal("must report no drop the second time — platform is already gone")
		}
	})

	t.Run("explicit set", func(t *testing.T) {
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"-a", "platform"}); err != nil {
			t.Fatal(err)
		}
		if ro.dropDefaultPlatformAttestor(cmd) {
			t.Fatal("must report no drop for an explicit -a set")
		}
		if !attestorsHave(ro.Attestations, "platform") {
			t.Fatalf("explicit set must be untouched, got %v", ro.Attestations)
		}
	})
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
