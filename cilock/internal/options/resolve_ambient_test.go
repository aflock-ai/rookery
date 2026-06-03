// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"os"
	"testing"

	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
)

// TestResolvePlatformDefaults_AmbientPlatformBinding verifies that an ambient CI
// workflow OIDC identity exposes CILOCK_PLATFORM_URL to the platform attestor
// WITHOUT a prior `cilock login` — so `cilock run` "just works" against the
// platform in CI. (newRunCmd is defined in resolve_platform_test.go.)
func TestResolvePlatformDefaults_AmbientPlatformBinding(t *testing.T) {
	const platformURLEnv = "CILOCK_PLATFORM_URL"

	// No stored login session (isolate the credential store), but an ambient
	// GitHub Actions OIDC identity is present and --archivista-oidc auto-enables.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
	_ = os.Unsetenv(platformURLEnv)
	t.Cleanup(func() { _ = os.Unsetenv(platformURLEnv) })
	platformconfig.MarkTrustedPlatformBinding("")
	t.Cleanup(func() { platformconfig.MarkTrustedPlatformBinding("") })

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	got := os.Getenv(platformURLEnv)
	if got == "" {
		t.Fatal("expected CILOCK_PLATFORM_URL to be set from the ambient workflow identity (no cilock login required)")
	}
	// The resolver must also install the in-process trust marker so the platform
	// attestor will honor the env var. Without it the attestor (correctly) refuses
	// to bind a raw, possibly-forged CILOCK_PLATFORM_URL.
	trusted, ok := platformconfig.TrustedPlatformBinding()
	if !ok || trusted != got {
		t.Fatalf("expected trusted-binding marker to match CILOCK_PLATFORM_URL %q, got marker=%q ok=%v", got, trusted, ok)
	}
}

// TestResolvePlatformDefaults_NoAmbientNoBinding is the negative control: with no
// login and no ambient identity, CILOCK_PLATFORM_URL stays unset (offline runs
// do not advertise a platform binding).
func TestResolvePlatformDefaults_NoAmbientNoBinding(t *testing.T) {
	const platformURLEnv = "CILOCK_PLATFORM_URL"

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	_ = os.Unsetenv(platformURLEnv)
	t.Cleanup(func() { _ = os.Unsetenv(platformURLEnv) })
	platformconfig.MarkTrustedPlatformBinding("")
	t.Cleanup(func() { platformconfig.MarkTrustedPlatformBinding("") })

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if got := os.Getenv(platformURLEnv); got != "" {
		t.Fatalf("expected CILOCK_PLATFORM_URL unset offline, got %q", got)
	}
	if trusted, ok := platformconfig.TrustedPlatformBinding(); ok {
		t.Fatalf("expected no trusted-binding marker offline, got %q", trusted)
	}
}
