// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platform

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// isolateCreds points the credential store at empty temp dirs so auth.Lookup
// finds no stored session (os.UserConfigDir/os.UserHomeDir derive from HOME).
func isolateCreds(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// markTrustedBinding installs the in-process trust marker the resolver sets and
// clears it again when the subtest ends, so the process-global state never leaks
// between cases. Mirrors what RunOptions.ResolvePlatformDefaults does after its
// same-origin + ambient-OIDC check.
func markTrustedBinding(t *testing.T, url string) {
	t.Helper()
	config.MarkTrustedPlatformBinding(url)
	t.Cleanup(func() { config.MarkTrustedPlatformBinding("") })
}

func TestAttest_AmbientWorkflowIdentity(t *testing.T) {
	t.Run("ambient identity + trusted CILOCK_PLATFORM_URL -> workflow-identity binding, no invented tenant", func(t *testing.T) {
		isolateCreds(t)
		t.Setenv(PlatformURLEnv, "https://platform.testifysec.com")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		markTrustedBinding(t, "https://platform.testifysec.com")

		a := New()
		if err := a.Attest(nil); err != nil {
			t.Fatalf("expected success under ambient identity, got: %v", err)
		}
		if !a.WorkflowIdentity {
			t.Fatal("expected WorkflowIdentity=true")
		}
		if a.PlatformURL == "" {
			t.Fatal("expected PlatformURL to be recorded")
		}
		if a.TenantID != "" || a.ProductID != "" {
			t.Fatalf("tenant/product must stay empty (server-resolved), got tenant=%q product=%q", a.TenantID, a.ProductID)
		}
		// Without a product id there is no high-confidence product subject yet.
		if len(a.Subjects()) != 0 {
			t.Fatalf("expected no binding subjects without tenant/product, got %v", a.Subjects())
		}
	})

	t.Run("ambient identity + forged CILOCK_PLATFORM_URL (no trust marker) -> soft skip, no forged binding", func(t *testing.T) {
		isolateCreds(t)
		// Hostile CI step exports the env var directly; the trusted resolver never
		// ran its same-origin check, so no in-process marker is set.
		t.Setenv(PlatformURLEnv, "https://attacker.example")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")

		a := New()
		err := a.Attest(nil)
		if err == nil || !strings.Contains(err.Error(), "skipping platform binding") {
			t.Fatalf("a raw CILOCK_PLATFORM_URL with no trust marker must NOT bind; got err=%v", err)
		}
		if a.WorkflowIdentity || a.PlatformURL != "" {
			t.Fatalf("forged env var must not produce a binding, got WorkflowIdentity=%v PlatformURL=%q", a.WorkflowIdentity, a.PlatformURL)
		}
	})

	t.Run("ambient identity + trust marker for a DIFFERENT url -> soft skip", func(t *testing.T) {
		isolateCreds(t)
		// Resolver authorized platform A, but the env var points at B (e.g. a later
		// hostile override). The mismatch must not bind.
		t.Setenv(PlatformURLEnv, "https://attacker.example")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		markTrustedBinding(t, "https://platform.testifysec.com")

		a := New()
		err := a.Attest(nil)
		if err == nil || !strings.Contains(err.Error(), "skipping platform binding") {
			t.Fatalf("a trust marker for a different url must NOT authorize binding the env-var url; got err=%v", err)
		}
		if a.WorkflowIdentity || a.PlatformURL != "" {
			t.Fatalf("url mismatch must not bind, got WorkflowIdentity=%v PlatformURL=%q", a.WorkflowIdentity, a.PlatformURL)
		}
	})

	t.Run("no session and no ambient identity -> soft skip", func(t *testing.T) {
		isolateCreds(t)
		t.Setenv(PlatformURLEnv, "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

		err := New().Attest(nil)
		if err == nil || !strings.Contains(err.Error(), "skipping platform binding") {
			t.Fatalf("expected a soft skip, got: %v", err)
		}
	})

	t.Run("ambient present but run did not target the platform (CILOCK_PLATFORM_URL unset) -> soft skip", func(t *testing.T) {
		isolateCreds(t)
		t.Setenv(PlatformURLEnv, "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")

		err := New().Attest(nil)
		if err == nil || !strings.Contains(err.Error(), "skipping platform binding") {
			t.Fatalf("ambient identity alone must not bind unless run set CILOCK_PLATFORM_URL; got: %v", err)
		}
	})
}
