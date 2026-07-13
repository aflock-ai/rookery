// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"fmt"
	"strings"
	"testing"

	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/aflock-ai/rookery/platformauth"
)

const (
	gateTenant  = "11111111-1111-1111-1111-111111111111"
	gateProduct = "22222222-2222-2222-2222-222222222222"
	gatePlatURL = "https://platform.testifysec.com"
)

// isolateForGate points the credential store at empty temp dirs (so auth.Lookup
// finds no stored session) and clears any resolved-binding marker afterward.
func isolateForGate(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Cleanup(func() { platformconfig.MarkResolvedBinding(platformconfig.ResolvedProductBinding{}) })
}

// enterAmbient sets the ambient-CI signals the gate keys on: a workflow OIDC
// endpoint and CILOCK_PLATFORM_URL (which ResolvePlatformDefaults sets after its
// same-origin check). Also stubs the login-token minter.
func enterAmbient(t *testing.T) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
	t.Setenv(platformURLEnv, gatePlatURL)
	orig := bindingMintLoginTokenFn
	t.Cleanup(func() { bindingMintLoginTokenFn = orig })
	bindingMintLoginTokenFn = func(string) (string, error) { return "login-token", nil }
}

func stubGateResolve(t *testing.T, fn func(url, bearer, selector string) (platformauth.Binding, error)) {
	t.Helper()
	orig := bindingResolveFn
	t.Cleanup(func() { bindingResolveFn = orig })
	bindingResolveFn = fn
}

func TestEnforcePlatformBinding_OptOut(t *testing.T) {
	isolateForGate(t)
	enterAmbient(t)
	stubGateResolve(t, func(string, string, string) (platformauth.Binding, error) {
		t.Fatal("resolve must not be called when opted out")
		return platformauth.Binding{}, nil
	})
	ro := &RunOptions{PlatformURL: gatePlatURL, NoProductBinding: true}
	if err := ro.enforcePlatformBinding(false); err != nil {
		t.Fatalf("opt-out must proceed, got %v", err)
	}
}

func TestEnforcePlatformBinding_PlatformDisabled(t *testing.T) {
	isolateForGate(t)
	enterAmbient(t)
	stubGateResolve(t, func(string, string, string) (platformauth.Binding, error) {
		t.Fatal("resolve must not be called when platform disabled")
		return platformauth.Binding{}, nil
	})
	ro := &RunOptions{PlatformURL: ""}
	if err := ro.enforcePlatformBinding(true); err != nil {
		t.Fatalf("platform-disabled must proceed, got %v", err)
	}
}

func TestEnforcePlatformBinding_NotAuthenticated(t *testing.T) {
	isolateForGate(t)
	// No ambient identity, no session.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv(platformURLEnv, "")
	stubGateResolve(t, func(string, string, string) (platformauth.Binding, error) {
		t.Fatal("resolve must not be called when not authenticated")
		return platformauth.Binding{}, nil
	})
	ro := &RunOptions{PlatformURL: gatePlatURL}
	if err := ro.enforcePlatformBinding(false); err != nil {
		t.Fatalf("unauthenticated run must proceed, got %v", err)
	}
}

func TestEnforcePlatformBinding_AmbientSuccess_MarksBinding(t *testing.T) {
	isolateForGate(t)
	enterAmbient(t)
	var gotBearer, gotAudienceless string
	stubGateResolve(t, func(url, bearer, selector string) (platformauth.Binding, error) {
		gotBearer = bearer
		gotAudienceless = url
		return platformauth.Binding{TenantID: gateTenant, TenantName: "Acme", ProductID: gateProduct, ProductName: "Widget"}, nil
	})
	ro := &RunOptions{PlatformURL: gatePlatURL}
	if err := ro.enforcePlatformBinding(false); err != nil {
		t.Fatalf("success path must proceed, got %v", err)
	}
	if gotBearer != "login-token" {
		t.Fatalf("gate must use the minted login token, got bearer %q", gotBearer)
	}
	if gotAudienceless != gatePlatURL {
		t.Fatalf("resolve target = %q, want %q", gotAudienceless, gatePlatURL)
	}
	rb, ok := platformconfig.ResolvedBinding(gatePlatURL)
	if !ok {
		t.Fatal("resolved binding was not threaded to the attestor")
	}
	if rb.ProductID != gateProduct || rb.TenantID != gateTenant {
		t.Fatalf("resolved binding = %+v", rb)
	}
}

func TestEnforcePlatformBinding_RepoNotMapped_HardFail(t *testing.T) {
	isolateForGate(t)
	enterAmbient(t)
	t.Setenv("GITHUB_REPOSITORY", "acme/widget")
	t.Setenv("GITHUB_REPOSITORY_ID", "424242")
	stubGateResolve(t, func(string, string, string) (platformauth.Binding, error) {
		return platformauth.Binding{}, &platformauth.RepositoryNotMappedError{
			TenantID: gateTenant, TenantName: "Acme",
		}
	})
	ro := &RunOptions{PlatformURL: gatePlatURL}
	err := ro.enforcePlatformBinding(false)
	if err == nil {
		t.Fatal("repository_not_mapped must hard-fail")
	}
	msg := err.Error()
	for _, want := range []string{"acme/widget", "424242", "Acme", gateTenant, "--no-product-binding", "cilock login --product"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q: %q", want, msg)
		}
	}
	if _, ok := platformconfig.ResolvedBinding(gatePlatURL); ok {
		t.Fatal("no binding must be marked on failure")
	}
}

func TestEnforcePlatformBinding_Ambiguous_HardFail_NamesCandidates(t *testing.T) {
	isolateForGate(t)
	enterAmbient(t)
	stubGateResolve(t, func(string, string, string) (platformauth.Binding, error) {
		return platformauth.Binding{}, &platformauth.AmbiguousProductError{
			TenantID: gateTenant, TenantName: "Acme", Repository: "acme/monorepo",
			Candidates: []platformauth.ProductCandidate{
				{ProductID: gateProduct, ProductName: "A"},
				{ProductID: "33333333-3333-3333-3333-333333333333", ProductName: "B"},
			},
		}
	})
	ro := &RunOptions{PlatformURL: gatePlatURL}
	err := ro.enforcePlatformBinding(false)
	if err == nil {
		t.Fatal("ambiguous_product must hard-fail")
	}
	msg := err.Error()
	for _, want := range []string{"acme/monorepo", gateProduct, "33333333-3333-3333-3333-333333333333", "cilock login --product"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q: %q", want, msg)
		}
	}
}

func TestEnforcePlatformBinding_EndpointUnreachable_SoftSkip(t *testing.T) {
	isolateForGate(t)
	enterAmbient(t)
	stubGateResolve(t, func(string, string, string) (platformauth.Binding, error) {
		// The ONLY class the fail-closed gate soft-skips: a genuinely-unavailable
		// endpoint (transport failure, 404-no-typed-body, 5xx, non-JSON 200).
		// ResolveBinding returns this typed error; the stub must too.
		return platformauth.Binding{}, &platformauth.BindingUnavailableError{
			Reason: "resolve-binding: https://platform.testifysec.com/api/auth/resolve-binding returned 404 (endpoint unavailable / not deployed)",
		}
	})
	ro := &RunOptions{PlatformURL: gatePlatURL}
	if err := ro.enforcePlatformBinding(false); err != nil {
		t.Fatalf("an unreachable/undeployed endpoint must SOFT-skip, got hard error: %v", err)
	}
	if _, ok := platformconfig.ResolvedBinding(gatePlatURL); ok {
		t.Fatal("no binding must be marked when the endpoint is unavailable")
	}
}

// TestEnforcePlatformBinding_UnknownError_HardFail locks the fail-closed
// contract: an unclassified error from the resolve exchange (NOT a typed
// BindingUnavailableError) must HARD-fail. A plain error is treated as a
// deterministic failure, never silently soft-skipped — an authenticated but
// misconfigured build must break rather than emit un-linkable evidence.
func TestEnforcePlatformBinding_UnknownError_HardFail(t *testing.T) {
	isolateForGate(t)
	enterAmbient(t)
	stubGateResolve(t, func(string, string, string) (platformauth.Binding, error) {
		return platformauth.Binding{}, fmt.Errorf("resolve-binding: some unexpected error")
	})
	ro := &RunOptions{PlatformURL: gatePlatURL}
	err := ro.enforcePlatformBinding(false)
	if err == nil {
		t.Fatal("an unclassified binding error must hard-fail (fail closed)")
	}
	if !strings.Contains(err.Error(), "--no-product-binding") {
		t.Fatalf("hard-fail message must name the opt-out remediation, got %q", err.Error())
	}
	if _, ok := platformconfig.ResolvedBinding(gatePlatURL); ok {
		t.Fatal("no binding must be marked on a hard failure")
	}
}
