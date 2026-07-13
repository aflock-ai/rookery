// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/platformauth"
)

// stubBinding points the binding exchange at a hermetic stub for the duration
// of a subtest so AmbientWorkflowLogin never touches the network.
func stubBinding(t *testing.T, fn func(platformURL, token, selector string) (platformauth.Binding, error)) {
	t.Helper()
	orig := resolveBindingFn
	t.Cleanup(func() { resolveBindingFn = orig })
	resolveBindingFn = fn
}

func TestWorkflowOIDCAvailable(t *testing.T) {
	t.Run("both env vars present", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		if !WorkflowOIDCAvailable() {
			t.Fatal("expected available when both env vars set")
		}
	})
	t.Run("missing request token is not available (self-hosted-runner false positive)", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
		if WorkflowOIDCAvailable() {
			t.Fatal("must require the request TOKEN too, not just the URL")
		}
	})
}

func TestAmbientWorkflowLogin(t *testing.T) {
	t.Run("no ambient identity -> error", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
		if _, err := AmbientWorkflowLogin("https://p", "https://p/login", ""); err == nil {
			t.Fatal("expected error when no ambient identity")
		}
	})

	t.Run("ambient present, probe ok, binding resolves -> marker with tenant/product, no stored token", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		orig := workflowOIDCFetcher
		t.Cleanup(func() { workflowOIDCFetcher = orig })
		var gotAudience string
		workflowOIDCFetcher = func(aud string) (string, error) { gotAudience = aud; return "probe-token", nil }
		var gotToken, gotSelector string
		stubBinding(t, func(_, token, selector string) (platformauth.Binding, error) {
			gotToken, gotSelector = token, selector
			return platformauth.Binding{
				TenantID: "11111111-1111-1111-1111-111111111111", TenantName: "Acme",
				ProductID: "22222222-2222-2222-2222-222222222222", ProductName: "Widget",
			}, nil
		})

		cred, err := AmbientWorkflowLogin("https://p", "https://p/login", "22222222-2222-2222-2222-222222222222")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.AuthMode != AuthModeWorkflowOIDC {
			t.Fatalf("AuthMode = %q, want %q", cred.AuthMode, AuthModeWorkflowOIDC)
		}
		if cred.Token != "" {
			t.Fatal("workflow-identity marker MUST NOT persist a token")
		}
		if cred.ProductID != "22222222-2222-2222-2222-222222222222" || cred.TenantID != "11111111-1111-1111-1111-111111111111" {
			t.Fatalf("binding not populated: %+v", cred)
		}
		if gotAudience != "https://p/login" {
			t.Fatalf("probe audience = %q, want the login audience", gotAudience)
		}
		if gotToken != "probe-token" {
			t.Fatalf("binding exchange got token %q, want the minted login token", gotToken)
		}
		if gotSelector != "22222222-2222-2222-2222-222222222222" {
			t.Fatalf("selector %q not forwarded to the binding exchange", gotSelector)
		}
	})

	t.Run("ambient present, endpoint unavailable -> bare marker (login still succeeds)", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		orig := workflowOIDCFetcher
		t.Cleanup(func() { workflowOIDCFetcher = orig })
		workflowOIDCFetcher = func(string) (string, error) { return "probe-token", nil }
		stubBinding(t, func(_, _, _ string) (platformauth.Binding, error) {
			return platformauth.Binding{}, fmt.Errorf("resolve-binding: request failed: connection refused")
		})

		cred, err := AmbientWorkflowLogin("https://p", "https://p/login", "")
		if err != nil {
			t.Fatalf("a transport failure must not fail login: %v", err)
		}
		if cred.ProductID != "" || cred.TenantID != "" {
			t.Fatalf("no binding expected on transport failure, got %+v", cred)
		}
	})

	t.Run("ambient present, repository_not_mapped -> hard error at login", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		orig := workflowOIDCFetcher
		t.Cleanup(func() { workflowOIDCFetcher = orig })
		workflowOIDCFetcher = func(string) (string, error) { return "probe-token", nil }
		stubBinding(t, func(_, _, _ string) (platformauth.Binding, error) {
			return platformauth.Binding{}, &platformauth.RepositoryNotMappedError{Repository: "acme/widget"}
		})

		if _, err := AmbientWorkflowLogin("https://p", "https://p/login", ""); err == nil {
			t.Fatal("a genuine repository_not_mapped must surface at login")
		}
	})

	t.Run("ambient present, probe fails -> hard error (not a silent marker)", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		orig := workflowOIDCFetcher
		t.Cleanup(func() { workflowOIDCFetcher = orig })
		workflowOIDCFetcher = func(string) (string, error) { return "", fmt.Errorf("403: missing id-token: write") }

		if _, err := AmbientWorkflowLogin("https://p", "https://p/login", ""); err == nil {
			t.Fatal("a failed probe must be a hard error")
		}
	})
}
