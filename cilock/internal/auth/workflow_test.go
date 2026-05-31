// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"fmt"
	"testing"
)

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
		if _, err := AmbientWorkflowLogin("https://p", "https://p/login"); err == nil {
			t.Fatal("expected error when no ambient identity")
		}
	})

	t.Run("ambient present, probe ok -> marker (no stored token, audience-pinned)", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		orig := workflowOIDCFetcher
		t.Cleanup(func() { workflowOIDCFetcher = orig })
		var gotAudience string
		workflowOIDCFetcher = func(aud string) (string, error) { gotAudience = aud; return "probe-token", nil }

		cred, err := AmbientWorkflowLogin("https://p", "https://p/login")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.AuthMode != AuthModeWorkflowOIDC {
			t.Fatalf("AuthMode = %q, want %q", cred.AuthMode, AuthModeWorkflowOIDC)
		}
		if cred.Token != "" {
			t.Fatal("workflow-identity marker MUST NOT persist a token")
		}
		if gotAudience != "https://p/login" {
			t.Fatalf("probe audience = %q, want the login audience", gotAudience)
		}
	})

	t.Run("ambient present, probe fails -> hard error (not a silent marker)", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		orig := workflowOIDCFetcher
		t.Cleanup(func() { workflowOIDCFetcher = orig })
		workflowOIDCFetcher = func(string) (string, error) { return "", fmt.Errorf("403: missing id-token: write") }

		if _, err := AmbientWorkflowLogin("https://p", "https://p/login"); err == nil {
			t.Fatal("a failed probe must be a hard error")
		}
	})
}
