// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

// sessionJWT builds an unsigned, JWT-shaped session token carrying the given
// scopes — enough for the client-side pre-flight, which never verifies the
// signature.
func sessionJWT(t *testing.T, scopes []string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	body, err := json.Marshal(map[string]any{"sub": "cred-1", "tenant_id": "t1", "scope": scopes})
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

// seedSession isolates the credential store to a temp dir and stores a session
// for platformURL with the given token. Returns the platform URL.
func seedSession(t *testing.T, token string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	const platformURL = "https://platform.example.com"
	if err := auth.Save(auth.Credential{PlatformURL: platformURL, Token: token, TenantID: "t1"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return platformURL
}

func quietTrustCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd
}

// TestRunTrust_RejectsSessionWithoutOIDCWrite is the faithful repro of the
// staging failure: a DEFAULT `cilock login` session (CILOCK_SCOPES, no
// oidc:write) drove `cilock trust` into an opaque platform 500
// ("createCredential credential missing required scope \"*\""). The pre-flight
// must now reject it locally — before any network call — with an actionable
// remedy that names `cilock login --allow-trust`.
func TestRunTrust_RejectsSessionWithoutOIDCWrite(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload", "attestation:read", "sign"}))

	err := runTrust(quietTrustCmd(), []string{"github", "acme/app"}, &options.TrustOptions{}, platformURL, true, false)
	if err == nil {
		t.Fatal("expected a pre-flight rejection for a session lacking oidc:write, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"oidc:write", "--allow-trust", "cilock login"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q; got: %s", want, msg)
		}
	}
	// It must NOT leak the opaque platform error — the whole point is to replace it.
	if strings.Contains(msg, "missing required scope") {
		t.Errorf("pre-flight should not surface the raw platform error: %s", msg)
	}
}

// TestRunTrust_AllowsSessionWithOIDCWrite proves the opt-in session passes the
// pre-flight: with oidc:write present, a --dry-run reaches the plan stage and
// returns nil (no network, no error).
func TestRunTrust_AllowsSessionWithOIDCWrite(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload", "attestation:read", "sign", "oidc:write"}))

	// dryRun=true: resolve + print the plan, then return before any GraphQL call.
	if err := runTrust(quietTrustCmd(), []string{"github", "acme/app"}, &options.TrustOptions{}, platformURL, true, true); err != nil {
		t.Fatalf("a session with oidc:write must pass the pre-flight, got: %v", err)
	}
}
