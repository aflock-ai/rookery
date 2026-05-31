// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// WorkflowOIDCAvailable reports whether an ambient CI workflow OIDC identity is
// present. It checks for the GitHub Actions OIDC token endpoint env vars
// (ACTIONS_ID_TOKEN_REQUEST_URL + ACTIONS_ID_TOKEN_REQUEST_TOKEN), NOT the
// broad GITHUB_ACTIONS flag — a self-hosted runner sets GITHUB_ACTIONS=true but
// may lack the token endpoint (no `id-token: write` permission), and treating
// that as an identity would be a false positive.
func WorkflowOIDCAvailable() bool {
	return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

// workflowOIDCFetcher obtains an ambient workflow OIDC token for the given
// audience. It is a package var so tests can stub the network call.
var workflowOIDCFetcher = fetchWorkflowOIDCToken

// AmbientWorkflowLogin establishes a workflow-identity session marker for a CI
// run. It does NOT store a long-lived token: it probes the ambient OIDC token
// endpoint once (audience-pinned, token discarded) to confirm the identity is
// usable — failing loudly if it is not — then records a marker credential with
// an empty Token and AuthModeWorkflowOIDC. `cilock run` sources a fresh ambient
// OIDC token per upload at call time, so nothing secret is persisted.
//
// The audience MUST be the platform's dedicated login audience
// (config.PlatformConfig.OIDCLoginAudience), never the Archivista-upload or
// Fulcio signing audience — see the confused-deputy note on OIDCLoginAudience.
func AmbientWorkflowLogin(platformURL, audience string) (*Credential, error) {
	if !WorkflowOIDCAvailable() {
		return nil, fmt.Errorf("no ambient workflow OIDC identity " +
			"(ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN not set — not in GitHub Actions, " +
			"or the job is missing `permissions: id-token: write`)")
	}
	// Probe: confirm we can actually mint a token for the login audience. The
	// token is discarded — run sources its own per-call. We never log it.
	if _, err := workflowOIDCFetcher(audience); err != nil {
		return nil, fmt.Errorf("workflow-identity login probe failed: %w", err)
	}
	return &Credential{PlatformURL: platformURL, AuthMode: AuthModeWorkflowOIDC}, nil
}

// fetchWorkflowOIDCToken requests a GitHub Actions OIDC token for the given
// audience. Mirrors the run-side fetcher; kept here so login has no dependency
// on the run package. The returned token is sensitive and MUST NOT be logged.
func fetchWorkflowOIDCToken(audience string) (string, error) {
	tokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if tokenURL == "" {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL not set")
	}
	bearerToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if bearerToken == "" {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")
	}

	u, err := url.Parse(tokenURL)
	if err != nil {
		return "", fmt.Errorf("parse OIDC token URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build OIDC token request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+bearerToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("OIDC token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode OIDC token response: %w", err)
	}
	if tokenResp.Value == "" {
		return "", fmt.Errorf("empty OIDC token in response")
	}
	return tokenResp.Value, nil
}
