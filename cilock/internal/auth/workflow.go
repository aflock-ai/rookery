// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/aflock-ai/rookery/platformauth"
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

// resolveBindingFn resolves the repository→tenant/product binding from the
// platform. A package var so tests can stub the network exchange.
var resolveBindingFn = platformauth.ResolveBinding

// AmbientWorkflowLogin establishes a workflow-identity session marker for a CI
// run. It does NOT store a long-lived token: it mints an ambient OIDC token for
// the login audience once (never persisted, never logged), uses it to resolve
// the repository's tenant/product binding, and records a marker credential with
// an empty Token and AuthModeWorkflowOIDC carrying the resolved tenant/product.
// `cilock run` re-mints a fresh ambient OIDC token and RE-RESOLVES the binding
// per run (the run-entry gate), so the persisted marker ids are display-only —
// never treated as authority.
//
// selectorProductID (from `cilock login --product`) disambiguates a repository
// that maps to multiple products.
//
// Binding resolution is BEST-EFFORT at login: a genuine config error
// (repository_not_mapped / ambiguous_product) is returned so the operator sees
// an actionable message, but a transport/availability failure (endpoint not
// deployed yet, 5xx) still yields the workflow-identity marker without a
// tenant/product — the run-entry gate is the enforcement point.
//
// The audience MUST be the platform's dedicated login audience
// (config.PlatformConfig.OIDCLoginAudience), never the Archivista-upload or
// Fulcio signing audience — see the confused-deputy note on OIDCLoginAudience.
func AmbientWorkflowLogin(platformURL, audience, selectorProductID string) (*Credential, error) {
	if !WorkflowOIDCAvailable() {
		return nil, fmt.Errorf("no ambient workflow OIDC identity " +
			"(ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN not set — not in GitHub Actions, " +
			"or the job is missing `permissions: id-token: write`)")
	}
	// Mint a login-audience token and confirm the identity is usable. Retained
	// only for the binding exchange below; never persisted, never logged.
	token, err := workflowOIDCFetcher(audience)
	if err != nil {
		return nil, fmt.Errorf("workflow-identity login probe failed: %w", err)
	}

	cred := &Credential{PlatformURL: platformURL, AuthMode: AuthModeWorkflowOIDC}

	binding, err := resolveBindingFn(platformURL, token, selectorProductID)
	if err != nil {
		// A genuine, reachable-endpoint config error is actionable — surface it.
		if errors.Is(err, platformauth.ErrRepositoryNotMapped) || errors.Is(err, platformauth.ErrAmbiguousProduct) {
			return nil, err
		}
		// Transport/availability failure (endpoint not deployed yet, 5xx): keep
		// the workflow-identity marker without a binding; the run gate resolves.
		return cred, nil
	}
	cred.TenantID = binding.TenantID
	cred.TenantName = binding.TenantName
	cred.ProductID = binding.ProductID
	cred.ProductName = binding.ProductName
	return cred, nil
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
