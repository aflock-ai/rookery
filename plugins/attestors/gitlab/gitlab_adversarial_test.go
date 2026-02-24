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

package gitlab

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FINDING 1: JWKS URL derived from untrusted CI_SERVER_URL
// Severity: HIGH
//
// When WITNESS_GITLAB_JWKS_URL is not set, the JWKS URL is constructed as:
//   fmt.Sprintf("%s/oauth/discovery/keys", a.CIServerUrl)
//
// CI_SERVER_URL comes from the environment. If an attacker controls
// CI_SERVER_URL, they control the JWKS endpoint, allowing them to serve
// their own signing keys and forge JWT tokens.
//
// This is worse than GitHub because:
// 1. GitHub at least has a hardcoded default JWKS URL
// 2. GitLab derives the JWKS URL from another untrusted env var
// =============================================================================

func TestAdversarial_JWKSUrlDerivedFromUntrustedEnv(t *testing.T) {
	var jwksRequested bool
	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksRequested = true
		t.Logf("Attacker JWKS endpoint hit: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		// Attacker serves their own keyset
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer attackerServer.Close()

	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", attackerServer.URL) // Attacker controls this
	// Ensure WITNESS_GITLAB_JWKS_URL is NOT set, forcing derivation from CI_SERVER_URL
	require.NoError(t, os.Unsetenv("WITNESS_GITLAB_JWKS_URL"))

	a := New(WithToken(fakeJWT()))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	_ = a.Attest(ctx)

	assert.True(t, jwksRequested,
		"BUG: JWKS URL is derived from untrusted CI_SERVER_URL. "+
			"An attacker who controls CI_SERVER_URL controls JWT verification. "+
			"The JWKS endpoint was hit at the attacker's server.")
}

// =============================================================================
// FINDING 2: WITNESS_GITLAB_JWKS_URL override - same SSRF as GitHub
// Severity: HIGH
//
// WITNESS_GITLAB_JWKS_URL can be set to any URL, redirecting JWT verification
// to an attacker-controlled endpoint.
// =============================================================================

func TestAdversarial_JWKSUrlOverrideSSRF(t *testing.T) {
	var jwksPath string
	attackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer attackerServer.Close()

	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://legitimate-gitlab.com")
	t.Setenv("WITNESS_GITLAB_JWKS_URL", attackerServer.URL+"/evil-jwks")

	a := New(WithToken(fakeJWT()))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	_ = a.Attest(ctx)

	assert.Equal(t, "/evil-jwks", jwksPath,
		"BUG: WITNESS_GITLAB_JWKS_URL takes precedence over CI_SERVER_URL-derived URL. "+
			"Attacker can override JWKS endpoint even when CI_SERVER_URL is legitimate.")
}

// =============================================================================
// FINDING 3: All env var fields are blindly trusted without validation
// Severity: MEDIUM
//
// Same pattern as GitHub: no cross-validation between JWT claims and env vars.
// An attacker can spoof ALL attestation fields by setting env vars.
// =============================================================================

func TestAdversarial_EnvVar_CompleteSpoofing(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.com")
	t.Setenv("CI_CONFIG_PATH", ".gitlab-ci.yml")
	t.Setenv("CI_JOB_ID", "999999")
	t.Setenv("CI_JOB_IMAGE", "docker:latest")
	t.Setenv("CI_JOB_NAME", "deploy-production")
	t.Setenv("CI_JOB_STAGE", "deploy")
	t.Setenv("CI_JOB_URL", "https://gitlab.com/legit-org/legit-repo/-/jobs/999999")
	t.Setenv("CI_PIPELINE_ID", "888888")
	t.Setenv("CI_PIPELINE_URL", "https://gitlab.com/legit-org/legit-repo/-/pipelines/888888")
	t.Setenv("CI_PROJECT_ID", "42")
	t.Setenv("CI_PROJECT_URL", "https://gitlab.com/legit-org/legit-repo")
	t.Setenv("CI_RUNNER_ID", "1")
	t.Setenv("CI_SERVER_HOST", "gitlab.com")

	// No JWT token available - attestor still succeeds
	require.NoError(t, os.Unsetenv("CI_JOB_JWT"))

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err, "Attestor should succeed even without JWT")

	// ALL fields are populated from untrusted env vars
	assert.Equal(t, "999999", a.JobID)
	assert.Equal(t, "deploy-production", a.JobName)
	assert.Equal(t, "deploy", a.JobStage)
	assert.Equal(t, "https://gitlab.com/legit-org/legit-repo/-/jobs/999999", a.JobUrl)
	assert.Equal(t, "888888", a.PipelineID)
	assert.Equal(t, "https://gitlab.com/legit-org/legit-repo/-/pipelines/888888", a.PipelineUrl)
	assert.Equal(t, "42", a.ProjectID)
	assert.Equal(t, "https://gitlab.com/legit-org/legit-repo", a.ProjectUrl)

	t.Log("BUG: All attestation fields are set from env vars without ANY validation. " +
		"An attacker who can set env vars can make this attestation claim to be from " +
		"any GitLab project, pipeline, job, etc.")
}

// =============================================================================
// FINDING 4: JWT is optional - attestation succeeds without it
// Severity: HIGH
//
// If no JWT token is found (CI_JOB_JWT not set, no token option, no
// tokenEnvVar option), the attestor logs a warning but SUCCEEDS.
// This means a completely forged GitLab environment (just env vars, no
// cryptographic proof) produces a valid attestation.
//
// Compare with GitHub which REQUIRES the JWT and fails if it can't be fetched.
// =============================================================================

func TestAdversarial_AttestSucceedsWithoutJWT(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.example.com")
	t.Setenv("CI_PIPELINE_URL", "https://gitlab.example.com/project/-/pipelines/1")
	t.Setenv("CI_PROJECT_URL", "https://gitlab.example.com/project")
	t.Setenv("CI_JOB_URL", "https://gitlab.example.com/project/-/jobs/1")

	// Ensure no JWT sources are available
	require.NoError(t, os.Unsetenv("CI_JOB_JWT"))

	a := New() // No WithToken, no WithTokenEnvVar
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err,
		"BUG: GitLab attestor succeeds without ANY JWT token. "+
			"There is no cryptographic proof of CI environment identity. "+
			"GitHub attestor correctly requires the JWT.")

	assert.Nil(t, a.JWT,
		"JWT field is nil - attestation has no cryptographic binding to CI identity")

	// Subjects are still created from unverified env vars
	subjects := a.Subjects()
	assert.NotEmpty(t, subjects,
		"BUG: Subjects are created even without JWT verification. "+
			"These subjects have NO cryptographic backing.")
}

// =============================================================================
// FINDING 5: tokenEnvVar allows reading arbitrary env vars
// Severity: MEDIUM
//
// WithTokenEnvVar allows specifying an arbitrary env var name to read
// the JWT from. If user input flows into this option, an attacker could
// read any environment variable as a "JWT token" and have it sent to
// the JWKS endpoint for "verification".
//
// More critically, the env var value is passed directly to jwt.New()
// and then sent in HTTP requests.
// =============================================================================

func TestAdversarial_TokenEnvVar_ArbitraryEnvRead(t *testing.T) {
	// Simulate attacker controlling the token env var name
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.example.com")
	// Put a "secret" in an unrelated env var
	t.Setenv("DATABASE_PASSWORD", "super-secret-password")

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	t.Setenv("WITNESS_GITLAB_JWKS_URL", jwksServer.URL+"/jwks")

	// If attacker can control the WithTokenEnvVar parameter, they can read
	// arbitrary env vars. The value gets passed to jwt.New() and then
	// sent to the JWKS endpoint in HTTP requests.
	a := New(WithTokenEnvVar("DATABASE_PASSWORD"))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	// Will fail because "super-secret-password" is not a valid JWT
	t.Logf("Attest error (expected - bad JWT format): %v", err)

	t.Log("NOTE: WithTokenEnvVar allows reading arbitrary env vars as JWT tokens. " +
		"If user input flows into this option, it could be used to exfiltrate env var values " +
		"through error messages or side channels.")
}

// =============================================================================
// FINDING 6: URL fields not validated as URLs
// Severity: MEDIUM
//
// CI_JOB_URL, CI_PIPELINE_URL, CI_PROJECT_URL are stored verbatim.
// They could contain javascript: URIs, data: URIs, paths with traversal, etc.
// =============================================================================

func TestAdversarial_EnvVar_MaliciousURLs(t *testing.T) {
	testCases := []struct {
		name       string
		envVar     string
		value      string
		fieldCheck func(*Attestor) string
	}{
		{
			name:       "javascript URI in job URL",
			envVar:     "CI_JOB_URL",
			value:      "javascript:alert('xss')",
			fieldCheck: func(a *Attestor) string { return a.JobUrl },
		},
		{
			name:       "data URI in pipeline URL",
			envVar:     "CI_PIPELINE_URL",
			value:      "data:text/html,<script>alert(1)</script>",
			fieldCheck: func(a *Attestor) string { return a.PipelineUrl },
		},
		{
			name:       "CRLF injection in project URL",
			envVar:     "CI_PROJECT_URL",
			value:      "https://gitlab.com/org/repo\r\nX-Injected: true",
			fieldCheck: func(a *Attestor) string { return a.ProjectUrl },
		},
		{
			name:       "null bytes in job URL",
			envVar:     "CI_JOB_URL",
			value:      "https://gitlab.com/\x00/evil",
			fieldCheck: func(a *Attestor) string { return a.JobUrl },
		},
		{
			name:       "extremely long URL",
			envVar:     "CI_PIPELINE_URL",
			value:      "https://gitlab.com/" + strings.Repeat("A", 100000),
			fieldCheck: func(a *Attestor) string { return a.PipelineUrl },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITLAB_CI", "true")
			t.Setenv("CI_SERVER_URL", "https://gitlab.com")
			t.Setenv(tc.envVar, tc.value)
			require.NoError(t, os.Unsetenv("CI_JOB_JWT"))

			a := New()
			ctx, err := attestation.NewContext("test", []attestation.Attestor{})
			require.NoError(t, err)

			err = a.Attest(ctx)
			require.NoError(t, err)

			gotValue := tc.fieldCheck(a)
			assert.Equal(t, tc.value, gotValue,
				"BUG: Malicious value %q stored verbatim in attestation field. "+
					"No URL validation or sanitization.", tc.value[:min(50, len(tc.value))])
		})
	}
}

// =============================================================================
// FINDING 7: Subjects computed from unsanitized URLs
// Severity: MEDIUM
//
// Same as GitHub: Subjects() creates digest-based subjects from PipelineUrl,
// JobUrl, ProjectUrl. All from env vars. Policy can be bypassed.
// =============================================================================

func TestAdversarial_SubjectsSpoofing(t *testing.T) {
	a := &Attestor{
		PipelineUrl: "https://gitlab.com/legit-org/legit-repo/-/pipelines/12345",
		JobUrl:      "https://gitlab.com/legit-org/legit-repo/-/jobs/67890",
		ProjectUrl:  "https://gitlab.com/legit-org/legit-repo",
	}

	subjects := a.Subjects()

	expectedKeys := []string{
		"pipelineurl:" + a.PipelineUrl,
		"joburl:" + a.JobUrl,
		"projecturl:" + a.ProjectUrl,
	}

	for _, key := range expectedKeys {
		_, exists := subjects[key]
		assert.True(t, exists,
			"BUG: Subject %q created from unvalidated URL field. "+
				"An attacker can produce subjects matching any legitimate pipeline.", key)
	}
}

// =============================================================================
// FINDING 8: BackRefs returns inconsistent results due to map iteration order
// Severity: LOW
//
// BackRefs() iterates over Subjects() map and breaks on the first
// "pipelineurl:" key. Map iteration order in Go is non-deterministic.
// If there were somehow multiple pipelineurl subjects, the returned
// backref would be unpredictable. In practice there's only one, but
// the pattern is fragile.
// =============================================================================

func TestAdversarial_BackRefsNondeterminism(t *testing.T) {
	a := &Attestor{
		PipelineUrl: "https://gitlab.com/project/-/pipelines/1",
		JobUrl:      "https://gitlab.com/project/-/jobs/1",
		ProjectUrl:  "https://gitlab.com/project",
	}

	// Run BackRefs() many times to check consistency
	var lastKey string
	for i := 0; i < 100; i++ {
		refs := a.BackRefs()
		require.Len(t, refs, 1)
		for k := range refs {
			if lastKey == "" {
				lastKey = k
			}
			assert.Equal(t, lastKey, k,
				"BackRefs returned different key on iteration %d", i)
		}
	}
}

// =============================================================================
// FINDING 9: CI_JOB_JWT fallback for GitLab < 17.0
// Severity: MEDIUM
//
// The code falls back to CI_JOB_JWT for GitLab < 17.0. CI_JOB_JWT is a
// deprecated variable that was available to ALL jobs by default. In
// GitLab >= 15.9, CI_JOB_JWT is deprecated, and in >= 17.0 it's removed.
// Using this as a fallback means the attestor works with the less-secure
// legacy token mechanism.
// =============================================================================

func TestAdversarial_LegacyJWTFallback(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.com")
	t.Setenv("CI_JOB_JWT", fakeJWT()) // Legacy env var

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	t.Setenv("WITNESS_GITLAB_JWKS_URL", jwksServer.URL+"/jwks")

	a := New() // No explicit token or tokenEnvVar
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	// Will get past the JWT fetch but may fail at signature verification
	t.Logf("Attest with legacy CI_JOB_JWT: %v", err)

	// The attestor should at least attempt JWT attestation
	assert.NotNil(t, a.JWT,
		"JWT should be set from legacy CI_JOB_JWT fallback")

	t.Log("NOTE: CI_JOB_JWT fallback uses a deprecated, less-secure token mechanism. " +
		"Consider requiring explicit token configuration for GitLab >= 17.0.")
}

// =============================================================================
// FINDING 10: Token priority can mask misconfiguration
// Severity: LOW
//
// The token resolution order is:
// 1. a.token (from WithToken)
// 2. os.Getenv(a.tokenEnvVar) (from WithTokenEnvVar)
// 3. os.Getenv("CI_JOB_JWT")
//
// If a.token is set but invalid, the attestor will fail without trying
// the other sources. There's no fallback chain.
// =============================================================================

func TestAdversarial_TokenPriorityMasking(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.com")
	t.Setenv("CI_JOB_JWT", fakeJWT()) // This is valid-ish

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	t.Setenv("WITNESS_GITLAB_JWKS_URL", jwksServer.URL+"/jwks")

	// WithToken takes priority, even if it's garbage
	a := New(WithToken("not-a-jwt"))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.Error(t, err,
		"Should fail because 'not-a-jwt' is not valid JWT format")

	t.Log("NOTE: WithToken takes priority over CI_JOB_JWT. If the explicit token " +
		"is invalid, CI_JOB_JWT is never tried. This is arguably correct behavior " +
		"(explicit > implicit) but can cause confusing failures.")
}

// =============================================================================
// FINDING 11: Empty subjects are still created
// Severity: LOW
//
// When URL env vars are not set, empty strings are used to create subjects.
// This means the attestation has subjects for empty URLs, which pollutes
// the subject namespace and could match other empty-URL attestations.
// =============================================================================

func TestAdversarial_EmptySubjectsCollision(t *testing.T) {
	// Two different attestors with empty URLs produce identical subjects
	a1 := &Attestor{PipelineUrl: "", JobUrl: "", ProjectUrl: ""}
	a2 := &Attestor{PipelineUrl: "", JobUrl: "", ProjectUrl: ""}

	s1 := a1.Subjects()
	s2 := a2.Subjects()

	assert.Equal(t, len(s1), len(s2))

	// All subjects match because they're all digests of empty string
	for key, digest1 := range s1 {
		digest2, exists := s2[key]
		assert.True(t, exists)
		assert.Equal(t, digest1, digest2,
			"BUG: Empty URL subjects collide. Two completely different GitLab "+
				"environments with missing URL env vars produce identical subjects, "+
				"potentially matching each other in policy evaluation.")
	}
}

// =============================================================================
// FINDING 12: No GITLAB_CI value validation
// Severity: LOW
//
// The check is os.Getenv("GITLAB_CI") != "true". This means GITLAB_CI=TRUE,
// GITLAB_CI=True, GITLAB_CI=1 all fail the check. This is inconsistent
// with how some CI systems set boolean env vars.
// =============================================================================

func TestAdversarial_GitlabCIValueVariants(t *testing.T) {
	testCases := []struct {
		value    string
		shouldOK bool
	}{
		{"true", true},
		{"TRUE", false},
		{"True", false},
		{"1", false},
		{"yes", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("GITLAB_CI=%q", tc.value), func(t *testing.T) {
			t.Setenv("GITLAB_CI", tc.value)
			require.NoError(t, os.Unsetenv("CI_JOB_JWT"))

			a := New()
			ctx, err := attestation.NewContext("test", []attestation.Attestor{})
			require.NoError(t, err)

			err = a.Attest(ctx)
			if tc.shouldOK {
				assert.NotErrorIs(t, err, ErrNotGitlab{})
			} else {
				assert.IsType(t, ErrNotGitlab{}, err,
					"GITLAB_CI=%q should be rejected", tc.value)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
