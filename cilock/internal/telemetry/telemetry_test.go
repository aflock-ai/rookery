// Copyright 2025 The Aflock Authors
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

package telemetry

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearTelemetryEnv blanks every env var that influences Report/optedOut/detectCI
// so each test starts from a known, CI-agnostic baseline. t.Setenv restores the
// prior value automatically at test end.
func clearTelemetryEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CILOCK_NO_TELEMETRY", "DO_NOT_TRACK", "CILOCK_PLATFORM_URL",
		"GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI", "CI",
	} {
		t.Setenv(k, "")
	}
}

// isolateConfig points os.UserConfigDir (and the jctl fallback's home) at a temp
// dir so auth.Lookup/auth.Save never touch the developer's real credentials.
func isolateConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir+"/.config")
}

// authenticate seeds a non-expired platform credential under the same key Report
// looks up (config.DefaultPlatformURL), putting the CLI in the "logged in" state.
func authenticate(t *testing.T, c auth.Credential) {
	t.Helper()
	c.PlatformURL = config.DefaultPlatformURL
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = time.Now().Add(time.Hour)
	}
	require.NoError(t, auth.Save(c))
}

// seedAmbientMarker writes a workflow-identity marker credential (the exact shape
// `cilock login` stores in CI: AuthModeWorkflowOIDC, EMPTY Token) for the given
// platform URL, putting the CLI in the pure-ambient state — a platform identity
// exists but there is no stored bearer.
func seedAmbientMarker(t *testing.T, platformURL string) {
	t.Helper()
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: platformURL,
		AuthMode:    auth.AuthModeWorkflowOIDC,
		// Token intentionally empty — the ambient marker never persists a bearer.
		ExpiresAt: time.Now().Add(time.Hour),
	}))
}

// captureServer stands in for the analytics hub. It records the single request
// it receives (method, headers, decoded JSON body) for assertions, and points
// the package-level endpoint at itself for the duration of the test.
type captureServer struct {
	mu      sync.Mutex
	hits    int
	method  string
	auth    string
	ctype   string
	payload map[string]any
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	cs := &captureServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		cs.hits++
		cs.method = r.Method
		cs.auth = r.Header.Get("Authorization")
		cs.ctype = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &cs.payload)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	prev := endpoint
	endpoint = srv.URL
	t.Cleanup(func() { endpoint = prev })
	return cs
}

func (cs *captureServer) Hits() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.hits
}

// ---- optedOut --------------------------------------------------------------

func TestOptedOut(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset", nil, false},
		{"cilock 1", map[string]string{"CILOCK_NO_TELEMETRY": "1"}, true},
		{"cilock true", map[string]string{"CILOCK_NO_TELEMETRY": "true"}, true},
		{"cilock TRUE mixed-case", map[string]string{"CILOCK_NO_TELEMETRY": "TRUE"}, true},
		{"cilock yes", map[string]string{"CILOCK_NO_TELEMETRY": "yes"}, true},
		{"cilock on padded", map[string]string{"CILOCK_NO_TELEMETRY": "  on  "}, true},
		{"do_not_track 1", map[string]string{"DO_NOT_TRACK": "1"}, true},
		{"do_not_track true", map[string]string{"DO_NOT_TRACK": "true"}, true},
		{"falsey value 0", map[string]string{"CILOCK_NO_TELEMETRY": "0"}, false},
		{"falsey value false", map[string]string{"DO_NOT_TRACK": "false"}, false},
		{"garbage value", map[string]string{"CILOCK_NO_TELEMETRY": "maybe"}, false},
		{"empty string", map[string]string{"DO_NOT_TRACK": ""}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearTelemetryEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			assert.Equal(t, tc.want, optedOut())
		})
	}
}

// ---- detectCI --------------------------------------------------------------

func TestDetectCI(t *testing.T) {
	tests := []struct {
		name         string
		env          map[string]string
		wantCI       bool
		wantProvider string
	}{
		{"no ci -> local", nil, false, "local"},
		{"github actions", map[string]string{"GITHUB_ACTIONS": "true"}, true, "github_actions"},
		{"gitlab", map[string]string{"GITLAB_CI": "true"}, true, "gitlab"},
		{"jenkins", map[string]string{"JENKINS_URL": "http://ci"}, true, "jenkins"},
		{"circleci", map[string]string{"CIRCLECI": "true"}, true, "circleci"},
		{"generic CI=true", map[string]string{"CI": "true"}, true, "unknown"},
		{"generic CI=1", map[string]string{"CI": "1"}, true, "unknown"},
		{"generic CI=TRUE case-insensitive", map[string]string{"CI": "TRUE"}, true, "unknown"},
		{"CI=false is not ci", map[string]string{"CI": "false"}, false, "local"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearTelemetryEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			gotCI, gotProvider := detectCI()
			assert.Equal(t, tc.wantCI, gotCI)
			assert.Equal(t, tc.wantProvider, gotProvider)
		})
	}
}

// detectCI precedence: GitHub Actions wins over the generic CI=true that GitHub
// also sets, so a GitHub run is never mislabeled "unknown".
func TestDetectCIPrecedence(t *testing.T) {
	clearTelemetryEnv(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("CI", "true") // GitHub Actions sets both; specific provider must win
	ci, provider := detectCI()
	assert.True(t, ci)
	assert.Equal(t, "github_actions", provider)
}

// ---- Report: no-op gates ---------------------------------------------------

// Opt-out short-circuits before any auth lookup or network call.
func TestReportOptedOutSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{Token: "jwt", Email: "a@b.com"})
	cs := newCaptureServer(t)

	t.Setenv("CILOCK_NO_TELEMETRY", "1")
	Report("verify", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "opted-out run must not POST")
}

// An empty command name is treated as a no-op (defensive guard).
func TestReportEmptyCommandSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{Token: "jwt", Email: "a@b.com"})
	cs := newCaptureServer(t)

	Report("", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "empty command name must not POST")
}

// The auth gate: with no stored credential the CLI is unauthenticated and sends
// nothing. This is the core privacy/identity invariant.
func TestReportUnauthenticatedSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t) // empty store, no jctl fallback file
	cs := newCaptureServer(t)

	Report("verify", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "unauthenticated run must not POST")
}

// An expired credential is not "authenticated" (auth.Lookup drops it), so Report
// must send nothing.
func TestReportExpiredCredentialSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{
		Token:     "stale",
		Email:     "a@b.com",
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	cs := newCaptureServer(t)

	Report("verify", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "expired credential must not POST")
}

// A stored credential with an empty token is not usable (no bearer); Report must
// send nothing rather than POST an unauthenticated event.
func TestReportEmptyTokenSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{Token: "", Email: "a@b.com"})
	cs := newCaptureServer(t)

	Report("verify", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "credential without a token must not POST")
}

// ---- Report: happy path payload + headers ----------------------------------

// The authenticated happy path: exactly one POST, correct headers, and a body
// carrying usage metadata + the email join key.
func TestReportAuthenticatedPostsUsageEvent(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	t.Setenv("GITHUB_ACTIONS", "true") // assert CI fields are populated
	authenticate(t, auth.Credential{
		Token:      "jwt-secret-bearer",
		Email:      "alice@acme.com",
		TenantName: "acme",
		TenantID:   "tid-123",
	})
	cs := newCaptureServer(t)

	Report("verify", "1.2.3", "success")

	require.Equal(t, 1, cs.Hits(), "authenticated run must POST exactly once")
	assert.Equal(t, http.MethodPost, cs.method)
	assert.Equal(t, "application/json", cs.ctype)
	// The platform session JWT is the bearer.
	assert.Equal(t, "Bearer jwt-secret-bearer", cs.auth)

	p := cs.payload
	require.NotNil(t, p)
	assert.Equal(t, "verify", p["command"])
	assert.Equal(t, "1.2.3", p["cli_version"])
	assert.Equal(t, "success", p["outcome"])
	assert.Equal(t, runtime.GOOS, p["os"])
	assert.Equal(t, runtime.GOARCH, p["arch"])
	assert.Equal(t, true, p["ci"])
	assert.Equal(t, "github_actions", p["ci_provider"])
	// Email is the documented cross-property identity join key.
	assert.Equal(t, "alice@acme.com", p["user_ref"])
	// TenantName is preferred for the account label when present.
	assert.Equal(t, "acme", p["account"])
}

// REDACTION INVARIANT: the bearer token must travel ONLY in the Authorization
// header, never as a field in the JSON body. The docstring promises we "never
// send the user's GitHub token" and only the platform bearer as a header.
func TestReportBodyDoesNotLeakToken(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{
		Token:       "jwt-secret-bearer",
		Email:       "alice@acme.com",
		TenantName:  "acme",
		ProductID:   "prod-should-not-appear",
		ProductName: "secret-product",
	})
	cs := newCaptureServer(t)

	Report("run", "9.9.9", "success")
	require.Equal(t, 1, cs.Hits())

	// No body field may carry the token value.
	for k, v := range cs.payload {
		if s, ok := v.(string); ok {
			assert.NotContains(t, s, "jwt-secret-bearer",
				"token value leaked into body field %q", k)
		}
	}
	// Usage-metadata-only: product identifiers/names are never transmitted.
	_, hasProductID := cs.payload["product_id"]
	_, hasProductName := cs.payload["product_name"]
	assert.False(t, hasProductID, "product_id must not be transmitted")
	assert.False(t, hasProductName, "product_name must not be transmitted")
	// And the token must not appear under any of these obvious key names either.
	for _, k := range []string{"token", "bearer", "jwt", "authorization"} {
		_, present := cs.payload[k]
		assert.False(t, present, "body must not contain a %q field", k)
	}
}

// account falls back to TenantID when TenantName is empty, so the event is still
// attributable to a tenant.
func TestReportAccountFallsBackToTenantID(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{
		Token:    "jwt",
		Email:    "bob@acme.com",
		TenantID: "tid-789",
		// TenantName intentionally empty
	})
	cs := newCaptureServer(t)

	Report("sign", "2.0.0", "success")
	require.Equal(t, 1, cs.Hits())
	assert.Equal(t, "tid-789", cs.payload["account"],
		"account must fall back to TenantID when TenantName is empty")
}

// A non-CI local run reports ci=false / provider=local in the payload.
func TestReportLocalRunMarksNotCI(t *testing.T) {
	clearTelemetryEnv(t) // ensures no CI env leaks in from the test host
	isolateConfig(t)
	authenticate(t, auth.Credential{Token: "jwt", Email: "c@d.com", TenantName: "t"})
	cs := newCaptureServer(t)

	Report("verify", "1.0.0", "success")
	require.Equal(t, 1, cs.Hits())
	assert.Equal(t, false, cs.payload["ci"])
	assert.Equal(t, "local", cs.payload["ci_provider"])
}

// Report must never panic or block the CLI when the hub is unreachable; it
// swallows transport errors. We point the endpoint at a closed server and assert
// the call returns cleanly.
func TestReportSwallowsTransportError(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{Token: "jwt", Email: "e@f.com", TenantName: "t"})

	// Start then immediately close a server to get a dead address.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close()
	prev := endpoint
	endpoint = dead
	t.Cleanup(func() { endpoint = prev })

	assert.NotPanics(t, func() {
		Report("verify", "1.0.0", "success")
	}, "Report must swallow transport errors and never panic")
}

// ---- Report: platform-awareness (CILOCK_PLATFORM_URL) -----------------------

// TestReportAttributesToResolvedPlatform pins the platform-awareness fix:
// telemetry follows the platform the command actually used (CILOCK_PLATFORM_URL,
// set by run/verify), not the hardcoded production default. Regression — staging
// / self-hosted / --platform-url usage was silently dropped because Report only
// ever looked up config.DefaultPlatformURL.
func TestReportAttributesToResolvedPlatform(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	const staging = "https://platform.aws-sandbox-staging.testifysec.dev"
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: staging, // NOT config.DefaultPlatformURL
		Token:       "staging-jwt",
		Email:       "ci@testifysec.com",
		TenantName:  "staging-tenant",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	t.Setenv("CILOCK_PLATFORM_URL", staging)
	cs := newCaptureServer(t)

	Report("run", "1.2.3", "success")

	require.Equal(t, 1, cs.Hits(), "telemetry must emit attributed to the resolved (staging) platform")
	assert.Equal(t, "Bearer staging-jwt", cs.auth)
	assert.Equal(t, "staging-tenant", cs.payload["account"])
	assert.Equal(t, "ci@testifysec.com", cs.payload["user_ref"])
}

// TestReportResolvedPlatformUnauthenticatedSendsNothing ensures credentials for
// one platform are never attributed to usage of another: targeting a platform
// with no stored credential emits nothing, even when logged in elsewhere.
func TestReportResolvedPlatformUnauthenticatedSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{Token: "prod-jwt", Email: "a@b.com", TenantName: "prod"}) // default platform only
	t.Setenv("CILOCK_PLATFORM_URL", "https://platform.aws-sandbox-staging.testifysec.dev")    // command targeted staging
	cs := newCaptureServer(t)

	Report("run", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "no credential for the resolved platform => no telemetry (no cross-platform leakage)")
}

// TestReportFallsBackToDefaultPlatform ensures back-compat: with no
// CILOCK_PLATFORM_URL set, Report still attributes to the default platform.
func TestReportFallsBackToDefaultPlatform(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	authenticate(t, auth.Credential{Token: "default-jwt", Email: "a@b.com", TenantName: "default-tenant"})
	cs := newCaptureServer(t) // CILOCK_PLATFORM_URL intentionally unset

	Report("verify", "1.2.3", "success")
	require.Equal(t, 1, cs.Hits(), "with no resolved platform, telemetry falls back to the default platform credential")
	assert.Equal(t, "default-tenant", cs.payload["account"])
}

// ---- Report: ambient GitHub Actions OIDC (keyless CI) -----------------------

// THE AMBIENT PRIVACY INVARIANT: in pure ambient mode (keyless CI), `cilock
// login` stores only a workflow-identity marker with an EMPTY Token. cilock IS
// interacting with the platform, but the only platform-acceptable bearer is the
// raw GHA OIDC token, whose claims embed repo/org/ref/sha — identifiers this
// package promises never to transmit. So Report MUST send nothing rather than
// leak. This pins that behavior so a future change can't silently start POSTing
// in the ambient case (which would either leak repo identity or rely on an
// unverified hub OIDC-bearer contract).
func TestReportAmbientWorkflowOIDCSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	// Simulate a GitHub Actions keyless CI run with an ambient identity present.
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.example/req")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ambient-req-token")
	seedAmbientMarker(t, config.DefaultPlatformURL)
	cs := newCaptureServer(t)

	Report("run", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(),
		"ambient workflow-identity marker (no bearer) must POST nothing — sending the raw GHA OIDC token would leak repo/org claims")
}

// Same as above but for a NON-default resolved platform (staging), as run/verify
// export CILOCK_PLATFORM_URL at runtime. The ambient no-op must hold regardless
// of which platform the command targeted.
func TestReportAmbientResolvedPlatformSendsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	const staging = "https://platform.aws-sandbox-staging.testifysec.dev"
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.example/req")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ambient-req-token")
	t.Setenv("CILOCK_PLATFORM_URL", staging)
	seedAmbientMarker(t, staging)
	cs := newCaptureServer(t)

	Report("run", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "ambient marker for the resolved staging platform must POST nothing")
}

// Opt-out still short-circuits even in the ambient case (defense in depth: the
// ambient path is already a no-op, but the opt-out guard must precede everything).
func TestReportAmbientRespectsOptOut(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.example/req")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ambient-req-token")
	t.Setenv("DO_NOT_TRACK", "1")
	seedAmbientMarker(t, config.DefaultPlatformURL)
	cs := newCaptureServer(t)

	Report("run", "1.2.3", "success")
	assert.Equal(t, 0, cs.Hits(), "opt-out must suppress telemetry in the ambient case too")
}

// A token-bearing session for the DEFAULT platform must still emit even when an
// ambient marker exists for a DIFFERENT platform — the ambient detection must not
// suppress a legitimate authenticated send (no cross-platform interference).
func TestReportAmbientMarkerElsewhereDoesNotSuppressAuthenticated(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	// Real bearer for the default platform (the resolved target)...
	authenticate(t, auth.Credential{Token: "real-jwt", Email: "a@b.com", TenantName: "acme"})
	// ...and an ambient marker for some other platform.
	seedAmbientMarker(t, "https://platform.aws-sandbox-staging.testifysec.dev")
	cs := newCaptureServer(t)

	Report("verify", "1.2.3", "success")
	require.Equal(t, 1, cs.Hits(), "an authenticated session must still emit; an unrelated ambient marker is irrelevant")
	assert.Equal(t, "Bearer real-jwt", cs.auth)
}

// A token-bearing browser session that ALSO happens to be tagged
// AuthModeWorkflowOIDC (defensive: a non-empty token always wins) still emits —
// the gate is the presence of a usable bearer, not the AuthMode label.
func TestReportTokenBearingMarkerStillEmits(t *testing.T) {
	clearTelemetryEnv(t)
	isolateConfig(t)
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: config.DefaultPlatformURL,
		Token:       "real-jwt",
		Email:       "a@b.com",
		TenantName:  "acme",
		AuthMode:    auth.AuthModeWorkflowOIDC, // label says workflow, but a real token is present
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	cs := newCaptureServer(t)

	Report("verify", "1.2.3", "success")
	require.Equal(t, 1, cs.Hits(), "a credential with a usable bearer must emit regardless of its AuthMode label")
	assert.Equal(t, "Bearer real-jwt", cs.auth)
}
