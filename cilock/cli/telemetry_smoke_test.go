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

//go:build integration

// Binary-level telemetry smoke gate. Builds the real cilock binary with the
// `cilocktelemetrytest` tag (which compiles in the CILOCK_TELEMETRY_ENDPOINT_FOR_TEST
// override), points it at a local mock analytics hub, and asserts the END-USER
// behavior of the shipped binary:
//
//   - authenticated to a platform + telemetry enabled  -> exactly ONE usage POST,
//     correct Bearer header + fields, and the bearer never leaks into the body;
//   - CILOCK_NO_TELEMETRY=1 / DO_NOT_TRACK=1            -> ZERO POSTs (opt-out smoke);
//   - no platform credential (own keys / offline)       -> ZERO POSTs (off by default).
//
// It drives `cilock version` — a purely local command that always succeeds — to
// fire the root PersistentPostRun telemetry hook that EVERY command shares,
// including `cilock login`. The telemetry POST is synchronous, so by the time the
// process exits the mock has received it: fully local + deterministic, no network
// egress and no id-token, so it is safe on forked PRs.
//
//	go test -v -tags=integration ./cli/...   # from the cilock module root
package cli_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHub stands in for analytics.testifysec.com/cli/t, recording the telemetry
// POSTs the cilock binary makes so the test can assert on them.
type mockHub struct {
	mu      sync.Mutex
	hits    int
	method  string
	authHdr string
	ctype   string
	payload map[string]any
}

func newMockHub(t *testing.T) (*mockHub, string) {
	t.Helper()
	h := &mockHub{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.hits++
		h.method = r.Method
		h.authHdr = r.Header.Get("Authorization")
		h.ctype = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &h.payload)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return h, srv.URL
}

func (h *mockHub) hitCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits
}

// buildCilockWithTestHook builds cilock from the module with the telemetry
// endpoint-override hook compiled in (-tags cilocktelemetrytest), so the binary
// can be pointed at a local mock hub. GOWORK=off mirrors the release build.
func buildCilockWithTestHook(t *testing.T) string {
	t.Helper()
	cilockRoot, err := filepath.Abs("..") // .../cilock/cli -> .../cilock
	require.NoError(t, err)
	bin := filepath.Join(t.TempDir(), "cilock")
	build := exec.Command("go", "build", "-tags", "cilocktelemetrytest", "-o", bin, "./cmd/cilock")
	build.Dir = cilockRoot
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build cilock (-tags cilocktelemetrytest): %v\n%s", buildErr, out)
	}
	return bin
}

// seedCredential writes a non-expired platform session for DefaultPlatformURL
// into homeDir via the same auth.Save the real `cilock login` uses, putting the
// binary into the authenticated state Report requires. HOME/XDG are pointed at
// homeDir so both this process (auth.Save) and the spawned binary resolve the
// same credential file on Linux and macOS.
func seedCredential(t *testing.T, homeDir string, c auth.Credential) {
	t.Helper()
	seedCredentialFor(t, homeDir, config.DefaultPlatformURL, c)
}

// seedCredentialFor is seedCredential for an explicit platform URL (e.g. staging),
// so a smoke case can prove telemetry follows the platform the command targeted.
func seedCredentialFor(t *testing.T, homeDir, platformURL string, c auth.Credential) {
	t.Helper()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
	c.PlatformURL = platformURL
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = time.Now().Add(time.Hour)
	}
	require.NoError(t, auth.Save(c))
}

// runVersion runs `cilock version` against the mock hub from an isolated HOME.
// `version` is local-only and always succeeds, inheriting the same root
// PersistentPostRun telemetry hook as `cilock login`.
func runVersion(t *testing.T, bin, homeDir, hubURL string, extraEnv ...string) {
	t.Helper()
	cmd := exec.Command(bin, "version")
	cmd.Env = append(os.Environ(),
		"HOME="+homeDir,
		"XDG_CONFIG_HOME="+filepath.Join(homeDir, ".config"),
		"CILOCK_TELEMETRY_ENDPOINT_FOR_TEST="+hubURL,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cilock version failed: %v\n%s", err, out)
	}
}

// TestTelemetryBinarySmoke is the CI gate: it proves the shipped binary emits a
// usage event when authenticated + enabled, and emits NOTHING when opted out or
// unauthenticated.
func TestTelemetryBinarySmoke(t *testing.T) {
	bin := buildCilockWithTestHook(t)

	t.Run("authenticated emits one usage event", func(t *testing.T) {
		home := t.TempDir()
		seedCredential(t, home, auth.Credential{
			Token:      "smoke-bearer-jwt",
			Email:      "smoke@testifysec.com",
			TenantName: "smoke-tenant",
			TenantID:   "tid-smoke",
		})
		hub, url := newMockHub(t)

		runVersion(t, bin, home, url)

		require.Equal(t, 1, hub.hitCount(), "authenticated run must POST exactly one telemetry event")
		assert.Equal(t, http.MethodPost, hub.method)
		assert.Equal(t, "application/json", hub.ctype)
		assert.Equal(t, "Bearer smoke-bearer-jwt", hub.authHdr, "platform session JWT must be the bearer")

		p := hub.payload
		require.NotNil(t, p)
		assert.Equal(t, "version", p["command"])
		assert.Equal(t, "success", p["outcome"])
		assert.Equal(t, runtime.GOOS, p["os"])
		assert.Equal(t, runtime.GOARCH, p["arch"])
		assert.Equal(t, "smoke@testifysec.com", p["user_ref"], "email is the cross-property identity join key")
		assert.Equal(t, "smoke-tenant", p["account"])
		_, hasVersion := p["cli_version"]
		assert.True(t, hasVersion, "payload must carry cli_version")

		// Redaction invariant: the platform bearer must never appear in the body.
		for k, v := range p {
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, "smoke-bearer-jwt", "token leaked into body field %q", k)
			}
		}
	})

	t.Run("CILOCK_NO_TELEMETRY suppresses telemetry", func(t *testing.T) {
		home := t.TempDir()
		seedCredential(t, home, auth.Credential{Token: "jwt", Email: "x@y.com", TenantName: "t"})
		hub, url := newMockHub(t)

		runVersion(t, bin, home, url, "CILOCK_NO_TELEMETRY=1")

		assert.Equal(t, 0, hub.hitCount(), "CILOCK_NO_TELEMETRY=1 must suppress all telemetry")
	})

	t.Run("DO_NOT_TRACK suppresses telemetry", func(t *testing.T) {
		home := t.TempDir()
		seedCredential(t, home, auth.Credential{Token: "jwt", Email: "x@y.com", TenantName: "t"})
		hub, url := newMockHub(t)

		runVersion(t, bin, home, url, "DO_NOT_TRACK=1")

		assert.Equal(t, 0, hub.hitCount(), "DO_NOT_TRACK=1 must suppress all telemetry")
	})

	t.Run("unauthenticated emits nothing", func(t *testing.T) {
		home := t.TempDir() // deliberately no seeded credential
		hub, url := newMockHub(t)

		runVersion(t, bin, home, url)

		assert.Equal(t, 0, hub.hitCount(), "no platform session must emit no telemetry (own-keys / off-by-default)")
	})

	// Platform-awareness: a credential for a NON-default platform (staging) plus
	// CILOCK_PLATFORM_URL pointing at it (as run/verify export at runtime) must
	// emit, attributed to that platform. Regression guard for the dropped-staging
	// telemetry bug.
	t.Run("resolved platform (staging) is attributed", func(t *testing.T) {
		const staging = "https://platform.aws-sandbox-staging.testifysec.dev"
		home := t.TempDir()
		seedCredentialFor(t, home, staging, auth.Credential{
			Token:      "staging-bearer",
			Email:      "ci@testifysec.com",
			TenantName: "staging-tenant",
		})
		hub, url := newMockHub(t)

		runVersion(t, bin, home, url, "CILOCK_PLATFORM_URL="+staging)

		require.Equal(t, 1, hub.hitCount(), "usage against the resolved staging platform must emit telemetry")
		assert.Equal(t, "Bearer staging-bearer", hub.authHdr)
		assert.Equal(t, "staging-tenant", hub.payload["account"])
	})
}
