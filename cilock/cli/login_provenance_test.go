// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedJctlSessionCLI writes a ~/.jctl/config.yaml under the test's isolated HOME
// with a single context whose judgeURL matches url and an INLINE token, so
// auth.Resolve picks it up via the jctl provider (NOT cilock's own store). Such a
// session declares no capabilities — the un-pinnable jctl shape from GHSA #5988.
func seedJctlSessionCLI(t *testing.T, url string) {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err, "resolve isolated HOME")
	jctlDir := filepath.Join(home, ".jctl")
	require.NoError(t, os.MkdirAll(jctlDir, 0o700))
	cfg := "" +
		"contexts:\n" +
		"  default:\n" +
		"    judgeURL: " + url + "\n" +
		"    token: jctl-session-token\n" +
		"    tenant_id: tenant-123\n" +
		"    tenant_name: Acme\n"
	require.NoError(t, os.WriteFile(filepath.Join(jctlDir, "config.yaml"), []byte(cfg), 0o600))
}

// TestWhoamiCmd_ShowsSourceAndPosture: a cilock-login session reports its source
// and a capability posture line that says trust-pinning is available.
func TestWhoamiCmd_ShowsSourceAndPosture(t *testing.T) {
	isolateCLIConfig(t)
	const url = "https://p.example.com"
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: url,
		Token:       "jwt-abc",
		Email:       "alice@acme-corp.com",
		AuthMode:    auth.AuthModeBrowser,
		TenantName:  "acme",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	cmd := WhoamiCmd()
	cmd.SetArgs([]string{"--platform-url", url})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "session:", "whoami must print a session provenance line")
	assert.Contains(t, got, "cilock-login", "cilock-store session must be labeled cilock-login")
	assert.Contains(t, got, "trust-pinning: available", "cilock session posture must report trust-pinning available")
}

// TestWhoamiCmd_JctlSessionPostureUnavailable: a jctl-sourced session reports
// its source and that trust-pinning is unavailable (the GHSA #5988 distinction).
func TestWhoamiCmd_JctlSessionPostureUnavailable(t *testing.T) {
	isolateCLIConfig(t)
	const url = "https://p.example.com"
	seedJctlSessionCLI(t, url)

	cmd := WhoamiCmd()
	cmd.SetArgs([]string{"--platform-url", url})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "session:", "whoami must print a session provenance line")
	assert.Contains(t, got, "jctl", "jctl-sourced session must surface its source")
	assert.Contains(t, got, "trust-pinning: unavailable", "jctl session posture must report trust-pinning unavailable")
}

// TestLogoutCmd_WarnsWhenJctlSessionRemains: after cilock removes its OWN
// credential, a jctl session for the same platform still resolves — logout must
// WARN rather than claim the operator is fully signed out. cilock must NEVER
// touch jctl's files.
func TestLogoutCmd_WarnsWhenJctlSessionRemains(t *testing.T) {
	isolateCLIConfig(t)
	const url = "https://p.example.com"

	// Both a cilock-store session AND a jctl session for the same platform.
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: url,
		Token:       "cilock-jwt",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	seedJctlSessionCLI(t, url)

	cmd := LogoutCmd()
	cmd.SetArgs([]string{"--platform-url", url})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "logged out", "logout must confirm cilock's own credential was removed")
	assert.Contains(t, got, "still authenticated", "logout must warn that a session still resolves")
	assert.Contains(t, got, "jctl auth logout", "warning must tell the operator how to fully sign out")

	// cilock must not have removed jctl's session — it still resolves.
	still, err := auth.Resolve(url, auth.ForBearer)
	require.NoError(t, err)
	require.NotNil(t, still, "jctl session must survive cilock logout (cilock never writes jctl's files)")
	assert.Equal(t, "jctl", still.Source)
}

// TestLogoutCmd_NoWarnWhenFullySignedOut: with only a cilock session, logout
// removes it and does NOT print a spurious still-authenticated warning.
func TestLogoutCmd_NoWarnWhenFullySignedOut(t *testing.T) {
	isolateCLIConfig(t)
	const url = "https://p.example.com"
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: url,
		Token:       "cilock-jwt",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	cmd := LogoutCmd()
	cmd.SetArgs([]string{"--platform-url", url})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "logged out")
	assert.NotContains(t, got, "still authenticated", "no warning when no other session remains")
}
