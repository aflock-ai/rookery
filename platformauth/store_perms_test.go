// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSave_TightensPreExisting0644File is the FINDING 2 regression gate: a
// fallback-mode write must land the session file at 0600 even when the target
// already exists at a looser mode like 0644. os.WriteFile alone preserves an
// existing file's mode, so a bearer token written inline would otherwise sit in a
// world-readable file. The atomic temp-file write + chmod must enforce 0600.
func TestSave_TightensPreExisting0644File(t *testing.T) {
	s := withFileFallback(t) // keyring disabled → token is written inline

	// Pre-create the session file at 0644 with some prior content, so the write
	// path must TIGHTEN an existing looser file (not just create a fresh 0600 one).
	require.NoError(t, os.MkdirAll(filepath.Dir(s.Path()), 0o700))
	require.NoError(t, os.WriteFile(s.Path(), []byte(`{"version":1,"credentials":{}}`), 0o644))
	info, err := os.Stat(s.Path())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "precondition: file starts world-readable")

	const secret = "fallback-bearer-jwt"
	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       secret,
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	info, err = os.Stat(s.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"a fallback-mode write must tighten a pre-existing 0644 file to 0600")

	// The token did land inline (fallback mode) — so 0600 actually matters here.
	raw, err := os.ReadFile(s.Path())
	require.NoError(t, err)
	assert.Contains(t, string(raw), secret, "fallback mode keeps the token inline")
}

// TestSave_FreshFileIs0600 confirms the create-from-nothing path also lands 0600
// (the no-pre-existing-file case), so both branches of the write are covered.
func TestSave_FreshFileIs0600(t *testing.T) {
	s := withFileFallback(t)
	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "fresh-bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))
	info, err := os.Stat(s.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "a fresh fallback write lands 0600")
}

// TestSave_TightensPreExisting0644File_KeyringMode covers the keyring-mode write
// too: even though the token is scrubbed to the keyring, the metadata file (which
// can still hold scope/email/identity) must not be left world-readable over a
// pre-existing 0644 file.
func TestSave_TightensPreExisting0644File_KeyringMode(t *testing.T) {
	s := withKeyring(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(s.Path()), 0o700))
	require.NoError(t, os.WriteFile(s.Path(), []byte(`{"version":1,"credentials":{}}`), 0o644))

	require.NoError(t, s.Save(Credential{
		PlatformURL: "https://p.example.com",
		Token:       "kr-bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	info, err := os.Stat(s.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"keyring-mode metadata write must also tighten a pre-existing 0644 file")
}
