// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func isolateCLIConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
}

// TestUseCmd_FastPathBindsProduct: `cilock use --product-id …` rebinds the
// working product directly against the stored session — no browser, no re-auth.
func TestUseCmd_FastPathBindsProduct(t *testing.T) {
	isolateCLIConfig(t)

	const url = "https://p.example.com"
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: url,
		Token:       "jwt-abc",
		AuthMode:    auth.AuthModeBrowser,
		TenantID:    "t-1",
		TenantName:  "acme",
		ExpiresAt:   time.Now().Add(time.Hour),
	}))

	cmd := UseCmd()
	cmd.SetArgs([]string{"--platform-url", url, "--product-id", "prod-9", "--product-name", "Widget"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	got, err := auth.LookupAny(url)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "prod-9", got.ProductID, "product id bound")
	assert.Equal(t, "Widget", got.ProductName, "product name bound")
	assert.Equal(t, "jwt-abc", got.Token, "fast path must not re-auth")
	assert.Equal(t, "t-1", got.TenantID, "tenant preserved")
	assert.Contains(t, out.String(), "Widget", "output surfaces the bound product")
}

// TestUseCmd_FastPathRequiresLogin: rebinding with no stored session errors.
func TestUseCmd_FastPathRequiresLogin(t *testing.T) {
	isolateCLIConfig(t)

	cmd := UseCmd()
	cmd.SetArgs([]string{"--platform-url", "https://nope.example.com", "--product-id", "p"})
	cmd.SetOut(&bytes.Buffer{})
	require.Error(t, cmd.Execute(), "use --product-id with no session must error")
}

// TestLoginCmd_TokenRequiresTenantAndProduct enforces the binding contract on the
// headless path: `cilock login --token` without --tenant-id/--product-id fails
// closed (the browser approve page supplies them for the interactive path).
func TestLoginCmd_TokenRequiresTenantAndProduct(t *testing.T) {
	isolateCLIConfig(t)
	cmd := LoginCmd()
	cmd.SetArgs([]string{"--platform-url", "https://p.example.com", "--token", "jwt-xyz"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	require.Error(t, cmd.Execute(), "--token login without tenant/product ids must fail closed")
}

// TestLoginCmd_TokenWithBindingPersists: a headless login that supplies the
// binding stores the full tenant+product scope.
func TestLoginCmd_TokenWithBindingPersists(t *testing.T) {
	isolateCLIConfig(t)
	const url = "https://p.example.com"
	cmd := LoginCmd()
	cmd.SetArgs([]string{
		"--platform-url", url, "--token", "jwt-xyz",
		"--tenant-id", "t-1", "--tenant-name", "acme",
		"--product-id", "prod-2", "--product-name", "Widget",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	got, err := auth.LookupAny(url)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "jwt-xyz", got.Token)
	assert.Equal(t, "t-1", got.TenantID)
	assert.Equal(t, "prod-2", got.ProductID)
	assert.Equal(t, "Widget", got.ProductName)
	assert.Contains(t, out.String(), "Widget", "login output surfaces the bound product")
}
