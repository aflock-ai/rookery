// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Unit tests for the four-phase CLI consolidation helpers (#234).
// Pure-function coverage — these are the building blocks the rest
// of the consolidation depends on, so flakes here cascade into
// every other test that uses --hardening / --capture-mode /
// --workload / --diagnose.

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitCaptureModeSuffix(t *testing.T) {
	cases := []struct {
		in, mode, backend string
	}{
		{"auto", "auto", ""},
		{"walk", "walk", ""},
		{"trace", "trace", ""},
		{"trace:ebpf", "trace", "ebpf"},
		{"trace:ptrace", "trace", "ptrace"},
		{"trace:auto", "trace", "auto"},
		{"auto:ebpf", "auto", "ebpf"},
		{"", "", ""},
		// Edge: only the first colon splits; trailing colons stay in backend.
		{"trace:foo:bar", "trace", "foo:bar"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			mode, backend := splitCaptureModeSuffix(c.in)
			assert.Equal(t, c.mode, mode)
			assert.Equal(t, c.backend, backend)
		})
	}
}

func TestApplyHardeningProfile_Standard(t *testing.T) {
	t.Setenv("CILOCK_FANOTIFY", "")
	t.Setenv("CILOCK_FSVERITY", "")
	require.NoError(t, os.Unsetenv("CILOCK_FANOTIFY"))
	require.NoError(t, os.Unsetenv("CILOCK_FSVERITY"))

	var zeroDrops bool
	require.NoError(t, applyHardeningProfile("standard", &zeroDrops, false))
	assert.Equal(t, "1", os.Getenv("CILOCK_FANOTIFY"))
	assert.Equal(t, "auto", os.Getenv("CILOCK_FSVERITY"))
	assert.False(t, zeroDrops, "standard profile must not flip require-zero-drops")
}

func TestApplyHardeningProfile_Strict(t *testing.T) {
	require.NoError(t, os.Unsetenv("CILOCK_FANOTIFY"))
	require.NoError(t, os.Unsetenv("CILOCK_FSVERITY"))

	var zeroDrops bool
	require.NoError(t, applyHardeningProfile("strict", &zeroDrops, false))
	assert.Equal(t, "1", os.Getenv("CILOCK_FANOTIFY"))
	assert.Equal(t, "1", os.Getenv("CILOCK_FSVERITY"))
	assert.True(t, zeroDrops, "strict profile must default require-zero-drops to true")
}

func TestApplyHardeningProfile_Strict_RespectsExplicitFlag(t *testing.T) {
	require.NoError(t, os.Unsetenv("CILOCK_FANOTIFY"))
	require.NoError(t, os.Unsetenv("CILOCK_FSVERITY"))

	// Operator explicitly passed --require-zero-drops=false; strict
	// must NOT silently overwrite that choice.
	zeroDrops := false
	require.NoError(t, applyHardeningProfile("strict", &zeroDrops, true))
	assert.False(t, zeroDrops, "explicit --require-zero-drops=false must win over profile default")
}

func TestApplyHardeningProfile_Off(t *testing.T) {
	require.NoError(t, os.Unsetenv("CILOCK_FANOTIFY"))
	require.NoError(t, os.Unsetenv("CILOCK_FSVERITY"))

	var zeroDrops bool
	require.NoError(t, applyHardeningProfile("off", &zeroDrops, false))
	assert.Equal(t, "off", os.Getenv("CILOCK_FANOTIFY"))
	assert.Equal(t, "off", os.Getenv("CILOCK_FSVERITY"))
	assert.False(t, zeroDrops)
}

func TestApplyHardeningProfile_OperatorEnvWins(t *testing.T) {
	// Operator pinned CILOCK_FANOTIFY=off in their CI env; strict
	// must not overwrite that — the explicit env always wins.
	t.Setenv("CILOCK_FANOTIFY", "off")
	require.NoError(t, os.Unsetenv("CILOCK_FSVERITY"))

	var zeroDrops bool
	require.NoError(t, applyHardeningProfile("strict", &zeroDrops, false))
	assert.Equal(t, "off", os.Getenv("CILOCK_FANOTIFY"), "operator env must beat profile default")
	assert.Equal(t, "1", os.Getenv("CILOCK_FSVERITY"))
}

func TestApplyHardeningProfile_UnknownProfile(t *testing.T) {
	var zeroDrops bool
	err := applyHardeningProfile("strictish", &zeroDrops, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "valid: off, standard, strict")
}

func TestApplyHardeningProfile_EmptyDefaultsToStandard(t *testing.T) {
	require.NoError(t, os.Unsetenv("CILOCK_FANOTIFY"))
	require.NoError(t, os.Unsetenv("CILOCK_FSVERITY"))

	var zeroDrops bool
	require.NoError(t, applyHardeningProfile("", &zeroDrops, false))
	assert.Equal(t, "1", os.Getenv("CILOCK_FANOTIFY"), "empty profile must apply standard defaults")
	assert.Equal(t, "auto", os.Getenv("CILOCK_FSVERITY"))
}

func TestDetectWorkloadAttestors_GoMod(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n"), 0o644))

	detected := detectWorkloadAttestors(dir)
	assert.Contains(t, detected, "go-build")
	assert.Contains(t, detected, "govulncheck")
}

func TestDetectWorkloadAttestors_PackageJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644))

	detected := detectWorkloadAttestors(dir)
	assert.Contains(t, detected, "sbom")
	assert.Contains(t, detected, "lockfiles")
}

func TestDetectWorkloadAttestors_GitDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))

	detected := detectWorkloadAttestors(dir)
	assert.Contains(t, detected, "git")
}

func TestDetectWorkloadAttestors_MixedRepo(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644))

	detected := detectWorkloadAttestors(dir)
	assert.Contains(t, detected, "go-build")
	assert.Contains(t, detected, "govulncheck")
	assert.Contains(t, detected, "sbom")
	assert.Contains(t, detected, "lockfiles")
	assert.Contains(t, detected, "git")
	assert.Contains(t, detected, "oci")
}

func TestDetectWorkloadAttestors_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	detected := detectWorkloadAttestors(dir)
	assert.Empty(t, detected, "empty workdir produces no auto-attestors")
}

func TestMergeAttestorNames_NoDuplicates(t *testing.T) {
	merged, added := mergeAttestorNames([]string{"environment", "git"}, []string{"go-build", "git"})
	assert.Equal(t, []string{"environment", "git", "go-build"}, merged)
	assert.Equal(t, []string{"go-build"}, added, "detected names already in operator list don't re-appear in added")
}

func TestMergeAttestorNames_PreservesOperatorOrder(t *testing.T) {
	// Operator-supplied order must come first; the auto-merge appends.
	merged, _ := mergeAttestorNames([]string{"z", "a", "m"}, []string{"b", "c"})
	assert.Equal(t, []string{"z", "a", "m", "b", "c"}, merged)
}

func TestMergeAttestorNames_NoOperatorList(t *testing.T) {
	merged, added := mergeAttestorNames(nil, []string{"go-build", "git"})
	assert.Equal(t, []string{"go-build", "git"}, merged)
	assert.Equal(t, []string{"go-build", "git"}, added)
}

func TestValidateUserCommand_NoArgs(t *testing.T) {
	// Empty args = no user command supplied; not an error path.
	assert.NoError(t, validateUserCommand(nil))
	assert.NoError(t, validateUserCommand([]string{}))
}

func TestValidateUserCommand_OnPath(t *testing.T) {
	// `sh` is on PATH in every reasonable test environment.
	assert.NoError(t, validateUserCommand([]string{"sh", "-c", "true"}))
}

func TestValidateUserCommand_NotFound(t *testing.T) {
	err := validateUserCommand([]string{"this-binary-definitely-does-not-exist-12345"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "this-binary-definitely-does-not-exist-12345")
}
