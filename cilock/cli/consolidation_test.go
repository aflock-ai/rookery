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

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Registered for their detector.yaml side effects: attestorExternalGenerators
	// reads the detection registry, so the tool-wrapper attestors it asserts on
	// must be linked into the test binary. The "sbom" format case is covered by
	// the embedded catalog (syft/cdxgen/bom) and needs no plugin import.
	_ "github.com/aflock-ai/rookery/plugins/attestors/go-build"
	_ "github.com/aflock-ai/rookery/plugins/attestors/govulncheck"
	_ "github.com/aflock-ai/rookery/plugins/attestors/oci"
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

// resolveDetectedAttestors: a fired plugin-backed detector attaches by name;
// a detection-only catalog entry attaches the format attestor(s) it feeds.
func TestResolveDetectedAttestors(t *testing.T) {
	reg := detection.NewRegistry()
	// Detection-only catalog entry: not an attestor itself; feeds "sbom".
	reg.Register("syft", []byte("apiVersion: cilock.detection/v0.1\n"+
		"name: syft\ndetection_only: true\ncategory: [sbom-generate]\n"+
		"emits_formats: [sbom]\npre:\n  match:\n    argv_prefix: [syft]"))

	// git, go-build, trivy are plugin-backed (registered attestors).
	registered := map[string]bool{"git": true, "go-build": true, "trivy": true}

	fire := func(name string) detection.FireDecision {
		return detection.FireDecision{Attestor: name, Gate: detection.GatePre}
	}

	t.Run("plugin-backed detector attaches by name", func(t *testing.T) {
		got := resolveDetectedAttestors([]detection.FireDecision{fire("git"), fire("go-build")}, registered, reg)
		assert.Equal(t, []string{"git", "go-build"}, got)
	})

	t.Run("detection-only entry attaches its emits_formats attestor", func(t *testing.T) {
		got := resolveDetectedAttestors([]detection.FireDecision{fire("syft")}, registered, reg)
		assert.Equal(t, []string{"sbom"}, got)
	})

	t.Run("mixed + dedupe", func(t *testing.T) {
		got := resolveDetectedAttestors([]detection.FireDecision{
			fire("git"), fire("syft"), fire("trivy"), fire("git"),
		}, registered, reg)
		assert.Equal(t, []string{"git", "sbom", "trivy"}, got)
	})

	t.Run("unknown detector with no emits_formats contributes nothing", func(t *testing.T) {
		got := resolveDetectedAttestors([]detection.FireDecision{fire("mystery")}, registered, reg)
		assert.Empty(t, got)
	})
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

func TestAttestorExternalGenerators_Known(t *testing.T) {
	// Phase 4 follow-up: pre-flight needs to know which generators
	// each attestor records. The set is now sourced from the detection
	// registry — for "sbom" that's every catalog entry emitting the sbom
	// format (syft, cdxgen, bom), not a hand-curated list.
	sbom := attestorExternalGenerators("sbom")
	assert.Contains(t, sbom, "syft")
	assert.Contains(t, sbom, "cdxgen")
	assert.Equal(t, []string{"govulncheck"}, attestorExternalGenerators("govulncheck"))
	assert.Equal(t, []string{"go"}, attestorExternalGenerators("go-build"))
}

func TestAttestorExternalGenerators_OCI_ToolWrapper(t *testing.T) {
	// oci recognizes the tools that PRODUCE an image (docker save, skopeo
	// copy, crane) via its own detector predicates — argv heads only.
	gens := attestorExternalGenerators("oci")
	assert.Contains(t, gens, "docker")
	assert.Contains(t, gens, "skopeo")
	assert.Contains(t, gens, "crane")
}

func TestAttestorExternalGenerators_SelfContained(t *testing.T) {
	// These attestors read workspace files / state directly; no
	// external tool is involved. Pre-flight must not warn about them.
	// (oci is NOT here — its detector recognizes docker/skopeo/crane,
	// the tools that produce an image; see the _OCI_ToolWrapper test.)
	for _, name := range []string{"git", "environment", "lockfiles", "secretscan"} {
		assert.Empty(t, attestorExternalGenerators(name),
			"attestor %q reads workspace state directly; should not have external generators", name)
	}
}

func TestAttestorWorkspacePrereq_Git(t *testing.T) {
	assert.Equal(t, ".git", attestorWorkspacePrereq("git"))
	assert.Empty(t, attestorWorkspacePrereq("sbom"))
}

func TestPreflightAttestorTooling_GitMissing(t *testing.T) {
	dir := t.TempDir()
	// .git/ deliberately absent → git attestor pre-flight must warn.
	warned := preflightAttestorTooling(dir, []string{"git", "environment"})
	assert.True(t, warned, "git attestor without .git/ must trigger a pre-flight warning")
}

func TestPreflightAttestorTooling_GitPresent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
	warned := preflightAttestorTooling(dir, []string{"git"})
	assert.False(t, warned, ".git/ present → git attestor pre-flight must not warn")
}

func TestPreflightAttestorTooling_SbomNoGenerator(t *testing.T) {
	// Swap execLookPath to simulate a PATH with no SBOM generators.
	orig := execLookPath
	defer func() { execLookPath = orig }()
	execLookPath = func(name string) (string, error) {
		return "", os.ErrNotExist
	}
	dir := t.TempDir()
	warned := preflightAttestorTooling(dir, []string{"sbom"})
	assert.True(t, warned, "sbom attestor with no generator on PATH must warn")
}

func TestPreflightAttestorTooling_SbomGeneratorOnPath(t *testing.T) {
	// One of the listed generators is on PATH → no warning fires.
	orig := execLookPath
	defer func() { execLookPath = orig }()
	execLookPath = func(name string) (string, error) {
		if name == "syft" {
			return "/usr/local/bin/syft", nil
		}
		return "", os.ErrNotExist
	}
	dir := t.TempDir()
	warned := preflightAttestorTooling(dir, []string{"sbom"})
	assert.False(t, warned, "sbom attestor with syft on PATH must NOT warn")
}
