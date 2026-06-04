// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
)

func TestApplyNoDefaultAttestors_Passthrough(t *testing.T) {
	defaults := []attestation.Attestor{product.New(), material.New()}
	got, err := applyNoDefaultAttestors(defaults, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 attestors with no overrides, got %d", len(got))
	}
}

func TestApplyNoDefaultAttestors_DropProduct(t *testing.T) {
	defaults := []attestation.Attestor{product.New(), material.New()}
	got, err := applyNoDefaultAttestors(defaults, []string{product.Name})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].Name() != material.Name {
		t.Fatalf("expected only material remaining, got %+v", got)
	}
}

func TestApplyNoDefaultAttestors_DropMaterial(t *testing.T) {
	defaults := []attestation.Attestor{product.New(), material.New()}
	got, err := applyNoDefaultAttestors(defaults, []string{material.Name})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].Name() != product.Name {
		t.Fatalf("expected only product remaining, got %+v", got)
	}
}

// TestApplyNoDefaultAttestors_DropBoth_Fails enforces the security
// invariant: a user MAY NOT disable every default attestor; doing
// so leaves the collection with no evidence to attest.
func TestApplyNoDefaultAttestors_DropBoth_Fails(t *testing.T) {
	defaults := []attestation.Attestor{product.New(), material.New()}
	_, err := applyNoDefaultAttestors(defaults, []string{product.Name, material.Name})
	if err == nil {
		t.Fatal("expected hard-fail when both default attestors are disabled")
	}
	if !strings.Contains(err.Error(), "SECURITY") {
		t.Fatalf("error should be flagged as a security warning, got: %v", err)
	}
}

func TestApplyNoDefaultAttestors_UnknownName_Fails(t *testing.T) {
	defaults := []attestation.Attestor{product.New(), material.New()}
	_, err := applyNoDefaultAttestors(defaults, []string{"not-a-real-attestor"})
	if err == nil {
		t.Fatal("expected error for unknown attestor name")
	}
	if !strings.Contains(err.Error(), "not a recognised default attestor") {
		t.Fatalf("error should explain unknown name, got: %v", err)
	}
}

// TestApplyNoDefaultAttestors_DropMaterial_WarnsBuildStepConsequence proves the
// drop warning now spells out the downstream build-step consequence (rec #8):
// a from-bundles build step built from a material-less bundle won't verify.
func TestApplyNoDefaultAttestors_DropMaterial_WarnsBuildStepConsequence(t *testing.T) {
	c := useCaptureLogger(t)
	defaults := []attestation.Attestor{product.New(), material.New()}
	if _, err := applyNoDefaultAttestors(defaults, []string{material.Name}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	joined := strings.Join(c.snapshot(), "\n")
	if !strings.Contains(joined, "build-step policies require material/v0.3 + product/v0.3") {
		t.Errorf("drop-material warning should explain the build-step requirement, got:\n%s", joined)
	}
	if !strings.Contains(joined, "won't verify end-to-end") {
		t.Errorf("drop-material warning should flag the verify consequence, got:\n%s", joined)
	}
}

// TestApplyNoDefaultAttestors_DropProduct_WarnsBuildStepConsequence proves the
// same consequence note fires when product is dropped.
func TestApplyNoDefaultAttestors_DropProduct_WarnsBuildStepConsequence(t *testing.T) {
	c := useCaptureLogger(t)
	defaults := []attestation.Attestor{product.New(), material.New()}
	if _, err := applyNoDefaultAttestors(defaults, []string{product.Name}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	joined := strings.Join(c.snapshot(), "\n")
	if !strings.Contains(joined, "build-step policies require material/v0.3 + product/v0.3") {
		t.Errorf("drop-product warning should explain the build-step requirement, got:\n%s", joined)
	}
}
