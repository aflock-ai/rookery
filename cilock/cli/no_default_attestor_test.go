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

// TestApplyNoDefaultAttestors_DropProduct_WarnsEvidenceLostAndNamesRemedy is the
// product-specific counterpart to the build-step note above, and it exists
// because a doc fix cannot reach a binary someone already installed.
//
// Dropping product to save envelope bytes trades evidence for convenience: the
// bundle keeps material (what went IN) and loses the only record of what the
// build produced. The warning has to name the cheaper remedy — narrowing the
// capture — or it is just a scolding, and the reader goes back to the flag.
//
// The remedy string is asserted in its SINGULAR form on purpose. The flag is
// registered as registry.StringConfigOption -> cmd.Flags().String
// (cilock/internal/options/options.go), i.e. pflag last-one-wins, NOT
// repeatable: passing it three times parses cleanly and silently applies only
// the third. A warning that told the operator to repeat the flag would hand
// them a fix that no-ops, which is worse than the flag it replaces.
func TestApplyNoDefaultAttestors_DropProduct_WarnsEvidenceLostAndNamesRemedy(t *testing.T) {
	c := useCaptureLogger(t)
	defaults := []attestation.Attestor{product.New(), material.New()}
	if _, err := applyNoDefaultAttestors(defaults, []string{product.Name}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	joined := strings.Join(c.snapshot(), "\n")

	// What is lost.
	if !strings.Contains(joined, "no record of what the build produced") {
		t.Errorf("drop-product warning must name the evidence lost, got:\n%s", joined)
	}
	// What to do instead.
	if !strings.Contains(joined, "--attestor-product-exclude-glob") {
		t.Errorf("drop-product warning must name the narrower remedy, got:\n%s", joined)
	}
	// The remedy must be described as a single glob, not a repeatable flag.
	if !strings.Contains(joined, "a single") {
		t.Errorf("drop-product warning must say the exclude-glob flag takes ONE pattern "+
			"(it is last-one-wins, not repeatable), got:\n%s", joined)
	}
}

// TestApplyNoDefaultAttestors_DropMaterial_OmitsProductRemedy is the control for
// the test above: it varies the attestor dropped and asserts the product-specific
// advice does NOT fire. Without it, a warning emitted unconditionally for every
// dropped attestor would pass the assertions above while being wrong — the
// product remedy is meaningless advice when the operator dropped material.
func TestApplyNoDefaultAttestors_DropMaterial_OmitsProductRemedy(t *testing.T) {
	c := useCaptureLogger(t)
	defaults := []attestation.Attestor{product.New(), material.New()}
	if _, err := applyNoDefaultAttestors(defaults, []string{material.Name}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	joined := strings.Join(c.snapshot(), "\n")
	if strings.Contains(joined, "--attestor-product-exclude-glob") {
		t.Errorf("dropping material must not advise the product exclude-glob remedy, got:\n%s", joined)
	}
}

// TestApplyNoDefaultAttestors_DropProduct_StillWarnsAndDoesNotRefuse pins the
// boundary the brief drew: this is a WARNING, not a new gate. The flag stays
// legitimate for genuine cases, and only dropping BOTH defaults is an error.
func TestApplyNoDefaultAttestors_DropProduct_StillWarnsAndDoesNotRefuse(t *testing.T) {
	defaults := []attestation.Attestor{product.New(), material.New()}
	got, err := applyNoDefaultAttestors(defaults, []string{product.Name})
	if err != nil {
		t.Fatalf("dropping product alone must remain permitted, got err: %v", err)
	}
	if len(got) != 1 || got[0].Name() != material.Name {
		t.Fatalf("expected material to survive, got %+v", got)
	}
}
