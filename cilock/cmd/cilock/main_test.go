package main

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestALPSEvidenceAttestorRegistered guards the release boundary: source in a
// sibling module is dead until the canonical cilock binary blank-imports it.
// This package-main test compiles the exact import set that ships.
func TestALPSEvidenceAttestorRegistered(t *testing.T) {
	attestors, err := attestation.GetAttestors([]string{"alps-evidence"})
	if err != nil {
		t.Fatalf("alps-evidence attestor not registered in the cilock binary: %v\n"+
			"fix: add its blank import to cmd/cilock/main.go", err)
	}
	if len(attestors) != 1 || attestors[0].Name() != "alps-evidence" {
		t.Fatalf("expected exactly one attestor named %q, got %+v", "alps-evidence", attestors)
	}
	const wantType = "https://aflock.ai/attestations/alps-evidence/v0.1"
	if got := attestors[0].Type(); got != wantType {
		t.Errorf("alps-evidence attestor type = %q, want %q", got, wantType)
	}
}

// TestALPSEvidenceInDetectionCatalog pins the other half of registration: its
// detector must be present so an agent-marked run can auto-plan the attestor.
func TestALPSEvidenceInDetectionCatalog(t *testing.T) {
	for _, name := range detection.Default().Names() {
		if name == "alps-evidence" {
			return
		}
	}
	t.Fatalf("alps-evidence missing from the binary detection catalog")
}

// TestFalcoAttestorRegistered guards against the falco attestor being
// advertised in the docs catalog (cilock.dev/tools/falco) while absent from the
// shipped binary. Because this test lives in package main, the test binary
// compiles the exact blank-import set in main.go — so a missing import fails
// here the same way the released binary fails: `cilock run -a falco ...` errors
// with attestor-not-found even though the plugin source exists in the tree.
func TestFalcoAttestorRegistered(t *testing.T) {
	attestors, err := attestation.GetAttestors([]string{"falco"})
	if err != nil {
		t.Fatalf("falco attestor not registered in the cilock binary: %v\n"+
			"fix: add a blank import of "+
			"github.com/aflock-ai/rookery/plugins/attestors/falco to cmd/cilock/main.go", err)
	}
	if len(attestors) != 1 || attestors[0].Name() != "falco" {
		t.Fatalf("expected exactly one attestor named %q, got %+v", "falco", attestors)
	}
	const wantType = "https://aflock.ai/attestations/falco/v0.1"
	if got := attestors[0].Type(); got != wantType {
		t.Errorf("falco attestor type = %q, want %q", got, wantType)
	}
}

// TestFalcoInDetectionCatalog asserts the falco detector.yaml is registered in
// the binary's detection catalog, so `cilock plan` can auto-detect a falco run.
// The docs catalog and the binary catalog must agree; this fails when the
// plugin is unimported (its init() never runs detection.Register).
func TestFalcoInDetectionCatalog(t *testing.T) {
	names := detection.Default().Names()
	for _, n := range names {
		if n == "falco" {
			return
		}
	}
	t.Fatalf("falco missing from the binary detection catalog; registered detectors: %v", names)
}
