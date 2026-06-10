package detection

import "testing"

func TestValidateOutputContract(t *testing.T) {
	canonical := []FixtureRef{{Name: "canonical", Role: FixtureCanonical}}
	cases := []struct {
		name    string
		c       *OutputContract
		wantErr bool
	}{
		{
			name: "valid postproduct contract",
			c: &OutputContract{
				PredicateType: "https://aflock.ai/attestations/scubagoggles/v0.1",
				RunType:       ContractRunPostProduct,
				Subjects: []SubjectClaim{
					{Prefix: "googleworkspace:tenant:", DigestAlgs: []string{"sha256"}},
					{Prefix: "googleworkspace:domain:"},
				},
				SchemaRequired: true,
				Fixtures:       canonical,
			},
		},
		{
			name: "empty fixture role defaults to canonical",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunProduct,
				Fixtures:      []FixtureRef{{Name: "happy"}},
			},
		},
		{
			name: "multi-type contract: predicate_type must be a member",
			c: &OutputContract{
				PredicateType:  "https://spdx.dev/Document",
				PredicateTypes: []string{"https://cyclonedx.org/bom", "https://spdx.dev/Document"},
				RunType:        ContractRunProduct,
				Fixtures:       canonical,
			},
		},
		{
			name: "multi-type contract: predicate_type NOT a member rejected",
			c: &OutputContract{
				PredicateType:  "https://aflock.ai/sbom/v0.1",
				PredicateTypes: []string{"https://cyclonedx.org/bom", "https://spdx.dev/Document"},
				RunType:        ContractRunProduct,
				Fixtures:       canonical,
			},
			wantErr: true,
		},
		{
			name: "valid tier + stability",
			c:    &OutputContract{PredicateType: "x", RunType: ContractRunProduct, Tier: TierRecommended, Stability: &OutputStability{Level: StabilityBestEffort}},
		},
		{
			name:    "bad tier",
			c:       &OutputContract{PredicateType: "x", RunType: ContractRunProduct, Tier: "ultra-popular"},
			wantErr: true,
		},
		{
			name:    "bad stability level",
			c:       &OutputContract{PredicateType: "x", RunType: ContractRunProduct, Stability: &OutputStability{Level: "rock-solid"}},
			wantErr: true,
		},
		{
			name:    "nil contract is fine (opt-in)",
			c:       nil,
			wantErr: false,
		},
		{
			name:    "missing predicate_type",
			c:       &OutputContract{RunType: ContractRunPostProduct, Fixtures: canonical},
			wantErr: true,
		},
		{
			name:    "bad run_type",
			c:       &OutputContract{PredicateType: "x", RunType: "nope", Fixtures: canonical},
			wantErr: true,
		},
		{
			name:    "verify run_type rejected (no false-green)",
			c:       &OutputContract{PredicateType: "x", RunType: ContractRunVerify, Fixtures: canonical},
			wantErr: true,
		},
		{
			name:    "execute run_type rejected (no false-green)",
			c:       &OutputContract{PredicateType: "x", RunType: ContractRunExecute, Fixtures: canonical},
			wantErr: true,
		},
		{
			name: "no fixtures = declared (valid, unproven)",
			c:    &OutputContract{PredicateType: "x", RunType: ContractRunProduct},
		},
		{
			name: "fixtures present but none canonical",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunProduct,
				Fixtures:      []FixtureRef{{Name: "empty", Role: FixtureNegative}},
			},
			wantErr: true,
		},
		{
			name: "bad fixture role",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunProduct,
				Fixtures:      []FixtureRef{{Name: "weird", Role: "sideways"}},
			},
			wantErr: true,
		},
		{
			name: "exit_behavior without negative fixture rejected",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunPostProduct,
				ExitBehavior:  &ExitBehaviorClaim{OnNoEvidence: ContractExitError, ErrorContains: "no products"},
				Fixtures:      canonical,
			},
			wantErr: true,
		},
		{
			name: "exit_behavior with negative fixture ok",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunPostProduct,
				ExitBehavior:  &ExitBehaviorClaim{OnNoEvidence: ContractExitError, ErrorContains: "no products"},
				Fixtures:      []FixtureRef{{Name: "happy", Role: FixtureCanonical}, {Name: "empty", Role: FixtureNegative}},
			},
		},
		{
			name: "backref not in subjects",
			c: &OutputContract{
				PredicateType:   "x",
				RunType:         ContractRunPostProduct,
				Subjects:        []SubjectClaim{{Prefix: "a:"}},
				BackRefSubjects: []string{"b:"},
				Fixtures:        canonical,
			},
			wantErr: true,
		},
		{
			name: "backrefs superset of backref_subjects valid",
			c: &OutputContract{
				PredicateType:   "x",
				RunType:         ContractRunPostProduct,
				Subjects:        []SubjectClaim{{Prefix: "trivy:artifact:"}},
				BackRefSubjects: []string{"trivy:artifact:"},
				BackRefs: []BackRefClaim{
					{Prefix: "imagedigest:", Description: "scan-target image digest"},
					{Prefix: "imagereference:", Description: "scan-target image reference"},
					{Prefix: "trivy:artifact:", Description: "fallback anchor"},
				},
				Fixtures: canonical,
			},
		},
		{
			name: "backrefs without backref_subjects valid (non-subject prefixes only)",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunPostProduct,
				BackRefs:      []BackRefClaim{{Prefix: "imagedigest:", Description: "image digest"}},
				Fixtures:      canonical,
			},
		},
		{
			name: "backrefs entry missing prefix rejected",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunPostProduct,
				BackRefs:      []BackRefClaim{{Prefix: "  ", Description: "image digest"}},
				Fixtures:      canonical,
			},
			wantErr: true,
		},
		{
			name: "backrefs entry missing description rejected",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunPostProduct,
				BackRefs:      []BackRefClaim{{Prefix: "imagedigest:"}},
				Fixtures:      canonical,
			},
			wantErr: true,
		},
		{
			name: "backrefs duplicate prefix rejected",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunPostProduct,
				BackRefs: []BackRefClaim{
					{Prefix: "imagedigest:", Description: "image digest"},
					{Prefix: "imagedigest:", Description: "image digest again"},
				},
				Fixtures: canonical,
			},
			wantErr: true,
		},
		{
			name: "backref_subjects entry missing from backrefs rejected when both present",
			c: &OutputContract{
				PredicateType:   "x",
				RunType:         ContractRunPostProduct,
				Subjects:        []SubjectClaim{{Prefix: "name:"}},
				BackRefSubjects: []string{"name:"},
				BackRefs:        []BackRefClaim{{Prefix: "imagedigest:", Description: "image digest"}},
				Fixtures:        canonical,
			},
			wantErr: true,
		},
		{
			name: "bad exit behavior value",
			c: &OutputContract{
				PredicateType: "x",
				RunType:       ContractRunPostProduct,
				ExitBehavior:  &ExitBehaviorClaim{OnNoEvidence: "explode"},
				Fixtures:      []FixtureRef{{Name: "happy"}, {Name: "empty", Role: FixtureNegative}},
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOutputContract(tc.c, "test-attestor")
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestContractRoundTripsInDetectorYAML proves a contract block parses through
// the full ParseDetectorYAML path (KnownFields(true) accepts the new key) and
// that an entry WITHOUT a contract still parses (backward compat).
func TestContractRoundTripsInDetectorYAML(t *testing.T) {
	withContract := []byte(`apiVersion: cilock.detection/v0.1
name: demo-attestor
description: demo
pre:
  match:
    argv_prefix: [demo]
contract:
  predicate_type: https://aflock.ai/attestations/demo/v0.1
  run_type: postproduct
  subjects:
    - prefix: "demo:thing:"
      digest_algs: [sha256]
  backrefs:
    - prefix: "imagedigest:"
      description: "non-subject anchor onto the built image"
    - prefix: "demo:thing:"
      description: "fallback anchor on the demo thing"
  backref_subjects:
    - "demo:thing:"
  emits_materials: true
  schema_required: true
  fixtures:
    - name: canonical
      role: canonical
`)
	d, err := ParseDetectorYAML(withContract)
	if err != nil {
		t.Fatalf("parse with contract: %v", err)
	}
	if d.Contract == nil {
		t.Fatal("contract not parsed")
	}
	if d.Contract.PredicateType != "https://aflock.ai/attestations/demo/v0.1" {
		t.Errorf("predicate_type = %q", d.Contract.PredicateType)
	}
	if len(d.Contract.Subjects) != 1 || d.Contract.Subjects[0].Prefix != "demo:thing:" {
		t.Errorf("subjects = %+v", d.Contract.Subjects)
	}
	if len(d.Contract.BackRefs) != 2 || d.Contract.BackRefs[0].Prefix != "imagedigest:" || d.Contract.BackRefs[0].Description == "" {
		t.Errorf("backrefs = %+v", d.Contract.BackRefs)
	}
	if len(d.Contract.BackRefSubjects) != 1 || d.Contract.BackRefSubjects[0] != "demo:thing:" {
		t.Errorf("backref_subjects = %+v", d.Contract.BackRefSubjects)
	}
	if len(d.Contract.Fixtures) != 1 || d.Contract.Fixtures[0].Name != "canonical" || d.Contract.Fixtures[0].Role != FixtureCanonical {
		t.Errorf("fixtures = %+v", d.Contract.Fixtures)
	}

	noContract := []byte(`apiVersion: cilock.detection/v0.1
name: legacy-attestor
pre:
  match:
    argv_prefix: [legacy]
`)
	d2, err := ParseDetectorYAML(noContract)
	if err != nil {
		t.Fatalf("parse without contract (backward compat): %v", err)
	}
	if d2.Contract != nil {
		t.Error("expected nil contract on legacy entry")
	}
}

// TestMultiTypeContractRoundTrip proves predicate_types parses (multi-predicate
// attestors like sbom that register SPDX + CycloneDX + native via
// RegisterAttestationWithTypes).
func TestMultiTypeContractRoundTrip(t *testing.T) {
	raw := []byte(`apiVersion: cilock.detection/v0.1
name: sbom-demo
pre:
  match:
    argv_prefix: [syft]
contract:
  predicate_type: https://cyclonedx.org/bom
  predicate_types:
    - https://cyclonedx.org/bom
    - https://spdx.dev/Document
  run_type: product
  exports: true
  export_configurable: true
  fixtures:
    - name: canonical
`)
	d, err := ParseDetectorYAML(raw)
	if err != nil {
		t.Fatalf("parse multi-type: %v", err)
	}
	if len(d.Contract.PredicateTypes) != 2 {
		t.Fatalf("predicate_types = %+v", d.Contract.PredicateTypes)
	}
	if d.Contract.Exports == nil || !*d.Contract.Exports {
		t.Errorf("exports = %v (want non-nil true)", d.Contract.Exports)
	}
	if !d.Contract.ExportConfigurable {
		t.Errorf("export_configurable = false (want true)")
	}
}

// TestContractProven distinguishes declared (static-only) contracts from
// fixture-proven ones — the tier the CI gate reports on.
func TestContractProven(t *testing.T) {
	declared := &OutputContract{PredicateType: "x", RunType: ContractRunProduct}
	if declared.Proven() {
		t.Error("contract with no fixtures should be declared, not proven")
	}
	negativeOnly := &OutputContract{PredicateType: "x", RunType: ContractRunProduct, Fixtures: []FixtureRef{{Name: "empty", Role: FixtureNegative}}}
	if negativeOnly.Proven() {
		t.Error("contract with only a negative fixture is not proven (no canonical real-run)")
	}
	proven := &OutputContract{PredicateType: "x", RunType: ContractRunProduct, Fixtures: []FixtureRef{{Name: "happy", Role: FixtureCanonical}}}
	if !proven.Proven() {
		t.Error("contract with a canonical fixture should be proven")
	}
	implicit := &OutputContract{PredicateType: "x", RunType: ContractRunProduct, Fixtures: []FixtureRef{{Name: "happy"}}}
	if !implicit.Proven() {
		t.Error("empty role defaults to canonical, so this should be proven")
	}
}
