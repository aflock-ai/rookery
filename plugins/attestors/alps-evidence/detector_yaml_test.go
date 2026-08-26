// Copyright 2026 TestifySec, Inc.
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
// See the License for the specific language governing permissions and
// limitations under the License.

package alpsevidence

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestDetectorYAMLParses is the per-plugin half of the catalog gate:
// scripts/check-detector-yamls.sh runs it for every plugin that ships a
// detector.yaml and asserts it actually executed. Beyond parsing, it pins the
// contract claims that must stay true to the code: the predicate type and run
// type mirror this package's constants, and the contract declares no subjects
// — the deliberate decision (see alps_evidence.go) that an agent-controlled
// predicate must never select what a collection is about.
func TestDetectorYAMLParses(t *testing.T) {
	d, err := detection.ParseDetectorYAML(detectorYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Name != Name {
		t.Errorf("name mismatch: yaml=%q plugin=%q", d.Name, Name)
	}
	if d.Pre == nil {
		t.Errorf("expected pre block")
	}
	if d.Post != nil {
		t.Errorf("alps-evidence is pre-only; post block should be absent")
	}
	if d.Contract == nil {
		t.Fatal("expected an output contract")
	}
	if d.Contract.PredicateType != Type {
		t.Errorf("contract predicate_type %q must equal the attestor Type %q", d.Contract.PredicateType, Type)
	}
	if d.Contract.RunType != "prematerial" {
		t.Errorf("contract run_type %q must mirror attestation.PreMaterialRunType", d.Contract.RunType)
	}
	if len(d.Contract.Subjects) != 0 {
		t.Errorf("alps-evidence must declare no subjects; every field is chosen by the process being described")
	}
	if len(d.Contract.BackRefSubjects) != 0 || len(d.Contract.BackRefs) != 0 {
		t.Errorf("alps-evidence must declare no backrefs")
	}
}
