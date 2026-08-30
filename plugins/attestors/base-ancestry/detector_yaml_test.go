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

package baseancestry

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestDetectorYAMLParses is the per-plugin half of the catalog gate
// (scripts/check-detector-yamls.sh). Beyond parsing, it pins the contract's
// claims to the code: the predicate and run types mirror the constants, and
// the contract declares no subjects — the git attestor beside this one owns
// the commit binding.
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
	if d.Contract == nil {
		t.Fatal("expected an output contract")
	}
	if d.Contract.PredicateType != Type {
		t.Errorf("contract predicate_type %q must equal the attestor Type %q", d.Contract.PredicateType, Type)
	}
	if d.Contract.RunType != "prematerial" {
		t.Errorf("contract run_type %q must mirror attestation.PreMaterialRunType", d.Contract.RunType)
	}
	if len(d.Contract.Subjects) != 0 || len(d.Contract.BackRefSubjects) != 0 || len(d.Contract.BackRefs) != 0 {
		t.Errorf("base-ancestry must declare no subjects or backrefs; the git attestor binds the commit")
	}
}
