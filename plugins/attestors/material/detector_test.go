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

package material

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}

// The contract is the reason the file exists: it must describe THIS attestor —
// the predicate type it signs and the phase it runs in — and it must never
// grow a detection gate, because a gate would re-add an always-on attestor the
// operator disabled with --no-default-attestor.
func TestDetectorContractDescribesTheLiveAttestor(t *testing.T) {
	d, err := detection.ParseDetectorYAML(detectorYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !d.AlwaysOn || d.Pre != nil || d.Post != nil {
		t.Fatalf("material must be always_on with no gate, got always_on=%v pre=%v post=%v", d.AlwaysOn, d.Pre != nil, d.Post != nil)
	}
	c := d.Contract
	if c == nil {
		t.Fatal("no contract")
	}
	a := New()
	if c.PredicateType != a.Type() {
		t.Errorf("contract predicate_type %q != live Type() %q", c.PredicateType, a.Type())
	}
	if c.RunType != string(a.RunType()) {
		t.Errorf("contract run_type %q != live RunType() %q", c.RunType, a.RunType())
	}
	if len(c.Subjects) != 1 || c.Subjects[0].Prefix != TreeSubjectName {
		t.Errorf("contract subjects %+v, want exactly %q", c.Subjects, TreeSubjectName)
	}
	if !c.EmitsMaterials || !c.Finalizes || !c.SchemaRequired {
		t.Errorf("contract must declare emits_materials, finalizes and schema_required; got %+v", c)
	}
	// The pre-plan never fires an always-on detector, whatever the argv.
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	plan := detection.RunPrePlanWith(reg, detection.PrePlan{Argv: []string{"go", "build", "./..."}})
	if len(plan.Fire) != 0 {
		t.Fatalf("material must never fire at pre-gate (it is attached on every run), got %+v", plan.Fire)
	}
}
