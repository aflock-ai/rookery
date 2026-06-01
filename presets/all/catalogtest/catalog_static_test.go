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

package catalogtest

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
	_ "github.com/aflock-ai/rookery/presets/all" // register every attestor + detector
)

// TestContractMatchesLiveInterfaces is the DECLARED tier of the catalog gate:
// for every registered detector.yaml that carries an output contract, it
// resolves the live attestor and asserts the contract's claims are consistent
// with the attestor's actual interfaces — WITHOUT needing a recorded fixture.
// This is what lets the whole catalog be migrated to contracts and gated at
// once: the fixture-driven harness (catalog_harness_test.go) proves the subset
// that has real-run fixtures; this proves every contract is at least honest
// about what the code does.
//
// A contract that claims EmitsProducts on a non-Producer, a predicate URI no
// attestor registers, or a run-type that disagrees with Attestor.RunType() is
// a lie the prose docs could carry silently — here it is a red test.
func TestContractMatchesLiveInterfaces(t *testing.T) {
	reg := detection.Default()
	all, failures := reg.LookupAll()
	for name, err := range failures {
		t.Errorf("detector %q failed to parse (contract validation is part of parse): %v", name, err)
	}

	declared, proven, withCreds := 0, 0, 0
	for name, d := range all {
		if d.Contract == nil {
			continue
		}
		declared++
		if d.Contract.Proven() {
			proven++
		}
		if len(d.Contract.Credentials) > 0 {
			withCreds++
		}
		c := d.Contract
		t.Run(name, func(t *testing.T) {
			a, err := attestation.GetAttestor(name)
			if err != nil {
				t.Fatalf("contract declared but no live attestor %q (detection-only entries must not carry an output contract): %v", name, err)
			}

			if got := string(a.RunType()); got != c.RunType {
				t.Errorf("run_type: contract says %q, live RunType() is %q", c.RunType, got)
			}

			// Every declared predicate URI must be registered, and the
			// attestor's own Type() must be one of them.
			types := c.PredicateTypes
			if len(types) == 0 {
				types = []string{c.PredicateType}
			}
			inSet := false
			for _, pt := range types {
				if _, ok := attestation.FactoryByType(pt); !ok {
					t.Errorf("predicate type %q is not registered to any attestor (typo, or attestor doesn't emit it)", pt)
				}
				if pt == a.Type() {
					inSet = true
				}
			}
			if !inSet {
				t.Errorf("live Type() %q is not among the contract's predicate type(s) %v", a.Type(), types)
			}

			if len(c.Subjects) > 0 {
				if _, ok := a.(attestation.Subjecter); !ok {
					t.Errorf("contract declares subjects but attestor does not implement Subjecter")
				}
			}
			if c.EmitsMaterials {
				if _, ok := a.(attestation.Materialer); !ok {
					t.Errorf("contract says emits_materials but attestor does not implement Materialer")
				}
			}
			if c.EmitsProducts {
				if _, ok := a.(attestation.Producer); !ok {
					t.Errorf("contract says emits_products but attestor does not implement Producer")
				}
			}
			if c.Exports != nil {
				if _, ok := a.(attestation.Exporter); !ok {
					t.Errorf("contract declares exports but attestor does not implement Exporter")
				}
			}
			if c.Finalizes {
				if _, ok := a.(attestation.Finalizer); !ok {
					t.Errorf("contract says finalizes but attestor does not implement Finalizer")
				}
			}
			if len(c.BackRefSubjects) > 0 {
				if _, ok := a.(attestation.BackReffer); !ok {
					t.Errorf("contract declares backref_subjects but attestor does not implement BackReffer")
				}
			}
			if len(c.MultiExported) > 0 {
				if _, ok := a.(attestation.MultiExporter); !ok {
					t.Errorf("contract declares multi_exported but attestor does not implement MultiExporter")
				}
			}
			if c.SchemaRequired && a.Schema() == nil {
				t.Errorf("contract says schema_required but Schema() returned nil")
			}
		})
	}

	t.Logf("catalog contract coverage: %d detectors, %d with a contract (%d fixture-proven, %d declared-only), %d document credentials",
		len(all), declared, proven, declared-proven, withCreds)
	if declared == 0 {
		t.Skip("no output contracts declared yet")
	}
}
