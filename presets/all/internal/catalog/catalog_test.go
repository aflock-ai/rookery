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

package catalog

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// TestEveryRegisteredAttestorIsInCatalog asserts (a): every attestor the live
// registry knows about appears, by name, in the generated catalog. A new
// attestor that forgets to surface here is the exact drift this generator
// exists to prevent.
func TestEveryRegisteredAttestorIsInCatalog(t *testing.T) {
	cat, err := Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	inCatalog := make(map[string]Entry, len(cat.Attestors))
	for _, e := range cat.Attestors {
		inCatalog[e.Name] = e
	}

	entries := attestation.RegistrationEntries()
	if len(entries) == 0 {
		t.Fatal("no registered attestors — presets/all blank import did not populate the registry (a zero here would let every other assertion pass vacuously)")
	}

	for _, re := range entries {
		a := re.Factory()
		name := a.Name()
		e, ok := inCatalog[name]
		if !ok {
			t.Errorf("registered attestor %q is missing from the generated catalog", name)
			continue
		}
		if !e.Registered {
			t.Errorf("attestor %q is registered live but the catalog marks it registered=false", name)
		}
	}
}

// TestPredicateTypeNonEmptyForTypedAttestors asserts (b): for every attestor
// whose live Type() is non-empty, the catalog entry's predicate_type is
// non-empty. A dropped predicate URI silently breaks any verifier policy keyed
// on it, so this is the highest-value field.
func TestPredicateTypeNonEmptyForTypedAttestors(t *testing.T) {
	cat, err := Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	byName := make(map[string]Entry, len(cat.Attestors))
	for _, e := range cat.Attestors {
		byName[e.Name] = e
	}

	for _, re := range attestation.RegistrationEntries() {
		a := re.Factory()
		if a.Type() == "" {
			continue // a typeless attestor legitimately has no predicate URI
		}
		e, ok := byName[a.Name()]
		if !ok {
			t.Errorf("attestor %q not in catalog", a.Name())
			continue
		}
		if e.PredicateType == "" {
			t.Errorf("attestor %q has live Type() %q but catalog predicate_type is empty", a.Name(), a.Type())
		}
		// The catalog's predicate_type must agree with the live attestor — a
		// mismatch means the join attached the wrong detector's contract.
		if e.PredicateType != a.Type() {
			t.Errorf("attestor %q: catalog predicate_type %q != live Type() %q", a.Name(), e.PredicateType, a.Type())
		}
	}
}

// TestDeterministic asserts (c): rendering twice yields byte-identical output.
// This is the property that makes docs/attestor-catalog.json diff-stable and
// safe to commit — any map-iteration nondeterminism or timestamp would fail
// here.
func TestDeterministic(t *testing.T) {
	first, err := Render()
	if err != nil {
		t.Fatalf("Render #1: %v", err)
	}
	for i := 2; i <= 5; i++ {
		next, err := Render()
		if err != nil {
			t.Fatalf("Render #%d: %v", i, err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("Render #%d is not byte-identical to #1 — catalog output is nondeterministic", i)
		}
	}
}

// TestCatalogParses asserts (d): the rendered bytes are valid JSON and carry
// the expected top-level shape. A consumer (the platform, an LLM agent) must be
// able to json.Unmarshal it.
func TestCatalogParses(t *testing.T) {
	data, err := Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var got Catalog
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("generated catalog is not valid JSON: %v", err)
	}
	if got.GeneratedFrom != GeneratedFrom {
		t.Errorf("generated_from = %q, want %q", got.GeneratedFrom, GeneratedFrom)
	}
	if got.AttestorCount != len(got.Attestors) {
		t.Errorf("attestor_count %d != len(attestors) %d", got.AttestorCount, len(got.Attestors))
	}
	if got.AttestorCount == 0 {
		t.Fatal("attestor_count is 0 — the catalog is empty")
	}
	// No entry may be both backed by a live attestor and marked detection-only.
	for _, e := range got.Attestors {
		if e.Registered && e.DetectionOnly {
			t.Errorf("attestor %q is both registered and detection_only — the join is wrong", e.Name)
		}
		if e.Name == "" {
			t.Error("an attestor entry has an empty name")
		}
	}
}
