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
	"os"
	"path/filepath"
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

// TestCommittedCatalogIsCurrent asserts the committed docs/attestor-catalog.json
// is exactly what Render produces from the registry and the detection catalog.
// A new catalog entry (#10186) changed the generator's input and nothing
// regenerated the file: verify-codegen runs only when ent/gqlgen inputs change,
// so the stale file reached main and every later full `jade generate` rewrote
// it. This test is the check that runs on the change that makes it stale.
//
// Regenerate: cd presets/all && GOWORK=off go run ./cmd/gen-catalog, or
// `jade generate`, which also copies it into judge-api.
func TestCommittedCatalogIsCurrent(t *testing.T) {
	want, err := Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "attestor-catalog.json"))
	if err != nil {
		t.Fatalf("read committed catalog: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/attestor-catalog.json is stale: regenerate it with " +
			"`cd presets/all && GOWORK=off go run ./cmd/gen-catalog` (or `jade generate`) and commit it")
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

// TestCompanionExportersAreDescribedByTheCatalog asserts (e): every attestor
// that emits companion envelopes (attestation.CompanionExporter) declares
// their predicate types statically (attestation.CompanionTyper), and the
// catalog carries exactly that list under `companions`. Without this, an
// attestor could sign an envelope type the catalog never mentions — which is
// how the material manifest shipped before this test existed.
func TestCompanionExportersAreDescribedByTheCatalog(t *testing.T) {
	cat, err := Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	byName := make(map[string]Entry, len(cat.Attestors))
	for _, e := range cat.Attestors {
		byName[e.Name] = e
	}

	described := 0
	for _, re := range attestation.RegistrationEntries() {
		a := re.Factory()
		name := a.Name()
		_, exporter := a.(attestation.CompanionExporter)
		typer, typed := a.(attestation.CompanionTyper)
		switch {
		case exporter && !typed:
			t.Errorf("attestor %q implements CompanionExporter but not CompanionTyper — the catalog cannot describe the envelopes it signs", name)
			continue
		case typed && !exporter:
			t.Errorf("attestor %q declares CompanionTypes but does not implement CompanionExporter — it declares envelopes it never emits", name)
			continue
		case !exporter:
			if len(byName[name].Companions) != 0 {
				t.Errorf("attestor %q is not a CompanionExporter but the catalog lists companions %v", name, byName[name].Companions)
			}
			continue
		}
		declared := typer.CompanionTypes()
		if len(declared) == 0 {
			t.Errorf("attestor %q implements CompanionExporter but CompanionTypes() is empty", name)
			continue
		}
		for _, ct := range declared {
			if ct == "" || ct == a.Type() {
				t.Errorf("attestor %q: companion type %q is empty or the attestor's own type", name, ct)
			}
		}
		if got := byName[name].Companions; !sameStringSet(got, declared) {
			t.Errorf("attestor %q: catalog companions %v != live CompanionTypes() %v", name, got, declared)
		}
		described++
	}
	if described == 0 {
		t.Fatal("no CompanionExporter in the registry — the material attestor should be one; a zero here lets the assertion pass vacuously")
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}
