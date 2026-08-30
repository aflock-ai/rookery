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
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/testkit"
	_ "github.com/aflock-ai/rookery/presets/all" // register every attestor + detector
)

// TestShownPredicateTypeIsTheEmittedType closes the gap a cold-start user hit
// with `cilock tools show sbom`: the CLI printed
// `predicate type: https://aflock.ai/attestations/sbom/v0.1`, the website
// rendered the same catalog entry, and the attestor then signed its evidence
// under `https://spdx.dev/Document` — so a policy written from the docs
// matched nothing, silently.
//
// Two surfaces must agree, per registered attestor:
//
//  1. What `cilock tools show` / `cilock attestors list` PRINT — they call
//     Type() on a freshly-constructed attestor — must equal the contract's
//     primary predicate_type (what the catalog JSON and website print).
//  2. That primary type must be one the attestor actually EMITS. The
//     recorded fixtures under testdata/fixtures are the ground truth for
//     "emits": each declares the predicate type the real run produced.
//
// (1) alone is not enough — both surfaces can agree on a type nobody ever
// signs, which is exactly the sbom case. (2) is what makes the test bite.
func TestShownPredicateTypeIsTheEmittedType(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "plugins", "attestors"))
	if err != nil {
		t.Fatalf("resolve plugins dir: %v", err)
	}
	fixtureDirs, err := filepath.Glob(filepath.Join(root, "*", "testdata", "fixtures"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	emitted := map[string]map[string]bool{} // attestor name -> set of fixture-recorded predicate types
	for _, fdir := range fixtureDirs {
		fxs, err := testkit.LoadFixtures(fdir)
		if err != nil {
			t.Fatalf("load fixtures from %s: %v", fdir, err)
		}
		for _, fx := range fxs {
			if emitted[fx.Attestor] == nil {
				emitted[fx.Attestor] = map[string]bool{}
			}
			emitted[fx.Attestor][fx.Expect.PredicateType] = true
		}
	}
	if len(emitted) == 0 {
		t.Fatalf("no fixtures found under %s — a skip here would be a false green", root)
	}

	all, failures := detection.Default().LookupAll()
	for name, err := range failures {
		t.Errorf("detector %q failed to parse: %v", name, err)
	}
	checked := 0
	for name, d := range all {
		if d.Contract == nil {
			continue
		}
		c := d.Contract
		t.Run(name, func(t *testing.T) {
			a, err := attestation.GetAttestor(name)
			if err != nil {
				t.Fatalf("contract declared but no live attestor %q: %v", name, err)
			}
			checked++
			// Surface 1: the CLI prints Type() of a fresh instance; the
			// catalog/website print the contract. They must be the same string.
			if got := a.Type(); got != c.PredicateType {
				t.Errorf("`cilock tools show %s` prints Type()=%q but the catalog/website print predicate_type=%q", name, got, c.PredicateType)
			}
			// Surface 2: the shown type must be one a real run emitted.
			types, ok := emitted[name]
			if !ok {
				return // no recorded run to compare against; surface 1 still holds
			}
			if !types[c.PredicateType] {
				t.Errorf("catalog shows predicate_type=%q for %s, but no recorded run ever emitted it (fixtures emit %v) — a policy keyed on the shown type matches nothing", c.PredicateType, name, keys(types))
			}
			for _, pt := range c.PredicateTypes {
				if !types[pt] {
					t.Errorf("catalog lists %q under predicate_types for %s, but no recorded run emits it (fixtures emit %v) — predicate_types is the set the attestor MAY emit, not a registration alias list", pt, name, keys(types))
				}
			}
		})
	}
	if checked == 0 {
		t.Fatal("no contracted attestors checked — registry wiring is broken")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
