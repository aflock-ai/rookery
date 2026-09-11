// Copyright 2025 The Witness Contributors
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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testdata/prechange_v03_material_predicate.json was CAPTURED, not written by
// hand: it is the material attestation out of a real collection envelope minted
// by the pre-change `cilock run` binary built from the commit this change
// branches off. It therefore has exactly the shape every v0.3 attestation
// already sitting in Archivista has — five keys, inline leaves, and no
// manifest fields at all.
//
// A hand-authored fixture would only prove the new reader agrees with the new
// author's idea of the old format. This one cannot: nothing in this change
// produced it.
const prechangeFixture = "prechange_v03_material_predicate.json"

func loadPrechangeFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", prechangeFixture))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

// TestPrechangeV03FixtureHasLegacyShape documents what the fixture IS, so a
// later edit that silently regenerates it with a new-shape producer — and
// thereby stops testing backward compatibility at all — fails instead of
// quietly passing.
func TestPrechangeV03FixtureHasLegacyShape(t *testing.T) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(loadPrechangeFixture(t), &keys); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	for _, want := range []string{"merkleRoot", "treeSize", "hashAlgorithm", "construction", "leaves"} {
		if _, present := keys[want]; !present {
			t.Errorf("fixture is missing %q", want)
		}
	}
	for _, forbidden := range []string{"manifestUploaded", "manifest"} {
		if _, present := keys[forbidden]; present {
			t.Fatalf("fixture carries %q — it was regenerated with a POST-change producer and no "+
				"longer tests backward compatibility. Re-capture it from a pre-change binary.", forbidden)
		}
	}
}

// TestPrechangeV03FixtureStillVerifies is the backward-compatibility bar: an
// envelope minted before this change must decode, expose its inline leaves,
// reconstruct its signed root, and rehydrate its materials map exactly as it
// did before — with the new manifest machinery inert.
func TestPrechangeV03FixtureStillVerifies(t *testing.T) {
	var a Attestor
	if err := json.Unmarshal(loadPrechangeFixture(t), &a); err != nil {
		t.Fatalf("a pre-change v0.3 predicate no longer decodes: %v", err)
	}

	if !a.HasInlineLeaves() {
		t.Fatal("inline leaves were not recognised on a pre-change predicate")
	}
	if got := len(a.Leaves()); got != int(a.TreeSize) {
		t.Errorf("got %d leaves, treeSize says %d", got, a.TreeSize)
	}
	if err := a.VerifyInlineLeaves(); err != nil {
		t.Fatalf("pre-change inline leaves no longer reconstruct the signed root: %v", err)
	}
	if got := len(a.Materials()); got != int(a.TreeSize) {
		t.Errorf("Materials() has %d entries, want %d", got, a.TreeSize)
	}

	// The manifest machinery must be completely inert on this shape.
	if a.ManifestUploaded != nil {
		t.Error("decoding a pre-change predicate invented a manifestUploaded value")
	}
	if a.ManifestState() != ManifestInline {
		t.Errorf("ManifestState()=%v, want ManifestInline", a.ManifestState())
	}
	if a.ManifestPending() {
		t.Error("a pre-change predicate would trigger a manifest resolution attempt")
	}
	if a.ManifestWithheld() {
		t.Error("a pre-change predicate was read as a signed manifestUploaded=false")
	}
	if a.ManifestDigest() != "" {
		t.Errorf("ManifestDigest()=%q, want empty", a.ManifestDigest())
	}
}

// TestPrechangeV03FixtureRoundTripsUnchanged: decoding and re-encoding a
// pre-change predicate must reproduce the same logical document. A re-encode
// that grew fields would mean any tool normalising stored evidence would start
// asserting things the original signer never said.
func TestPrechangeV03FixtureRoundTripsUnchanged(t *testing.T) {
	raw := loadPrechangeFixture(t)
	var a Attestor
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(&a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var before, after map[string]any
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatalf("unmarshal before: %v", err)
	}
	if err := json.Unmarshal(out, &after); err != nil {
		t.Fatalf("unmarshal after: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("round trip changed the key set: before=%v after=%v", sortedKeys(before), sortedKeys(after))
	}
	for k := range before {
		if _, present := after[k]; !present {
			t.Errorf("round trip dropped key %q", k)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
