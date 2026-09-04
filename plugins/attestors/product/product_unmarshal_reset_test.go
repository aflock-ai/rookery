// Copyright 2026 The Rookery Contributors
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

package product

import (
	"encoding/json"
	"testing"
)

// TestUnmarshalResetsDerivedStateBetweenDecodes pins the reuse guard on
// UnmarshalJSON: decoding a leaf-less v0.3 predicate (sidecar-only /
// pre-inline shape) into an Attestor that previously decoded an inline one
// must not keep the earlier products. They are derived from the earlier
// predicate's leaves, and this predicate signed none — Products() feeds
// artifactsFrom edge matching, so carrying them forward would let a verifier
// satisfy an edge with evidence the predicate at hand never claimed.
func TestUnmarshalResetsDerivedStateBetweenDecodes(t *testing.T) {
	inline, err := json.Marshal(makeAttestor(t, map[string]string{"bin/app": "one", "lib/x.so": "two"}))
	if err != nil {
		t.Fatalf("marshal inline: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(inline, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(generic, "leaves")
	leafless, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal leaf-less: %v", err)
	}

	var a Attestor
	if err := json.Unmarshal(inline, &a); err != nil {
		t.Fatalf("decode inline: %v", err)
	}
	if len(a.Products()) != 2 {
		t.Fatalf("inline decode should hydrate 2 products, got %d", len(a.Products()))
	}
	if err := json.Unmarshal(leafless, &a); err != nil {
		t.Fatalf("decode leaf-less: %v", err)
	}
	if got := a.Products(); len(got) != 0 {
		t.Fatalf("a leaf-less predicate decoded into a reused Attestor carried %d stale products from the previous decode: %v", len(got), got)
	}
	if len(a.leaves) != 0 {
		t.Fatalf("stale leaves survived the second decode: %d", len(a.leaves))
	}

	// Reverse order: a leaf-less decode followed by an inline one hydrates.
	var b Attestor
	if err := json.Unmarshal(leafless, &b); err != nil {
		t.Fatalf("decode leaf-less: %v", err)
	}
	if err := json.Unmarshal(inline, &b); err != nil {
		t.Fatalf("decode inline: %v", err)
	}
	if got := len(b.Products()); got != 2 {
		t.Fatalf("inline decode after a leaf-less one hydrated %d products, want 2", got)
	}
}

// TestUnmarshalResetsRootBytesBetweenDecodes covers the second half of the
// same hazard. rootBytes is populated by Attest (never by a decode), and
// RootBytes() feeds the inclusion-proof attestor's in-memory tree check, so a
// root left over from an earlier run must not survive a decode that describes
// a different tree.
func TestUnmarshalResetsRootBytesBetweenDecodes(t *testing.T) {
	a := makeAttestor(t, map[string]string{"bin/app": "one", "lib/x.so": "two"})
	if len(a.RootBytes()) == 0 {
		t.Fatalf("precondition: an attested Attestor should hold root bytes")
	}
	inline, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal inline: %v", err)
	}
	if err := json.Unmarshal(inline, a); err != nil {
		t.Fatalf("decode into the same Attestor: %v", err)
	}
	if got := a.RootBytes(); len(got) != 0 {
		t.Fatalf("root bytes from the earlier tree survived a decode: %x", got)
	}
}
