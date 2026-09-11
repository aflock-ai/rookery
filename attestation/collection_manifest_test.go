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

package attestation

import (
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

// fakeHydrator stands in for the material attestor at the collection layer.
// The material package lives in its own module and cannot be imported here
// (that would invert the dependency), so the CONTRACT is what gets tested:
// pending/not-pending routing, the not-found error, and the guarantee that a
// non-pending attestor is never consulted at all.
type fakeHydrator struct {
	pending    bool
	withheld   bool
	digest     string
	hydrated   bool
	hydrateBy  []byte
	hydrateErr error
	// consulted records whether the collection asked us for anything, which is
	// how the "no fetch is attempted" guarantee is actually observed rather
	// than assumed.
	consulted bool
}

func (f *fakeHydrator) Name() string                     { return "fake-material" }
func (f *fakeHydrator) Type() string                     { return "https://example.test/attestations/fake/v0.1" }
func (f *fakeHydrator) RunType() RunType                 { return MaterialRunType }
func (f *fakeHydrator) Attest(*AttestationContext) error { return nil }
func (f *fakeHydrator) Schema() *jsonschema.Schema       { return jsonschema.Reflect(&fakeHydrator{}) }

func (f *fakeHydrator) Materials() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{}
}
func (f *fakeHydrator) ManifestPending() bool  { return f.pending }
func (f *fakeHydrator) ManifestWithheld() bool { return f.withheld }
func (f *fakeHydrator) ManifestDigest() string { f.consulted = true; return f.digest }
func (f *fakeHydrator) HydrateFromManifest(predicate []byte) error {
	if f.hydrateErr != nil {
		return f.hydrateErr
	}
	f.hydrated = true
	f.hydrateBy = predicate
	return nil
}

func collectionWith(a Attestor) *Collection {
	return &Collection{
		Name: "test",
		Attestations: []CollectionAttestation{
			{Type: a.Type(), Attestation: a},
		},
	}
}

// TestHydrateManifestsResolvesPending is the happy path: a pending attestor is
// handed exactly the bytes registered under the digest it named.
func TestHydrateManifestsResolvesPending(t *testing.T) {
	f := &fakeHydrator{pending: true, digest: "abc123"}
	c := collectionWith(f)

	if !c.ManifestsPending() {
		t.Fatal("ManifestsPending() should be true")
	}
	body := []byte(`{"schemaVersion":"x"}`)
	err := c.HydrateManifests(func(d string) ([]byte, bool) {
		if d != "abc123" {
			t.Errorf("looked up %q, want abc123", d)
		}
		return body, true
	})
	if err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	if !f.hydrated {
		t.Error("attestor was never hydrated")
	}
	if string(f.hydrateBy) != string(body) {
		t.Errorf("hydrated with %q, want %q", f.hydrateBy, body)
	}
}

// TestHydrateManifestsNotFoundIsItsOwnError is the "not found" row. A manifest
// the producer SAID it published but that we do not hold is a finding — it must
// not be silently skipped, and it must not be reported as a mismatch.
func TestHydrateManifestsNotFound(t *testing.T) {
	f := &fakeHydrator{pending: true, digest: "missing"}
	c := collectionWith(f)

	err := c.HydrateManifests(func(string) ([]byte, bool) { return nil, false })
	if err == nil {
		t.Fatal("a missing manifest passed silently")
	}
	if !errors.Is(err, ErrManifestNotResolved) {
		t.Fatalf("got %v, want ErrManifestNotResolved", err)
	}
	if f.hydrated {
		t.Error("attestor was hydrated despite the manifest not being found")
	}
}

// TestHydrateManifestsPropagatesHydratorError: the attestor's own distinct
// errors (unreadable vs mismatch) must reach the caller intact, not be
// flattened into the collection's not-found error.
func TestHydrateManifestsPropagatesHydratorError(t *testing.T) {
	sentinel := errors.New("root mismatch sentinel")
	f := &fakeHydrator{pending: true, digest: "abc", hydrateErr: sentinel}
	c := collectionWith(f)

	err := c.HydrateManifests(func(string) ([]byte, bool) { return []byte("{}"), true })
	if err == nil {
		t.Fatal("expected the hydrator's error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want it to wrap the hydrator's own error", err)
	}
	if errors.Is(err, ErrManifestNotResolved) {
		t.Fatal("a hydration FAILURE was reported as a missing manifest; the two must stay distinct")
	}
}

// TestNonPendingIsNeverConsulted is the guarantee that makes the state table
// stable under a store outage: an attestor that is inline, legacy, or has
// signed manifestUploaded=false is never asked for a digest and never triggers
// a lookup, so no amount of storage unavailability can reclassify it.
func TestNonPendingIsNeverConsulted(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *fakeHydrator
	}{
		{"inline / legacy", &fakeHydrator{pending: false}},
		{"withheld (manifestUploaded=false)", &fakeHydrator{pending: false, withheld: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := collectionWith(tc.f)
			if c.ManifestsPending() {
				t.Error("ManifestsPending() should be false")
			}
			called := false
			if err := c.HydrateManifests(func(string) ([]byte, bool) { called = true; return nil, false }); err != nil {
				t.Fatalf("hydrate should be a no-op, got %v", err)
			}
			if called {
				t.Error("a lookup was attempted for a non-pending attestor")
			}
			if tc.f.consulted {
				t.Error("the attestor was asked for a manifest digest it should never have been asked for")
			}
		})
	}
}

// TestMaterialManifestWithheldOnlyCountsMaterialers mirrors HasInlineMaterials:
// a product attestor's manifest state says nothing about consumed materials.
func TestMaterialManifestWithheld(t *testing.T) {
	withheld := &fakeHydrator{withheld: true}
	if !collectionWith(withheld).MaterialManifestWithheld() {
		t.Error("a withheld material manifest was not reported")
	}
	notWithheld := &fakeHydrator{}
	if collectionWith(notWithheld).MaterialManifestWithheld() {
		t.Error("a non-withheld attestor was reported as withheld")
	}
}

// TestHydrateManifestsOnEmptyCollection: no attestors, no work, no error.
func TestHydrateManifestsOnEmptyCollection(t *testing.T) {
	c := &Collection{Name: "empty"}
	if c.ManifestsPending() {
		t.Error("an empty collection reported a pending manifest")
	}
	if err := c.HydrateManifests(func(string) ([]byte, bool) { return nil, false }); err != nil {
		t.Errorf("hydrate on an empty collection: %v", err)
	}
}
