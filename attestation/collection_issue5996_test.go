// Copyright 2021 The Witness Contributors
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
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

// subjOnlyAttestor is a minimal Subjecter used to exercise Collection.Subjects().
type subjOnlyAttestor struct {
	subjects map[string]cryptoutil.DigestSet
}

func (a *subjOnlyAttestor) Name() string                              { return "subj" }
func (a *subjOnlyAttestor) Type() string                              { return "subj" }
func (a *subjOnlyAttestor) RunType() RunType                          { return "" }
func (a *subjOnlyAttestor) Schema() *jsonschema.Schema                { return nil }
func (a *subjOnlyAttestor) Attest(*AttestationContext) error          { return nil }
func (a *subjOnlyAttestor) Subjects() map[string]cryptoutil.DigestSet { return a.subjects }

// TestSecurity_Issue5996_SubjectsResolvedTypeNamespace asserts the SECURE
// behavior: Collection.Subjects() must namespace subject keys by the RESOLVED
// (canonical) attestation type, so an attestation carrying a legacy URI and one
// carrying the canonical URI alias to the same subject key. Keying by the raw
// type lets the same logical subject occupy two distinct namespaces depending
// on which URI form the producer happened to emit.
func TestSecurity_Issue5996_SubjectsResolvedTypeNamespace(t *testing.T) {
	const legacyType = "https://witness.dev/attestations/product/v0.1"
	const canonicalType = "https://aflock.ai/attestations/product/v0.1"

	// Sanity: these must actually be a legacy/canonical alias pair.
	if ResolveLegacyType(legacyType) != canonicalType {
		t.Fatalf("test precondition: %q must resolve to %q", legacyType, canonicalType)
	}

	digest := cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: 0}: "abc"}
	subjects := map[string]cryptoutil.DigestSet{"file:main": digest}

	legacyColl := Collection{
		Attestations: []CollectionAttestation{
			{Type: legacyType, Attestation: &subjOnlyAttestor{subjects: subjects}},
		},
	}
	canonicalColl := Collection{
		Attestations: []CollectionAttestation{
			{Type: canonicalType, Attestation: &subjOnlyAttestor{subjects: subjects}},
		},
	}

	legacyKeys := legacyColl.Subjects()
	canonicalKeys := canonicalColl.Subjects()

	if len(legacyKeys) != 1 || len(canonicalKeys) != 1 {
		t.Fatalf("expected exactly one subject key each; got legacy=%v canonical=%v", legacyKeys, canonicalKeys)
	}

	var legacyKey, canonicalKey string
	for k := range legacyKeys {
		legacyKey = k
	}
	for k := range canonicalKeys {
		canonicalKey = k
	}

	if legacyKey != canonicalKey {
		t.Fatalf("legacy and canonical types must produce the SAME subject key; got %q vs %q", legacyKey, canonicalKey)
	}
}
