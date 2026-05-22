// Copyright 2026 The Aflock Authors
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

// Verify-only decoders for the historical v0.1 and v0.2 product predicate
// shapes. These exist so cilock verify can still consume attestations that
// pre-date the v0.3 hard cut. They are NEVER selected by `cilock run` (the
// runtime selector matches on Name(), and the legacy decoders return a
// distinct name with a version suffix so the v0.3 producer wins for
// `--attestations product`).
//
// What each decoder does:
//
//  - UnmarshalJSON: parses the historical per-file map (path -> Product)
//    that v0.1 and v0.2 published as the predicate body.
//  - Subjects(): emits one `file:<path>` subject per product so the
//    policy engine's BFS can match historical attestations by file digest,
//    regardless of whether the original Statement.Subject array contained
//    per-file entries (v0.1) or a single tree root (v0.2).
//  - BackRefs(): returns empty. Per-file BackRefs on historical attestations
//    are an explosion risk (every legacy attestation that touched a
//    `.gitignore` would chain across the corpus). Verifiers walk the
//    Statement.Subject array directly for per-file lookups.
//  - Attest(): refuses with errLegacyDecodeOnly so an accidental producer
//    path fails loudly. Only the v0.3 Attestor produces.

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	// legacyV01Name and legacyV02Name are the registry names for the
	// verify-only decoders. They are deliberately different from Name so
	// that `cilock run --attestations product` selects v0.3, never the
	// decoders.
	legacyV01Name = "product-v0.1"
	legacyV02Name = "product-v0.2"

	// LegacyV01Type is the v0.1 predicate URI we accept for verification.
	LegacyV01Type = "https://aflock.ai/attestations/product/v0.1"

	// LegacyV02Type is the v0.2 predicate URI we accept for verification.
	LegacyV02Type = "https://aflock.ai/attestations/product/v0.2"
)

// errLegacyDecodeOnly is returned by Attest() on the legacy decoders so an
// accidental producer-mode invocation fails clearly.
var errLegacyDecodeOnly = errors.New("legacy product attestor is verify-only: use v0.3 to produce new attestations")

func init() {
	// Register both legacy types alongside the v0.3 producer. RegisterAttestation
	// is name+type keyed, so the v0.3 producer (registered in product.go) and
	// these decoders coexist without collision.
	attestation.RegisterAttestation(
		legacyV01Name,
		LegacyV01Type,
		attestation.ProductRunType,
		func() attestation.Attestor { return newLegacyDecoder(LegacyV01Type) },
	)
	attestation.RegisterAttestation(
		legacyV02Name,
		LegacyV02Type,
		attestation.ProductRunType,
		func() attestation.Attestor { return newLegacyDecoder(LegacyV02Type) },
	)
}

// LegacyDecoder is the verify-only decoder for v0.1 and v0.2 product
// predicates. It reads the historical per-file map directly from the
// predicate JSON and exposes per-file subjects for policy evaluation.
type LegacyDecoder struct {
	predicateType string
	products      map[string]attestation.Product
}

func newLegacyDecoder(predicateType string) *LegacyDecoder {
	return &LegacyDecoder{predicateType: predicateType}
}

// Name returns the registry name of this decoder, with a version suffix so
// the v0.3 producer wins selection for `--attestations product`.
func (a *LegacyDecoder) Name() string {
	switch a.predicateType {
	case LegacyV01Type:
		return legacyV01Name
	case LegacyV02Type:
		return legacyV02Name
	}
	return "product-legacy"
}

// Type returns the predicate URI this decoder was instantiated for.
func (a *LegacyDecoder) Type() string { return a.predicateType }

// RunType is the same as the v0.3 producer — required by the interface but
// not exercised at verify time.
func (a *LegacyDecoder) RunType() attestation.RunType { return attestation.ProductRunType }

// Schema returns a JSON schema matching the historical per-file map.
func (a *LegacyDecoder) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(map[string]attestation.Product{})
}

// Attest refuses to produce a new attestation. v0.1 and v0.2 are no longer
// emittable; use v0.3.
func (a *LegacyDecoder) Attest(_ *attestation.AttestationContext) error {
	return errLegacyDecodeOnly
}

// MarshalJSON emits the per-file map exactly as v0.1 / v0.2 did, so
// round-tripping a decoded attestation produces byte-equivalent output for
// re-verification.
func (a *LegacyDecoder) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.products)
}

// UnmarshalJSON decodes the historical predicate body into the per-file
// map. Both v0.1 and v0.2 used the same shape; only Statement.Subject
// differed at sign time.
func (a *LegacyDecoder) UnmarshalJSON(data []byte) error {
	prods := make(map[string]attestation.Product)
	if err := json.Unmarshal(data, &prods); err != nil {
		return fmt.Errorf("legacy product (%s): decode predicate: %w", a.predicateType, err)
	}
	a.products = prods
	return nil
}

// Subjects emits one entry per recorded product so the policy engine's
// subject-graph BFS can match historical attestations by per-file digest,
// regardless of whether the original Statement.Subject was per-file (v0.1)
// or a single tree root (v0.2). The subject name format follows v0.1's
// `file:<path>` convention.
func (a *LegacyDecoder) Subjects() map[string]cryptoutil.DigestSet {
	out := make(map[string]cryptoutil.DigestSet, len(a.products))
	for path, prod := range a.products {
		if prod.Digest == nil {
			continue
		}
		out["file:"+path] = prod.Digest
	}
	return out
}

// BackRefs deliberately returns empty. Per-file BackRefs on historical
// attestations are an explosion risk in the verify-time BFS (every legacy
// attestation that touched a common file like `.gitignore` would chain
// thousands of unrelated attestations together). Per-file lookups still
// work via Subjects (each subject is in the in-toto subject index); they
// just don't auto-expand the frontier.
func (a *LegacyDecoder) BackRefs() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{}
}

// Products exposes the decoded map for in-process consumers (link, slsa)
// that historically read product data via this interface. Required so
// existing Rego rules and link-attestor wiring continue to work against
// decoded legacy attestations.
func (a *LegacyDecoder) Products() map[string]attestation.Product {
	return a.products
}

