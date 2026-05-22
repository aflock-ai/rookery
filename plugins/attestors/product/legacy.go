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

// Verify-only decoder for the historical v0.1 product predicate shape. It
// exists so cilock verify can still consume pre-cutover attestations. v0.2
// is NOT supported — that wire format had a single-subject hash-chain root
// that was deprecated in favour of v0.3's Merkle tree. We register a v0.2
// stub that errors on decode so operators encountering a v0.2 envelope get
// a clear "unsupported version" message rather than a confusing
// "predicate type not registered" lookup miss.
//
// What the decoder does:
//
//  - UnmarshalJSON: parses the historical per-file map (path -> Product)
//    that v0.1 published as the predicate body.
//  - Subjects(): emits one `file:<path>` subject per product so the policy
//    engine's BFS can match historical attestations by file digest.
//  - BackRefs(): returns empty. Per-file BackRefs on historical
//    attestations are an explosion risk (every legacy attestation that
//    touched `.gitignore` would chain across the corpus). Verifiers walk
//    the Statement.Subject array directly for per-file lookups.
//  - Attest(): refuses with errLegacyDecodeOnly so an accidental producer
//    path fails loudly. Only the v0.3 Attestor produces.
//
// `cilock run --attestations product` always selects the v0.3 producer
// because the legacy decoder registers under a different name
// ("product-v0.1").

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	// legacyV01Name is the registry name for the verify-only v0.1
	// decoder. It is deliberately different from Name so `cilock run
	// --attestations product` selects v0.3, never the decoder.
	legacyV01Name = "product-v0.1"

	// LegacyV01Type is the v0.1 predicate URI we accept for verification.
	LegacyV01Type = "https://aflock.ai/attestations/product/v0.1"

	// unsupportedV02Name is the registry name for the v0.2 error stub.
	unsupportedV02Name = "product-v0.2"

	// UnsupportedV02Type is the v0.2 predicate URI. We register a stub
	// that always errors so encountering a v0.2 envelope produces a
	// clear "unsupported" diagnostic instead of a registry miss.
	UnsupportedV02Type = "https://aflock.ai/attestations/product/v0.2"
)

// errLegacyDecodeOnly is returned by Attest() on the v0.1 decoder so an
// accidental producer-mode invocation fails clearly.
var errLegacyDecodeOnly = errors.New("legacy product attestor is verify-only: use v0.3 to produce new attestations")

// ErrV02Unsupported is returned by every method of the v0.2 stub. v0.2
// envelopes must be re-issued under v0.3; no in-place decode path exists.
var ErrV02Unsupported = errors.New("product v0.2 predicate format is not supported by this cilock build; v0.2 attestations must be re-issued under v0.3 (https://aflock.ai/attestations/product/v0.3)")

func init() {
	// Register the v0.1 decoder alongside the v0.3 producer.
	// RegisterAttestation is name+type keyed, so the v0.3 producer
	// (registered in product.go) and this decoder coexist without
	// collision.
	attestation.RegisterAttestation(
		legacyV01Name,
		LegacyV01Type,
		attestation.ProductRunType,
		func() attestation.Attestor { return newLegacyDecoder() },
	)
	// Register the v0.2 error stub. Any code path that resolves the v0.2
	// predicate URI now gets a typed *V02Unsupported back whose every
	// method returns ErrV02Unsupported, instead of a "predicate type not
	// registered" miss in FactoryByType.
	attestation.RegisterAttestation(
		unsupportedV02Name,
		UnsupportedV02Type,
		attestation.ProductRunType,
		func() attestation.Attestor { return &V02Unsupported{} },
	)
}

// V02Unsupported is a registry stub for the historical v0.2 product
// predicate URI. Every interface method returns ErrV02Unsupported so
// operators encountering a v0.2 envelope get a clear error path. We
// deliberately do NOT carry a decoder for v0.2 — its hash-chain root
// shape was superseded by v0.3's Merkle tree and is not maintainable.
type V02Unsupported struct{}

func (*V02Unsupported) Name() string                                   { return unsupportedV02Name }
func (*V02Unsupported) Type() string                                   { return UnsupportedV02Type }
func (*V02Unsupported) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (*V02Unsupported) Schema() *jsonschema.Schema                     { return &jsonschema.Schema{} }
func (*V02Unsupported) Attest(_ *attestation.AttestationContext) error { return ErrV02Unsupported }
func (*V02Unsupported) MarshalJSON() ([]byte, error)                   { return nil, ErrV02Unsupported }
func (*V02Unsupported) UnmarshalJSON(_ []byte) error                   { return ErrV02Unsupported }
func (*V02Unsupported) Subjects() map[string]cryptoutil.DigestSet      { return nil }
func (*V02Unsupported) BackRefs() map[string]cryptoutil.DigestSet      { return nil }
func (*V02Unsupported) Products() map[string]attestation.Product       { return nil }

// LegacyDecoder is the verify-only decoder for v0.1 product predicates.
// It reads the historical per-file map directly from the predicate JSON
// and exposes per-file subjects for policy evaluation.
type LegacyDecoder struct {
	products map[string]attestation.Product
}

func newLegacyDecoder() *LegacyDecoder { return &LegacyDecoder{} }

// Name returns the registry name of this decoder, with a version suffix
// so the v0.3 producer wins selection for `--attestations product`.
func (a *LegacyDecoder) Name() string { return legacyV01Name }

// Type returns the v0.1 predicate URI.
func (a *LegacyDecoder) Type() string { return LegacyV01Type }

// RunType is the same as the v0.3 producer — required by the interface
// but not exercised at verify time.
func (a *LegacyDecoder) RunType() attestation.RunType { return attestation.ProductRunType }

// Schema returns a JSON schema matching the historical per-file map.
func (a *LegacyDecoder) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(map[string]attestation.Product{})
}

// Attest refuses to produce a new attestation. v0.1 is no longer
// emittable; use v0.3.
func (a *LegacyDecoder) Attest(_ *attestation.AttestationContext) error {
	return errLegacyDecodeOnly
}

// MarshalJSON emits the per-file map exactly as v0.1 did, so
// round-tripping a decoded attestation produces byte-equivalent output
// for re-verification.
func (a *LegacyDecoder) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.products)
}

// UnmarshalJSON decodes the historical predicate body into the per-file
// map.
func (a *LegacyDecoder) UnmarshalJSON(data []byte) error {
	prods := make(map[string]attestation.Product)
	if err := json.Unmarshal(data, &prods); err != nil {
		return fmt.Errorf("legacy product (v0.1): decode predicate: %w", err)
	}
	a.products = prods
	return nil
}

// Subjects emits one entry per recorded product so the policy engine's
// subject-graph BFS can match historical attestations by per-file
// digest. The subject name format follows v0.1's `file:<path>`
// convention.
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
// attestations are an explosion risk in the verify-time BFS (every
// legacy attestation that touched a common file like `.gitignore` would
// chain thousands of unrelated attestations together). Per-file lookups
// still work via Subjects (each subject is in the in-toto subject
// index); they just don't auto-expand the frontier.
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
