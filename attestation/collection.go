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
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/invopop/jsonschema"
)

const CollectionType = "https://aflock.ai/attestation-collection/v0.1"
const LegacyCollectionType = "https://witness.testifysec.com/attestation-collection/v0.1"

type Collection struct {
	Name         string                  `json:"name"`
	Attestations []CollectionAttestation `json:"attestations"`
	// RecordedBackRefs is the producer's declaration of this collection's
	// back-references, captured at collection build time from every attestor
	// implementing BackReffer (keys use the same <attestor-type>/<name>
	// format as the live aggregation). Serializing them makes the edge set
	// part of the signed payload, so consumers — the platform's supply-chain
	// graph and verifiers that decode unregistered plugin attestor types as
	// RawAttestation — recover the edges without typed attestor factories.
	// Nil on collections serialized before this field existed; BackRefs()
	// falls back to live aggregation for those.
	RecordedBackRefs map[string]cryptoutil.DigestSet `json:"backrefs,omitempty"`
}

type CollectionAttestation struct {
	Type        string    `json:"type"`
	Attestation Attestor  `json:"attestation"`
	StartTime   time.Time `json:"starttime"`
	EndTime     time.Time `json:"endtime"`
}

// RawAttestation holds attestation data as raw JSON for types that don't have
// a registered factory. This allows verification (Rego/AI policy evaluation)
// to work without importing specific attestor plugins.
type RawAttestation struct {
	typeName string
	data     json.RawMessage
}

// NewRawAttestation returns a RawAttestation with the given predicate type URI
// and raw JSON payload. This is the escape hatch used by callers (e.g. the
// external-attestations source path) that need to wrap a bare predicate when
// no typed factory is registered for the predicate type. Rego still sees the
// raw predicate JSON via MarshalJSON.
func NewRawAttestation(predicateType string, data json.RawMessage) *RawAttestation {
	return &RawAttestation{typeName: predicateType, data: data}
}

func (r *RawAttestation) Name() string     { return r.typeName }
func (r *RawAttestation) Type() string     { return r.typeName }
func (r *RawAttestation) RunType() RunType { return "" }
func (r *RawAttestation) Attest(*AttestationContext) error {
	return fmt.Errorf("raw attestation cannot attest")
}
func (r *RawAttestation) Schema() *jsonschema.Schema   { return nil }
func (r *RawAttestation) MarshalJSON() ([]byte, error) { return r.data, nil }

// A consumer without plugin factories still verifies modern inventory bindings.
// The embedded raw marshaler preserves the parent's signed representation.
type rawInventoryAttestation struct {
	*RawAttestation
	root    string
	size    uint64
	ref     *fileinventory.Reference
	entries []fileinventory.Entry
}

func (r *rawInventoryAttestation) InventoryReference() *fileinventory.Reference { return r.ref }
func (r *rawInventoryAttestation) HydrateInventory(body []byte) error {
	entries, err := fileinventory.Verify(r.ref, body, r.ref.Kind, r.root, r.size)
	if err != nil {
		return err
	}
	r.entries = entries
	return nil
}
func (r *rawInventoryAttestation) Materials() map[string]cryptoutil.DigestSet {
	out := map[string]cryptoutil.DigestSet{}
	if r.ref.Kind == string(MaterialRunType) {
		for _, e := range r.entries {
			out[e.Path] = cryptoutil.DigestSet{{Hash: crypto.SHA256}: e.FileDigest}
		}
	}
	return out
}
func (r *rawInventoryAttestation) Products() map[string]Product {
	out := map[string]Product{}
	if r.ref.Kind == string(ProductRunType) {
		for _, e := range r.entries {
			out[e.Path] = Product{Digest: cryptoutil.DigestSet{{Hash: crypto.SHA256}: e.FileDigest}, MimeType: e.MIMEType}
		}
	}
	return out
}

func withRawInventory(a Attestor) (Attestor, error) {
	r, ok := a.(*RawAttestation)
	if !ok {
		return a, nil
	}
	kind := ""
	switch ResolveLegacyType(r.Type()) {
	case "https://aflock.ai/attestations/material/v0.3":
		kind = string(MaterialRunType)
	case "https://aflock.ai/attestations/product/v0.3":
		kind = string(ProductRunType)
	default:
		return a, nil
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(r.data, &keys); err != nil {
		// This is only a probe for modern predicates; leave legacy data raw.
		keys = nil
	}
	modern := false
	for key := range keys {
		modern = modern || strings.EqualFold(key, "inventory")
	}
	if !modern {
		return a, nil
	}
	var p struct {
		MerkleRoot string                   `json:"merkleRoot"`
		TreeSize   uint64                   `json:"treeSize"`
		Inventory  *fileinventory.Reference `json:"inventory"`
	}
	if err := fileinventory.DecodeParent(r.data, kind, &p); err != nil {
		return nil, err
	}
	return &rawInventoryAttestation{RawAttestation: r, root: p.MerkleRoot, size: p.TreeSize, ref: p.Inventory}, nil
}

func NewCollection(name string, attestors []CompletedAttestor) Collection {
	collection := Collection{
		Name:         name,
		Attestations: make([]CollectionAttestation, 0),
	}

	for _, completed := range attestors {
		collection.Attestations = append(collection.Attestations, NewCollectionAttestation(completed))
	}

	if backRefs := collection.aggregateBackRefs(); len(backRefs) > 0 {
		collection.RecordedBackRefs = backRefs
	}

	return collection
}

func NewCollectionAttestation(completed CompletedAttestor) CollectionAttestation {
	return CollectionAttestation{
		Type:        completed.Attestor.Type(),
		Attestation: completed.Attestor,
		StartTime:   completed.StartTime,
		EndTime:     completed.EndTime,
	}
}

func (c *CollectionAttestation) UnmarshalJSON(data []byte) error {
	proposed := struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
		StartTime   time.Time       `json:"starttime"`
		EndTime     time.Time       `json:"endtime"`
	}{}

	if err := json.Unmarshal(data, &proposed); err != nil {
		return err
	}

	// Resolve legacy URIs before factory lookup
	resolvedType := ResolveLegacyType(proposed.Type)

	factory, ok := FactoryByType(resolvedType)
	if ok {
		newAttest := factory()
		if err := json.Unmarshal(proposed.Attestation, &newAttest); err != nil {
			return err
		}
		c.Attestation = newAttest
	} else {
		// No factory registered — preserve raw JSON for policy evaluation
		c.Attestation = &RawAttestation{
			typeName: proposed.Type,
			data:     proposed.Attestation,
		}
		var err error
		c.Attestation, err = withRawInventory(c.Attestation)
		if err != nil {
			return err
		}
	}

	c.Type = proposed.Type
	c.StartTime = proposed.StartTime
	c.EndTime = proposed.EndTime
	return nil
}

func (c *Collection) Subjects() map[string]cryptoutil.DigestSet {
	allSubjects := make(map[string]cryptoutil.DigestSet)
	for _, collectionAttestation := range c.Attestations {
		if subjecter, ok := collectionAttestation.Attestation.(Subjecter); ok {
			// Namespace by the resolved/canonical type so a legacy URI and its
			// aflock.ai equivalent alias to the same subject key rather than
			// occupying two distinct namespaces.
			resolvedType := ResolveLegacyType(collectionAttestation.Type)
			subjects := subjecter.Subjects()
			for subject, digest := range subjects {
				allSubjects[fmt.Sprintf("%v/%v", resolvedType, subject)] = digest
			}
		}
	}

	return allSubjects
}

// Artifacts returns a map of digestsets that describe the union of the materials and products from the collection.
// This essentially gives a view of end state of the files after all the attestors in the collection ran.
func (c *Collection) Artifacts() map[string]cryptoutil.DigestSet {
	allMaterials := make(map[string]cryptoutil.DigestSet)
	allProducts := make(map[string]cryptoutil.DigestSet)
	for _, attestation := range c.Attestations {
		if materialer, ok := attestation.Attestation.(Materialer); ok {
			for k, v := range materialer.Materials() {
				allMaterials[k] = v
			}
		}

		if producer, ok := attestation.Attestation.(Producer); ok {
			for k, v := range producer.Products() {
				allProducts[k] = v.Digest
			}
		}
	}

	for k, v := range allProducts {
		allMaterials[k] = v
	}

	return allMaterials
}

func (c *Collection) Materials() map[string]cryptoutil.DigestSet {
	materials := make(map[string]cryptoutil.DigestSet)
	for _, attestation := range c.Attestations {
		if materialer, ok := attestation.Attestation.(Materialer); ok {
			for k, v := range materialer.Materials() {
				materials[k] = v
			}
		}
	}

	return materials
}

// InlineLeafVerifier is implemented by attestors (product, material v0.3) that
// embed their per-file Merkle leaves in the signed predicate by default. The
// engine calls VerifyInlineLeaves before trusting any Materials()/Products()
// rehydrated from those inline leaves for sidecar-free artifactsFrom chain
// checks: the envelope signature covers the leaves, but this guards against a
// signer (or a bug) committing a Merkle root that doesn't match the leaves it
// shipped, which would otherwise let chain comparison run on attacker-chosen
// data. Implementations MUST return nil when they carry no inline leaves
// (nothing to trust; the sidecar/legacy path governs instead).
type InlineLeafVerifier interface {
	VerifyInlineLeaves() error
}

// VerifyInlineLeaves runs VerifyInlineLeaves on every attestation in the
// collection that embeds inline Merkle leaves, returning the first failure.
// It returns nil when no attestation carries inline leaves (e.g. legacy
// sidecar-only collections) — absence of inline data is not an error here; the
// engine's strict/sidecar gate decides whether that absence is acceptable.
func (c *Collection) VerifyInlineLeaves() error {
	for _, attestation := range c.Attestations {
		if verifier, ok := attestation.Attestation.(InlineLeafVerifier); ok {
			if err := verifier.VerifyInlineLeaves(); err != nil {
				return fmt.Errorf("%s: %w", attestation.Type, err)
			}
		}
	}
	return nil
}

// InlineLeafReporter is implemented by attestors that can report whether they
// committed their per-file leaves inline (even an empty set). See
// Collection.HasInlineMaterials.
type InlineLeafReporter interface {
	HasInlineLeaves() bool
}

// ManifestHydrator is implemented by attestors whose per-file leaves may live
// in a DETACHED manifest object rather than inline in the signed predicate.
//
// The contract has three parts and the separation between them is the point:
//
//   - ManifestPending reports, FROM THE SIGNED PREDICATE ALONE, whether a
//     resolution should even be attempted. No network access. This is what
//     keeps "the producer chose not to publish" from ever being confused with
//     "the producer published and we could not read it" — a store outage
//     cannot move an attestation between those two states.
//   - ManifestDigest names the content to look for. A digest, not a URL.
//   - HydrateFromManifest binds candidate bytes and populates the leaves only
//     after the digest matches AND the tree rebuilds to the signed root. It
//     returns distinct errors for "unreadable" and "mismatch" so a re-signed
//     root is never filed as a missing object.
type ManifestHydrator interface {
	ManifestPending() bool
	ManifestDigest() string
	HydrateFromManifest(predicate []byte) error
}

var ErrInventoryNotResolved = errors.New("required file inventory is unavailable")

// ResolveInventories verifies available modern inventories before exposing file
// maps. requiredKind is material, product, all, or empty (optional). Missing
// optional data is not an empty-set claim; consumers of file maps must require
// the relevant kind. Legacy HydrateManifests behavior is deliberately separate.
func (c *Collection) ResolveInventories(lookup func(string) ([]byte, bool), requiredKind string) error {
	if requiredKind != "" && requiredKind != string(MaterialRunType) && requiredKind != string(ProductRunType) && requiredKind != "all" {
		return fmt.Errorf("invalid required inventory kind %q", requiredKind)
	}
	for i := range c.Attestations {
		if err := c.Attestations[i].resolveInventory(lookup, requiredKind); err != nil {
			return err
		}
	}
	return nil
}

func (a *CollectionAttestation) resolveInventory(lookup func(string) ([]byte, bool), requiredKind string) error {
	resolved, err := withRawInventory(a.Attestation)
	if err != nil {
		return fmt.Errorf("%s inventory: %w", a.Type, err)
	}
	a.Attestation = resolved
	reporter, ok := a.Attestation.(InventoryReporter)
	if !ok || reporter.InventoryReference() == nil {
		return nil
	}
	ref := reporter.InventoryReference()
	if err := ref.Validate(ref.Kind); err != nil {
		return fmt.Errorf("%s inventory: %w", a.Type, err)
	}
	required := requiredKind == "all" || requiredKind == ref.Kind
	if requiredKind != "" && !required {
		return nil
	}
	if ref.State == fileinventory.StateOmitted {
		if required {
			return fmt.Errorf("%s: %w: %s details were omitted", a.Type, ErrInventoryNotResolved, ref.Kind)
		}
		return nil
	}
	var body []byte
	var found bool
	if lookup != nil {
		body, found = lookup(ref.Digest)
	}
	if !found {
		if required {
			return fmt.Errorf("%s: %w: %s", a.Type, ErrInventoryNotResolved, ref.Digest)
		}
		return nil
	}
	hydrator, ok := a.Attestation.(InventoryHydrator)
	if !ok {
		return fmt.Errorf("%s: cannot verify referenced file inventory", a.Type)
	}
	if err := hydrator.HydrateInventory(body); err != nil {
		return fmt.Errorf("%s inventory: %w", a.Type, err)
	}
	return nil
}

// HydrateManifests resolves any detached leaf manifests this collection's
// attestors reference, using lookup to supply candidate predicate bytes by
// sha256.
//
// lookup returns (bytes, true) when it holds a candidate. Returning false is
// "not found", which the hydrator turns into a distinct unreadable error — it
// is NOT silently treated as "there was nothing to fetch".
//
// Attestors with nothing pending are left completely untouched, so this is a
// no-op for every inline (today's default) and legacy attestation.
func (c *Collection) HydrateManifests(lookup func(sha256 string) ([]byte, bool)) error {
	for _, attestation := range c.Attestations {
		hydrator, ok := attestation.Attestation.(ManifestHydrator)
		if !ok || !hydrator.ManifestPending() {
			continue
		}
		digest := hydrator.ManifestDigest()
		body, found := lookup(digest)
		if !found {
			return fmt.Errorf("%s: %w: no manifest with digest %s among the loaded envelopes", attestation.Type, ErrManifestNotResolved, digest)
		}
		if err := hydrator.HydrateFromManifest(body); err != nil {
			return fmt.Errorf("%s: %w", attestation.Type, err)
		}
	}
	return nil
}

// ErrManifestNotResolved is returned by HydrateManifests when a predicate
// states its manifest was published but no candidate with that digest is among
// the envelopes the verifier holds.
//
// Deliberately NOT the same as "the producer did not publish": that is a
// benign, signed statement, whereas this is a claim the verifier could not
// stand up, and the two must remain distinguishable in a verdict.
var ErrManifestNotResolved = errors.New("referenced material manifest was not found")

// ManifestWithholder is implemented by attestors that can state, under
// signature, that they deliberately did not publish their leaves.
type ManifestWithholder interface {
	ManifestWithheld() bool
}

// MaterialManifestWithheld reports whether the collection's material attestor
// signed a statement that it did not publish its leaves.
//
// This exists purely so a leaf-less chain failure can say WHICH kind of
// leaf-less it is. "The producer opted out, re-run it with --material-manifest"
// is an actionable, expected condition; "this attestation predates the feature
// or had its leaves stripped" is not the same thing and gets its own message.
// Both still fail closed — the distinction is in the diagnosis, never in the
// verdict.
func (c *Collection) MaterialManifestWithheld() bool {
	for _, attestation := range c.Attestations {
		if _, isMaterialer := attestation.Attestation.(Materialer); !isMaterialer {
			continue
		}
		if w, ok := attestation.Attestation.(ManifestWithholder); ok && w.ManifestWithheld() {
			return true
		}
	}
	return false
}

// ManifestsPending reports whether any attestor in the collection is waiting on
// a detached manifest. Callers use it to decide whether to spend a lookup at
// all — an entirely inline collection (today's default) answers false and skips
// the resolution path completely.
func (c *Collection) ManifestsPending() bool {
	for _, attestation := range c.Attestations {
		if hydrator, ok := attestation.Attestation.(ManifestHydrator); ok && hydrator.ManifestPending() {
			return true
		}
	}
	return false
}

// HasInlineMaterials reports whether the collection's MATERIAL set is committed
// inline and is therefore authoritative — including an authoritative empty set
// (a step that provably consumed nothing, e.g. a build in an isolated
// workingdir). The engine uses this so strict-chain mode can accept a verified
// empty material set without a sidecar, while still failing closed on a
// leaf-less attestation whose empty Materials() is merely unknown. Only the
// material attestor counts (it implements Materialer); a product attestor's
// inline leaves say nothing about consumed materials.
func (c *Collection) HasInlineMaterials() bool {
	for _, attestation := range c.Attestations {
		if _, isMaterialer := attestation.Attestation.(Materialer); !isMaterialer {
			continue
		}
		if reporter, ok := attestation.Attestation.(InlineLeafReporter); ok && reporter.HasInlineLeaves() {
			return true
		}
	}
	return false
}

// BackRefs returns the collection's back-references. When the collection
// carries recorded backrefs (signed wire format), those are authoritative —
// this is what lets RawAttestation-decoded plugin attestors keep their edges.
// Collections from before the field existed fall back to live aggregation
// over typed attestors.
func (c *Collection) BackRefs() map[string]cryptoutil.DigestSet {
	if c.RecordedBackRefs != nil {
		return c.RecordedBackRefs
	}

	return c.aggregateBackRefs()
}

// aggregateBackRefs computes back-references from every attestor in the
// collection that implements BackReffer, namespacing keys by attestor type.
func (c *Collection) aggregateBackRefs() map[string]cryptoutil.DigestSet {
	backRefs := make(map[string]cryptoutil.DigestSet)
	for _, attestation := range c.Attestations {
		if backReffer, ok := attestation.Attestation.(BackReffer); ok {
			for backRef, digest := range backReffer.BackRefs() {
				backRefs[fmt.Sprintf("%v/%v", attestation.Type, backRef)] = digest
			}
		}
	}

	return backRefs
}
