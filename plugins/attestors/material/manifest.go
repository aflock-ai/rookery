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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/log"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/invopop/jsonschema"
)

// The detached material manifest.
//
// The material predicate's claim is the Merkle ROOT; the per-file leaves are
// the proof material one specific consumer (the artifactsFrom chain) needs.
// On this repository the leaves are 99.7% of a push-tests envelope while the
// only policy evaluated on a push never reads them. This file provides the
// second home for those leaves: a companion DSSE envelope, referenced from the
// signed material predicate by CONTENT DIGEST rather than by URL, so a manifest
// that arrives by any path — the local companion file, an Archivista subject
// walk, a bundle handed to --attestations — can be bound to the exact envelope
// that named it.
//
// NOTE ON THE CURRENT DEFAULT: leaves are still inlined by default. This change
// adds the manifest subsystem and the opt-in flag only; flipping the default is
// a separate change, deliberately sequenced after the chain-consuming producers
// have opted in.

const (
	// ManifestType is the predicate type of the companion manifest envelope.
	//
	// This is a new attestor FAMILY ("material-manifest"), not a new version of
	// the "material" family. That distinction is load-bearing: judge-api's
	// drift guard (TestTrackedFamiliesHaveNoUnknownVersions) fails when a
	// TRACKED family gains an unknown version, and it derives the family by
	// splitting at the last "/". "material-manifest/v0.1" therefore parses as
	// family "material-manifest", which no platform inventory tracks, and is
	// ignored rather than failing. Bumping "material" to v0.4 would instead
	// have broken every exact-URI consumer — which is why the material
	// predicate stays at v0.3 and gains only additive fields.
	ManifestType = "https://aflock.ai/attestations/material-manifest/v0.1"

	// ManifestName is the registry/companion name for the manifest attestor.
	//
	// The workflow names a companion result "<parent>/<companion>", and
	// `cilock run` turns that into the on-disk file "<outfile>-material-manifest.json"
	// (its "/"-to-"-" sanitizer). Keeping this "manifest" is what produces that
	// filename with no special-casing in the CLI's write loop.
	ManifestName = "manifest"

	// ManifestSource is the Sidecar.Source discriminator. Purely informational
	// inside the sidecar shape, but pinned here so a manifest built from a
	// product tree cannot masquerade as a material manifest.
	ManifestSource = "material"
)

var (
	// ErrMaterialManifestNotPublished is state (a): the signed predicate says
	// manifestUploaded:false. The producer made a deliberate, SIGNED statement
	// that it did not publish the leaves. This is decided from the predicate
	// alone — no fetch is attempted — so a store outage can never turn this
	// into ErrMaterialManifestUnreadable, nor the reverse.
	ErrMaterialManifestNotPublished = errors.New(
		"material: the producer did not publish its leaf manifest (manifestUploaded=false); " +
			"re-run the producing step with `cilock run --material-manifest` to publish it")

	// ErrMaterialManifestUnreadable is state (c), sub-cause "could not read":
	// the predicate says the manifest was uploaded, but it is not among the
	// envelopes the verifier holds, or its bytes do not parse.
	//
	// This is NEVER downgraded to ErrMaterialManifestNotPublished. "The producer
	// said it uploaded and we cannot read it" is a finding, not a benign
	// absence.
	ErrMaterialManifestUnreadable = errors.New(
		"material: the leaf manifest this predicate references could not be read")

	// ErrMaterialManifestMismatch is state (c), sub-cause "mismatch": a manifest
	// was found but it does not belong to this predicate — either its bytes do
	// not hash to the referenced digest, or its leaves do not rebuild the signed
	// merkleRoot.
	//
	// Kept distinct from ErrMaterialManifestUnreadable on purpose: a mismatch
	// means someone signed a root that does not match the leaves, and filing
	// that as a network blip would lose the only signal that it happened.
	ErrMaterialManifestMismatch = errors.New(
		"material: the leaf manifest does not match the signed commitment")

	// ErrMaterialManifestTooLarge: the manifest's compact encoding exceeds
	// inclusionproof.MaxManifestBytes, the ONE limit both sides honour. The
	// producer returns it instead of publishing (so `cilock run
	// --material-manifest` fails loudly with the limit in the message rather
	// than minting a manifest every verifier would refuse), and a consumer
	// wraps it — together with ErrMaterialManifestMismatch, since state (c)
	// still applies — when handed a body over the same limit.
	ErrMaterialManifestTooLarge = errors.New(
		"material: the leaf manifest exceeds inclusionproof.MaxManifestBytes")
)

// manifestByteCeiling is inclusionproof.MaxManifestBytes, held in a variable
// ONLY so the package tests can exercise the real producer and consumer paths
// at a small ceiling instead of allocating half a gigabyte. Production code
// never assigns it; TestManifestByteLimitIsTheSharedConstant pins its value.
var manifestByteCeiling = inclusionproof.MaxManifestBytes

// checkManifestSize is the producer-side half of the shared limit: n is the
// compact encoded size of a manifest about to be published.
func checkManifestSize(n int) error {
	if n > manifestByteCeiling {
		return fmt.Errorf("%w: the manifest encodes to %d bytes but the limit shared by producer and consumer, inclusionproof.MaxManifestBytes, is %d; "+
			"a consumer would refuse it before reading it, so it is not published — reduce the material set (fewer or shorter paths) or run without --material-manifest",
			ErrMaterialManifestTooLarge, n, manifestByteCeiling)
	}
	return nil
}

// ManifestRef is the reference the material predicate carries to its detached
// leaf manifest. The reference is a DIGEST, never a URL: Archivista may serve
// the object from any path, and the envelope names the CONTENT.
//
// It is emitted UNCONDITIONALLY — including when manifestUploaded is false.
// That costs ~120 bytes and is what lets a manifest that arrives later, by any
// route, be bound to this exact envelope.
type ManifestRef struct {
	// Digest is the content digest of the manifest PREDICATE bytes, keyed by
	// algorithm ("sha256"). Not the digest of the enclosing DSSE envelope or
	// statement — those are not stable across signers or timestamps.
	Digest map[string]string `json:"digest"`

	// Bytes is the length of the manifest predicate's compact JSON encoding.
	Bytes int `json:"bytes"`
}

// SHA256 returns the sha256 entry of the reference, or "" when absent.
func (m *ManifestRef) SHA256() string {
	if m == nil {
		return ""
	}
	return m.Digest["sha256"]
}

// ManifestAttestor is the companion attestation carrying the detached leaves.
//
// Its predicate is the existing inclusionproof.Sidecar shape VERBATIM, which is
// why no new schema and no Archivista change are needed: ReadSidecar already
// shape-validates it (including len(leaves) == treeSize) and Sidecar.Reconstruct
// already rebuilds and re-derives the root. Reusing the shape also delivers the
// per-leaf shrink for free — a SidecarLeaf is {path, fileDigest} with no
// leafHash, because the leaf hash is derivable from those two.
type ManifestAttestor struct {
	sidecar inclusionproof.Sidecar
}

// Compile-time interface checks.
var (
	_ attestation.Attestor  = &ManifestAttestor{}
	_ attestation.Subjecter = &ManifestAttestor{}
)

// NewManifest builds a manifest attestor over an already-validated sidecar.
func NewManifest(s inclusionproof.Sidecar) *ManifestAttestor {
	return &ManifestAttestor{sidecar: s}
}

func (m *ManifestAttestor) Name() string                 { return ManifestName }
func (m *ManifestAttestor) Type() string                 { return ManifestType }
func (m *ManifestAttestor) RunType() attestation.RunType { return RunType }

// Attest refuses. The manifest is DERIVED from the material attestor's
// completed walk, never collected independently; it is handed to the workflow
// through Companions(). Registering a producer that could be selected with
// `-a material-manifest` would let a caller request an empty manifest with no
// tree behind it.
func (m *ManifestAttestor) Attest(_ *attestation.AttestationContext) error {
	return fmt.Errorf("material manifest is a companion of the %q attestor and cannot be attested directly", Name)
}

func (m *ManifestAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&inclusionproof.Sidecar{})
}

// Sidecar returns the carried sidecar.
func (m *ManifestAttestor) Sidecar() inclusionproof.Sidecar { return m.sidecar }

// Subjects returns the manifest's OWN subject only: the tree root it carries.
//
// It deliberately does NOT inherit the collection's commit/author subjects the
// way exported sidecars do. Keyed by the root, the manifest is reachable from
// the collection by one subject-graph hop, but it never appears in a
// commit-keyed lookup — so it cannot consume one of the small number of
// envelope-examination slots Pushgate spends per sha.
func (m *ManifestAttestor) Subjects() map[string]cryptoutil.DigestSet {
	if m.sidecar.MerkleRoot == "" {
		return map[string]cryptoutil.DigestSet{}
	}
	return map[string]cryptoutil.DigestSet{
		TreeSubjectName: {
			cryptoutil.DigestValue{Hash: cryptoSha256}: m.sidecar.MerkleRoot,
		},
	}
}

func (m *ManifestAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.sidecar)
}

func (m *ManifestAttestor) UnmarshalJSON(data []byte) error {
	s, err := inclusionproof.ReadSidecar(bytes.NewReader(data))
	if err != nil {
		return err
	}
	m.sidecar = s
	return nil
}

// manifestPredicateBytes returns the canonical byte encoding of a manifest
// predicate together with its sha256, both of which the material predicate's
// ManifestRef commits to.
//
// The encoding is COMPACT JSON. encoding/json compacts a MarshalJSON result
// when embedding it, so the bytes that end up inside the signed statement equal
// the bytes hashed here. A consumer hashes json.Compact of the statement's raw
// predicate for the same reason — to be safe against a pretty-printing
// intermediary that re-indented the document in transit.
func manifestPredicateBytes(s inclusionproof.Sidecar) ([]byte, string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, "", fmt.Errorf("material manifest: encode: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, "", fmt.Errorf("material manifest: compact: %w", err)
	}
	b := compact.Bytes()
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

// buildManifestSidecar rebuilds the canonical sidecar from the attestor's
// in-memory leaves. It routes through the SAME inclusionproof.BuildSidecar the
// inline-leaf verifier uses, so the manifest's root is computed by the
// identical code path that the signed merkleRoot is checked against — the two
// cannot drift.
func (a *Attestor) buildManifestSidecar() (inclusionproof.Sidecar, error) {
	digests := make(map[string]string, len(a.leaves))
	for _, lf := range a.leaves {
		digests[lf.Path] = lf.FileDigest
	}
	if len(digests) != len(a.leaves) {
		return inclusionproof.Sidecar{}, fmt.Errorf("material manifest: leaves contain duplicate paths (%d leaves, %d distinct paths)", len(a.leaves), len(digests))
	}
	side, err := inclusionproof.BuildSidecar(ManifestSource, digests)
	if err != nil {
		return inclusionproof.Sidecar{}, fmt.Errorf("material manifest: build: %w", err)
	}
	if side.MerkleRoot != a.MerkleRoot {
		// Refuse to publish a manifest that does not rebuild the root we are
		// about to sign. Emitting one would create exactly the dangling,
		// mismatching reference the consumer states exist to detect.
		return inclusionproof.Sidecar{}, fmt.Errorf("material manifest: leaves rebuild root %s but the attestor committed %s", side.MerkleRoot, a.MerkleRoot)
	}
	return side, nil
}

// WithManifest opts the producer in to publishing its leaves as a detached
// manifest. Default OFF, per the ruling that a user must opt IN to uploading
// additional data.
//
// The flag governs only what a RUNNING attestor emits. It does not change the
// claim: the tree is always computed and the root is always signed either way.
func WithManifest(enabled bool) Option {
	return func(a *Attestor) { a.emitManifest = enabled }
}

// finishManifestRef stamps the two additive predicate fields once the tree is
// final. Called from every path that finishes a tree (both Attest branches and
// Finalize), so a new-shape producer ALWAYS emits manifestUploaded and
// manifest.digest — including when the answer is "false".
//
// That unconditional emission is the point: a signed `false` is a different
// statement from an absent key, and only the former lets a verifier tell "the
// producer chose not to publish" from "this predicate predates the feature, or
// the field was stripped" without a network round trip.
func (a *Attestor) finishManifestRef() error {
	a.Inventory, a.inventoryBytes = nil, nil
	if a.compactInventory && a.TreeSize != 0 {
		a.Manifest, a.ManifestUploaded = nil, nil
		return a.finishInventory()
	}
	side, err := a.buildManifestSidecar()
	if err != nil {
		return err
	}
	body, digest, err := manifestPredicateBytes(side)
	if err != nil {
		return err
	}
	if a.emitManifest {
		// The producer honours the SAME byte limit the consumer applies
		// (inclusionproof.MaxManifestBytes). Refusing here — before anything is
		// signed — is what keeps "valid but unreadable by every verifier" from
		// being a state a manifest can be in. A producer that is NOT
		// publishing is not size-checked: the digest reference it emits is a
		// binding, not a publication.
		if err := checkManifestSize(len(body)); err != nil {
			return err
		}
	}
	uploaded := a.emitManifest
	a.ManifestUploaded = &uploaded
	a.Manifest = &ManifestRef{
		Digest: map[string]string{"sha256": digest},
		Bytes:  len(body),
	}
	return nil
}

// Companions implements attestation.CompanionExporter.
//
// It returns the manifest envelope when — and only when — the producer opted
// in. Returning nil is the default and leaves the workflow untouched.
func (a *Attestor) Companions() []attestation.Attestor {
	if a.Inventory != nil {
		if a.Inventory.State != "detached" || len(a.inventoryBytes) == 0 {
			return nil
		}
		return []attestation.Attestor{attestation.NewInventoryCompanion("material", a.inventoryBytes)}
	}
	if !a.emitManifest {
		return nil
	}
	side, err := a.buildManifestSidecar()
	if err != nil {
		// The material attestor already succeeded and its root is signed; a
		// manifest that cannot be built is a companion failure, not a reason to
		// destroy the collection. The predicate still says manifestUploaded is
		// whatever the producer intended, so a consumer that cannot then resolve
		// it reports state (c) — "could not read" — which is the honest answer.
		//
		// But it must NOT be silent here: the operator asked for a manifest and
		// is not getting one, and the only other signal is a chain failure at
		// verify time, somewhere else, later, for someone else.
		log.Warnf("--material-manifest: could not build the leaf manifest, so none will be published "+
			"(the signed predicate still references it, and a consumer will report it as unreadable): %v", err)
		return nil
	}
	// finishManifestRef already refused an oversized tree before anything was
	// signed, so this cannot fire on a normal run; it is the guard for a caller
	// that reaches Companions() by another route. Never publish above the
	// shared limit.
	if body, _, err := manifestPredicateBytes(side); err != nil {
		log.Warnf("--material-manifest: could not encode the leaf manifest, so none will be published: %v", err)
		return nil
	} else if err := checkManifestSize(len(body)); err != nil {
		log.Warnf("--material-manifest: %v", err)
		return nil
	}
	return []attestation.Attestor{NewManifest(side)}
}

// CompanionTypes implements attestation.CompanionTyper: the predicate types
// Companions() may emit, answerable from a fresh instance with no run behind
// it. This is what lets the attestor catalog describe the companion envelope
// (Companions() itself answers only after Attest, and only when opted in).
func (a *Attestor) CompanionTypes() []string {
	return []string{ManifestType, fileinventory.Type}
}

// HydrateFromManifest binds a detached manifest to this predicate and, only on
// success, populates the leaves and the Materials() map.
//
// The order of checks is the whole point of the function:
//
//  1. the manifest bytes must hash to the digest the SIGNED predicate names —
//     this is the integrity gate, and it is what makes the manifest's own
//     signature unnecessary for integrity (a manifest whose bytes hash to the
//     referenced digest IS the manifest, whoever served it);
//  2. the bytes must parse as a sidecar (ReadSidecar also enforces
//     len(leaves) == treeSize);
//  3. the tree must be REBUILT from the leaves and its root compared to the
//     signed merkleRoot. Comparing two stored root strings would prove nothing;
//     the tree is rebuilt every time.
//
// Each failure carries a distinct error so a mismatch is never filed as a
// missing object.
func (a *Attestor) HydrateFromManifest(predicate []byte) error {
	if a.Inventory != nil {
		return fmt.Errorf("material: inventory references require HydrateInventory")
	}
	want := a.Manifest.SHA256()
	if want == "" {
		return fmt.Errorf("%w: the predicate carries no manifest digest to bind against", ErrMaterialManifestUnreadable)
	}

	// Bound the work BEFORE any of it is done. Everything below — compacting,
	// hashing, parsing, rebuilding the tree — is proportional to the bytes
	// handed in, and those bytes come from whatever the verifier loaded, not
	// from the signer. Two limits, both known before reading a byte:
	//   - the signed reference records the manifest's compact size, and a body
	//     that cannot compact down to it cannot hash to the signed digest
	//     either (whitespace is the only slack, allowed generously);
	//   - inclusionproof.MaxManifestBytes is the byte limit the PRODUCER
	//     honoured when it published, so a body above it is not a manifest any
	//     conformant producer emitted, whatever it claims.
	if len(predicate) > manifestByteCeiling {
		return fmt.Errorf("%w: %w: manifest is %d bytes, the limit is %d", ErrMaterialManifestMismatch, ErrMaterialManifestTooLarge, len(predicate), manifestByteCeiling)
	}
	if limit := manifestByteLimit(a.Manifest.Bytes); len(predicate) > limit {
		return fmt.Errorf("%w: manifest is %d bytes but the signed reference allows at most %d", ErrMaterialManifestMismatch, len(predicate), limit)
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, predicate); err != nil {
		return fmt.Errorf("%w: manifest is not valid JSON: %v", ErrMaterialManifestUnreadable, err)
	}
	sum := sha256.Sum256(compact.Bytes())
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("%w: manifest bytes hash to %s but the signed predicate references %s", ErrMaterialManifestMismatch, got, want)
	}

	side, err := inclusionproof.ReadSidecar(bytes.NewReader(compact.Bytes()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMaterialManifestUnreadable, err)
	}

	// Rebuild the tree from the leaves and compare to the SIGNED root, not to
	// the sidecar's own claimed root. Reconstruct checks the leaves against the
	// sidecar's root; this second comparison is what binds the sidecar to the
	// material predicate.
	if _, _, err := side.Reconstruct(); err != nil {
		return fmt.Errorf("%w: %v", ErrMaterialManifestMismatch, err)
	}
	if side.MerkleRoot != a.MerkleRoot {
		return fmt.Errorf("%w: manifest leaves rebuild root %s but the signed merkleRoot is %s", ErrMaterialManifestMismatch, side.MerkleRoot, a.MerkleRoot)
	}
	if side.TreeSize != a.TreeSize {
		return fmt.Errorf("%w: manifest treeSize %d but the signed treeSize is %d", ErrMaterialManifestMismatch, side.TreeSize, a.TreeSize)
	}

	leaves := make([]MaterialLeaf, 0, len(side.Leaves))
	for _, lf := range side.Leaves {
		leafBytes, err := inclusionproof.LeafHash(lf.Path, lf.FileDigest)
		if err != nil {
			return fmt.Errorf("%w: leaf %q: %v", ErrMaterialManifestMismatch, lf.Path, err)
		}
		leaves = append(leaves, MaterialLeaf{
			Path:       lf.Path,
			FileDigest: lf.FileDigest,
			LeafHash:   hex.EncodeToString(leafBytes),
		})
	}
	a.setLeaves(leaves)
	return nil
}

// ManifestDigest reports the sha256 of the manifest this predicate references,
// or "" when it references none. Part of attestation.ManifestHydrator.
func (a *Attestor) ManifestDigest() string {
	if a.Inventory != nil {
		return ""
	}
	return a.Manifest.SHA256()
}

// manifestByteLimit is the most bytes HydrateFromManifest will look at for a
// manifest whose signed reference records signedBytes of compact JSON. A
// pretty-printed copy is allowed to be larger (whitespace only), but never
// more than inclusionproof.MaxManifestBytes — the SAME ceiling the producer
// refused to publish above, so there is no per-leaf heuristic here that a
// producer could innocently exceed; a reference that recorded no size gets the
// ceiling alone.
func manifestByteLimit(signedBytes int) int {
	const whitespaceSlack = 4 // a pretty-printer's worst plausible expansion
	ceiling := manifestByteCeiling
	if signedBytes <= 0 {
		return ceiling
	}
	limit := signedBytes*whitespaceSlack + 4096
	if limit > ceiling {
		return ceiling
	}
	return limit
}

// ManifestPending reports whether a manifest resolution should be ATTEMPTED,
// decided from the signed predicate alone. Part of attestation.ManifestHydrator.
//
// True only in state (b)-pending: the producer signed manifestUploaded:true and
// the leaves are not already inline. Every other state answers false, which is
// what guarantees no fetch is attempted for a "not published" or legacy
// predicate and therefore that a store outage cannot reclassify one.
func (a *Attestor) ManifestPending() bool {
	return a.Inventory == nil && a.ManifestState() == ManifestPublished
}

// ManifestWithheld reports state (a): the producer signed manifestUploaded:false.
// Part of attestation.ManifestWithholder.
func (a *Attestor) ManifestWithheld() bool {
	return a.Inventory == nil && a.ManifestState() == ManifestNotPublished
}

// ManifestState classifies what the signed predicate says about its leaves,
// WITHOUT any network access. The engine decides whether to attempt a
// resolution from this alone, which is what keeps "the producer chose not to
// publish" and "we could not read what the producer published" from collapsing
// into each other under a store outage.
type ManifestState int

const (
	// ManifestInline — the leaves are in the predicate. Today's default and the
	// shape of every v0.3 envelope minted so far.
	ManifestInline ManifestState = iota

	// ManifestLegacyLeafless — no manifestUploaded key AND no leaves. A
	// pre-change producer that suppressed its leaves. Absence of the key is
	// explicitly NOT read as false: an absent key and a stripped key look
	// identical, so this stays its own state and keeps today's fail-closed
	// behaviour.
	ManifestLegacyLeafless

	// ManifestNotPublished — manifestUploaded:false. A SIGNED statement that
	// the producer chose not to publish the leaves.
	ManifestNotPublished

	// ManifestPublished — manifestUploaded:true. A resolution should be
	// attempted; failing to find it is a finding, not a benign absence.
	ManifestPublished
)

// ManifestState returns the state this predicate is in.
func (a *Attestor) ManifestState() ManifestState {
	if a.HasInlineLeaves() {
		return ManifestInline
	}
	if a.ManifestUploaded == nil {
		return ManifestLegacyLeafless
	}
	if *a.ManifestUploaded {
		return ManifestPublished
	}
	return ManifestNotPublished
}

// setLeaves installs a leaf list and the derived materials map together, so the
// two can never disagree. Used by UnmarshalJSON and by manifest hydration.
func (a *Attestor) setLeaves(leaves []MaterialLeaf) {
	if leaves == nil {
		leaves = []MaterialLeaf{}
	}
	a.leaves = leaves
	a.materials = make(map[string]cryptoutil.DigestSet, len(leaves))
	for _, lf := range leaves {
		a.materials[lf.Path] = cryptoutil.DigestSet{{Hash: cryptoSha256}: lf.FileDigest}
	}
}
