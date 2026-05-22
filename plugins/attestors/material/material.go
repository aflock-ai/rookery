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

// Package material implements the v0.3 material attestor.
//
// v0.3 is a HARD CUT for production: the v0.3 attestor is the ONLY producer
// registered for the canonical "material" attestor name. The predicate type
// is bumped to "https://aflock.ai/attestations/material/v0.3" and the
// per-file subjects emitted by v0.1 are replaced with a single deterministic
// RFC 6962 Merkle root over the input file set. The per-file (path, digest)
// pairs are no longer embedded in the signed predicate — they are written
// to a separate tree sidecar file alongside the attestation. The predicate
// carries only the Merkle root, the tree size, and the two pinned algorithm
// constants ("sha256" / "RFC6962"). Verifiers reconstruct the leaves from
// the sidecar and recompute the root to check inclusion.
//
// Historical v0.1 attestations remain verify-only via the LegacyDecoder
// (see legacy.go), registered under the distinct attestor name
// "material-v0.1" and predicate URI .../material/v0.1. The decoder refuses
// Attest() so it cannot be invoked as a producer.
//
// # Leaf encoding
//
// Each leaf commits to a (path, file-digest) pair. The encoding is the
// concatenation:
//
//	leafContent := path-bytes || 0x00 || file-digest-bytes
//
// where path-bytes is the UTF-8 of the path normalized to forward slashes
// (so the root is portable across operating systems) and file-digest-bytes
// is the RAW 32-byte sha256 of the file (not its hex form). The attestor
// pre-hashes:
//
//	leafHash := sha256(leafContent)
//
// and passes the resulting 32-byte digest to attestation/merkle.NewTree.
// The merkle wrapper then applies its own RFC 6962 §2.1 0x00 leaf prefix
// internally. Pre-hashing at the attestor keeps the leaf-encoding contract
// in the attestor module, where it can be locked down by tests — and lets
// us trivially share that encoding with the v0.3 product attestor so a
// material tree and a product tree over the same input list produce
// byte-identical roots (see the cross-coherence test in the test suite).
//
// # Why the leaf encoding MUST match the product attestor
//
// The verifiability story for v0.3 depends on a single canonical leaf
// encoding shared by both attestors. If two attestors over the same input
// list disagreed on leaf bytes, an inclusion proof rooted in one tree would
// not verify against a root sourced from the other, and consumers couldn't
// substitute one for the other in a chain. The cross-coherence test
// (TestV03_010_LeafFormatConsistencyWithProduct) is the spec lock for that
// invariant: do not change leaf encoding here without changing it in the
// product attestor in the same commit.
package material

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/file"
	"github.com/aflock-ai/rookery/attestation/merkle"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/invopop/jsonschema"
)

// cryptoSha256 is the DigestSet key the v0.3 attestor uses to publish the
// Merkle root. Pulled out as a package-level value so the Subjects() and
// BackRefs() paths can't drift on the key shape — both must hand back the
// same algorithm identifier or downstream subject equality breaks.
var cryptoSha256 = crypto.SHA256

const (
	// Name is the registry name for the material attestor. Unchanged
	// across versions so CLI flags, presets, and policy step lookups
	// keep working — only the predicate type version changed.
	Name = "material"

	// Type is the v0.3 predicate type URI. The bump from v0.1 signals a
	// breaking change in BOTH subject semantics (per-file → tree) AND
	// predicate shape (per-file map → merkle root + constants). v0.3 is
	// the only producer registered under the "material" name; v0.1 is
	// supported verify-only via the LegacyDecoder in legacy.go.
	Type = "https://aflock.ai/attestations/material/v0.3"

	// RunType is unchanged from v0.1: the attestor still records the
	// state of the working directory before the build step runs.
	RunType = attestation.MaterialRunType

	// HashAlgorithm is the only algorithm v0.3 emits. Embedded in the
	// predicate so verifiers can reject any predicate that claims
	// something else — defense against hash-algorithm-confusion proof
	// forgery (see attestation/merkle package doc).
	HashAlgorithm = "sha256"

	// Construction is the tree construction identifier. v0.3 uses RFC
	// 6962 §2.1 exclusively (the algorithm implemented by the
	// attestation/merkle wrapper). Embedded for the same reason as
	// HashAlgorithm.
	Construction = "RFC6962"

	// TreeSubjectName is the single in-toto subject key emitted by the
	// v0.3 attestor. Mirrors the product attestor's "tree:products" so
	// consumers can pattern-match on a stable prefix.
	TreeSubjectName = "tree:materials"
)

// Compile-time interface checks. Any drift here is a build break, not a
// runtime failure.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.Materialer = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ MaterialAttestor       = &Attestor{}
)

// MaterialAttestor is the consumer-facing interface preserved across the
// v0.1 → v0.3 cut. slsa and link attestors type-assert this when they walk
// completed attestors; keeping the interface intact means those callers
// don't need to know which predicate version produced the data.
type MaterialAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error

	// Materialer — still returns the per-file (path → DigestSet) map so
	// downstream attestors (slsa, link) can enumerate materials. The
	// per-file data is NOT in the signed predicate anymore, but it is
	// available in memory for the duration of the run.
	Materials() map[string]cryptoutil.DigestSet
}

func init() {
	// v0.3 is a hard cut for production: only the v0.3 attestor is
	// registered under the canonical "material" name. The verify-only
	// v0.1 decoder lives in legacy.go and registers separately under
	// the "material-v0.1" name + .../material/v0.1 predicate URI.
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// Option configures the attestor at construction time. Kept as a typed
// function alias so future configuration knobs can be added without
// breaking the New() signature.
type Option func(*Attestor)

// Attestor is the v0.3 material attestor.
//
// The exported fields below are what gets marshaled into the signed
// predicate. Everything else — including the per-file leaf list — lives
// only in memory and the sidecar.
type Attestor struct {
	// MerkleRoot is the lowercase hex encoding of the RFC 6962 Merkle
	// root over the material set's leaves. Always 64 hex chars
	// (sha256). An empty material set still has a deterministic root
	// (sha256 of the empty string per RFC 6962 §2.1), so this field is
	// never empty in a successfully-attested predicate.
	MerkleRoot string `json:"merkleRoot"`

	// TreeSize is the leaf count of the tree. Zero is valid (empty
	// material set).
	TreeSize uint64 `json:"treeSize"`

	// HashAlgorithmField pins the algorithm verifiers must use. v0.3
	// only ever emits "sha256". Embedded in the signed predicate so a
	// verifier that finds anything else can refuse the predicate up
	// front rather than failing later at the proof-check layer.
	HashAlgorithmField string `json:"hashAlgorithm"`

	// ConstructionField pins the tree construction. v0.3 only ever
	// emits "RFC6962". Same hardening rationale as HashAlgorithmField.
	ConstructionField string `json:"construction"`

	// leaves carries the per-file (path, fileDigest, leafHash) triples
	// that built the tree. JSON-elided with "-" so the signed
	// predicate stays compact — the data lives in the sidecar
	// instead. Kept in memory so Materials() and the sidecar writer
	// can both access it.
	leaves []MaterialLeaf `json:"-"`

	// materials is the raw (path → DigestSet) walk output, preserved
	// for the Materialer interface. Indexed by the OS-native path key
	// the walker produced; consumers that need a portable form can
	// use the leaves slice instead. Not marshaled.
	materials map[string]cryptoutil.DigestSet `json:"-"`
}

// MaterialLeaf is one (path, file-digest, leaf-hash) triple. The leaf
// hash is the pre-hashed input fed into the merkle wrapper — exposing it
// in the sidecar lets verifiers recompute the tree without reimplementing
// the leaf encoding.
type MaterialLeaf struct {
	// Path is the forward-slash-normalized relative path to the
	// material file. Always uses '/' regardless of the OS that ran
	// the attestor, so the root is portable.
	Path string `json:"path"`

	// FileDigest is the lowercase hex sha256 of the file's contents.
	// 64 hex chars. NOT the leaf hash — the leaf hash is computed
	// from (path, this digest) below.
	FileDigest string `json:"fileDigest"`

	// LeafHash is the lowercase hex sha256 of
	// (path-bytes || 0x00 || file-digest-bytes). 64 hex chars. This
	// is the value passed to merkle.NewTree as a 32-byte leaf
	// (after hex-decoding).
	LeafHash string `json:"leafHash"`
}

// New constructs an unpopulated Attestor. Options are applied in order;
// none are defined yet — the parameter is reserved for the same shape as
// the product attestor so future knobs (e.g., include/exclude globs) can
// be added without an API change.
func New(opts ...Option) *Attestor {
	a := &Attestor{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema reflects the SIGNED predicate shape — just the four scalar
// fields. The per-file leaves are not in the predicate, so they are not
// in the schema either. Keeping the schema in sync with MarshalJSON is
// what keeps Archivista's predicate validator from rejecting v0.3 data.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&Attestor{})
}

// Attest walks the working directory, builds a Merkle tree over the
// recorded materials, and stores the root + size on the attestor. The
// walk uses the same RecordArtifacts call the v0.1 attestor used — only
// the post-processing changed.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	// Same walk semantics as v0.1: no include/exclude globs (material
	// attestor captures the entire workdir pre-build), no tracing
	// overlay (tracing data only matters for products).
	mats, err := file.RecordArtifacts(
		ctx.WorkingDir(),
		nil,
		ctx.Hashes(),
		map[string]struct{}{},
		false,
		map[string]bool{},
		ctx.DirHashGlob(),
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("material attestor: record artifacts: %w", err)
	}

	a.materials = mats
	leaves, err := buildLeaves(mats)
	if err != nil {
		return fmt.Errorf("material attestor: build leaves: %w", err)
	}
	a.leaves = leaves

	// Decode leaf hex back to raw 32-byte digests for the merkle
	// wrapper. Pre-hashing in buildLeaves keeps the encoding contract
	// in ONE place (this file) but the wrapper insists on raw bytes.
	leafDigests, err := decodeLeafHashes(a.leaves)
	if err != nil {
		return fmt.Errorf("material attestor: decode leaf hashes: %w", err)
	}

	tree, err := merkle.NewTree(leafDigests)
	if err != nil {
		return fmt.Errorf("material attestor: build merkle tree: %w", err)
	}

	a.MerkleRoot = hex.EncodeToString(tree.Root())
	a.TreeSize = tree.Size()
	a.HashAlgorithmField = HashAlgorithm
	a.ConstructionField = Construction

	return nil
}

// buildLeaves turns the walker output into the canonical sorted leaf
// list. The sort key is the FORWARD-SLASH-NORMALIZED path so the merkle
// root is portable across operating systems — without this step a
// Windows-recorded attestation would produce a different root when
// re-hashed on Linux.
func buildLeaves(mats map[string]cryptoutil.DigestSet) ([]MaterialLeaf, error) {
	out := make([]MaterialLeaf, 0, len(mats))
	for path, ds := range mats {
		digest := extractSha256(ds)
		normalized := inclusionproof.NormalizePath(path)
		// inclusionproof.LeafHash is the single canonical leaf encoder
		// shared with the product attestor. It validates that the
		// fileDigestHex is a real 32-byte sha256 — material rejects
		// files lacking a sha256 (e.g., sockets, broken symlinks)
		// rather than silently building a tree over a defensive empty
		// digest. The v0.3 contract is that every leaf is anchored to
		// a real artifact digest.
		leafBytes, err := inclusionproof.LeafHash(normalized, digest)
		if err != nil {
			return nil, fmt.Errorf("material %q: %w", normalized, err)
		}
		out = append(out, MaterialLeaf{
			Path:       normalized,
			FileDigest: digest,
			LeafHash:   hex.EncodeToString(leafBytes),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// extractSha256 returns the hex sha256 from a DigestSet, or "" if there
// is none. The DigestSet may also carry sha1, gitoid, dirhash, etc., but
// the merkle tree commits to sha256 only — that's the algorithm the
// wrapper supports and the only one we publish in the predicate.
func extractSha256(ds cryptoutil.DigestSet) string {
	for dv, d := range ds {
		// Skip gitoid and dirhash entries: they aren't a raw
		// content sha256 of the file bytes, even when their hash
		// field is crypto.SHA256.
		if dv.GitOID || dv.DirHash {
			continue
		}
		if dv.Hash == crypto.SHA256 {
			return d
		}
	}
	return ""
}

// computeLeafHashHex is a test-only convenience wrapper over the
// canonical inclusionproof.LeafHash, so TestV03_010 can call a free
// function. Production code uses inclusionproof.LeafHash directly in
// buildLeaves (which propagates errors instead of swallowing them).
//
// Returns "" on error.
func computeLeafHashHex(path, fileDigestHex string) string {
	b, err := inclusionproof.LeafHash(path, fileDigestHex)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// decodeLeafHashes turns the hex leaf hashes from the in-memory leaves
// slice back into the raw 32-byte slices the merkle wrapper wants.
// Validates length so a malformed leaf is caught before it confuses the
// wrapper's index math.
func decodeLeafHashes(leaves []MaterialLeaf) ([][]byte, error) {
	out := make([][]byte, len(leaves))
	for i, l := range leaves {
		raw, err := hex.DecodeString(l.LeafHash)
		if err != nil {
			return nil, fmt.Errorf("leaf %d (%s): %w", i, l.Path, err)
		}
		if len(raw) != merkle.HashSize {
			return nil, fmt.Errorf("leaf %d (%s): hash length %d, want %d", i, l.Path, len(raw), merkle.HashSize)
		}
		out[i] = raw
	}
	return out, nil
}

// MarshalJSON serializes ONLY the four exported scalar fields. The
// leaves slice and materials map have json:"-" tags so they are
// excluded automatically; we still implement MarshalJSON explicitly so
// the schema remains a stable, documented contract independent of
// struct-field reordering.
func (a *Attestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		MerkleRoot         string `json:"merkleRoot"`
		TreeSize           uint64 `json:"treeSize"`
		HashAlgorithmField string `json:"hashAlgorithm"`
		ConstructionField  string `json:"construction"`
	}{
		MerkleRoot:         a.MerkleRoot,
		TreeSize:           a.TreeSize,
		HashAlgorithmField: a.HashAlgorithmField,
		ConstructionField:  a.ConstructionField,
	})
}

// UnmarshalJSON reads the four exported scalar fields. Materials and
// leaves are not reconstructed — they live in the sidecar.
func (a *Attestor) UnmarshalJSON(data []byte) error {
	aux := struct {
		MerkleRoot         string `json:"merkleRoot"`
		TreeSize           uint64 `json:"treeSize"`
		HashAlgorithmField string `json:"hashAlgorithm"`
		ConstructionField  string `json:"construction"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	a.MerkleRoot = aux.MerkleRoot
	a.TreeSize = aux.TreeSize
	a.HashAlgorithmField = aux.HashAlgorithmField
	a.ConstructionField = aux.ConstructionField
	return nil
}

// Materials returns the per-file (path → DigestSet) map. Preserved for
// the Materialer interface so slsa and link attestors keep working
// across the v0.1 → v0.3 cut. The data is NOT in the signed predicate;
// downstream attestors must consume it during the same run.
func (a *Attestor) Materials() map[string]cryptoutil.DigestSet {
	return a.materials
}

// Subjects returns the in-toto subject set. v0.3 emits exactly ONE
// subject — "tree:materials" — whose sha256 digest is the Merkle root.
// This is the change that lets v0.3 scale to large material sets
// without exploding Archivista's MySQL placeholder budget.
//
// Returns an empty map when the attestor has not been Attest'd yet OR
// the Attest call produced an empty material set with a zero root.
// Either way, callers should never see a partial subject.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	if a.MerkleRoot == "" {
		return map[string]cryptoutil.DigestSet{}
	}
	return map[string]cryptoutil.DigestSet{
		TreeSubjectName: {
			cryptoutil.DigestValue{Hash: cryptoSha256}: a.MerkleRoot,
		},
	}
}

// BackRefs mirrors Subjects: the tree subject is the canonical handle
// for cross-attestation lookup, so the single "tree:materials" entry is
// also the back-ref. This matches the planned reshape that the product
// attestor follows in #127 — both attestors now hand exactly one
// back-ref to Archivista per attestation, keyed on the tree root.
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	return a.Subjects()
}

// Leaves returns the in-memory leaf list. Exported so the cilock run
// sidecar hook (and downstream consumers of the in-process attestor
// state) can build the canonical inclusion-proof sidecar without
// re-reading any on-disk form. The single sidecar format is defined
// in plugins/attestors/inclusion-proof; this attestor does not
// duplicate that schema.
func (a *Attestor) Leaves() []MaterialLeaf {
	return a.leaves
}
