// Copyright 2026 The Witness Contributors
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

// Package product implements the v0.3 product attestor.
//
// # Predicate shape
//
// A v0.3 product attestor publishes a single in-toto subject named
// `tree:products` whose digest is the SHA-256 Merkle root of the product set.
// The predicate JSON carries the root, the tree size, and the algorithm /
// construction identifiers so verifiers can refuse anything that claims
// another shape. Per-file data is NOT in the predicate — it lives in a
// sidecar file for the inclusion-proof attestor to consume later.
//
// # Leaf encoding (coordinate with the inclusion-proof attestor)
//
// Two-step hashing keeps the attestation/merkle wrapper API contract clean
// (every leaf is exactly HashSize bytes) while still cryptographically
// binding the file path to the file content:
//
//  1. Per file, compute the path-prefixed pre-hash
//     leafPreHash = sha256(path-bytes || 0x00 || file-digest-bytes-raw32)
//     The path is the UTF-8 file path (forward slashes, see
//     portableNormalize); 0x00 is a single NUL delimiter; the file digest is
//     the raw 32-byte SHA-256 of the file content.
//
//  2. Pass leafPreHash (32 bytes) into merkle.NewTree([][]byte). The wrapper
//     applies its own 0x00 leaf domain prefix per RFC 6962 §2.1, so the
//     hash the Merkle tree actually commits to is
//     H(0x00 || sha256(path || 0x00 || file-digest)).
//
// This guarantees:
//   - Two files with identical content but different paths produce distinct
//     leaf hashes and distinct roots.
//   - The path is cryptographically bound at the leaf level.
//   - The merkle wrapper sees only HashSize leaves, preserving its
//     fixed-length-leaf invariant.
//
// # Determinism
//
// Leaves are sorted by their forward-slash-normalized path before tree
// construction. Two attestations recorded against the same logical product
// set always produce the same root regardless of host OS or filesystem walk
// order.
package product

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/file"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/gabriel-vasile/mimetype"
	"github.com/gobwas/glob"
	"github.com/invopop/jsonschema"
)

const (
	// Name is the canonical attestor name registered with the attestation
	// registry. The CLI flag `--attestations product` references this.
	Name = "product"

	// Type is the v0.3 predicate type URI. v0.3 is a HARD CUT from v0.2:
	// the predicate shape is different (root + size + algo, no per-file
	// map), and v0.1 / v0.2 are no longer registered. Historical
	// attestations stored under v0.1 / v0.2 type URIs will fail to
	// deserialize and must be re-issued.
	Type = "https://aflock.ai/attestations/product/v0.3"

	// RunType places the attestor in the post-product phase, identical to
	// v0.1 / v0.2.
	RunType = attestation.ProductRunType

	// HashAlgorithm is the algorithm identifier published in the predicate
	// so verifiers can refuse anything that claims another algorithm. The
	// underlying merkle wrapper hardcodes SHA-256 as a defence against
	// hash-algorithm-confusion attacks.
	HashAlgorithm = "sha256"

	// Construction identifies the Merkle construction. Verifiers must
	// refuse anything that claims another construction.
	Construction = "RFC6962"

	// ProductName is kept as a re-export of Name for in-repo consumers
	// (link, slsa) that switch on the attestor's canonical name. New code
	// should use Name.
	ProductName = Name

	// TreeSubjectName is the single subject the attestor emits. It exists
	// as an exported constant so verifiers can build subject filters
	// without copying the literal string.
	TreeSubjectName = "tree:products"

	defaultIncludeGlob = "*"
	defaultExcludeGlob = ""
)

// ProductAttestor is the interface in-repo consumers (the link and slsa
// attestors) use to obtain the in-memory product map without depending on
// the concrete *Attestor type. Subjects() and Products() match the
// attestation library's Subjecter / Producer interfaces.
type ProductAttestor interface {
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Subjects() map[string]cryptoutil.DigestSet
	Products() map[string]attestation.Product
}

// Compile-time interface checks.
var (
	_ attestation.Attestor   = (*Attestor)(nil)
	_ attestation.Subjecter  = (*Attestor)(nil)
	_ attestation.Producer   = (*Attestor)(nil)
	_ attestation.BackReffer = (*Attestor)(nil)
	_ ProductAttestor        = (*Attestor)(nil)
)

// Attestor implements the v0.3 product attestor.
//
// The exported predicate fields (MerkleRoot, TreeSize, HashAlgorithmField,
// ConstructionField) are what get marshalled into the in-toto Statement's
// predicate. The lowercase fields are run-time state used to build the
// tree, including the per-file leaf data that the sidecar writer consumes.
// leaves is intentionally not in the predicate — clients must use
// WriteSidecar to capture the full tree contents.
type Attestor struct {
	// Predicate fields. These are the bytes any verifier needs to refuse
	// or accept the attestation; nothing else from this struct ends up in
	// the signed DSSE statement.
	MerkleRoot         string `json:"merkleRoot"`
	TreeSize           uint64 `json:"treeSize"`
	HashAlgorithmField string `json:"hashAlgorithm"`
	ConstructionField  string `json:"construction"`

	// Internal state — NOT part of the predicate. The `json:"-"` tags
	// keep them out of MarshalJSON so the signed Statement never carries
	// per-file data. WriteSidecar reads `leaves` to emit the sidecar
	// alongside the (signed) envelope.
	products            map[string]attestation.Product `json:"-"`
	baseArtifacts       map[string]cryptoutil.DigestSet
	leaves              []ProductLeaf `json:"-"`
	rootBytes           []byte        `json:"-"`
	includeGlob         string
	compiledIncludeGlob glob.Glob
	excludeGlob         string
	compiledExcludeGlob glob.Glob
}

// ProductLeaf describes one entry of the input tree. The Merkle leaf
// digest the tree commits to is H(0x00 || LeafHash) — the merkle wrapper
// applies the 0x00 RFC 6962 leaf prefix to the value passed into NewTree.
// LeafHash itself is the pre-hash H(path || 0x00 || file-digest).
type ProductLeaf struct {
	Path       string `json:"path"`
	FileDigest string `json:"fileDigest"`
	LeafHash   string `json:"leafHash"`
}

// Option configures a new Attestor.
type Option func(*Attestor)

// WithIncludeGlob restricts the recorded product set to paths matching the
// glob (default "*" — all files).
func WithIncludeGlob(g string) Option {
	return func(a *Attestor) { a.includeGlob = g }
}

// WithExcludeGlob removes paths matching the glob from the recorded
// product set (default empty — exclude nothing).
func WithExcludeGlob(g string) Option {
	return func(a *Attestor) { a.excludeGlob = g }
}

// New constructs an Attestor with default globs (include="*", exclude="").
func New(opts ...Option) *Attestor {
	a := &Attestor{
		includeGlob:        defaultIncludeGlob,
		excludeGlob:        defaultExcludeGlob,
		HashAlgorithmField: HashAlgorithm,
		ConstructionField:  Construction,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func configOptions() []registry.Configurer {
	return []registry.Configurer{
		registry.StringConfigOption(
			"include-glob",
			"Pattern to use when recording products. Files that match this pattern will be included as subjects on the attestation.",
			defaultIncludeGlob,
			func(a attestation.Attestor, includeGlob string) (attestation.Attestor, error) {
				prod, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}
				WithIncludeGlob(includeGlob)(prod)
				return prod, nil
			},
		),
		registry.StringConfigOption(
			"exclude-glob",
			"Pattern to use when recording products. Files that match this pattern will be excluded as subjects on the attestation.",
			defaultExcludeGlob,
			func(a attestation.Attestor, excludeGlob string) (attestation.Attestor, error) {
				prod, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}
				WithExcludeGlob(excludeGlob)(prod)
				return prod, nil
			},
		),
	}
}

func init() {
	// v0.3 is a HARD CUT. v0.1 (LegacyProductType) and v0.2 (the old
	// ProductType) are NOT registered. Verifiers that need to read
	// historical attestations must use an older cilock build.
	attestation.RegisterAttestation(
		Name,
		Type,
		RunType,
		func() attestation.Attestor { return New() },
		configOptions()...,
	)
}

// Name returns the attestor's registered name.
func (a *Attestor) Name() string { return Name }

// Type returns the v0.3 predicate type URI.
func (a *Attestor) Type() string { return Type }

// RunType places the attestor in the post-product phase.
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema is the JSON schema for the predicate as it ships in the DSSE
// Statement. It reflects the struct fields with json tags, which excludes
// the run-time leaves slice. MarshalJSON honours the same exclusion.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&Attestor{})
}

// Attest walks the product set, computes the per-file pre-hashes, sorts
// them deterministically, and builds the Merkle tree. The signed
// predicate's MerkleRoot is the resulting tree root in hex.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	compiledIncludeGlob, err := glob.Compile(a.includeGlob)
	if err != nil {
		return err
	}
	a.compiledIncludeGlob = compiledIncludeGlob

	compiledExcludeGlob, err := glob.Compile(a.excludeGlob)
	if err != nil {
		return err
	}
	a.compiledExcludeGlob = compiledExcludeGlob

	a.baseArtifacts = ctx.Materials()

	processWasTraced := false
	openedFileSet := map[string]bool{}
	for _, completed := range ctx.CompletedAttestors() {
		cmd, ok := completed.Attestor.(*commandrun.CommandRun)
		if !ok || !cmd.TracingEnabled() {
			continue
		}
		processWasTraced = true
		for _, process := range cmd.Processes {
			for fname := range process.OpenedFiles {
				openedFileSet[fname] = true
			}
		}
	}

	digestMap, err := file.RecordArtifacts(
		ctx.WorkingDir(),
		a.baseArtifacts,
		ctx.Hashes(),
		map[string]struct{}{},
		processWasTraced,
		openedFileSet,
		ctx.DirHashGlob(),
		a.compiledIncludeGlob,
		a.compiledExcludeGlob,
	)
	if err != nil {
		return err
	}

	a.products = fromDigestMap(ctx.WorkingDir(), digestMap)
	return a.buildTree()
}

// buildTree filters the product set through the include / exclude globs,
// sorts the survivors by normalized path, computes per-file leaf
// pre-hashes, and constructs the Merkle tree.
func (a *Attestor) buildTree() error {
	pairs := a.includedProductPairs()

	leaves := make([]ProductLeaf, 0, len(pairs))
	preHashes := make([][]byte, 0, len(pairs))

	for _, p := range pairs {
		prod, ok := a.products[p.originalKey]
		if !ok {
			continue
		}
		digestHex, ok := prod.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
		if !ok {
			// A product without a SHA-256 digest is a contract
			// violation by file.RecordArtifacts. Refuse to build a
			// tree that silently omits files.
			return fmt.Errorf("product %q has no sha256 digest; v0.3 requires sha256", p.normalized)
		}
		digestBytes, err := hex.DecodeString(digestHex)
		if err != nil {
			return fmt.Errorf("product %q has malformed sha256 hex digest: %w", p.normalized, err)
		}
		if len(digestBytes) != sha256.Size {
			return fmt.Errorf("product %q sha256 digest has length %d, want %d", p.normalized, len(digestBytes), sha256.Size)
		}

		leafPreHash := leafDigest(p.normalized, digestBytes)
		leaves = append(leaves, ProductLeaf{
			Path:       p.normalized,
			FileDigest: digestHex,
			LeafHash:   hex.EncodeToString(leafPreHash),
		})
		preHashes = append(preHashes, leafPreHash)
	}

	tree, err := merkle.NewTree(preHashes)
	if err != nil {
		return fmt.Errorf("building merkle tree: %w", err)
	}

	root := tree.Root()
	a.leaves = leaves
	a.rootBytes = root
	a.MerkleRoot = hex.EncodeToString(root)
	a.TreeSize = tree.Size()
	a.HashAlgorithmField = HashAlgorithm
	a.ConstructionField = Construction
	return nil
}

// leafDigest returns the path-bound pre-hash that the Merkle tree
// commits to (after applying its own 0x00 RFC 6962 leaf prefix).
//
// leafDigest = sha256(path || 0x00 || file-digest-raw)
//
// path is the forward-slash-normalized UTF-8 file path; fileDigest is the
// raw 32-byte SHA-256 of the file content.
func leafDigest(path string, fileDigest []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(path))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(fileDigest)
	return h.Sum(nil)
}

// Products returns the per-file product map for in-process consumers
// (link, slsa). It is NOT part of the predicate.
func (a *Attestor) Products() map[string]attestation.Product { return a.products }

// Subjects returns the single tree:products subject. If the product set
// is empty the subject is still emitted, with the digest set to the
// RFC 6962 empty-tree root (sha256("")), so verifiers can refuse a
// missing root rather than treating empty as absent. Per the v0.3 spec
// the predicate ALWAYS carries a root.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		TreeSubjectName: a.rootDigestSet(),
	}
}

// BackRefs mirrors Subjects per the v0.3 spec: the tree:products subject
// is the only chainable subject the attestor produces. (Issue #126
// intentionally narrowed BackRefs to the tree subject only.)
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		TreeSubjectName: a.rootDigestSet(),
	}
}

func (a *Attestor) rootDigestSet() cryptoutil.DigestSet {
	return cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA256}: a.MerkleRoot,
	}
}

// MarshalJSON publishes only the predicate fields. The leaves slice is
// kept out of the signed Statement; sidecar consumers use WriteSidecar.
func (a *Attestor) MarshalJSON() ([]byte, error) {
	type predicate struct {
		MerkleRoot    string `json:"merkleRoot"`
		TreeSize      uint64 `json:"treeSize"`
		HashAlgorithm string `json:"hashAlgorithm"`
		Construction  string `json:"construction"`
	}
	return json.Marshal(predicate{
		MerkleRoot:    a.MerkleRoot,
		TreeSize:      a.TreeSize,
		HashAlgorithm: a.HashAlgorithmField,
		Construction:  a.ConstructionField,
	})
}

// UnmarshalJSON restores the predicate fields from JSON. The leaves and
// products maps are NOT in the predicate; verifiers must obtain those
// from the sidecar (if it was retained) or recompute them from the build
// outputs.
func (a *Attestor) UnmarshalJSON(data []byte) error {
	type predicate struct {
		MerkleRoot    string `json:"merkleRoot"`
		TreeSize      uint64 `json:"treeSize"`
		HashAlgorithm string `json:"hashAlgorithm"`
		Construction  string `json:"construction"`
	}
	var p predicate
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	a.MerkleRoot = p.MerkleRoot
	a.TreeSize = p.TreeSize
	a.HashAlgorithmField = p.HashAlgorithm
	a.ConstructionField = p.Construction
	return nil
}

// SidecarSchemaVersion is the schema URI emitted at the top of every
// product-tree sidecar file.
const SidecarSchemaVersion = "https://aflock.ai/product-tree-sidecar/v0.1"

// Sidecar is the JSON shape of the side-channel tree file. It is NOT
// signed and NOT part of the attestation envelope — producers may discard
// it. The inclusion-proof attestor (cilock prove) consumes it to emit
// per-file proofs against the published Merkle root.
type Sidecar struct {
	SchemaVersion string        `json:"schemaVersion"`
	MerkleRoot    string        `json:"merkleRoot"`
	TreeSize      uint64        `json:"treeSize"`
	HashAlgorithm string        `json:"hashAlgorithm"`
	Construction  string        `json:"construction"`
	Leaves        []ProductLeaf `json:"leaves"`
}

// WriteSidecar serializes the full tree contents (root, size, algo, and
// every per-file leaf) to path. The sidecar is NOT signed and NOT part of
// the attestation envelope — producers MAY discard it. cilock prove uses
// it to generate inclusion proofs for individual files after the fact.
//
// The MerkleRoot and FileDigest fields are emitted with a "sha256:"
// prefix so the sidecar self-describes the algorithm. Callers reading the
// sidecar should strip the prefix before decoding.
func (a *Attestor) WriteSidecar(path string) error {
	sidecar := a.Sidecar()
	data, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling product tree sidecar: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing product tree sidecar: %w", err)
	}
	return nil
}

// Sidecar builds the side-channel tree record from the attestor's
// in-memory state. Exposed separately from WriteSidecar so callers can
// embed the sidecar in their own envelope formats.
func (a *Attestor) Sidecar() Sidecar {
	leaves := make([]ProductLeaf, len(a.leaves))
	for i, l := range a.leaves {
		leaves[i] = ProductLeaf{
			Path:       l.Path,
			FileDigest: "sha256:" + l.FileDigest,
			LeafHash:   "sha256:" + l.LeafHash,
		}
	}
	return Sidecar{
		SchemaVersion: SidecarSchemaVersion,
		MerkleRoot:    "sha256:" + a.MerkleRoot,
		TreeSize:      a.TreeSize,
		HashAlgorithm: a.HashAlgorithmField,
		Construction:  a.ConstructionField,
		Leaves:        leaves,
	}
}

// Leaves returns the raw (unprefixed) per-file leaf records used to build
// the tree. Used by tests and by the inclusion-proof attestor when it
// constructs proofs in-process.
func (a *Attestor) Leaves() []ProductLeaf {
	out := make([]ProductLeaf, len(a.leaves))
	copy(out, a.leaves)
	return out
}

// RootBytes returns the raw 32-byte Merkle root. Used by the
// inclusion-proof attestor to verify proofs against the same in-memory
// tree.
func (a *Attestor) RootBytes() []byte {
	out := make([]byte, len(a.rootBytes))
	copy(out, a.rootBytes)
	return out
}

// =====================================================================
// Internal helpers
// =====================================================================

// portableNormalize rewrites a relative path to its canonical form.
// Backslashes are unconditionally replaced with forward slashes — we do
// NOT use filepath.ToSlash because that helper is OS-aware (it leaves
// backslashes alone on non-Windows hosts), which would make a
// Windows-recorded attestation produce a different Merkle root when
// re-hashed on Linux. The Merkle root must be a function of the
// predicate alone, regardless of host OS.
func portableNormalize(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob
// library can panic on certain patterns that compile successfully but
// trigger out-of-bounds access during matching. We treat panics as
// non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}

type productPair struct {
	normalized  string
	originalKey string
}

func (a *Attestor) includedProductPairs() []productPair {
	pairs := make([]productPair, 0, len(a.products))
	for name := range a.products {
		normalized := portableNormalize(name)
		if a.compiledExcludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledExcludeGlob, normalized); err != nil {
				log.Debugf("exclude glob match error for path %q: %v", normalized, err)
			} else if matched {
				continue
			}
		}
		if a.compiledIncludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledIncludeGlob, normalized); err != nil {
				log.Debugf("include glob match error for path %q: %v", normalized, err)
			} else if !matched {
				continue
			}
		}
		pairs = append(pairs, productPair{normalized: normalized, originalKey: name})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].normalized < pairs[j].normalized
	})
	return pairs
}

func fromDigestMap(workingDir string, digestMap map[string]cryptoutil.DigestSet) map[string]attestation.Product {
	products := make(map[string]attestation.Product, len(digestMap))
	for name, digestSet := range digestMap {
		full := filepath.Join(workingDir, name)
		mimeType, err := getFileContentType(full)
		if err != nil {
			mimeType = "unknown"
		}
		if mimeType == "application/octet-stream" {
			if info, err := os.Stat(full); err == nil && info.IsDir() {
				mimeType = "text/directory"
			}
		}
		products[name] = attestation.Product{
			MimeType: mimeType,
			Digest:   digestSet,
		}
	}
	return products
}

func getFileContentType(fileName string) (string, error) {
	contentType, err := mimetype.DetectFile(fileName)
	if err != nil {
		return "", err
	}
	return contentType.String(), nil
}

// IsSPDXJson returns true if the leading bytes of a JSON document look
// like SPDX. Re-exported because the sbom attestor uses it for MIME
// detection.
func IsSPDXJson(buf []byte) bool {
	maxLen := len(buf)
	if maxLen > 500 {
		maxLen = 500
	}
	header := buf[:maxLen]
	return bytes.Contains(header, []byte(`"spdxVersion":"SPDX-`)) ||
		bytes.Contains(header, []byte(`"spdxVersion": "SPDX-`))
}

// IsCycloneDXJson returns true if the leading bytes of a JSON document
// look like CycloneDX. Re-exported because the sbom attestor uses it for
// MIME detection.
func IsCycloneDXJson(buf []byte) bool {
	maxLen := len(buf)
	if maxLen > 500 {
		maxLen = 500
	}
	header := buf[:maxLen]
	return bytes.Contains(header, []byte(`"bomFormat":"CycloneDX"`)) ||
		bytes.Contains(header, []byte(`"bomFormat": "CycloneDX"`))
}

func init() {
	// Custom MIME-type detectors registered once at process start.
	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return IsSPDXJson(buf)
	}, "application/spdx+json", ".spdx.json")

	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return IsCycloneDXJson(buf)
	}, "application/vnd.cyclonedx+json", ".cdx.json")

	mimetype.Lookup("text/xml").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`<?xml version="1.0" encoding="UTF-8"?><bom xmlns="http://cyclonedx.org/schema/bom/`))
	}, "application/vnd.cyclonedx+xml", ".cdx.xml")

	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`{"@context":"https://openvex.dev/ns`))
	}, "application/vex+json", ".vex.json")

	mimetype.Lookup("text/plain").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`sha256:`))
	}, "text/sha256+text", ".sha256")
}
