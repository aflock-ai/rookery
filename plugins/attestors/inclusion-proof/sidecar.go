// Copyright 2026 TestifySec, Inc.
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

package inclusionproof

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/merkle"
)

// SidecarSchemaVersion is the version tag emitted in every sidecar so
// that future schema changes can be detected and refused without trying
// to interpret a layout the reader does not understand.
const SidecarSchemaVersion = "rookery.inclusion-proof.sidecar/v0.1"

// SidecarLeaf is one entry in the sidecar's leaf list. Paths are stored
// in their portable (forward-slash) form so the sidecar is OS-independent;
// FileDigest is the lowercase hex SHA-256 of the file's content.
type SidecarLeaf struct {
	Path       string `json:"path"`
	FileDigest string `json:"fileDigest"`
}

// Sidecar is the JSON document the v0.3 product and material attestors
// emit alongside their signed envelope. It captures every input the
// inclusion-proof attestor needs to reconstruct the Merkle tree and
// emit per-leaf proofs.
//
// # Determinism contract
//
// `Leaves` is sorted lexicographically by Path. The producing attestor
// MUST sort the same way; reconstructed roots will only match across
// implementations if the leaf ordering is identical. The exported
// sidecar helpers below (BuildSidecar / Reconstruct) enforce sorting
// so callers cannot silently produce a non-canonical sidecar.
//
// # Why a sidecar and not a verifier-side reconstruction
//
// The signed product/material predicate only carries the Merkle root,
// not the leaf set — keeping the predicate small. The sidecar carries
// the full leaf set so `cilock prove` can rebuild the tree locally and
// emit per-leaf proofs without re-walking the working directory.
//
// The sidecar is NOT signed: it's an input to `cilock prove`, and
// `cilock prove` itself produces the signed inclusion-proof predicate.
// If a sidecar is tampered with, the reconstructed Merkle root will not
// match the root in the producing attestor's signed predicate, and
// reconstruction will refuse to emit a proof — which is the integrity
// check that matters.
type Sidecar struct {
	SchemaVersion string `json:"schemaVersion"`
	// Source is "product" or "material" — purely informational, so a
	// human reading the JSON can tell which attestor wrote it.
	Source string `json:"source"`
	// MerkleRoot is the hex-encoded SHA-256 Merkle root of the leaves
	// after applying the v0.3 leaf encoding (sha256(path || 0x00 ||
	// fileDigestBytes)) and the RFC 6962 §2.1 tree construction.
	MerkleRoot string `json:"merkleRoot"`
	// TreeSize is len(Leaves). Stored explicitly so a verifier can use
	// it without re-walking the leaf array.
	TreeSize uint64 `json:"treeSize"`
	// HashAlgorithm and Construction MUST equal HashAlgorithm and
	// Construction in the inclusion-proof package — pinned hard.
	HashAlgorithm string `json:"hashAlgorithm"`
	Construction  string `json:"construction"`
	// Leaves is the deterministic sorted leaf list.
	Leaves []SidecarLeaf `json:"leaves"`
}

// BuildSidecar constructs and validates a Sidecar from an unordered
// (path -> fileDigestHex) map. It is intentionally pure-functional:
// callers (i.e. the v0.3 product/material attestors and `cilock run`'s
// post-run hook) pass in the digest map and get back a fully-validated
// Sidecar with the canonical Merkle root pre-computed.
//
// The hashing must match the bytewise encoding in LeafHash; any drift
// will cause `cilock prove` to refuse the sidecar (the reconstructed
// root won't match Sidecar.MerkleRoot).
func BuildSidecar(source string, digests map[string]string) (Sidecar, error) {
	paths := make([]string, 0, len(digests))
	for p := range digests {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	leaves := make([]SidecarLeaf, 0, len(paths))
	preHashed := make([][]byte, 0, len(paths))
	for _, p := range paths {
		dg := digests[p]
		preHash, err := LeafHash(p, dg)
		if err != nil {
			return Sidecar{}, fmt.Errorf("build sidecar: leaf %q: %w", p, err)
		}
		leaves = append(leaves, SidecarLeaf{Path: p, FileDigest: strings.ToLower(dg)})
		preHashed = append(preHashed, preHash)
	}

	tree, err := merkle.NewTree(preHashed)
	if err != nil {
		return Sidecar{}, fmt.Errorf("build sidecar: %w", err)
	}

	return Sidecar{
		SchemaVersion: SidecarSchemaVersion,
		Source:        source,
		MerkleRoot:    hex.EncodeToString(tree.Root()),
		TreeSize:      tree.Size(),
		HashAlgorithm: HashAlgorithm,
		Construction:  Construction,
		Leaves:        leaves,
	}, nil
}

// WriteSidecar marshals the sidecar to JSON and writes it to w.
func WriteSidecar(w io.Writer, s Sidecar) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&s)
}

// WriteSidecarFile is a convenience that writes a sidecar to path.
func WriteSidecarFile(path string, s Sidecar) error {
	f, err := os.Create(path) //nolint:gosec // G304: path is a CLI-derived sidecar path
	if err != nil {
		return fmt.Errorf("create sidecar file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return WriteSidecar(f, s)
}

// ReadSidecar parses and shape-validates a sidecar from r. It does NOT
// reconstruct the tree (callers do that explicitly via Reconstruct).
func ReadSidecar(r io.Reader) (Sidecar, error) {
	var s Sidecar
	dec := json.NewDecoder(r)
	if err := dec.Decode(&s); err != nil {
		return Sidecar{}, fmt.Errorf("decode sidecar: %w", err)
	}
	if s.SchemaVersion != SidecarSchemaVersion {
		return Sidecar{}, fmt.Errorf("sidecar schemaVersion=%q is not supported (need %q)", s.SchemaVersion, SidecarSchemaVersion)
	}
	if s.HashAlgorithm != HashAlgorithm {
		return Sidecar{}, fmt.Errorf("sidecar hashAlgorithm=%q is not supported (need %q)", s.HashAlgorithm, HashAlgorithm)
	}
	if s.Construction != Construction {
		return Sidecar{}, fmt.Errorf("sidecar construction=%q is not supported (need %q)", s.Construction, Construction)
	}
	if uint64(len(s.Leaves)) != s.TreeSize {
		return Sidecar{}, fmt.Errorf("sidecar treeSize=%d but %d leaves were carried", s.TreeSize, len(s.Leaves))
	}
	return s, nil
}

// ReadSidecarFile is a convenience that reads a sidecar from path.
func ReadSidecarFile(path string) (Sidecar, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is a CLI-supplied sidecar path
	if err != nil {
		return Sidecar{}, fmt.Errorf("open sidecar file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return ReadSidecar(f)
}

// Reconstruct rebuilds the Merkle tree from the sidecar's leaf list and
// returns the tree itself along with the lookup table from portable path
// to leaf index. It re-derives the root and refuses to return on
// mismatch — that's the integrity check `cilock prove` relies on to
// detect a tampered sidecar before it emits a useless proof.
//
// ErrSidecarRootMismatch is returned when the reconstructed root does
// not match the sidecar's claimed root. Callers should propagate it as
// "sidecar corrupted; refusing to emit proof".
func (s *Sidecar) Reconstruct() (*merkle.Tree, map[string]uint64, error) {
	// Verify sort order. A non-sorted sidecar would produce a different
	// Merkle root than any conformant producer wrote, so reject loudly.
	for i := 1; i < len(s.Leaves); i++ {
		if s.Leaves[i].Path < s.Leaves[i-1].Path {
			return nil, nil, fmt.Errorf("sidecar leaves are not lexicographically sorted (leaf %d %q < leaf %d %q)", i, s.Leaves[i].Path, i-1, s.Leaves[i-1].Path)
		}
	}

	preHashed := make([][]byte, len(s.Leaves))
	index := make(map[string]uint64, len(s.Leaves))
	for i, leaf := range s.Leaves {
		h, err := LeafHash(leaf.Path, leaf.FileDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("reconstruct: leaf %d %q: %w", i, leaf.Path, err)
		}
		preHashed[i] = h
		if _, dupe := index[leaf.Path]; dupe {
			return nil, nil, fmt.Errorf("reconstruct: duplicate leaf path %q", leaf.Path)
		}
		index[leaf.Path] = uint64(i)
	}

	tree, err := merkle.NewTree(preHashed)
	if err != nil {
		return nil, nil, fmt.Errorf("reconstruct: %w", err)
	}

	claimedRoot, err := hex.DecodeString(s.MerkleRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("reconstruct: sidecar merkleRoot is not hex: %w", err)
	}
	got := tree.Root()
	if !subtleEqual(claimedRoot, got) {
		return nil, nil, ErrSidecarRootMismatch
	}
	if tree.Size() != s.TreeSize {
		return nil, nil, fmt.Errorf("reconstruct: tree size mismatch (sidecar=%d, computed=%d)", s.TreeSize, tree.Size())
	}
	return tree, index, nil
}

// ErrSidecarRootMismatch is the sentinel error returned by
// Sidecar.Reconstruct when the recomputed Merkle root does not match
// the sidecar's claimed root. Callers (i.e. `cilock prove`) match on it
// to emit the "sidecar root mismatch" diagnostic.
var ErrSidecarRootMismatch = errors.New("sidecar root mismatch: reconstructed Merkle root does not match the root claimed in the sidecar — refusing to emit a proof that won't verify")
