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

// MaxLeaves bounds the number of leaves accepted at every tree-build /
// reconstruction entry point. A v0.3 collection inlines its leaves into the
// DSSE-signed predicate, so VerifyInlineLeaves rebuilds the tree from
// attestation-supplied (and possibly MITM'd / crafted) leaves on every passed
// collection. Without a cap, a single bounded (<512 MiB) attestation carrying
// ~5-6M leaves forces multi-GB allocation (leaves slice + products/materials
// map + preHashed [][]byte + the merkle node store). 2^20 is orders of
// magnitude above any real build's product/material count yet kills the
// resource-exhaustion vector. This is a DoS guard, not a soundness control —
// it never causes a wrong PASS, only a clean rejection.
const MaxLeaves = 1 << 20

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
	if len(digests) > MaxLeaves {
		return Sidecar{}, fmt.Errorf("build sidecar: %d entries exceeds MaxLeaves=%d", len(digests), MaxLeaves)
	}
	entries := make([]LeafEntry, 0, len(digests))
	for p, dg := range digests {
		entries = append(entries, LeafEntry{Path: p, DigestHex: strings.ToLower(dg)})
	}
	entries = DedupAndSortByDigest(entries)

	leaves := make([]SidecarLeaf, 0, len(entries))
	preHashed := make([][]byte, 0, len(entries))
	for _, e := range entries {
		preHash, err := LeafHash(e.Path, e.DigestHex)
		if err != nil {
			return Sidecar{}, fmt.Errorf("build sidecar: leaf %q: %w", e.Path, err)
		}
		leaves = append(leaves, SidecarLeaf{Path: e.Path, FileDigest: e.DigestHex})
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

// LeafEntry is a (path, lowercase-hex content digest) pair feeding a v0.3
// Merkle tree build. The path is carried for human-readable metadata only;
// it is NOT part of the leaf hash (see LeafHash).
type LeafEntry struct {
	Path      string
	DigestHex string
}

// DedupAndSortByDigest returns the canonical, deterministic leaf set for a v0.3
// tree. Since the leaf hash now binds CONTENT only (the path was removed), two
// distinct paths sharing a digest would otherwise produce two byte-identical
// leaves — which the RFC6962 wrapper deliberately does NOT collapse (its
// CVE-2012-2459 defense). That would make the producer tree diverge from any
// digest-only reconstruction (Archivista discovery / VerifyInlineLeaves). So we
// collapse equal digests to ONE leaf here, at production time:
//   - sort by (digestHex, path) ascending,
//   - keep one survivor per unique digest: the lexicographically-smallest path
//     (deterministic so the inline-leaf JSON is byte-stable run-to-run).
//
// All three production tree-build sites (BuildSidecar, product.buildTree,
// material.buildLeaves) route through this single helper so they can never
// drift, mirroring the single-LeafHash-encoder discipline.
func DedupAndSortByDigest(entries []LeafEntry) []LeafEntry {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].DigestHex != entries[j].DigestHex {
			return entries[i].DigestHex < entries[j].DigestHex
		}
		return entries[i].Path < entries[j].Path
	})
	out := make([]LeafEntry, 0, len(entries))
	var last string
	for i, e := range entries {
		if i > 0 && e.DigestHex == last {
			continue // same digest: smallest path already kept (sorted)
		}
		out = append(out, e)
		last = e.DigestHex
	}
	return out
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
	// DoS guard: reject an oversized sidecar before any tree allocation. The
	// treeSize check fires on a tiny JSON lying about its size; the leaf-count
	// check fires on a genuinely huge (but <512 MiB) leaf array.
	if s.TreeSize > MaxLeaves {
		return Sidecar{}, fmt.Errorf("sidecar treeSize=%d exceeds MaxLeaves=%d", s.TreeSize, MaxLeaves)
	}
	if len(s.Leaves) > MaxLeaves {
		return Sidecar{}, fmt.Errorf("sidecar carries %d leaves, exceeds MaxLeaves=%d", len(s.Leaves), MaxLeaves)
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
	if len(s.Leaves) > MaxLeaves {
		return nil, nil, fmt.Errorf("reconstruct: %d leaves exceeds MaxLeaves=%d", len(s.Leaves), MaxLeaves)
	}
	// Verify canonical order. Leaves are sorted by (fileDigest, path) and carry
	// at most one entry per unique digest (the leaf hash binds content only, so
	// equal digests collapse — see DedupAndSortByDigest). Any other order would
	// produce a different Merkle root than a conformant producer wrote, so
	// reject loudly. The returned index is keyed by fileDigest.
	for i := 1; i < len(s.Leaves); i++ {
		prev, cur := s.Leaves[i-1], s.Leaves[i]
		if cur.FileDigest < prev.FileDigest || (cur.FileDigest == prev.FileDigest && cur.Path < prev.Path) {
			return nil, nil, fmt.Errorf("sidecar leaves are not in canonical (fileDigest,path) order (leaf %d %q/%q < leaf %d %q/%q)", i, cur.FileDigest, cur.Path, i-1, prev.FileDigest, prev.Path)
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
		if _, dupe := index[leaf.FileDigest]; dupe {
			return nil, nil, fmt.Errorf("reconstruct: duplicate leaf digest %q", leaf.FileDigest)
		}
		index[leaf.FileDigest] = uint64(i)
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
