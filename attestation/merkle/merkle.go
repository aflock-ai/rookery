// Package merkle is an opinionated, vetted wrapper around
// github.com/transparency-dev/merkle that exposes the RFC 6962 §2.1 Merkle
// tree primitives and inclusion-proof verification used by the v0.3 product
// and material attestors.
//
// # Hash algorithm pinning
//
// This package intentionally hardcodes the hash algorithm to SHA-256. The
// public API never accepts an algorithm parameter. This is a deliberate
// guardrail against "hash algorithm confusion" attacks where a proof
// self-declares the algorithm (and an attacker forges a collision under a
// weak one). Predicates emitted by the v0.3 attestors will publish the
// constant strings exposed below so that verifiers can refuse anything that
// claims another algorithm.
//
// # Domain separation
//
// All hashing follows RFC 6962 §2.1: leaves are prefixed with 0x00 and
// interior nodes with 0x01. Callers pass the raw bytes of a leaf's digest
// (typically a SHA-256 of the object the leaf commits to); the wrapper
// applies the 0x00 prefix when building the tree and when verifying. Callers
// MUST NOT pre-apply the prefix.
//
// # Multi-proofs are not exposed
//
// CVE-2023-34459 (OpenZeppelin merkle-tree multi-proof zero-internal-node
// forgery) showed that a verifier accepting a flat list of proof + flags can
// be tricked into treating an unauthenticated leaf as an interior node. We
// deliberately do not ship a multi-proof primitive in v1. If a future
// attestor needs to commit to a set rather than a sequence, we will add a
// purpose-specific API with its own audit and CVE-grounded tests rather
// than expose a general multi-proof surface.
//
// # Constant-time root comparison
//
// Final root comparisons go through crypto/subtle.ConstantTimeCompare rather
// than bytes.Equal. Inclusion verification leaks no information by design
// (the proof structure is public), but constant-time comparison is the
// correct default for any path that mixes attacker-supplied bytes with a
// secret-style "expected" value — and it costs nothing here.
package merkle

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Construction is the canonical tree construction identifier emitted in v0.3
// predicates.
const Construction = "RFC6962"

// Hash is the algorithm identifier emitted in v0.3 predicates. The wrapper
// only supports SHA-256; this constant exists for predicate authors to copy.
const Hash = "sha256"

// HashSize is the byte length of every leaf, interior, and root hash.
const HashSize = sha256.Size

// hasher is the SHA-256 RFC 6962 hasher. Kept as a package-level value so the
// API never exposes a way to swap algorithms.
var hasher = rfc6962.DefaultHasher

// Tree is an immutable RFC 6962 Merkle tree over a fixed leaf set.
type Tree struct {
	size   uint64
	hashes [][][]byte // hashes[level][index]
}

// NewTree builds an RFC 6962 Merkle tree from the given leaf digests.
// leaves[i] is the i-th leaf's raw digest bytes (sha256). NewTree internally
// applies the 0x00 leaf domain prefix and the 0x01 interior prefix per
// RFC 6962 §2.1. The empty slice produces a tree of size zero whose root is
// SHA-256("") per RFC 6962 §2.1.
func NewTree(leaves [][]byte) (*Tree, error) {
	t := &Tree{}
	for i, l := range leaves {
		if len(l) != HashSize {
			return nil, fmt.Errorf("merkle: leaf %d has length %d, want %d", i, len(l), HashSize)
		}
		t.appendLeaf(hasher.HashLeaf(l))
	}
	return t, nil
}

// appendLeaf inserts a leaf hash and folds completed perfect subtrees, using
// the same algorithm as transparency-dev/merkle/testonly.Tree (the canonical
// reference implementation in that module). We re-host the row-by-row store
// here so callers never depend on a /testonly path.
func (t *Tree) appendLeaf(hash []byte) {
	level := 0
	for ; (t.size>>level)&1 == 1; level++ {
		row := append(t.hashes[level], hash)
		hash = hasher.HashChildren(row[len(row)-2], hash)
		t.hashes[level] = row
	}
	if level == len(t.hashes) {
		t.hashes = append(t.hashes, nil)
	}
	t.hashes[level] = append(t.hashes[level], hash)
	t.size++
}

// Root returns the Merkle root of the tree.
func (t *Tree) Root() []byte {
	if t.size == 0 {
		return hasher.EmptyRoot()
	}
	ids := compact.RangeNodes(0, t.size, nil)
	hashes := t.getNodes(ids)
	hash := hashes[len(hashes)-1]
	for i := len(hashes) - 2; i >= 0; i-- {
		hash = hasher.HashChildren(hashes[i], hash)
	}
	return hash
}

// Size returns the leaf count of the tree.
func (t *Tree) Size() uint64 {
	return t.size
}

// InclusionProof returns the audit path for the leaf at the given index.
// Requires 0 <= index < Size(). The returned slice contains HashSize-byte
// hashes ordered from lower-tree levels to upper, per RFC 6962 §2.1.1.
func (t *Tree) InclusionProof(index uint64) ([][]byte, error) {
	if index >= t.size {
		return nil, fmt.Errorf("merkle: index %d out of range for tree size %d", index, t.size)
	}
	nodes, err := proof.Inclusion(index, t.size)
	if err != nil {
		return nil, fmt.Errorf("merkle: inclusion proof: %w", err)
	}
	return nodes.Rehash(t.getNodes(nodes.IDs), hasher.HashChildren)
}

func (t *Tree) getNodes(ids []compact.NodeID) [][]byte {
	hashes := make([][]byte, len(ids))
	for i, id := range ids {
		hashes[i] = t.hashes[id.Level][id.Index]
	}
	return hashes
}

// VerifyInclusion verifies an audit path. leafHash is the raw digest of the
// leaf (without the 0x00 prefix — VerifyInclusion applies it).
//
// Returns nil on success and a descriptive error on failure. Error messages
// distinguish digest size, tree-size sentinel, index range, proof element
// length, and root mismatch so callers can log usefully. The upstream
// proof.RootFromInclusionProof enforces exact audit-path length for
// (treeSize, leafIndex), so a too-short or too-long path is rejected at the
// crypto layer before the root comparison.
func VerifyInclusion(treeSize, leafIndex uint64, leafHash []byte, proofPath [][]byte, root []byte) error {
	if treeSize == 0 {
		return errors.New("merkle: cannot verify inclusion against an empty tree")
	}
	if len(root) != HashSize {
		return fmt.Errorf("merkle: root has length %d, want %d", len(root), HashSize)
	}
	if err := validateLeafAndProofShape(leafHash, proofPath); err != nil {
		return err
	}
	// The wrapper's contract is that callers pass the RAW leaf digest
	// (without the 0x00 prefix); RFC 6962 §2.1 says interior chaining starts
	// from MTH({leaf}) = H(0x00 || leaf). Apply the leaf prefix here so the
	// upstream RootFromInclusionProof — which assumes its leafHash argument
	// is already H(0x00 || leaf) — receives the right input.
	calc, err := proof.RootFromInclusionProof(hasher, leafIndex, treeSize, hasher.HashLeaf(leafHash), proofPath)
	if err != nil {
		return fmt.Errorf("merkle: %w", err)
	}
	// constant-time: never replace this with bytes.Equal. Final root
	// comparison goes through crypto/subtle.ConstantTimeCompare per the
	// package-doc rationale (verified in TestConstantTimeRootCompareBehaviour).
	if subtle.ConstantTimeCompare(calc, root) != 1 {
		return errors.New("merkle: calculated root does not match expected root")
	}
	return nil
}

// RootFromInclusionProof recomputes the root from leafHash + proofPath
// without trusting any claimed root. It is the safe primitive for callers
// who want to compare against multiple candidate roots (e.g., chained
// VSAs).
func RootFromInclusionProof(treeSize, leafIndex uint64, leafHash []byte, proofPath [][]byte) ([]byte, error) {
	if treeSize == 0 {
		return nil, errors.New("merkle: cannot derive root from an empty tree")
	}
	if err := validateLeafAndProofShape(leafHash, proofPath); err != nil {
		return nil, err
	}
	r, err := proof.RootFromInclusionProof(hasher, leafIndex, treeSize, hasher.HashLeaf(leafHash), proofPath)
	if err != nil {
		return nil, fmt.Errorf("merkle: %w", err)
	}
	return r, nil
}

func validateLeafAndProofShape(leafHash []byte, proofPath [][]byte) error {
	if len(leafHash) != HashSize {
		return fmt.Errorf("merkle: leafHash has length %d, want %d", len(leafHash), HashSize)
	}
	for i, p := range proofPath {
		if len(p) != HashSize {
			return fmt.Errorf("merkle: proof element %d has length %d, want %d", i, len(p), HashSize)
		}
	}
	return nil
}
