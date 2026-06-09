// Copyright 2026 TestifySec, Inc.
//
// SPDX-License-Identifier: Apache-2.0

package inclusionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the v0.3 leaf-hash CLEAN BREAK: the path is no longer an
// input to the leaf hash. Path authentication now comes from the DSSE
// signature over the always-inline leaves, not from the Merkle commitment.
//
// NOTE on domain separation: LeafHashWithDomain provides cross-APPLICATION
// separation (E4 citation-hijack) and these tests assert that API property.
// The software-build product/material attestors use the EMPTY (canonical)
// domain today — they are separated from each other by distinct, root-specific
// inclusion proofs (tested in attestation/merkle TestCrossTreeProofReplay), not
// by a domain. Non-empty domains are reserved for future per-application
// attestor types (corpus citation, sensor telemetry, ...).
//
// Written RED before the implementation: they fail against the path-in-hash
// construction and go green once LeafHashWithDomain drops the path.

// TestLeafHash_PathIndependent: the same content digest hashes to the same
// leaf regardless of the path. This is the property that makes a traced
// build's absolute-path product leaf reconstructible from the artifact alone
// (Archivista digest-discovery) and makes attestations reproducible.
func TestLeafHash_PathIndependent(t *testing.T) {
	d := digestHex([]byte("identical-content"))

	a, err := LeafHash("/tmp/build/cilock", d)
	require.NoError(t, err)
	b, err := LeafHash("cilock", d)
	require.NoError(t, err)
	c, err := LeafHash("some/other/path", d)
	require.NoError(t, err)

	assert.Equal(t, a, b, "leaf hash must not depend on the path")
	assert.Equal(t, a, c, "leaf hash must not depend on the path")
}

// TestLeafHash_EmptyPathAccepted: with the path out of the hash, an empty
// path is no longer special — it must not error.
func TestLeafHash_EmptyPathAccepted(t *testing.T) {
	d := digestHex([]byte("body"))
	h, err := LeafHash("", d)
	require.NoError(t, err)
	require.Len(t, h, sha256.Size)
}

// TestLeafHash_DigestOnlyConstruction: empty-domain leaf == sha256(rawDigest).
func TestLeafHash_DigestOnlyConstruction(t *testing.T) {
	body := []byte("payload")
	d := digestHex(body)
	raw, err := hex.DecodeString(d)
	require.NoError(t, err)

	want := sha256.Sum256(raw)
	got, err := LeafHash("ignored/path", d)
	require.NoError(t, err)
	assert.Equal(t, want[:], got, "empty-domain leaf = sha256(rawDigest)")
}

// TestLeafHashWithDomain_DomainOnlyConstruction: non-empty-domain leaf ==
// sha256(domain || 0x00 || rawDigest). Domain separation is retained.
func TestLeafHashWithDomain_DomainOnlyConstruction(t *testing.T) {
	d := digestHex([]byte("payload"))
	raw, err := hex.DecodeString(d)
	require.NoError(t, err)

	h := sha256.New()
	h.Write([]byte("rookery-product/v0.3"))
	h.Write([]byte{0x00})
	h.Write(raw)
	want := h.Sum(nil)

	got, err := LeafHashWithDomain("rookery-product/v0.3", "any/path", d)
	require.NoError(t, err)
	assert.Equal(t, want, got, "domain leaf = sha256(domain || 0x00 || rawDigest)")
}

// TestLeafHashWithDomain_SeparationPreserved: the E4 citation-hijack defense
// MUST survive remove-path — different domains (and the empty domain) yield
// distinct leaves for the same digest.
func TestLeafHashWithDomain_SeparationPreserved(t *testing.T) {
	d := digestHex([]byte("shared-content"))

	empty, err := LeafHashWithDomain("", "p", d)
	require.NoError(t, err)
	prod, err := LeafHashWithDomain("rookery-product/v0.3", "p", d)
	require.NoError(t, err)
	mat, err := LeafHashWithDomain("rookery-material/v0.3", "p", d)
	require.NoError(t, err)

	assert.NotEqual(t, empty, prod, "domain must separate from empty")
	assert.NotEqual(t, empty, mat, "domain must separate from empty")
	assert.NotEqual(t, prod, mat, "distinct domains must separate")
}

// TestBuildSidecar_DedupByDigest pins the v0.3 dedup invariant: now that the
// leaf hash binds content only, two distinct paths with the SAME digest MUST
// collapse to ONE leaf (else the producer tree diverges from any digest-only
// reconstruction). The surviving leaf keeps the lexicographically-smallest
// path, and the deduped root equals the single-leaf root.
func TestBuildSidecar_DedupByDigest(t *testing.T) {
	d := digestHex([]byte("same-content"))

	two, err := BuildSidecar("build", map[string]string{"b/y": d, "a/x": d})
	require.NoError(t, err)
	one, err := BuildSidecar("build", map[string]string{"a/x": d})
	require.NoError(t, err)

	require.Equal(t, uint64(1), two.TreeSize, "equal-digest leaves must collapse to one")
	require.Len(t, two.Leaves, 1)
	assert.Equal(t, "a/x", two.Leaves[0].Path, "survivor keeps the smallest path")
	assert.Equal(t, one.MerkleRoot, two.MerkleRoot, "deduped root == single-leaf root")
}

// TestBuildSidecar_Deterministic: same logical input (any map order) yields a
// byte-stable sidecar (root AND leaf order), required for reproducible builds.
func TestBuildSidecar_Deterministic(t *testing.T) {
	d1 := digestHex([]byte("one"))
	d2 := digestHex([]byte("two"))
	d3 := digestHex([]byte("three"))

	a, err := BuildSidecar("build", map[string]string{"p1": d1, "p2": d2, "p3": d3})
	require.NoError(t, err)
	b, err := BuildSidecar("build", map[string]string{"p3": d3, "p1": d1, "p2": d2})
	require.NoError(t, err)

	assert.Equal(t, a.MerkleRoot, b.MerkleRoot)
	assert.Equal(t, a.Leaves, b.Leaves, "leaf order is canonical regardless of input order")
}

// TestReconstruct_TamperRejection deterministically proves the soundness
// property the fuzzer exercises: a tampered leaf set (content digest flipped,
// leaf added, dropped, or duplicated) keeping the honest claimed root/size MUST
// fail Reconstruct. Path-only edits are intentionally NOT root-bound (the DSSE
// signature over the inline leaves protects the path) and reconstruct OK here.
func TestReconstruct_TamperRejection(t *testing.T) {
	dg := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	honest, err := BuildSidecar("build", map[string]string{"a": dg("A"), "b": dg("B"), "c": dg("C")})
	require.NoError(t, err)
	require.Equal(t, uint64(3), honest.TreeSize)
	_, _, err = honest.Reconstruct()
	require.NoError(t, err, "honest sidecar must reconstruct")

	clone := func() Sidecar {
		s := honest
		s.Leaves = append([]SidecarLeaf(nil), honest.Leaves...)
		return s
	}

	t.Run("digest_flip_each_leaf_rejected", func(t *testing.T) {
		for k := range honest.Leaves {
			s := clone()
			raw, _ := hex.DecodeString(s.Leaves[k].FileDigest)
			raw[0] ^= 0x01
			s.Leaves[k].FileDigest = hex.EncodeToString(raw)
			_, _, e := s.Reconstruct()
			require.Error(t, e, "content tamper on leaf %d must be rejected", k)
		}
	})
	t.Run("extra_leaf_rejected", func(t *testing.T) {
		s := clone()
		s.Leaves = append(s.Leaves, SidecarLeaf{Path: "z", FileDigest: dg("SMUGGLED")})
		_, _, e := s.Reconstruct()
		require.Error(t, e, "an extra leaf under the honest root must be rejected")
	})
	t.Run("drop_each_leaf_rejected", func(t *testing.T) {
		for k := range honest.Leaves {
			s := clone()
			s.Leaves = append(s.Leaves[:k:k], honest.Leaves[k+1:]...)
			_, _, e := s.Reconstruct()
			require.Error(t, e, "dropping leaf %d must be rejected", k)
		}
	})
	t.Run("duplicate_each_leaf_rejected", func(t *testing.T) {
		for k := range honest.Leaves {
			s := clone()
			s.Leaves = append(s.Leaves, honest.Leaves[k])
			_, _, e := s.Reconstruct()
			require.Error(t, e, "duplicating leaf %d must be rejected", k)
		}
	})
	t.Run("path_only_change_reconstructs_DSSE_protects_path", func(t *testing.T) {
		s := clone()
		last := len(s.Leaves) - 1
		s.Leaves[last].Path += "~moved" // same digest, still canonical order
		_, _, e := s.Reconstruct()
		require.NoError(t, e, "path is not root-bound by design; the DSSE signature protects it")
	})
}

// TestSidecar_DoSCapRejectsOversizedTreeSize guards the unbounded-leaf DoS:
// a tiny crafted sidecar claiming an enormous treeSize must be rejected at
// decode, before any tree allocation. (The leaf-array path is bounded by the
// same MaxLeaves cap + the 512 MiB bundle limit.)
func TestSidecar_DoSCapRejectsOversizedTreeSize(t *testing.T) {
	j := fmt.Sprintf(`{"schemaVersion":%q,"source":"x","merkleRoot":"00","treeSize":%d,"hashAlgorithm":%q,"construction":%q,"leaves":[]}`,
		SidecarSchemaVersion, uint64(MaxLeaves)+1, HashAlgorithm, Construction)
	_, err := ReadSidecar(strings.NewReader(j))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds MaxLeaves")
}
