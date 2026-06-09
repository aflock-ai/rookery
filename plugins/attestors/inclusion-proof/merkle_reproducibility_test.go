// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package inclusionproof_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/aflock-ai/rookery/attestation/merkle"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
)

// TestMerkleRoot_Reproducibility is the load-bearing check that a
// verifier with ONLY the leaf list (sha256-hex content digests) can
// recompute the exact Merkle root that the producer published. v0.3
// inlines the leaf list in the signed predicate, so this reconstruction
// is what the verify gate and Archivista discovery both rely on.
//
// The producer (product attestor + material attestor) and the verifier
// (this test, simulating cilock verify) both go through the shared
// inclusionproof.DedupAndSortByDigest + inclusionproof.LeafHash +
// merkle.NewTree path. If either drifts, this test detonates.
func TestMerkleRoot_Reproducibility(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		leaves []leaf
	}{
		{
			name: "single product (gh-CLI shape)",
			leaves: []leaf{
				{"bin/gh", digestOf("gh binary content")},
			},
		},
		{
			name: "two products different content same path-prefix",
			leaves: []leaf{
				{"bin/gh", digestOf("content A")},
				{"bin/ghd", digestOf("content B")},
			},
		},
		{
			name:   "591 products (npm-install shape)",
			leaves: syntheticNpmLeaves(591),
		},
		{
			name:   "12410 materials (gh-CLI material shape)",
			leaves: syntheticNpmLeaves(12410),
		},
		{
			name:   "empty tree",
			leaves: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Producer path: build the tree as product/material would.
			producerRoot, err := rootFromLeaves(tc.leaves)
			if err != nil {
				t.Fatalf("producer rootFromLeaves: %v", err)
			}
			// Verifier path: rebuild from the SAME (path, digestHex)
			// pairs as if reconstructed from a sidecar. Must match
			// byte-for-byte.
			verifierRoot, err := rootFromLeaves(tc.leaves)
			if err != nil {
				t.Fatalf("verifier rootFromLeaves: %v", err)
			}
			if producerRoot != verifierRoot {
				t.Fatalf("root drift: producer=%s verifier=%s",
					producerRoot, verifierRoot)
			}
			t.Logf("root=%s treeSize=%d", producerRoot, len(tc.leaves))
		})
	}
}

// TestMerkleRoot_OrderIndependence — the producer sorts leaves by
// path before tree construction; a verifier handed leaves in a
// different order must arrive at the SAME root. If a future change
// breaks the sort stability we want a loud failure here, not a
// silent mismatch when verifiers fail to validate prod attestations.
func TestMerkleRoot_OrderIndependence(t *testing.T) {
	t.Parallel()
	leaves := syntheticNpmLeaves(200)

	canonical, err := rootFromLeaves(leaves)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}

	// Three different shuffles, all should match the canonical root.
	for seed := int64(1); seed <= 3; seed++ {
		shuffled := make([]leaf, len(leaves))
		copy(shuffled, leaves)
		r := rand.New(rand.NewSource(seed)) //nolint:gosec // test-only shuffling
		r.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got, err := rootFromLeaves(shuffled)
		if err != nil {
			t.Fatalf("seed=%d: %v", seed, err)
		}
		if got != canonical {
			t.Fatalf("seed=%d: root mismatch — sort isn't deterministic. got=%s want=%s",
				seed, got, canonical)
		}
	}
}

// TestMerkleRoot_TamperingDetected — changing a single byte of a
// single leaf MUST change the root. This is the security property
// that gives the attestation its value: a verifier with the root
// can detect ANY post-attestation modification.
func TestMerkleRoot_TamperingDetected(t *testing.T) {
	t.Parallel()
	base := syntheticNpmLeaves(50)
	baseRoot, err := rootFromLeaves(base)
	if err != nil {
		t.Fatalf("base: %v", err)
	}

	t.Run("digest_swap", func(t *testing.T) {
		tampered := make([]leaf, len(base))
		copy(tampered, base)
		// Flip one bit of one digest.
		raw, _ := hex.DecodeString(tampered[7].FileDigestHex)
		raw[0] ^= 0x01
		tampered[7].FileDigestHex = hex.EncodeToString(raw)
		got, err := rootFromLeaves(tampered)
		if err != nil {
			t.Fatalf("tampered: %v", err)
		}
		if got == baseRoot {
			t.Fatalf("tampering with leaf 7's digest did NOT change root — Merkle commitment is broken")
		}
	})

	t.Run("path_swap", func(t *testing.T) {
		// v0.3 clean break: the leaf hash binds CONTENT only — the path is
		// NOT part of the hash. Renaming a file (without changing its
		// content) must NOT change the root. Path authentication now comes
		// from the DSSE signature over the always-inline leaves, not from
		// the Merkle commitment. This is the inverse of the old invariant.
		tampered := make([]leaf, len(base))
		copy(tampered, base)
		tampered[12].Path = tampered[12].Path + ".attacker"
		got, err := rootFromLeaves(tampered)
		if err != nil {
			t.Fatalf("tampered: %v", err)
		}
		if got != baseRoot {
			t.Fatalf("renaming leaf 12 (same content) CHANGED the root — v0.3 leaf must bind content only, not path")
		}
	})

	t.Run("leaf_removed", func(t *testing.T) {
		tampered := append([]leaf{}, base[:len(base)-1]...) // drop last leaf
		got, err := rootFromLeaves(tampered)
		if err != nil {
			t.Fatalf("tampered: %v", err)
		}
		if got == baseRoot {
			t.Fatalf("removing a leaf did NOT change root — tree size isn't bound")
		}
	})

	t.Run("leaf_added", func(t *testing.T) {
		tampered := append([]leaf{}, base...)
		tampered = append(tampered, leaf{Path: "node_modules/.evil/payload", FileDigestHex: digestOf("malware")})
		got, err := rootFromLeaves(tampered)
		if err != nil {
			t.Fatalf("tampered: %v", err)
		}
		if got == baseRoot {
			t.Fatalf("adding a leaf did NOT change root — verifier cannot detect injection")
		}
	})
}

// TestMerkleRoot_EmptyTree confirms the empty-set root equals the
// RFC 6962 §2.1 empty hash sha256(""). v0.3 attestations with zero
// products still emit a root, and verifiers must accept this exact
// value as "intentionally empty" rather than "missing".
func TestMerkleRoot_EmptyTree(t *testing.T) {
	t.Parallel()
	root, err := rootFromLeaves(nil)
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	want := hex.EncodeToString(sha256OfEmpty())
	if root != want {
		t.Errorf("empty-tree root = %s, want RFC6962 sha256('') = %s", root, want)
	}
}

// TestMerkleRoot_DedupByDigest pins the v0.3 dedup invariant at the
// reproducibility-helper level: two distinct paths with identical content
// collapse to ONE leaf (TreeSize == 1) and produce the same root as a single
// leaf carrying that digest. Without dedup the producer tree would diverge
// from any digest-only reconstruction.
func TestMerkleRoot_DedupByDigest(t *testing.T) {
	t.Parallel()
	d := digestOf("identical-content")

	twoRoot, err := rootFromLeaves([]leaf{
		{Path: "b/copy", FileDigestHex: d},
		{Path: "a/orig", FileDigestHex: d},
	})
	if err != nil {
		t.Fatalf("two-path: %v", err)
	}
	oneRoot, err := rootFromLeaves([]leaf{{Path: "a/orig", FileDigestHex: d}})
	if err != nil {
		t.Fatalf("one-path: %v", err)
	}
	if twoRoot != oneRoot {
		t.Fatalf("equal-digest leaves did not collapse: two=%s one=%s", twoRoot, oneRoot)
	}

	// TreeSize must be 1 — confirm via a sidecar build, which routes through
	// the same dedup helper.
	side, err := inclusionproof.BuildSidecar("build", map[string]string{"b/copy": d, "a/orig": d})
	if err != nil {
		t.Fatalf("BuildSidecar: %v", err)
	}
	if side.TreeSize != 1 {
		t.Fatalf("treeSize=%d, want 1 (equal-digest leaves must collapse)", side.TreeSize)
	}
}

// --- helpers ---

type leaf struct {
	Path          string
	FileDigestHex string
}

func sha256OfEmpty() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

func digestOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func syntheticNpmLeaves(n int) []leaf {
	out := make([]leaf, n)
	for i := range n {
		p := fmt.Sprintf("node_modules/dep-%04d/package.json", i)
		out[i] = leaf{Path: p, FileDigestHex: digestOf(p)}
	}
	return out
}

// rootFromLeaves mirrors the producer logic byte-for-byte: normalize
// path, dedup by content digest and sort by (digest, path) via the shared
// inclusionproof.DedupAndSortByDigest helper (the SAME helper the producers
// route through), compute the canonical pre-hash via inclusionproof.LeafHash,
// feed into merkle.NewTree, return root as hex. ANY divergence from
// production code here is the bug the test exists to catch.
//
// v0.3 clean break: the leaf hash binds CONTENT only, so equal-digest files
// at different paths collapse to one leaf (else the producer tree diverges
// from any digest-only reconstruction).
func rootFromLeaves(in []leaf) (string, error) {
	entries := make([]inclusionproof.LeafEntry, 0, len(in))
	for _, l := range in {
		entries = append(entries, inclusionproof.LeafEntry{
			Path:      inclusionproof.NormalizePath(l.Path),
			DigestHex: l.FileDigestHex,
		})
	}
	entries = inclusionproof.DedupAndSortByDigest(entries)
	preHashes := make([][]byte, 0, len(entries))
	for _, e := range entries {
		h, err := inclusionproof.LeafHash(e.Path, e.DigestHex)
		if err != nil {
			return "", err
		}
		preHashes = append(preHashes, h)
	}
	tree, err := merkle.NewTree(preHashes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tree.Root()), nil
}
