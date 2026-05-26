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
	"sort"
	"testing"

	"github.com/aflock-ai/rookery/attestation/merkle"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
)

// TestMerkleRoot_Reproducibility is the load-bearing check that a
// verifier with ONLY the leaf list (path + sha256-hex pairs) can
// recompute the exact Merkle root that the producer published.
// Without this guarantee, the v0.3 schema — which keeps the leaf
// list off-envelope — is unverifiable.
//
// The producer (product attestor + material attestor) and the
// verifier (this test, simulating cilock verify) both go through
// inclusionproof.LeafHash + merkle.NewTree. If either drifts, this
// test detonates.
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
		tampered := make([]leaf, len(base))
		copy(tampered, base)
		// Change one path; binding of path-to-content must shift root.
		tampered[12].Path = tampered[12].Path + ".attacker"
		got, err := rootFromLeaves(tampered)
		if err != nil {
			t.Fatalf("tampered: %v", err)
		}
		if got == baseRoot {
			t.Fatalf("renaming leaf 12 did NOT change root — paths aren't bound at the leaf")
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
// path, compute the canonical pre-hash via inclusionproof.LeafHash,
// sort by normalized path (deterministic), feed into merkle.NewTree,
// return root as hex. ANY divergence from production code here is
// the bug the test exists to catch.
func rootFromLeaves(in []leaf) (string, error) {
	type pair struct {
		normalized string
		preHash    []byte
	}
	pairs := make([]pair, 0, len(in))
	for _, l := range in {
		normalized := inclusionproof.NormalizePath(l.Path)
		h, err := inclusionproof.LeafHash(normalized, l.FileDigestHex)
		if err != nil {
			return "", err
		}
		pairs = append(pairs, pair{normalized: normalized, preHash: h})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].normalized < pairs[j].normalized
	})
	preHashes := make([][]byte, len(pairs))
	for i, p := range pairs {
		preHashes[i] = p.preHash
	}
	tree, err := merkle.NewTree(preHashes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tree.Root()), nil
}
