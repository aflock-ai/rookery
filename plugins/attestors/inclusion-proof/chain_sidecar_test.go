// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package inclusionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/merkle"
)

// sourceTreeFor builds a step-1 product Merkle tree under a given domain
// and returns the bindings + leaves a producer would publish + the
// signed envelope digest (synthesized for the test).
func sourceTreeFor(t *testing.T, domain string, in []SidecarLeaf) (SourceStepRef, []SidecarLeaf) {
	t.Helper()
	leaves := append([]SidecarLeaf{}, in...)
	for i := range leaves {
		leaves[i].Path = NormalizePath(leaves[i].Path)
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Path < leaves[j].Path })

	preHashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := LeafHashWithDomain(domain, l.Path, l.FileDigest)
		if err != nil {
			t.Fatalf("sourceTreeFor: %v", err)
		}
		preHashes[i] = h
	}
	tree, err := merkle.NewTree(preHashes)
	if err != nil {
		t.Fatalf("sourceTreeFor: NewTree: %v", err)
	}

	// Fake envelope digest — in production this is sha256(DSSE payload).
	envDigest := sha256.Sum256([]byte("test envelope payload " + domain))
	return SourceStepRef{
		StepName:       "source",
		EnvelopeDigest: hex.EncodeToString(envDigest[:]),
		MerkleRoot:     hex.EncodeToString(tree.Root()),
		TreeSize:       tree.Size(),
		Domain:         domain,
	}, leaves
}

func digestStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestChainSidecar_HappyPath proves the de-risk question: can a
// producer at step 2 build a chain sidecar from step 1's leaves +
// the materials it consumed, and can a separate verifier confirm
// every proof using only the signed root?
func TestChainSidecar_HappyPath(t *testing.T) {
	const domain = "rookery-product/v0.3"
	source, leaves := sourceTreeFor(t, domain, []SidecarLeaf{
		{Path: "src/main.go", FileDigest: digestStr("main")},
		{Path: "src/util.go", FileDigest: digestStr("util")},
		{Path: "src/parser.go", FileDigest: digestStr("parser")},
		{Path: "go.mod", FileDigest: digestStr("module")},
		{Path: "go.sum", FileDigest: digestStr("sum")},
	})

	// Step 2 consumes a SUBSET of step 1's products (the realistic case).
	consumed := []ConsumedMaterial{
		{Path: "src/main.go", FileDigest: digestStr("main")},
		{Path: "src/parser.go", FileDigest: digestStr("parser")},
		{Path: "go.mod", FileDigest: digestStr("module")},
	}

	chain, err := BuildChainSidecar(source, leaves, consumed)
	if err != nil {
		t.Fatalf("BuildChainSidecar: %v", err)
	}
	if len(chain.MaterialProofs) != len(consumed) {
		t.Fatalf("expected %d proofs, got %d", len(consumed), len(chain.MaterialProofs))
	}

	// Verifier side: knows only the signed envelope (digest + root +
	// treeSize + domain), receives the chain sidecar, validates.
	if err := VerifyChainSidecar(chain); err != nil {
		t.Fatalf("VerifyChainSidecar: %v", err)
	}
	t.Logf("verified %d inclusion proofs against source root %s (size %d)",
		len(chain.MaterialProofs), source.MerkleRoot, source.TreeSize)
}

// TestChainSidecar_RejectsMaterialNotInSource is the producer-side
// guard against fabricating a proof for a material that wasn't in the
// upstream product set. Closes the construction-time hole — a chain
// sidecar that doesn't exist can't be tampered with.
func TestChainSidecar_RejectsMaterialNotInSource(t *testing.T) {
	const domain = "rookery-product/v0.3"
	source, leaves := sourceTreeFor(t, domain, []SidecarLeaf{
		{Path: "src/legit.go", FileDigest: digestStr("legit")},
	})
	consumed := []ConsumedMaterial{
		{Path: "src/payload.go", FileDigest: digestStr("malware")},
	}
	_, err := BuildChainSidecar(source, leaves, consumed)
	if err == nil {
		t.Fatalf("BuildChainSidecar fabricated a proof for a non-source material")
	}
	if !strings.Contains(err.Error(), "NOT a product of source step") {
		t.Errorf("expected 'NOT a product of source step' in error, got: %v", err)
	}
}

// TestChainSidecar_RejectsDigestMismatch — the path is in source but
// the consumed material's digest differs. Producer must refuse rather
// than generate a proof that wouldn't verify anyway (loud failure at
// construction is better than a confusing failure at verify time).
func TestChainSidecar_RejectsDigestMismatch(t *testing.T) {
	const domain = "rookery-product/v0.3"
	source, leaves := sourceTreeFor(t, domain, []SidecarLeaf{
		{Path: "src/main.go", FileDigest: digestStr("v1")},
	})
	consumed := []ConsumedMaterial{
		{Path: "src/main.go", FileDigest: digestStr("v2 (attacker)")},
	}
	_, err := BuildChainSidecar(source, leaves, consumed)
	if err == nil {
		t.Fatalf("BuildChainSidecar accepted a digest mismatch")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("expected 'digest' in error, got: %v", err)
	}
}

// TestChainSidecar_TamperedAuditPath_RejectedAtVerify — even if a
// hostile producer built a sidecar with a fabricated audit path, the
// verifier's cryptographic check catches it.
func TestChainSidecar_TamperedAuditPath_RejectedAtVerify(t *testing.T) {
	const domain = "rookery-product/v0.3"
	source, leaves := sourceTreeFor(t, domain, []SidecarLeaf{
		{Path: "a", FileDigest: digestStr("a")},
		{Path: "b", FileDigest: digestStr("b")},
		{Path: "c", FileDigest: digestStr("c")},
		{Path: "d", FileDigest: digestStr("d")},
	})
	chain, err := BuildChainSidecar(source, leaves, []ConsumedMaterial{
		{Path: "a", FileDigest: digestStr("a")},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Flip one bit of one audit-path entry.
	raw, _ := hex.DecodeString(chain.MaterialProofs[0].AuditPath[0])
	raw[0] ^= 0x01
	chain.MaterialProofs[0].AuditPath[0] = hex.EncodeToString(raw)

	err = VerifyChainSidecar(chain)
	if err == nil {
		t.Fatalf("verifier accepted tampered audit path")
	}
	var ce ErrChainProofFailed
	if !errors.As(err, &ce) {
		t.Errorf("expected ErrChainProofFailed, got %T: %v", err, err)
	}
}

// TestChainSidecar_DomainSeparation_PreventsCrossDomainReuse — proves
// the issue #191 motivation: a proof generated under domain A cannot
// be replayed under domain B even with identical (path, digest) leaf
// data. Closes threat-model E4 (citation hijacking) cryptographically.
//
// The attack model: attacker has a valid chain sidecar produced under
// domain A (e.g. they legitimately consumed software-supply-chain
// products), and tries to claim those same proofs cover the consumption
// under domain B (e.g. corpus citation). Domain separation must make
// the proofs non-transferable across domain boundaries.
//
// Uses a 4-leaf tree so the audit path is non-empty — single-leaf
// trees would let the verifier reconstruct the root by hashing the
// claimed leaf alone, which trivially succeeds under any claimed
// domain consistent with the supplied root.
func TestChainSidecar_DomainSeparation_PreventsCrossDomainReuse(t *testing.T) {
	const domainA = "rookery-product/v0.3"
	const domainB = "corpus-citation-v1"

	// Same logical leaves under two domains.
	logical := []SidecarLeaf{
		{Path: "shared/a.dat", FileDigest: digestStr("a")},
		{Path: "shared/b.dat", FileDigest: digestStr("b")},
		{Path: "shared/c.dat", FileDigest: digestStr("c")},
		{Path: "shared/d.dat", FileDigest: digestStr("d")},
	}
	consumed := []ConsumedMaterial{
		{Path: "shared/a.dat", FileDigest: digestStr("a")},
	}

	sourceA, leavesA := sourceTreeFor(t, domainA, logical)
	sourceB, _ := sourceTreeFor(t, domainB, logical)
	if sourceA.MerkleRoot == sourceB.MerkleRoot {
		t.Fatalf("domain separation broken: identical leaves yielded identical roots across domains")
	}

	chainA, err := BuildChainSidecar(sourceA, leavesA, consumed)
	if err != nil {
		t.Fatalf("buildA: %v", err)
	}

	// Attacker holds chainA. They forge a sidecar claiming the proofs
	// cover domain-B consumption: re-tag the domain + envelope ref,
	// but the audit path is still from domain A's tree. The verifier
	// MUST detect this because hashing the leaf under domain B and
	// reconstructing through A's audit path won't yield B's root.
	forged := chainA
	forged.SourceStep.Domain = domainB
	forged.SourceStep.MerkleRoot = sourceB.MerkleRoot
	forged.SourceStep.EnvelopeDigest = sourceB.EnvelopeDigest

	err = VerifyChainSidecar(forged)
	if err == nil {
		t.Fatalf("verifier accepted cross-domain proof reuse — citation hijacking still possible")
	}
	var ce ErrChainProofFailed
	if !errors.As(err, &ce) {
		t.Errorf("expected ErrChainProofFailed, got %T: %v", err, err)
	}
}

// TestChainSidecar_RejectsUnsortedSourceLeaves — index correctness
// depends on the producer feeding leaves in the same order the tree
// was originally built. Catch sort drift at construction.
func TestChainSidecar_RejectsUnsortedSourceLeaves(t *testing.T) {
	const domain = "rookery-product/v0.3"
	source, leaves := sourceTreeFor(t, domain, []SidecarLeaf{
		{Path: "src/a.go", FileDigest: digestStr("a")},
		{Path: "src/b.go", FileDigest: digestStr("b")},
	})
	// Reverse on purpose.
	reversed := []SidecarLeaf{leaves[1], leaves[0]}
	_, err := BuildChainSidecar(source, reversed, []ConsumedMaterial{
		{Path: "src/a.go", FileDigest: digestStr("a")},
	})
	if err == nil {
		t.Fatalf("BuildChainSidecar accepted unsorted leaves")
	}
}

// TestChainSidecar_TreeSizeMismatch — defends against a producer that
// supplies a leaves slice whose length disagrees with source.TreeSize.
// Catches a class of bugs where the sidecar load shape silently
// truncates or pads.
func TestChainSidecar_TreeSizeMismatch(t *testing.T) {
	source, leaves := sourceTreeFor(t, "rookery-product/v0.3", []SidecarLeaf{
		{Path: "a", FileDigest: digestStr("a")},
		{Path: "b", FileDigest: digestStr("b")},
	})
	// Lie about TreeSize.
	source.TreeSize = 99
	_, err := BuildChainSidecar(source, leaves, []ConsumedMaterial{
		{Path: "a", FileDigest: digestStr("a")},
	})
	if err == nil {
		t.Fatalf("BuildChainSidecar accepted tree-size mismatch")
	}
}

// TestChainSidecar_HeavyMaterialSet exercises a realistic-scale chain
// (matches the gh-CLI material treeSize=12410) to confirm proof
// generation + verification stay tractable on real workloads.
func TestChainSidecar_HeavyMaterialSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short: heavy chain build")
	}
	const domain = "rookery-product/v0.3"
	const n = 12410
	leaves := make([]SidecarLeaf, n)
	for i := range n {
		leaves[i] = SidecarLeaf{
			Path:       sortedPath(i),
			FileDigest: digestStr(sortedPath(i)),
		}
	}
	source, leaves := sourceTreeFor(t, domain, leaves)

	// Consume 100 random-ish materials from the tree.
	consumed := make([]ConsumedMaterial, 0, 100)
	for i := 0; i < n; i += n / 100 {
		consumed = append(consumed, ConsumedMaterial{
			Path:       leaves[i].Path,
			FileDigest: leaves[i].FileDigest,
		})
	}

	chain, err := BuildChainSidecar(source, leaves, consumed)
	if err != nil {
		t.Fatalf("BuildChainSidecar (heavy): %v", err)
	}
	if err := VerifyChainSidecar(chain); err != nil {
		t.Fatalf("VerifyChainSidecar (heavy): %v", err)
	}
	t.Logf("heavy chain: source tree size %d, %d proofs, avg audit path %d hashes",
		source.TreeSize, len(chain.MaterialProofs), len(chain.MaterialProofs[0].AuditPath))
}

func sortedPath(i int) string {
	// zero-padded so lexicographic sort == numeric sort
	const prefix = "src/file-"
	digits := "0123456789abcdef"
	var b [8]byte
	for j := 7; j >= 0; j-- {
		b[j] = digits[i&0xf]
		i >>= 4
	}
	return prefix + string(b[:]) + ".go"
}

// TestLeafHashWithDomain_EmptyDomainIsBackCompat confirms that empty
// domain produces the EXACT same bytes as the legacy LeafHash. This
// guarantees existing v0.3 attestations keep verifying after #191
// lands.
func TestLeafHashWithDomain_EmptyDomainIsBackCompat(t *testing.T) {
	path := "src/main.go"
	digest := digestStr("content")
	legacy, err := LeafHash(path, digest)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	domained, err := LeafHashWithDomain("", path, digest)
	if err != nil {
		t.Fatalf("domained: %v", err)
	}
	if hex.EncodeToString(legacy) != hex.EncodeToString(domained) {
		t.Fatalf("back-compat broken: LeafHash=%s LeafHashWithDomain(empty)=%s",
			hex.EncodeToString(legacy), hex.EncodeToString(domained))
	}
}

// TestLeafHashWithDomain_NonEmptyDomainShifts confirms that a
// non-empty domain produces a DIFFERENT hash than empty for the same
// (path, digest) pair.
func TestLeafHashWithDomain_NonEmptyDomainShifts(t *testing.T) {
	path := "src/main.go"
	digest := digestStr("content")
	empty, _ := LeafHashWithDomain("", path, digest)
	domained, _ := LeafHashWithDomain("rookery-product/v0.3", path, digest)
	if hex.EncodeToString(empty) == hex.EncodeToString(domained) {
		t.Fatalf("domain separation broken: same hash with/without domain")
	}
}
