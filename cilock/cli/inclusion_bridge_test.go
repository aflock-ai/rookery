// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
)

// productCollectionEnvelope builds a DSSE envelope carrying an
// attestation-collection whose only sub-attestation is a product v0.3 tree.
// The Merkle root and treeSize are computed from digests via the canonical
// BuildSidecar so the fixture matches exactly what the producer emits. When
// inline is true the per-file leaves are embedded in the predicate (the
// default product behaviour); when false they are omitted (WithSuppressInline-
// Leaves). rootOverride, when non-empty, replaces the committed root — used to
// simulate a signer/bug shipping leaves that don't fold to the committed root.
func productCollectionEnvelope(t *testing.T, digests map[string]string, inline bool, rootOverride string) dsse.Envelope {
	t.Helper()
	return collectionEnvelope(t, productTreeType, digests, inline, rootOverride)
}

// collectionEnvelope is productCollectionEnvelope generalised over the
// sub-attestation tree type (product vs material), so adversarial cases can
// target either path.
func collectionEnvelope(t *testing.T, treeType string, digests map[string]string, inline bool, rootOverride string) dsse.Envelope {
	t.Helper()
	side, err := inclusionproof.BuildSidecar("product", digests)
	if err != nil {
		t.Fatalf("BuildSidecar: %v", err)
	}
	root := side.MerkleRoot
	if rootOverride != "" {
		root = rootOverride
	}

	type leaf struct {
		Path       string `json:"path"`
		FileDigest string `json:"fileDigest"`
		LeafHash   string `json:"leafHash"`
	}
	tree := map[string]any{
		"merkleRoot":    root,
		"treeSize":      side.TreeSize,
		"hashAlgorithm": "sha256",
		"construction":  "RFC6962",
	}
	if inline {
		leaves := make([]leaf, 0, len(side.Leaves))
		for _, l := range side.Leaves {
			leaves = append(leaves, leaf{Path: l.Path, FileDigest: l.FileDigest})
		}
		tree["leaves"] = leaves
	}
	treeRaw, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}

	stmt := map[string]any{
		"predicateType": collectionPredicateType,
		"predicate": map[string]any{
			"attestations": []map[string]any{
				{"type": treeType, "attestation": json.RawMessage(treeRaw)},
			},
		},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal stmt: %v", err)
	}
	return dsse.Envelope{Payload: payload}
}

func subjectDigest(hexDigest string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{{Hash: crypto.SHA256}: hexDigest}
}

// hasRoot reports whether the given root hex appears as a SHA-256 subject.
func hasRoot(subjects []cryptoutil.DigestSet, rootHex string) bool {
	for _, ds := range subjects {
		for dv, h := range ds {
			if dv.Hash == crypto.SHA256 && !dv.GitOID && h == rootHex {
				return true
			}
		}
	}
	return false
}

const (
	digApp1 = "1111111111111111111111111111111111111111111111111111111111111111"
	digApp2 = "2222222222222222222222222222222222222222222222222222222222222222"
	digApp3 = "3333333333333333333333333333333333333333333333333333333333333333"
	digNope = "9999999999999999999999999999999999999999999999999999999999999999"
)

func multiLeafDigests() map[string]string {
	return map[string]string{
		"bin/app1": digApp1,
		"bin/app2": digApp2,
		"bin/app3": digApp3,
	}
}

// THE FIX: a multi-leaf product tree with inline leaves resolves any single
// file's digest to the signed root with no inclusion-proof envelope and no
// artifact path — the case that previously failed with exit 1.
func TestInlineLeaves_MultiLeaf_NoEnvelope_NoPath(t *testing.T) {
	digests := multiLeafDigests()
	env := productCollectionEnvelope(t, digests, true, "")
	side, _ := inclusionproof.BuildSidecar("product", digests)

	// Request only app2's digest, with NO artifact path.
	in := []cryptoutil.DigestSet{subjectDigest(digApp2)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if !hasRoot(out, side.MerkleRoot) {
		t.Fatalf("expected tree root %s added as subject for matching inline leaf; got %v", side.MerkleRoot, out)
	}
}

// Fail closed: leaves that do NOT reconstruct to the committed root must never
// bridge an artifact, even when the requested digest matches a leaf. Mirrors
// product/material.VerifyInlineLeaves.
func TestInlineLeaves_ForgedLeaves_FailClosed(t *testing.T) {
	digests := multiLeafDigests()
	// Commit a root that does NOT match the inline leaves.
	env := productCollectionEnvelope(t, digests, true, digNope)
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{subjectDigest(digApp2)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if hasRoot(out, side.MerkleRoot) {
		t.Fatalf("authentic leaf root must not be added when it is not the committed root")
	}
	if hasRoot(out, digNope) {
		t.Fatalf("forged committed root must not be added: leaves do not reconstruct to it")
	}
}

// A digest absent from every leaf is not bridged.
func TestInlineLeaves_AbsentArtifact(t *testing.T) {
	digests := multiLeafDigests()
	env := productCollectionEnvelope(t, digests, true, "")
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{subjectDigest(digNope)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if hasRoot(out, side.MerkleRoot) {
		t.Fatalf("absent artifact digest must not bridge to the tree root")
	}
}

// Suppressed inline leaves with no inclusion-proof envelope and no artifact
// path: nothing to bridge a multi-leaf tree, so the root is not added. (The
// producer-side opt-out fallback; per-file claims then need a proof envelope.)
func TestInlineLeaves_Suppressed_MultiLeaf_NoBridge(t *testing.T) {
	digests := multiLeafDigests()
	env := productCollectionEnvelope(t, digests, false, "")
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{subjectDigest(digApp2)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if hasRoot(out, side.MerkleRoot) {
		t.Fatalf("suppressed leaves + no proof must not bridge a multi-leaf tree")
	}
}

// No regression: the single-leaf reconstruct shortcut still bridges a sole
// product (treeSize==1) from (basename, digest) when leaves are suppressed.
func TestSingleLeafShortcut_NoRegression(t *testing.T) {
	digests := map[string]string{"app": digApp1}
	env := productCollectionEnvelope(t, digests, false, "") // suppressed leaves
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{subjectDigest(digApp1)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "/some/dir/app", digApp1)

	if !hasRoot(out, side.MerkleRoot) {
		t.Fatalf("single-leaf shortcut regressed: expected root %s, got %v", side.MerkleRoot, out)
	}
}

// Single-leaf trees also resolve via the inline-leaf path with no artifact
// path at all (an improvement: the bare `-s <digest>` case now works).
func TestInlineLeaves_SingleLeaf_NoPath(t *testing.T) {
	digests := map[string]string{"app": digApp1}
	env := productCollectionEnvelope(t, digests, true, "")
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{subjectDigest(digApp1)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if !hasRoot(out, side.MerkleRoot) {
		t.Fatalf("single-leaf inline path should resolve with no artifact path; got %v", out)
	}
}

// ---------------------------------------------------------------------------
// Adversarial tests: the core promise is that a file is bridged ONLY when it
// is genuinely committed in the SIGNED tree. Every attack below tries to get
// an attacker-chosen digest accepted; all must fail closed.
// ---------------------------------------------------------------------------

const digMalicious = "dddddddd" + "dddddddd" + "dddddddd" + "dddddddd" +
	"dddddddd" + "dddddddd" + "dddddddd" + "dddddddd"

// LEAF INJECTION: an attacker appends a leaf for their own artifact to the
// inline set but keeps the original (honest) committed root. The injected
// leaf must NOT be bridged, because the tampered leaf set no longer folds to
// the committed root. This is the headline attack the root-recompute guards.
func TestAdversarial_LeafInjection_FailClosed(t *testing.T) {
	honest := multiLeafDigests()
	honestSide, _ := inclusionproof.BuildSidecar("product", honest)

	tampered := multiLeafDigests()
	tampered["bin/evil"] = digMalicious // attacker appends their file

	// Commit the HONEST root but ship the TAMPERED (4-leaf) inline set.
	env := productCollectionEnvelope(t, tampered, true, honestSide.MerkleRoot)

	in := []cryptoutil.DigestSet{subjectDigest(digMalicious)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if hasRoot(out, honestSide.MerkleRoot) {
		t.Fatalf("injected leaf must not bridge to the honest committed root")
	}
}

// LEAF SUBSTITUTION: an attacker swaps an existing leaf's fileDigest to their
// own artifact's digest while keeping the original committed root. Must fail
// closed — the substituted set recomputes to a different root.
func TestAdversarial_LeafSubstitution_FailClosed(t *testing.T) {
	honest := multiLeafDigests()
	honestSide, _ := inclusionproof.BuildSidecar("product", honest)

	tampered := multiLeafDigests()
	tampered["bin/app2"] = digMalicious // same path, attacker content

	env := productCollectionEnvelope(t, tampered, true, honestSide.MerkleRoot)

	in := []cryptoutil.DigestSet{subjectDigest(digMalicious)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if hasRoot(out, honestSide.MerkleRoot) {
		t.Fatalf("substituted leaf digest must not bridge to the honest committed root")
	}
}

// CROSS-TREE CONFUSION: two collections with disjoint file sets. A digest in
// tree A must bridge ONLY A's root, never B's — the bridge must not leak a
// match across unrelated trees.
func TestAdversarial_CrossTree_NoLeak(t *testing.T) {
	treeA := map[string]string{"a/x": digApp1, "a/y": digApp2}
	treeB := map[string]string{"b/p": digApp3, "b/q": digNope}
	sideA, _ := inclusionproof.BuildSidecar("product", treeA)
	sideB, _ := inclusionproof.BuildSidecar("product", treeB)
	if sideA.MerkleRoot == sideB.MerkleRoot {
		t.Fatal("test setup: trees must have distinct roots")
	}

	envA := productCollectionEnvelope(t, treeA, true, "")
	envB := productCollectionEnvelope(t, treeB, true, "")

	in := []cryptoutil.DigestSet{subjectDigest(digApp1)} // in A only
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{envA, envB}, "", "")

	if !hasRoot(out, sideA.MerkleRoot) {
		t.Fatalf("digest present in tree A should bridge A's root")
	}
	if hasRoot(out, sideB.MerkleRoot) {
		t.Fatalf("digest absent from tree B must not bridge B's root")
	}
}

// MATERIAL TREE: the bridge must resolve inline leaves carried by a material
// v0.3 sub-attestation too, not only product — proving the path is
// tree-type-agnostic (the root recompute is source-independent).
func TestInlineLeaves_MaterialTree(t *testing.T) {
	digests := multiLeafDigests()
	env := collectionEnvelope(t, materialTreeType, digests, true, "")
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{subjectDigest(digApp3)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if !hasRoot(out, side.MerkleRoot) {
		t.Fatalf("material-tree inline leaf should bridge; got %v", out)
	}
}

// DEDUPE: several requested digests matching different leaves of the SAME tree
// must add that tree's root exactly once, not once per match.
func TestInlineLeaves_MultiMatch_DedupesRoot(t *testing.T) {
	digests := multiLeafDigests()
	env := productCollectionEnvelope(t, digests, true, "")
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{subjectDigest(digApp1), subjectDigest(digApp2)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	count := 0
	for _, ds := range out {
		for dv, h := range ds {
			if dv.Hash == crypto.SHA256 && !dv.GitOID && h == side.MerkleRoot {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("tree root should be added exactly once across multiple leaf matches, got %d", count)
	}
}

// NON-SHA256 / GITOID requests are ignored: a gitoid-flagged subject whose hex
// happens to equal a leaf digest must NOT bridge (the bridge only considers
// plain SHA-256 file digests).
func TestAdversarial_GitOIDRequest_Ignored(t *testing.T) {
	digests := multiLeafDigests()
	env := productCollectionEnvelope(t, digests, true, "")
	side, _ := inclusionproof.BuildSidecar("product", digests)

	in := []cryptoutil.DigestSet{{{Hash: crypto.SHA256, GitOID: true}: digApp1}}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{env}, "", "")

	if hasRoot(out, side.MerkleRoot) {
		t.Fatalf("gitoid-flagged subject must not be treated as a plain file digest")
	}
}
