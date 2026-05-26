// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package inclusionproof

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation/merkle"
)

// ChainSidecarSchemaVersion is the version tag emitted in every chain
// sidecar so verifiers can refuse formats they don't understand. Bump
// on any breaking schema change.
const ChainSidecarSchemaVersion = "rookery.chain-proof.sidecar/v0.1"

// SourceStepRef binds a chain sidecar to the specific upstream
// attestation it claims to chain from. The envelopeDigest field is the
// load-bearing field: a proof against tree root R could in principle
// be replayed across ANY attestation that happens to publish the same
// root. Binding to envelopeDigest (SHA-256 of the source step's DSSE
// payload) makes that replay impossible without a SHA-256 second-
// preimage. Closes threat-model D1.
type SourceStepRef struct {
	StepName       string `json:"stepName"`
	EnvelopeDigest string `json:"envelopeDigest"` // lowercase hex of sha256(source step's DSSE payload)
	MerkleRoot     string `json:"merkleRoot"`     // lowercase hex; must match payload's product/material root
	TreeSize       uint64 `json:"treeSize"`
	Domain         string `json:"domain"` // leaf-hash domain tag; per-attestor-type hardcoded
}

// MaterialProof is one consumed material's RFC 6962 inclusion proof
// against the SourceStepRef's tree. Path and FileDigest are recorded
// so the verifier can re-derive the leaf hash with the canonical
// LeafHashWithDomain encoding. LeafIndex + AuditPath together drive
// merkle.VerifyInclusion.
type MaterialProof struct {
	Path       string   `json:"path"`
	FileDigest string   `json:"fileDigest"` // lowercase hex sha256
	LeafIndex  uint64   `json:"leafIndex"`
	AuditPath  []string `json:"auditPath"` // lowercase hex sibling hashes
}

// ChainSidecar is the off-envelope document a step-N producer publishes
// alongside its signed attestation when it claims materials drawn from
// step-(N-1). For each consumed material the sidecar carries the
// inclusion-proof data needed by an offline verifier to confirm that
// material was a product of the upstream step — without that verifier
// loading the upstream step's full leaf set.
//
// The sidecar is NOT signed directly; its integrity comes from:
//
//  1. SourceStep.EnvelopeDigest binding to the signed upstream envelope.
//  2. Each MaterialProof being cryptographically verified against
//     SourceStep.MerkleRoot, which itself is bound to the signed
//     upstream predicate.
//
// Any tampering with the sidecar leaves either fails the inclusion
// proof or makes the envelope-digest reference dangle.
type ChainSidecar struct {
	SchemaVersion  string          `json:"schemaVersion"`
	SourceStep     SourceStepRef   `json:"sourceStep"`
	MaterialProofs []MaterialProof `json:"materialProofs"`
}

// ConsumedMaterial describes one (path, digest) pair the downstream
// step says it consumed. Producers feed these into BuildChainSidecar
// alongside the upstream step's leaf list; the helper looks each one
// up, generates the proof, and refuses to fabricate proofs for
// materials that don't appear in the upstream set.
type ConsumedMaterial struct {
	Path       string
	FileDigest string // lowercase hex sha256
}

// BuildChainSidecar generates inclusion proofs for each ConsumedMaterial
// against the upstream step's tree, returning a complete ChainSidecar
// ready to publish.
//
// Inputs:
//   - source: the upstream step's signing-time bindings (envelope digest,
//     root, size, domain). Caller is responsible for filling these out
//     correctly from the source step's signed envelope and sidecar.
//   - sourceLeaves: the upstream step's complete leaf set in tree order
//     (i.e., as ordered when the producer built the tree). Same as what
//     comes out of Sidecar.Leaves after Reconstruct().
//   - consumed: the downstream step's claimed materials, in any order.
//
// The function:
//
//  1. Validates that every ConsumedMaterial appears in sourceLeaves at
//     a matching digest. A material with no match is a producer-side
//     error and BuildChainSidecar refuses (closes threat-model D-class
//     attacks at construction time, before the sidecar exists to be
//     signed).
//  2. Rebuilds the Merkle tree from sourceLeaves to extract audit paths.
//  3. Emits a MaterialProof per consumed item, sorted by path for
//     deterministic ordering.
//
//nolint:gocognit,gocyclo // linear validate → rebuild → sort → emit; splitting would obscure the producer-side bail-outs
func BuildChainSidecar(source SourceStepRef, sourceLeaves []SidecarLeaf, consumed []ConsumedMaterial) (ChainSidecar, error) {
	if source.EnvelopeDigest == "" {
		return ChainSidecar{}, errors.New("BuildChainSidecar: source.EnvelopeDigest must be set (binds chain to specific source attestation, not just root)")
	}
	if source.MerkleRoot == "" {
		return ChainSidecar{}, errors.New("BuildChainSidecar: source.MerkleRoot must be set")
	}
	if uint64(len(sourceLeaves)) != source.TreeSize {
		return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: source.TreeSize=%d but %d leaves supplied", source.TreeSize, len(sourceLeaves))
	}

	// Build index for O(1) lookup by normalized path, asserting that the
	// supplied leaves are sorted (so leafIndex below matches the tree's
	// internal index). The producer-side sidecar contract is "leaves
	// sorted by NormalizePath ascending"; rebuilding without that
	// invariant would silently shift indices.
	idxByPath := make(map[string]int, len(sourceLeaves))
	for i, l := range sourceLeaves {
		// i-1 only evaluated when i > 0; bounds-safe. gosec G602 false positive.
		if i > 0 && sourceLeaves[i-1].Path >= sourceLeaves[i].Path { //nolint:gosec // bounded by i > 0 guard
			return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: sourceLeaves not sorted by path (leaf %d=%q >= leaf %d=%q)", i-1, sourceLeaves[i-1].Path, i, sourceLeaves[i].Path) //nolint:gosec // bounded by i > 0 guard above
		}
		idxByPath[l.Path] = i
	}

	// Recompute pre-hashes in tree order using the same domain as the
	// upstream step. If the domain doesn't match, the rebuilt root
	// won't match the signed root — caller will catch this when they
	// validate SourceStep.MerkleRoot against the rebuilt one.
	preHashes := make([][]byte, len(sourceLeaves))
	for i, l := range sourceLeaves {
		h, err := LeafHashWithDomain(source.Domain, l.Path, l.FileDigest)
		if err != nil {
			return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: leaf %d (%q): %w", i, l.Path, err)
		}
		preHashes[i] = h
	}
	tree, err := merkle.NewTree(preHashes)
	if err != nil {
		return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: rebuilding tree: %w", err)
	}
	rebuilt := hex.EncodeToString(tree.Root())
	if rebuilt != source.MerkleRoot {
		return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: rebuilt root %s does not match supplied source.MerkleRoot %s (domain mismatch, leaf-order drift, or tampered source sidecar)", rebuilt, source.MerkleRoot)
	}

	// Sort consumed materials by path for deterministic sidecar output.
	sortedConsumed := make([]ConsumedMaterial, len(consumed))
	copy(sortedConsumed, consumed)
	for i := range sortedConsumed {
		sortedConsumed[i].Path = NormalizePath(sortedConsumed[i].Path)
	}
	sort.Slice(sortedConsumed, func(i, j int) bool {
		return sortedConsumed[i].Path < sortedConsumed[j].Path
	})

	proofs := make([]MaterialProof, 0, len(sortedConsumed))
	for _, m := range sortedConsumed {
		idx, ok := idxByPath[m.Path]
		if !ok {
			return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: consumed material %q is NOT a product of source step (no inclusion proof possible)", m.Path)
		}
		if sourceLeaves[idx].FileDigest != m.FileDigest {
			return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: consumed material %q digest %s does not match source product digest %s", m.Path, m.FileDigest, sourceLeaves[idx].FileDigest)
		}
		path, err := tree.InclusionProof(uint64(idx)) //nolint:gosec // idx bound by sourceLeaves length
		if err != nil {
			return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: generating proof for %q: %w", m.Path, err)
		}
		auditPath := make([]string, len(path))
		for i, h := range path {
			auditPath[i] = hex.EncodeToString(h)
		}
		proofs = append(proofs, MaterialProof{
			Path:       m.Path,
			FileDigest: m.FileDigest,
			LeafIndex:  uint64(idx), //nolint:gosec // bounded
			AuditPath:  auditPath,
		})
	}

	return ChainSidecar{
		SchemaVersion:  ChainSidecarSchemaVersion,
		SourceStep:     source,
		MaterialProofs: proofs,
	}, nil
}

// VerifyChainSidecar checks every MaterialProof against the SourceStep's
// signed Merkle root. The caller MUST have independently confirmed that
// SourceStep.EnvelopeDigest matches the upstream step's actual envelope
// digest (and that envelope was signed by a trusted key) — this helper
// validates the cryptographic chain from a sidecar to a root but does
// NOT establish trust in the root itself.
//
// Returns nil on full success. Returns a typed ErrChainProofFailed when
// any individual proof fails, naming the offending material's path so
// the verifier can surface a precise error to the operator.
func VerifyChainSidecar(s ChainSidecar) error {
	if s.SchemaVersion != ChainSidecarSchemaVersion {
		return fmt.Errorf("chain sidecar: unsupported schema %q (want %q)", s.SchemaVersion, ChainSidecarSchemaVersion)
	}
	if s.SourceStep.EnvelopeDigest == "" {
		return errors.New("chain sidecar: SourceStep.EnvelopeDigest must be set")
	}
	rootBytes, err := hex.DecodeString(s.SourceStep.MerkleRoot)
	if err != nil {
		return fmt.Errorf("chain sidecar: source.MerkleRoot not hex: %w", err)
	}
	for i, mp := range s.MaterialProofs {
		leafHash, err := LeafHashWithDomain(s.SourceStep.Domain, mp.Path, mp.FileDigest)
		if err != nil {
			return ErrChainProofFailed{Path: mp.Path, Index: i, Reason: err.Error()}
		}
		auditPath, err := decodeAuditPath(mp.AuditPath)
		if err != nil {
			return ErrChainProofFailed{Path: mp.Path, Index: i, Reason: err.Error()}
		}
		if err := merkle.VerifyInclusion(s.SourceStep.TreeSize, mp.LeafIndex, leafHash, auditPath, rootBytes); err != nil {
			return ErrChainProofFailed{Path: mp.Path, Index: i, Reason: err.Error()}
		}
	}
	return nil
}

// ErrChainProofFailed is the precise error a verifier can surface
// when a single material's inclusion proof fails to verify against
// the source step's signed root. Carries enough context to report
// "material X failed to prove provenance from step Y" without dumping
// the full chain.
type ErrChainProofFailed struct {
	Path   string
	Index  int
	Reason string
}

func (e ErrChainProofFailed) Error() string {
	return fmt.Sprintf("chain proof failed for material %q (index %d): %s", e.Path, e.Index, e.Reason)
}
