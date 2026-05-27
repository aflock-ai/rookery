// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package chain holds the canonical multi-step chain-of-custody
// primitives the v0.3 policy verifier uses to cryptographically link
// attestation collections via per-material RFC 6962 inclusion proofs.
//
// This package lives under attestation/ (the core module) rather than
// plugins/attestors/inclusion-proof/ (a plugin module) so that
// attestation/policy can depend on it without crossing the layering
// boundary that makes verify-isolated-builds fail.
//
// LeafHash + LeafHashWithDomain are duplicated here byte-for-byte
// from plugins/attestors/inclusion-proof. The two definitions MUST
// stay byte-identical — a test in the inclusion-proof package
// asserts this. Drift would break verification.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/merkle"
	"golang.org/x/text/unicode/norm"
)

// ChainSidecarSchemaVersion is the version tag emitted in every chain
// sidecar so verifiers can refuse formats they don't understand.
const ChainSidecarSchemaVersion = "rookery.chain-proof.sidecar/v0.1"

// SourceStepRef binds a chain sidecar to the specific upstream
// attestation it claims to chain from. EnvelopeDigest is the
// load-bearing field: a proof against tree root R could in principle
// be replayed across any attestation that publishes the same root.
// Binding to envelopeDigest (sha256 of the source step's DSSE
// payload) makes that replay impossible without a SHA-256 second-
// preimage. Closes threat-model D1 (cross-step proof replay).
type SourceStepRef struct {
	StepName       string `json:"stepName"`
	EnvelopeDigest string `json:"envelopeDigest"`
	MerkleRoot     string `json:"merkleRoot"`
	TreeSize       uint64 `json:"treeSize"`
	Domain         string `json:"domain"`
}

// MaterialProof is one consumed material's RFC 6962 inclusion proof
// against the SourceStepRef's tree.
type MaterialProof struct {
	Path       string   `json:"path"`
	FileDigest string   `json:"fileDigest"`
	LeafIndex  uint64   `json:"leafIndex"`
	AuditPath  []string `json:"auditPath"`
}

// ChainSidecar is the off-envelope document a step-N producer
// publishes alongside its signed attestation when it claims
// materials drawn from step-(N-1). For each consumed material the
// sidecar carries the inclusion-proof data needed by an offline
// verifier to confirm that material was a product of the upstream
// step — without that verifier loading the upstream step's full leaf
// set.
//
// The sidecar is NOT signed directly; its integrity comes from:
//
//  1. SourceStep.EnvelopeDigest binding to the signed upstream
//     envelope.
//  2. Each MaterialProof being cryptographically verified against
//     SourceStep.MerkleRoot, which itself is bound to the signed
//     upstream predicate.
type ChainSidecar struct {
	SchemaVersion  string          `json:"schemaVersion"`
	SourceStep     SourceStepRef   `json:"sourceStep"`
	MaterialProofs []MaterialProof `json:"materialProofs"`
}

// ConsumedMaterial describes one (path, digest) pair the downstream
// step says it consumed. Fed into BuildChainSidecar alongside the
// upstream step's leaf list.
type ConsumedMaterial struct {
	Path       string
	FileDigest string
}

// SidecarLeaf is one entry in the upstream step's leaf sidecar — the
// per-file (path, sha256) pairs the upstream producer published.
// Duplicated here from plugins/attestors/inclusion-proof.SidecarLeaf
// so the policy module can reconstruct trees without importing the
// plugin module.
type SidecarLeaf struct {
	Path       string
	FileDigest string
}

// LeafHash is the v0.3 leaf pre-hash for a (path, fileDigest) pair:
// sha256(path || 0x00 || rawFileDigest). The merkle wrapper applies
// the RFC 6962 0x00 leaf domain prefix on top of this when building
// or verifying the tree.
//
// Empty domain matches the legacy inclusion-proof.LeafHash byte-for-
// byte; this is the back-compat anchor for existing v0.3 software-
// supply-chain attestations.
func LeafHash(path, fileDigestHex string) ([]byte, error) {
	return LeafHashWithDomain("", path, fileDigestHex)
}

// LeafHashWithDomain is LeafHash with explicit cryptographic domain
// separation. The domain is NUL-delimited and prefixed to the path
// so a proof under domain A does not verify under domain B even with
// identical (path, digest) leaf data. Closes threat-model E4 across
// application domains (corpus citation, sensor telemetry, etc.).
//
// Domain values are HARDCODED per attestor type. Recognised today:
//
//   - "" (empty)               — legacy / v0.3 software-build (back-compat)
//   - "rookery-product/v0.3"   — product attestor (proposed)
//   - "rookery-material/v0.3"  — material attestor (proposed)
//
// Future per-application domains get their own attestor type with
// their own hardcoded domain.
func LeafHashWithDomain(domain, path, fileDigestHex string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("leaf path must not be empty")
	}
	digest, err := hex.DecodeString(fileDigestHex)
	if err != nil {
		return nil, fmt.Errorf("file digest must be hex: %w", err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("file digest must decode to %d bytes (got %d)", sha256.Size, len(digest))
	}
	h := sha256.New()
	if domain != "" {
		_, _ = h.Write([]byte(domain))
		_, _ = h.Write([]byte{0x00})
	}
	_, _ = h.Write([]byte(path))
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(digest)
	return h.Sum(nil), nil
}

// NormalizePath returns the canonical, portable form of a path used
// by every v0.3 leaf encoder. Two normalizations apply:
//
//  1. Backslash → forward slash. Windows paths produced by the same
//     logical build hash identically to POSIX paths.
//  2. Unicode NFC normalization. macOS HFS+ / APFS stores paths as
//     NFD (decomposed) by default; Linux ext4 / xfs preserves bytes
//     (usually NFC from build tools). The same logical material
//     `café.txt` becomes NFD on macOS and NFC on Linux. Without
//     this step, the two hash to different leaf bytes and chain
//     verification fails cross-platform — same build, different
//     sidecars, no match. NFC is the W3C recommendation for
//     compose-then-compare workflows (Unicode TR #15).
//
// The legacy inclusion-proof.NormalizePath (which this used to
// mirror) only did step 1. Pure-ASCII paths verify identically
// under either function — only non-ASCII material names diverge,
// and that divergence is the bug being fixed here.
func NormalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	return norm.NFC.String(p)
}

// BuildChainSidecar generates inclusion proofs for each
// ConsumedMaterial against the upstream step's tree and returns a
// complete ChainSidecar ready to publish.
//
// Validates: every ConsumedMaterial appears in sourceLeaves at a
// matching digest, sourceLeaves are sorted by NormalizePath, the
// rebuilt tree root matches source.MerkleRoot (catches domain
// mismatch, leaf-order drift, tampered source sidecar). Producer
// errors here mean the chain cannot be honestly constructed.
func BuildChainSidecar(source SourceStepRef, sourceLeaves []SidecarLeaf, consumed []ConsumedMaterial) (ChainSidecar, error) { //nolint:gocyclo,gocognit // linear validate → rebuild → sort → emit; splitting would obscure the producer-side bail-outs
	if source.EnvelopeDigest == "" {
		return ChainSidecar{}, errors.New("BuildChainSidecar: source.EnvelopeDigest must be set (binds chain to specific source attestation, not just root)")
	}
	if source.MerkleRoot == "" {
		return ChainSidecar{}, errors.New("BuildChainSidecar: source.MerkleRoot must be set")
	}
	if uint64(len(sourceLeaves)) != source.TreeSize {
		return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: source.TreeSize=%d but %d leaves supplied", source.TreeSize, len(sourceLeaves))
	}

	idxByPath := make(map[string]int, len(sourceLeaves))
	for i, l := range sourceLeaves {
		// i-1 only evaluated when i > 0; bounds-safe. gosec G602 false positive.
		if i > 0 && sourceLeaves[i-1].Path >= sourceLeaves[i].Path { //nolint:gosec // bounded by i > 0 guard
			return ChainSidecar{}, fmt.Errorf("BuildChainSidecar: sourceLeaves not sorted by path (leaf %d=%q >= leaf %d=%q)", i-1, sourceLeaves[i-1].Path, i, sourceLeaves[i].Path) //nolint:gosec // bounded by i > 0 guard above
		}
		idxByPath[l.Path] = i
	}

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

// VerifyChainSidecar checks every MaterialProof against the
// SourceStep's signed Merkle root. The caller MUST have
// independently confirmed that SourceStep.EnvelopeDigest matches the
// upstream step's actual envelope digest — this helper validates the
// cryptographic chain from a sidecar to a root but does NOT
// establish trust in the root itself.
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

// ErrChainProofFailed is the typed error a verifier surfaces when a
// material's inclusion proof fails. Carries enough context to report
// "material X failed to prove provenance from step Y."
type ErrChainProofFailed struct {
	Path   string
	Index  int
	Reason string
}

func (e ErrChainProofFailed) Error() string {
	return fmt.Sprintf("chain proof failed for material %q (index %d): %s", e.Path, e.Index, e.Reason)
}

// decodeAuditPath converts hex-encoded audit path entries to the
// [][]byte shape merkle.VerifyInclusion expects.
func decodeAuditPath(in []string) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, s := range in {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("audit-path element %d is not hex: %w", i, err)
		}
		if len(b) != sha256.Size {
			return nil, fmt.Errorf("audit-path element %d is %d bytes, want %d", i, len(b), sha256.Size)
		}
		out[i] = b
	}
	return out, nil
}
