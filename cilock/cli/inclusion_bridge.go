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
	"encoding/hex"
	"encoding/json"
	"path/filepath"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
)

// Predicate types used to recognise the evidence the bridge consumes.
const (
	collectionPredicateType = "https://aflock.ai/attestation-collection/v0.1"
	productTreeType         = "https://aflock.ai/attestations/product/v0.3"
	materialTreeType        = "https://aflock.ai/attestations/material/v0.3"
)

// treeCommitment is a (merkleRoot, treeSize) pair pulled from a product or
// material v0.3 sub-attestor inside a loaded collection. Per RFC 6962 and
// the CVE-2026-22703 defence, BOTH values are taken from the collection's
// signed predicate — never from an inclusion-proof envelope, which could
// otherwise pick its own tree size.
type treeCommitment struct {
	rootHex  string
	treeSize uint64
}

// expandSubjectsWithInclusionProofs bridges a primary artifact (a plain file
// digest, e.g. from --artifactfile) to a product/material Merkle-tree
// collection whose only subject is the tree:products root.
//
// The verifier matches collections to a step by subject digest. A binary
// committed as a product carries the tree ROOT as the collection subject,
// not its own file hash, so `cilock verify <binary>` finds nothing. This
// pass repairs that: for each signed inclusion-proof envelope whose
// FileDigest matches a requested artifact subject, it RFC 6962-verifies the
// audit path against the trusted (root, treeSize) of a loaded collection's
// product/material tree, and on success adds that tree root as an additional
// subject — so the collection now matches.
//
// Safety:
//   - treeSize and root come from the collection's predicate (CVE-2026-22703).
//   - The audit-path check (inclusionproof.Attestor.Verify) means forging
//     inclusion of a file NOT in the tree is a Merkle second-preimage attack.
//   - Adding a tree root as a candidate subject grants NO trust on its own:
//     the policy engine still verifies the matched collection's signature
//     against the step functionary. A bogus collection+proof pair is rejected
//     downstream at signature verification.
func expandSubjectsWithInclusionProofs(subjects []cryptoutil.DigestSet, envelopes []dsse.Envelope, artifactPath, artifactDigestHex string) []cryptoutil.DigestSet {
	requested := map[string]bool{}
	for _, ds := range subjects {
		for dv, h := range ds {
			if dv.Hash == crypto.SHA256 && !dv.GitOID {
				requested[h] = true
			}
		}
	}
	if len(requested) == 0 {
		return subjects
	}

	var (
		commitments []treeCommitment
		proofs      []*inclusionproof.Attestor
	)
	for _, env := range envelopes {
		var stmt struct {
			PredicateType string          `json:"predicateType"`
			Predicate     json.RawMessage `json:"predicate"`
		}
		if err := json.Unmarshal(env.Payload, &stmt); err != nil {
			continue
		}
		switch stmt.PredicateType {
		case collectionPredicateType:
			var coll struct {
				Attestations []struct {
					Type        string          `json:"type"`
					Attestation json.RawMessage `json:"attestation"`
				} `json:"attestations"`
			}
			if err := json.Unmarshal(stmt.Predicate, &coll); err != nil {
				continue
			}
			for _, a := range coll.Attestations {
				if a.Type != productTreeType && a.Type != materialTreeType {
					continue
				}
				var tree struct {
					MerkleRoot string `json:"merkleRoot"`
					TreeSize   uint64 `json:"treeSize"`
				}
				if err := json.Unmarshal(a.Attestation, &tree); err == nil && tree.MerkleRoot != "" && tree.TreeSize > 0 {
					commitments = append(commitments, treeCommitment{rootHex: tree.MerkleRoot, treeSize: tree.TreeSize})
				}
			}
		case inclusionproof.Type:
			var p inclusionproof.Attestor
			if err := json.Unmarshal(stmt.Predicate, &p); err != nil {
				continue
			}
			proofs = append(proofs, &p)
		}
	}
	if len(commitments) == 0 {
		return subjects
	}

	added := map[string]bool{}

	// Single-leaf shortcut (no sidecar required): when the artifact is the
	// SOLE product of a step (treeSize==1), the tree has no interior nodes —
	// the RFC 6962 root IS the leaf hash, and the audit path is empty. We can
	// therefore reconstruct the expected root directly from (basename, digest)
	// using the canonical BuildSidecar (the exact producer-side encoding, so
	// no drift), and match it against a collection commitment. This is the
	// common case for a single released binary: no inclusion-proof envelope
	// and no chain sidecar needed for the primary artifact. The root only
	// matches when the committed tree IS exactly {basename: digest} — a multi-
	// leaf tree has a different root, so this never false-matches.
	if artifactPath != "" && artifactDigestHex != "" {
		base := filepath.Base(artifactPath)
		if side, err := inclusionproof.BuildSidecar("product", map[string]string{base: artifactDigestHex}); err == nil {
			for _, c := range commitments {
				if c.rootHex == side.MerkleRoot && !added[c.rootHex] {
					added[c.rootHex] = true
					subjects = append(subjects, cryptoutil.DigestSet{{Hash: crypto.SHA256}: c.rootHex})
					log.Debugf("inclusion-proof bridge: single-leaf artifact %s reconstructs product tree %s; added as subject", artifactDigestHex, c.rootHex)
				}
			}
		}
	}

	for _, p := range proofs {
		if !requested[p.FileDigest] || added[p.TreeRoot] {
			continue
		}
		for _, c := range commitments {
			// The proof must reference this committed tree, and the audit
			// path must reconstruct the collection's trusted root using the
			// collection's trusted treeSize.
			if c.rootHex != p.TreeRoot {
				continue
			}
			rootBytes, err := hex.DecodeString(c.rootHex)
			if err != nil {
				continue
			}
			if err := p.Verify(c.treeSize, rootBytes); err != nil {
				log.Debugf("inclusion-proof bridge: %s not provably in tree %s: %v", p.FileDigest, c.rootHex, err)
				continue
			}
			added[p.TreeRoot] = true
			subjects = append(subjects, cryptoutil.DigestSet{{Hash: crypto.SHA256}: c.rootHex})
			log.Debugf("inclusion-proof bridge: artifact %s proven in product tree %s; added tree root as subject", p.FileDigest, c.rootHex)
			break
		}
	}
	return subjects
}
