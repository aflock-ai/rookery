// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

package product

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
)

var (
	_ attestation.InventoryExporter = (*Attestor)(nil)
	_ attestation.InventoryHydrator = (*Attestor)(nil)
	_ attestation.CompanionExporter = (*Attestor)(nil)
	_ attestation.CompanionTyper    = (*Attestor)(nil)
)

// WithCompactInventory bounds the complete inline predicate in serialized bytes.
// Detachment retains every captured path without changing capture or upload.
func WithCompactInventory(inlineBytes int) Option {
	return func(a *Attestor) { a.compactInventory, a.inlineInventoryBytes = true, inlineBytes }
}

func (a *Attestor) InventoryReference() *fileinventory.Reference {
	if a.Inventory == nil {
		return nil
	}
	ref := *a.Inventory
	return &ref
}

func (a *Attestor) finishInventory(pairs []productPair) error {
	if a.inlineInventoryBytes < 0 {
		return fmt.Errorf("product: inventory inline byte budget cannot be negative")
	}
	if a.TreeSize == 0 {
		return nil
	}
	entries := make([]fileinventory.Entry, 0, len(pairs))
	paths := make(map[string]bool, len(pairs))
	lossy := false
	for _, p := range pairs {
		prod := a.products[p.originalKey]
		// Witness-only paths are not in the content commitment.
		if prod.Digest == nil {
			continue
		}
		entries = append(entries, fileinventory.Entry{
			Path:       p.originalKey,
			FileDigest: prod.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}],
			MIMEType:   prod.MimeType,
			Kind:       detectProductKind(p.normalized),
		})
		lossy = lossy || paths[p.normalized] || p.normalized != p.originalKey
		paths[p.normalized] = true
	}
	inline, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if !lossy && len(entries) == len(a.leaves) && len(inline) <= a.inlineInventoryBytes {
		return nil
	}
	mode := a.captureMode
	if mode == "" {
		mode = "unknown"
	}
	ref, body, err := fileinventory.Encode("product", mode, entries)
	if err != nil {
		return err
	}
	if _, err := fileinventory.Verify(ref, body, "product", a.MerkleRoot, a.TreeSize); err != nil {
		return err
	}
	a.Inventory, a.inventoryBytes = ref, body
	return nil
}

func (a *Attestor) InventoryBytes() ([]byte, error) {
	if _, err := fileinventory.Verify(a.Inventory, a.inventoryBytes, "product", a.MerkleRoot, a.TreeSize); err != nil {
		return nil, err
	}
	return bytes.Clone(a.inventoryBytes), nil
}

// Companions exposes retained inventories to the workflow's companion signer.
func (a *Attestor) Companions() []attestation.Attestor {
	if a.Inventory == nil || a.Inventory.State != "detached" || len(a.inventoryBytes) == 0 {
		return nil
	}
	return []attestation.Attestor{attestation.NewInventoryCompanion("product", a.inventoryBytes)}
}

// CompanionTypes declares the companion predicate type without requiring a run.
func (a *Attestor) CompanionTypes() []string {
	return []string{fileinventory.Type}
}

func (a *Attestor) HydrateInventory(body []byte) error {
	if a.HashAlgorithmField != HashAlgorithm || a.ConstructionField != Construction {
		return fmt.Errorf("product: invalid inventory parent algorithms")
	}
	entries, err := fileinventory.Verify(a.Inventory, body, "product", a.MerkleRoot, a.TreeSize)
	if err != nil {
		return err
	}
	leaves := make([]ProductLeaf, 0, len(entries))
	products := make(map[string]attestation.Product, len(entries))
	for _, e := range entries {
		raw, _ := hex.DecodeString(e.FileDigest)
		prehash := sha256.Sum256(raw)
		leaves = append(leaves, ProductLeaf{Path: e.Path, FileDigest: e.FileDigest, LeafHash: hex.EncodeToString(prehash[:]), MimeType: e.MIMEType, Kind: e.Kind})
		products[e.Path] = attestation.Product{MimeType: e.MIMEType, Digest: cryptoutil.DigestSet{{Hash: crypto.SHA256}: e.FileDigest}}
	}
	a.leaves, a.products, a.inventoryBytes = leaves, products, bytes.Clone(body)
	return nil
}
