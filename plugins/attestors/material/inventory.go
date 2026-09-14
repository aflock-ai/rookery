// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

package material

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
)

var (
	_ attestation.InventoryExporter = (*Attestor)(nil)
	_ attestation.InventoryHydrator = (*Attestor)(nil)
)

// WithCompactInventory omits material details unless retention is requested.
// Capture and the in-memory baseline are unchanged. This option does not upload.
func WithCompactInventory(retain bool) Option {
	return func(a *Attestor) { a.compactInventory, a.retainInventory = true, retain }
}

func (a *Attestor) InventoryReference() *fileinventory.Reference {
	if a.Inventory == nil {
		return nil
	}
	ref := *a.Inventory
	return &ref
}

func (a *Attestor) finishInventory() error {
	mode := a.captureMode
	if mode == "" {
		mode = "unknown"
	}
	entries := make([]fileinventory.Entry, 0, len(a.materials))
	for path, ds := range a.materials {
		// Match extractSha256's raw-content key, without dropping malformed
		// selected values or mutating the full capture baseline.
		if digest, selected := ds[cryptoutil.DigestValue{Hash: crypto.SHA256}]; selected {
			entries = append(entries, fileinventory.Entry{Path: path, FileDigest: digest})
		}
	}
	if !a.retainInventory {
		a.Inventory = fileinventory.NewOmitted("material", mode, len(entries))
		return a.Inventory.Validate("material")
	}
	ref, body, err := fileinventory.Encode("material", mode, entries)
	if err != nil {
		return err
	}
	if _, err := fileinventory.Verify(ref, body, "material", a.MerkleRoot, a.TreeSize); err != nil {
		return err
	}
	a.Inventory, a.inventoryBytes = ref, body
	return nil
}

func (a *Attestor) InventoryBytes() ([]byte, error) {
	if _, err := fileinventory.Verify(a.Inventory, a.inventoryBytes, "material", a.MerkleRoot, a.TreeSize); err != nil {
		return nil, err
	}
	return bytes.Clone(a.inventoryBytes), nil
}

func (a *Attestor) HydrateInventory(body []byte) error {
	if a.HashAlgorithmField != HashAlgorithm || a.ConstructionField != Construction {
		return fmt.Errorf("material: invalid inventory parent algorithms")
	}
	entries, err := fileinventory.Verify(a.Inventory, body, "material", a.MerkleRoot, a.TreeSize)
	if err != nil {
		return err
	}
	leaves := make([]MaterialLeaf, 0, len(entries))
	for _, e := range entries {
		raw, _ := hex.DecodeString(e.FileDigest)
		prehash := sha256.Sum256(raw)
		leaves = append(leaves, MaterialLeaf{Path: e.Path, FileDigest: e.FileDigest, LeafHash: hex.EncodeToString(prehash[:])})
	}
	a.setLeaves(leaves)
	a.inventoryBytes = bytes.Clone(body)
	return nil
}
