// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/invopop/jsonschema"
)

// InventoryReporter exposes the signed reference, or nil for a legacy predicate.
type InventoryReporter interface {
	InventoryReference() *fileinventory.Reference
}

// InventoryExporter returns retained predicate bytes, not an upload decision.
type InventoryExporter interface {
	InventoryReporter
	InventoryBytes() ([]byte, error)
}

// InventoryHydrator installs entries only after verifying the signed binding.
type InventoryHydrator interface {
	InventoryReporter
	HydrateInventory([]byte) error
}

type inventoryCompanion struct {
	kind string
	body []byte
}

// NewInventoryCompanion carries producer bytes without inheriting parent subjects.
// It is not a material/product attestor and cannot collect evidence independently.
func NewInventoryCompanion(kind string, body []byte) Attestor {
	return &inventoryCompanion{kind: kind, body: bytes.Clone(body)}
}

func (a *inventoryCompanion) Name() string { return "inventory" }
func (a *inventoryCompanion) Type() string { return fileinventory.Type }
func (a *inventoryCompanion) RunType() RunType {
	if a.kind == string(MaterialRunType) {
		return MaterialRunType
	}
	return ProductRunType
}
func (a *inventoryCompanion) Attest(_ *AttestationContext) error {
	return fmt.Errorf("file inventory is a derived companion and cannot attest directly")
}
func (a *inventoryCompanion) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&fileinventory.Payload{})
}
func (a *inventoryCompanion) MarshalJSON() ([]byte, error) {
	if _, err := fileinventory.Decode(a.body, a.kind); err != nil {
		return nil, err
	}
	// encoding/json compacts and HTML-escapes Marshaler bytes. Refuse any change
	// rather than emit different bytes under the original digest subject.
	embedded, err := json.Marshal(json.RawMessage(a.body))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(embedded, a.body) {
		return nil, fmt.Errorf("file inventory: companion encoding must preserve exact predicate bytes")
	}
	return bytes.Clone(a.body), nil
}
func (a *inventoryCompanion) Subjects() map[string]cryptoutil.DigestSet {
	sum := sha256.Sum256(a.body)
	return map[string]cryptoutil.DigestSet{
		"inventory:" + a.kind: {{Hash: crypto.SHA256}: hex.EncodeToString(sum[:])},
	}
}
