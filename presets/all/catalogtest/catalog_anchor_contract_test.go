// jade:ring local
// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package catalogtest

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	_ "github.com/aflock-ai/rookery/presets/all" // register every attestor + detector
)

// TestAnchorRegistryRowsAreImplemented is the rookery half of `jade check
// anchors` (docs/design/attestation-anchors.md A13, A14; lane D15-3): the
// registry and the registered attestors agree in both directions.
//
//   - every anchor row names a registered attestor that implements Anchorer,
//     and every acceptor row one that implements Acceptor;
//   - every registered attestor that implements Anchorer (or Acceptor) has at
//     least one anchor (or acceptor) row under its own type.
//
// Rows whose code is owed by a named later lane are listed in pendingRows. A
// pending row that becomes implemented fails here, so the list only shrinks.
func TestAnchorRegistryRowsAreImplemented(t *testing.T) {
	pendingRows := map[[2]string]string{
		{"https://aflock.ai/attestations/oci/v0.1", "imageid:"}:        "L5a (oci Anchors)",
		{"https://aflock.ai/attestations/oci/v0.1", "registrydigest:"}: "L5a (oci Acceptors)",
	}

	rowsByType := map[string]map[attestation.AnchorClass]bool{}
	for _, row := range attestation.AnchorRegistryRows() {
		if rowsByType[row.Attestor] == nil {
			rowsByType[row.Attestor] = map[attestation.AnchorClass]bool{}
		}
		rowsByType[row.Attestor][row.Class] = true
		if row.Class == attestation.ClassNotAnchor {
			continue
		}
		factory, ok := attestation.FactoryByType(row.Attestor)
		if !ok {
			t.Errorf("registry row %s %s names an attestor that is not registered", row.Attestor, row.Prefix)
			continue
		}
		a := factory()
		var implemented bool
		switch row.Class {
		case attestation.ClassAnchor:
			_, implemented = a.(attestation.Anchorer)
		case attestation.ClassAcceptor:
			_, implemented = a.(attestation.Acceptor)
		}
		lane, pending := pendingRows[[2]string{row.Attestor, row.Prefix}]
		switch {
		case pending && implemented:
			t.Errorf("%s %s is implemented now; remove it from pendingRows (%s)", row.Attestor, row.Prefix, lane)
		case !pending && !implemented:
			t.Errorf("%s row %s %s is declared but %s does not implement it", row.Class, row.Attestor, row.Prefix, a.Name())
		}
	}

	for _, entry := range attestation.RegistrationEntries() {
		a := entry.Factory()
		if _, ok := a.(attestation.Anchorer); ok && !rowsByType[a.Type()][attestation.ClassAnchor] {
			t.Errorf("%s implements Anchorer but %s has no anchor row in anchor_registry.json", a.Name(), a.Type())
		}
		if _, ok := a.(attestation.Acceptor); ok && !rowsByType[a.Type()][attestation.ClassAcceptor] {
			t.Errorf("%s implements Acceptor but %s has no acceptor row in anchor_registry.json", a.Name(), a.Type())
		}
	}
}
