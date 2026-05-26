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

package product

import "github.com/aflock-ai/rookery/attestation"

// SetDroppedForTesting injects a value into the unexported
// droppedByClassification field. Cross-package tests (cilock/cli)
// exercise the empty-bundle warning, which reads this value via
// DroppedByClassification(). Production code never calls this helper;
// the field is set inside Attest's trace path.
//
// Kept in a dedicated _helpers file rather than an _export_test.go so
// it is callable from a different package's tests. The function is
// safe to call before Attest runs; Attest will overwrite the value.
func SetDroppedForTesting(a *Attestor, n int) {
	if a == nil {
		return
	}
	a.droppedByClassification = n
}

// SetProductsForTesting injects a product map into the unexported
// products field. Same rationale as SetDroppedForTesting — lets
// cilock/cli unit tests exercise the empty-bundle warning's
// "products non-empty → quiet" branch without running a full Attest.
func SetProductsForTesting(a *Attestor, products map[string]attestation.Product) {
	if a == nil {
		return
	}
	a.products = products
}
