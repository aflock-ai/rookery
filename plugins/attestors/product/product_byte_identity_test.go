// Copyright 2025 The Witness Contributors
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

import (
	"encoding/json"
	"testing"
)

// TestProductPredicateBytesAreUnchanged pins the EXACT serialized bytes of the
// v0.3 product predicate.
//
// # WHY THIS TEST EXISTS
//
// The reuse guard in UnmarshalJSON clears derived in-memory state; it must not
// move a single byte on the wire. The product predicate is the statement's
// join key — the subjects downstream consumers reference a build by — so
// "the wire shape is untouched" is a claim that deserves evidence rather than
// assertion. A reviewer can read the diff and see only a decode-side reset;
// what a diff CANNOT show is that a shared dependency (the inclusion-proof
// leaf encoder, the merkle wrapper, a JSON helper) did not shift the bytes
// underneath it.
//
// The literal below pins the shipped shape: field ORDER, the
// "leaves,omitempty" behaviour, and every leaf field including the two
// additive ones (mimeType, kind) that must stay omitempty so pre-existing
// v0.3 attestations round-trip byte-identically.
//
// If you are here because this test failed: do not update the literal to make
// it green. A change to product's wire bytes is a change to the join key that
// every artifactsFrom chain and every subject lookup depends on, and it needs
// its own decision.
func TestProductPredicateBytesAreUnchanged(t *testing.T) {
	a := &Attestor{
		MerkleRoot:         "c12a16a9000000000000000000000000000000000000000000000000009687d0",
		TreeSize:           2,
		HashAlgorithmField: HashAlgorithm,
		ConstructionField:  Construction,
		leaves: []ProductLeaf{
			{
				Path:       "bin/app",
				FileDigest: "1111111111111111111111111111111111111111111111111111111111111111",
				LeafHash:   "2222222222222222222222222222222222222222222222222222222222222222",
				MimeType:   "application/x-executable",
				Kind:       "binary",
			},
			{
				Path:       "dist/app.tar.gz",
				FileDigest: "3333333333333333333333333333333333333333333333333333333333333333",
				LeafHash:   "4444444444444444444444444444444444444444444444444444444444444444",
			},
		},
	}

	const want = `{"merkleRoot":"c12a16a9000000000000000000000000000000000000000000000000009687d0","treeSize":2,"hashAlgorithm":"sha256","construction":"RFC6962","leaves":[{"path":"bin/app","fileDigest":"1111111111111111111111111111111111111111111111111111111111111111","leafHash":"2222222222222222222222222222222222222222222222222222222222222222","mimeType":"application/x-executable","kind":"binary"},{"path":"dist/app.tar.gz","fileDigest":"3333333333333333333333333333333333333333333333333333333333333333","leafHash":"4444444444444444444444444444444444444444444444444444444444444444"}]}`

	got, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal product predicate: %v", err)
	}
	if string(got) != want {
		t.Fatalf("product predicate bytes CHANGED.\n got: %s\nwant: %s", got, want)
	}
}
