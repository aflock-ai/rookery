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
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/testkit"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	_ "github.com/aflock-ai/rookery/presets/all"
)

// An attestor's Schema() is a published contract: it is what
// `cilock attestors schema <name>` prints and what a verifier writes policy
// against. invopop reflects it with additionalProperties:false, so a field the
// attestor actually SIGNS but the schema does not mention makes every real
// attestation fail validation against its own declared schema.
//
// testkit.AssertContract already checks this for the 28 attestors that own a
// recorded fixture. The tests here close the gap the harness cannot reach:
// attestors with no fixture, and predicate shapes that only appear when the
// attestor has real data (an empty run can conform while a populated one does
// not — which is exactly how product/v0.3 drifted).

// TestProductPredicateWithInlineLeavesValidatesAgainstSchema pins the specific
// regression. product/v0.3 ALWAYS inlines a `leaves` array (see
// product.MarshalJSON), each leaf optionally carrying `mimeType` and `kind`.
// Schema() used to reflect the Attestor struct, where `leaves` is `json:"-"`,
// so the published schema listed only the four scalar fields and rejected
// every real predicate with "additionalProperties 'leaves' not allowed".
//
// A zero-value product predicate carries no leaves and would have passed, so
// this test deliberately populates one — including both optional per-leaf
// metadata fields, which are the shape this PR added.
func TestProductPredicateWithInlineLeavesValidatesAgainstSchema(t *testing.T) {
	a, err := attestation.GetAttestor("product")
	if err != nil {
		t.Fatalf("GetAttestor(product): %v", err)
	}

	// Built from the exported predicate type MarshalJSON itself uses, so this
	// is the emitted shape by construction rather than a hand-copied guess.
	predicate, err := json.Marshal(product.Predicate{
		MerkleRoot:    "8f1e2d0c",
		TreeSize:      2,
		HashAlgorithm: "sha256",
		Construction:  "rfc6962",
		Leaves: []product.ProductLeaf{
			{
				Path:       "dist/caddy-darwin",
				FileDigest: "aa11",
				LeafHash:   "bb22",
				MimeType:   "application/x-mach-binary",
			},
			{
				Path:       "dist/app.spdx.json",
				FileDigest: "cc33",
				LeafHash:   "dd44",
				MimeType:   "application/json",
				Kind:       "spdx",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal product predicate: %v", err)
	}

	testkit.AssertPredicateMatchesSchema(t, "product", a.Schema(), predicate)
}

// TestProductLeaflessPredicateStillValidates: `leaves` is omitempty, so a v0.3
// attestation recorded before inline leaves (or one with no products at all)
// must keep validating. Guards the fix against over-tightening into a schema
// that requires the new array.
func TestProductLeaflessPredicateStillValidates(t *testing.T) {
	a, err := attestation.GetAttestor("product")
	if err != nil {
		t.Fatalf("GetAttestor(product): %v", err)
	}
	predicate, err := json.Marshal(product.Predicate{
		MerkleRoot:    "8f1e2d0c",
		TreeSize:      0,
		HashAlgorithm: "sha256",
		Construction:  "rfc6962",
	})
	if err != nil {
		t.Fatalf("marshal product predicate: %v", err)
	}
	testkit.AssertPredicateMatchesSchema(t, "product", a.Schema(), predicate)
}

// TestSecretscanPredicateWithConsumedReportsValidatesAgainstSchema covers the
// other predicate shape this PR added. secretscan has no detector.yaml and no
// fixture, so the harness never reaches it; its Schema() is reflected straight
// off the Attestor struct, which DOES carry consumedReports — this test pins
// that, so a future move of the field behind a custom marshaller (product's
// exact failure mode) cannot land silently.
func TestSecretscanPredicateWithConsumedReportsValidatesAgainstSchema(t *testing.T) {
	a, err := attestation.GetAttestor("secretscan")
	if err != nil {
		t.Fatalf("GetAttestor(secretscan): %v", err)
	}

	schemaJSON, err := json.Marshal(a.Schema())
	if err != nil {
		t.Fatalf("marshal secretscan Schema(): %v", err)
	}
	if !strings.Contains(string(schemaJSON), `"consumedReports"`) {
		t.Fatalf("secretscan Schema() does not describe consumedReports, so a predicate carrying it cannot validate: %s", schemaJSON)
	}

	// A predicate carrying a consumed report must validate against the
	// published schema (invopop emits additionalProperties:false).
	predicate := []byte(`{"findings":[],"consumedReports":[{"path":"gitleaks.sarif","sha256":"aa11","driver":"gitleaks","results":3,"deduplicated":2}]}`)
	testkit.AssertPredicateMatchesSchema(t, "secretscan", a.Schema(), predicate)
}

// TestMaterialPredicateShapesValidateAgainstSchema is product's regression,
// for material. material/v0.3 has inlined `leaves` since the version cut while
// Schema() reflected the Attestor struct, where `leaves` is `json:"-"` — so
// every real material predicate failed validation against its own published
// schema, and the manifest fields this change adds would have been the next
// two. Schema() now reflects the single predicate type MarshalJSON and
// UnmarshalJSON share. Every shape a producer can sign, and every decoded
// shape that can be re-encoded, is checked: the populated inline predicate
// (with and without a published manifest), the detached predicate (no leaves
// key), and the authoritative-empty one ("leaves":[]).
func TestMaterialPredicateShapesValidateAgainstSchema(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []struct{ path, body string }{
		{"a.txt", "alpha\n"},
		{"sub/b.txt", "beta\n"},
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f.path)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.path), []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	for _, manifest := range []bool{false, true} {
		a := material.New(material.WithManifest(manifest))
		ctx, err := attestation.NewContext("schema", []attestation.Attestor{a},
			attestation.WithHashes(hashes), attestation.WithWorkingDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := ctx.RunAttestors(); err != nil {
			t.Fatalf("manifest=%v: %v", manifest, err)
		}
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"leaves":[{`) {
			t.Fatalf("manifest=%v: the populated predicate must inline leaves for this test to mean anything: %s", manifest, raw)
		}
		testkit.AssertPredicateMatchesSchema(t, "material", a.Schema(), raw)
	}

	const emptyRoot = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for name, body := range map[string]string{
		"detached":            `{"merkleRoot":"` + emptyRoot + `","treeSize":0,"hashAlgorithm":"sha256","construction":"RFC6962","manifestUploaded":true,"manifest":{"digest":{"sha256":"00"},"bytes":2}}`,
		"authoritative-empty": `{"merkleRoot":"` + emptyRoot + `","treeSize":0,"hashAlgorithm":"sha256","construction":"RFC6962","leaves":[]}`,
	} {
		var a material.Attestor
		if err := json.Unmarshal([]byte(body), &a); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		raw, err := json.Marshal(&a)
		if err != nil {
			t.Fatalf("%s: encode: %v", name, err)
		}
		testkit.AssertPredicateMatchesSchema(t, "material", a.Schema(), raw)
	}
}
