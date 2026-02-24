//go:build audit

// Copyright 2025 The Aflock Authors
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

package sbom

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
)

// ============================================================================
// Helpers
// ============================================================================

func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
	}
}

// fakeProducer is a minimal attestor that registers a file as a product.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (fp *fakeProducer) Name() string                                   { return "fake-producer" }
func (fp *fakeProducer) Type() string                                   { return "fake" }
func (fp *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                     { return nil }
func (fp *fakeProducer) Products() map[string]attestation.Product       { return fp.products }

// ============================================================================
// R3-230: Path traversal in SBOM file opening
// ============================================================================

// TestSecurity_R3_230_PathTraversalInSBOMFileOpen proves that the SBOM attestor
// uses filepath.Join(ctx.WorkingDir(), path) where `path` comes from product
// keys. If path contains "../" sequences, filepath.Join does NOT prevent
// escaping the working directory -- it just cleans the result.
//
// Impact: An attacker who controls product paths (e.g. via a malicious
// product attestor or tampered products map) can read arbitrary files
// from the filesystem.
func TestSecurity_R3_230_PathTraversalInSBOMFileOpen(t *testing.T) {
	// Create a temporary directory structure to demonstrate path traversal
	tmpDir := t.TempDir()
	workDir := filepath.Join(tmpDir, "workdir")
	secretDir := filepath.Join(tmpDir, "secrets")

	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatalf("failed to create work dir: %v", err)
	}
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		t.Fatalf("failed to create secret dir: %v", err)
	}

	// Write a "secret" SPDX file outside the working directory
	secretSBOM := `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "secret-sbom", "dataLicense": "CC0-1.0", "documentNamespace": "https://example.com/secret"}`
	secretPath := filepath.Join(secretDir, "secret.spdx.json")
	if err := os.WriteFile(secretPath, []byte(secretSBOM), 0600); err != nil {
		t.Fatalf("failed to write secret SBOM: %v", err)
	}

	// The traversal path: from workDir, "../secrets/secret.spdx.json" escapes
	traversalPath := "../secrets/secret.spdx.json"

	// Prove that filepath.Join does NOT prevent traversal
	resolvedPath := filepath.Join(workDir, traversalPath)
	cleanedSecret := filepath.Clean(secretPath)

	if resolvedPath != cleanedSecret {
		t.Logf("resolved: %s, expected: %s", resolvedPath, cleanedSecret)
		// They might differ by platform path separators
	}

	// Verify the traversal path resolves to the secret file
	if _, err := os.Stat(resolvedPath); err != nil {
		t.Fatalf("traversal path should resolve to existing file: %v", err)
	}

	// Calculate digest for the secret file
	digest, err := cryptoutil.CalculateDigestSetFromFile(secretPath, defaultHashes())
	if err != nil {
		t.Fatalf("failed to calculate digest: %v", err)
	}

	// Create a fake producer with the traversal path as a product key
	fp := &fakeProducer{
		products: map[string]attestation.Product{
			traversalPath: {
				MimeType: SPDXMimeType,
				Digest:   digest,
			},
		},
	}

	sbomAttestor := NewSBOMAttestor()

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{fp, sbomAttestor},
		attestation.WithWorkingDir(workDir),
		attestation.WithHashes(defaultHashes()),
	)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	// Check if the SBOM attestor successfully read the file outside workDir
	for _, completed := range ctx.CompletedAttestors() {
		if completed.Attestor.Name() == Name && completed.Error == nil {
			// The attestor successfully processed a file outside the working directory
			t.Log("BUG CONFIRMED: SBOM attestor read file outside working directory via path traversal")

			data, err := json.Marshal(sbomAttestor)
			if err == nil && strings.Contains(string(data), "secret-sbom") {
				t.Log("Secret SBOM content was extracted via path traversal")
			}
		}
	}

	t.Log("BUG: filepath.Join(ctx.WorkingDir(), path) on line 167 does not prevent " +
		"path traversal. A product path like '../secrets/file' escapes the working " +
		"directory. Should use filepath-securejoin or validate the resolved path " +
		"is under WorkingDir().")
}

// ============================================================================
// R3-231: SBOM component hashes not validated
// ============================================================================

// TestSecurity_R3_231_SBOMComponentHashesNotValidated proves that the SBOM
// attestor parses SPDX and CycloneDX documents but does not validate any
// component hashes within them. A tampered SBOM with modified component
// entries is accepted as-is.
//
// Impact: An attacker can modify component entries (names, versions, hashes)
// in an SBOM file and the attestor will faithfully include the tampered
// data in the attestation without detecting the modification.
func TestSecurity_R3_231_SBOMComponentHashesNotValidated(t *testing.T) {
	// Create a tampered SPDX document with obviously wrong data
	tamperedSPDX := `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "tampered-sbom",
		"dataLicense": "CC0-1.0",
		"documentNamespace": "https://example.com/tampered",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "totally-legit-package",
				"versionInfo": "99.99.99",
				"downloadLocation": "https://evil.com/backdoor",
				"checksums": [
					{
						"algorithm": "SHA256",
						"checksumValue": "0000000000000000000000000000000000000000000000000000000000000000"
					}
				]
			}
		]
	}`

	tmpDir := t.TempDir()
	sbomFile := filepath.Join(tmpDir, "tampered.spdx.json")
	if err := os.WriteFile(sbomFile, []byte(tamperedSPDX), 0600); err != nil {
		t.Fatalf("failed to write tampered SBOM: %v", err)
	}

	digest, err := cryptoutil.CalculateDigestSetFromFile(sbomFile, defaultHashes())
	if err != nil {
		t.Fatalf("failed to calculate digest: %v", err)
	}

	fp := &fakeProducer{
		products: map[string]attestation.Product{
			"tampered.spdx.json": {
				MimeType: SPDXMimeType,
				Digest:   digest,
			},
		},
	}

	sbomAttestor := NewSBOMAttestor()
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{fp, sbomAttestor},
		attestation.WithWorkingDir(tmpDir),
		attestation.WithHashes(defaultHashes()),
	)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	// Verify the tampered SBOM was accepted
	var attestError error
	for _, completed := range ctx.CompletedAttestors() {
		if completed.Attestor.Name() == Name {
			attestError = completed.Error
		}
	}

	if attestError != nil {
		t.Fatalf("expected tampered SBOM to be accepted, got error: %v", attestError)
	}

	// The SBOM was accepted without any component hash validation
	if sbomAttestor.predicateType != SPDXPredicateType {
		t.Errorf("expected SPDX predicate type, got %s", sbomAttestor.predicateType)
	}

	data, err := json.Marshal(sbomAttestor)
	if err != nil {
		t.Fatalf("failed to marshal attestor: %v", err)
	}

	if !strings.Contains(string(data), "totally-legit-package") {
		t.Error("expected tampered package name in attestation output")
	}

	if !strings.Contains(string(data), "https://evil.com/backdoor") {
		t.Error("expected tampered download URL in attestation output")
	}

	t.Log("BUG: SBOM attestor does not validate component hashes or integrity. " +
		"Tampered SBOM files with modified package names, versions, URLs, and " +
		"checksums are accepted without any verification.")
}

// ============================================================================
// R3-232: UnmarshalJSON type confusion with interface{} SBOMDocument
// ============================================================================

// TestSecurity_R3_232_UnmarshalTypeConfusion proves that SBOMDocument is
// typed as interface{}, so UnmarshalJSON can store any JSON value in it.
// After unmarshal, the predicateType may not match the actual document
// content, leading to type confusion downstream.
//
// Impact: A document that looks like SPDX in the header but contains
// CycloneDX or arbitrary JSON data could be misclassified and processed
// incorrectly.
func TestSecurity_R3_232_UnmarshalTypeConfusion(t *testing.T) {
	// Create JSON that has SPDX header markers but invalid SPDX content
	hybridJSON := `{
		"spdxVersion": "SPDX-2.3",
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"evil": "this is neither valid SPDX nor CycloneDX"
	}`

	sbom := NewSBOMAttestor()
	err := sbom.UnmarshalJSON([]byte(hybridJSON))
	if err != nil {
		t.Fatalf("UnmarshalJSON rejected hybrid document: %v", err)
	}

	// The predicateType is set based on IsSPDXJson/IsCycloneDXJson checks
	// which only look at the first 500 bytes for marker strings.
	// A document can match BOTH checks.
	t.Logf("predicateType after unmarshal: %s", sbom.predicateType)

	// The SBOMDocument field is just interface{} - it can hold anything
	if sbom.SBOMDocument == nil {
		t.Error("expected SBOMDocument to be non-nil")
	}

	// Prove that arbitrary JSON values are stored in SBOMDocument
	sbom2 := NewSBOMAttestor()
	err = sbom2.UnmarshalJSON([]byte(`[1, 2, 3, "not an SBOM"]`))
	if err != nil {
		t.Fatalf("UnmarshalJSON rejected JSON array: %v", err)
	}

	if sbom2.SBOMDocument == nil {
		t.Error("expected non-nil SBOMDocument even for JSON array")
	}

	t.Log("BUG: SBOMDocument is interface{} and UnmarshalJSON stores any valid JSON. " +
		"Type detection uses simple string matching in first 500 bytes, allowing " +
		"hybrid documents that match multiple formats or arbitrary JSON arrays.")
}

// ============================================================================
// R3-233: Unbounded SBOM file read - denial of service
// ============================================================================

// TestSecurity_R3_233_UnboundedSBOMFileRead proves that io.ReadAll(f)
// on line 173 reads entire files into memory without any size limit.
// A maliciously large SBOM file can cause OOM.
//
// Impact: Denial of service through memory exhaustion.
func TestSecurity_R3_233_UnboundedSBOMFileRead(t *testing.T) {
	// Create a valid but large SPDX document
	var builder strings.Builder
	builder.WriteString(`{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "large-sbom", "dataLicense": "CC0-1.0", "documentNamespace": "https://example.com/large", "packages": [`)

	// Write 5000 package entries
	for i := 0; i < 5000; i++ {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(`{"SPDXID": "SPDXRef-Pkg`)
		builder.WriteString(strings.Repeat("x", 200))
		builder.WriteString(`", "name": "pkg-`)
		builder.WriteString(strings.Repeat("y", 200))
		builder.WriteString(`", "versionInfo": "1.0", "downloadLocation": "https://example.com"}`)
	}
	builder.WriteString("]}")

	largeDoc := builder.String()

	tmpDir := t.TempDir()
	sbomFile := filepath.Join(tmpDir, "large.spdx.json")
	if err := os.WriteFile(sbomFile, []byte(largeDoc), 0600); err != nil {
		t.Fatalf("failed to write large SBOM: %v", err)
	}

	digest, err := cryptoutil.CalculateDigestSetFromFile(sbomFile, defaultHashes())
	if err != nil {
		t.Fatalf("failed to calculate digest: %v", err)
	}

	fp := &fakeProducer{
		products: map[string]attestation.Product{
			"large.spdx.json": {
				MimeType: SPDXMimeType,
				Digest:   digest,
			},
		},
	}

	sbomAttestor := NewSBOMAttestor()
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{fp, sbomAttestor},
		attestation.WithWorkingDir(tmpDir),
		attestation.WithHashes(defaultHashes()),
	)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	// The attestor read the entire large file without any size limit
	var attestError error
	for _, completed := range ctx.CompletedAttestors() {
		if completed.Attestor.Name() == Name {
			attestError = completed.Error
		}
	}

	if attestError != nil {
		t.Fatalf("expected large SBOM to be accepted, got error: %v", attestError)
	}

	t.Logf("SBOM attestor successfully read %d byte file without size limit", len(largeDoc))
	t.Log("BUG: io.ReadAll(f) on line 173 reads entire files without bounds. " +
		"No maximum file size is enforced. A crafted multi-GB SBOM file " +
		"would cause OOM.")
}

// ============================================================================
// R3-234: Product MIME type determines SBOM format without content verification
// ============================================================================

// TestSecurity_R3_234_MimeTypeDeterminesFormatWithoutContentCheck proves that
// the SBOM format (SPDX vs CycloneDX) is determined solely by the product's
// MIME type (lines 158-165), not by the actual content. A file with SPDX MIME
// type but CycloneDX content will be parsed as SPDX, leading to errors or
// incorrect data.
//
// Impact: MIME type mismatch causes silent parse failures or incorrect SBOM
// interpretation. An attacker controlling MIME types can cause the wrong
// parser to be used.
func TestSecurity_R3_234_MimeTypeDeterminesFormatWithoutContentCheck(t *testing.T) {
	// Create a CycloneDX document but register it with SPDX MIME type
	cycloneDXContent := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"metadata": {
			"component": {
				"name": "test-component",
				"version": "1.0.0",
				"type": "application"
			}
		}
	}`

	tmpDir := t.TempDir()
	sbomFile := filepath.Join(tmpDir, "mismatch.json")
	if err := os.WriteFile(sbomFile, []byte(cycloneDXContent), 0600); err != nil {
		t.Fatalf("failed to write mismatched SBOM: %v", err)
	}

	digest, err := cryptoutil.CalculateDigestSetFromFile(sbomFile, defaultHashes())
	if err != nil {
		t.Fatalf("failed to calculate digest: %v", err)
	}

	// Register as SPDX MIME type even though content is CycloneDX
	fp := &fakeProducer{
		products: map[string]attestation.Product{
			"mismatch.json": {
				MimeType: SPDXMimeType, // Wrong! Content is CycloneDX
				Digest:   digest,
			},
		},
	}

	sbomAttestor := NewSBOMAttestor()
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{fp, sbomAttestor},
		attestation.WithWorkingDir(tmpDir),
		attestation.WithHashes(defaultHashes()),
	)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	// Check what happened - the SPDX parser tried to parse CycloneDX content
	for _, completed := range ctx.CompletedAttestors() {
		if completed.Attestor.Name() == Name {
			if completed.Error != nil {
				t.Logf("SPDX parser failed on CycloneDX content (expected): %v", completed.Error)
			} else {
				t.Log("SPDX parser accepted CycloneDX content - format confusion!")
			}
		}
	}

	t.Log("BUG: SBOM format is determined by MIME type alone (lines 158-165), " +
		"not by content inspection. A MIME type mismatch causes the wrong " +
		"parser to be used, leading to silent failures or incorrect data.")
}

// ============================================================================
// R3-235: SBOM attestor uses product.IsSPDXJson for type detection by
//         header sniffing - first 500 bytes only
// ============================================================================

// TestSecurity_R3_235_TypeDetectionByHeaderSniffing proves that the
// UnmarshalJSON method detects SBOM format using product.IsSPDXJson and
// product.IsCycloneDXJson, which only examine the first 500 bytes.
// A document with a normal header but malicious body passes detection.
//
// Impact: Type detection can be spoofed by placing the right markers in
// the first 500 bytes while the rest of the document is something else.
func TestSecurity_R3_235_TypeDetectionByHeaderSniffing(t *testing.T) {
	// SPDX detection checks for "spdxVersion":"SPDX- in first 500 bytes
	if !product.IsSPDXJson([]byte(`{"spdxVersion":"SPDX-2.3"}`)) {
		t.Fatal("IsSPDXJson should detect valid SPDX marker")
	}

	// CycloneDX detection checks for "bomFormat":"CycloneDX" in first 500 bytes
	if !product.IsCycloneDXJson([]byte(`{"bomFormat":"CycloneDX"}`)) {
		t.Fatal("IsCycloneDXJson should detect valid CycloneDX marker")
	}

	// A document with SPDX marker but that's actually not valid SPDX
	fakeSPDX := `{"spdxVersion":"SPDX-2.3", "evil": true}`
	if !product.IsSPDXJson([]byte(fakeSPDX)) {
		t.Error("expected IsSPDXJson to match based on header alone")
	}

	// A document that matches BOTH detectors
	ambiguous := `{"spdxVersion":"SPDX-2.3", "bomFormat":"CycloneDX"}`
	isSPDX := product.IsSPDXJson([]byte(ambiguous))
	isCDX := product.IsCycloneDXJson([]byte(ambiguous))

	if isSPDX && isCDX {
		t.Log("BUG: Document matches BOTH SPDX and CycloneDX detection. " +
			"In UnmarshalJSON, the first check wins (SPDX), but the document " +
			"could be interpreted differently by other tools.")
	}

	// Content beyond 500 bytes is never inspected
	padding := strings.Repeat(" ", 500)
	hiddenSPDX := padding + `"spdxVersion":"SPDX-2.3"`
	if product.IsSPDXJson([]byte(hiddenSPDX)) {
		t.Error("expected IsSPDXJson to miss marker beyond 500 bytes")
	} else {
		t.Log("Confirmed: IsSPDXJson only examines first 500 bytes")
	}

	t.Log("BUG: SBOM type detection in UnmarshalJSON uses header sniffing " +
		"(first 500 bytes) via product.IsSPDXJson/IsCycloneDXJson. This is " +
		"easily spoofed and can produce ambiguous results.")
}
