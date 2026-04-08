// Copyright 2021 The Witness Contributors
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
	"archive/tar"
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromDigestMap(t *testing.T) {
	testDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte("test"), []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	assert.NoError(t, err)
	testDigestSet := make(map[string]cryptoutil.DigestSet)
	testDigestSet["test"] = testDigest
	result := fromDigestMap("", testDigestSet)
	assert.Len(t, result, 1)
	digest := result["test"].Digest
	assert.True(t, digest.Equal(testDigest))
}

func TestAttestorName(t *testing.T) {
	a := New()
	assert.Equal(t, a.Name(), ProductName)
}

func TestAttestorType(t *testing.T) {
	a := New()
	assert.Equal(t, a.Type(), ProductType)
}

func TestAttestorRunType(t *testing.T) {
	a := New()
	assert.Equal(t, a.RunType(), ProductRunType)
}

func TestAttestorAttest(t *testing.T) {
	a := New()
	testDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte("test"), []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		t.Errorf("Failed to calculate digest set from bytes: %v", err)
	}

	testDigestSet := make(map[string]cryptoutil.DigestSet)
	testDigestSet["test"] = testDigest
	a.baseArtifacts = testDigestSet
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))
}

func TestGetFileContentType(t *testing.T) {
	// Create a temporary directory for the test
	tempDir := t.TempDir()

	// Create a temporary text file.
	textFile, err := os.CreateTemp(tempDir, "test-*.txt")
	require.NoError(t, err)
	_, err = textFile.WriteString("This is a test file.")
	require.NoError(t, err)
	textFilePath := textFile.Name()
	textFile.Close()

	// Create a temporary PDF file with extension.
	pdfFile, err := os.CreateTemp(tempDir, "test-*")
	require.NoError(t, err)
	//write to pdf so it has correct file signature 25 50 44 46 2D
	_, err = pdfFile.WriteAt([]byte{0x25, 0x50, 0x44, 0x46, 0x2D}, 0)
	require.NoError(t, err)
	pdfFilePath := pdfFile.Name()
	pdfFile.Close()

	// Create a temporary tar file with no extension.
	tarFile, err := os.CreateTemp(tempDir, "test-*")
	require.NoError(t, err)
	tarBuffer := new(bytes.Buffer)
	writer := tar.NewWriter(tarBuffer)
	header := &tar.Header{
		Name: "test.txt",
		Size: int64(len("This is a test file.")),
	}
	require.NoError(t, writer.WriteHeader(header))
	_, err = writer.Write([]byte("This is a test file."))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	_, err = tarFile.Write(tarBuffer.Bytes())
	require.NoError(t, err)
	tarFilePath := tarFile.Name()
	tarFile.Close()
	// Open the temporary tar file using os.Open.
	tarFile, err = os.Open(tarFile.Name())
	require.NoError(t, err)
	defer func() {
		tarFile.Close()
		os.Remove(tarFile.Name())
	}()
	// Define the test cases.
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{"text file with extension", textFilePath, "text/plain; charset=utf-8"},
		{"PDF file with no extension", pdfFilePath, "application/pdf"},
		{"tar file with no extension", tarFilePath, "application/x-tar"},
	}

	// Run the test cases.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contentType, err := getFileContentType(test.filePath)
			require.NoError(t, err)
			require.Equal(t, test.expected, contentType)
		})
	}
}

func TestIncludeExcludeGlobs(t *testing.T) {
	workingDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(workingDir, "subdir"), 0777))
	files := []string{
		filepath.Join(workingDir, "test.txt"),
		filepath.Join(workingDir, "test.exe"),
		filepath.Join(workingDir, "subdir", "test.txt"),
		filepath.Join(workingDir, "subdir", "test.exe"),
	}

	for _, file := range files {
		f, err := os.Create(file)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	// Use forward slashes here because Subjects() normalizes product paths
	// to forward slashes before merkle hashing. Test expectations live in
	// the same coordinate space the attestor produces.
	tests := []struct {
		name                string
		includeGlob         string
		excludeGlob         string
		expectedProductKeys []string // keys that should be in the predicate (after normalization)
		expectTreeSubject   bool     // whether Subjects() should emit the single tree subject
	}{
		{"match all", "*", "", []string{"test.txt", "test.exe", "subdir/test.txt", "subdir/test.exe"}, true},
		{"include only exes", "*.exe", "", []string{"test.exe", "subdir/test.exe"}, true},
		{"exclude exes", "*", "*.exe", []string{"test.txt", "subdir/test.txt"}, true},
		{"include only files in subdir", "subdir/*", "", []string{"subdir/test.txt", "subdir/test.exe"}, true},
		{"exclude files in subdir", "*", "subdir/*", []string{"test.txt", "test.exe"}, true},
		{"include nothing", "", "", []string{}, false},
		{"exclude everything", "", "*", []string{}, false},
	}

	// assertTreeSubject asserts that Subjects() emits the single
	// `tree:products` subject (or no subjects if no products were included).
	// It also verifies the merkle root is deterministic by recomputing it
	// from the included product set.
	assertTreeSubject := func(t *testing.T, a *Attestor, expected []string, expectTree bool) {
		t.Helper()
		subjects := a.Subjects()
		if !expectTree {
			assert.Empty(t, subjects, "no included products should produce no subjects")
			return
		}
		require.Len(t, subjects, 1, "exactly one tree subject expected")
		root, ok := subjects[TreeSubjectName]
		require.True(t, ok, "subject must be named %q", TreeSubjectName)
		require.NotEmpty(t, root, "merkle root digest set must not be empty")

		// Recompute the merkle root over the expected file set using the
		// products map and confirm it matches what Subjects() returned.
		// This catches any future regression that breaks merkle determinism.
		recomputed := computeExpectedMerkleRoot(t, a, expected)
		assert.True(t, recomputed.Equal(root), "merkle root must match recomputation: got %v expected %v", root, recomputed)
	}

	assertProductsMatch := func(t *testing.T, products map[string]attestation.Product, expected []string) {
		t.Helper()
		productPaths := make([]string, 0, len(products))
		for path := range products {
			productPaths = append(productPaths, filepath.ToSlash(path))
		}
		assert.ElementsMatch(t, productPaths, expected)
	}

	t.Run("default include all", func(t *testing.T) {
		ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
		require.NoError(t, err)
		a := New()
		require.NoError(t, a.Attest(ctx))
		allFiles := []string{"test.txt", "test.exe", "subdir/test.txt", "subdir/test.exe"}
		assertTreeSubject(t, a, allFiles, true)
		assertProductsMatch(t, a.Products(), allFiles)
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(workingDir))
			require.NoError(t, err)
			a := New()
			WithIncludeGlob(test.includeGlob)(a)
			WithExcludeGlob(test.excludeGlob)(a)
			require.NoError(t, a.Attest(ctx))
			assertTreeSubject(t, a, test.expectedProductKeys, test.expectTreeSubject)
			// Products map should still contain everything that was filtered at
			// record time (the include/exclude semantics there are unchanged).
			assertProductsMatch(t, a.Products(), test.expectedProductKeys)
		})
	}
}

// computeExpectedMerkleRoot is a test helper that recomputes the same merkle
// root the production code emits, so the test verifies the *value* of the
// root rather than just its presence. If the production hashing logic ever
// drifts from this helper, the test will fail loudly.
func computeExpectedMerkleRoot(t *testing.T, a *Attestor, expectedFiles []string) cryptoutil.DigestSet {
	t.Helper()

	// Mirror Subjects()'s sort order — forward-slash normalized, then
	// lexically sorted.
	normalized := make([]string, 0, len(expectedFiles))
	for _, f := range expectedFiles {
		normalized = append(normalized, filepath.ToSlash(f))
	}
	// Local copy to avoid mutating the caller's slice.
	files := append([]string(nil), normalized...)
	sortStrings(files)

	// Walk one product to discover the algorithm set.
	algos := map[cryptoutil.DigestValue]struct{}{}
	for _, name := range files {
		// products map is keyed by OS path, but Subjects() works in
		// forward-slash space. Look up the product in either form.
		p, ok := a.products[name]
		if !ok {
			p, ok = a.products[filepath.FromSlash(name)]
		}
		require.True(t, ok, "test setup: product %q not in attestor.products", name)
		for dv := range p.Digest {
			algos[dv] = struct{}{}
		}
	}

	root := make(cryptoutil.DigestSet, len(algos))
	for dv := range algos {
		h := dv.New()
		for _, name := range files {
			p, ok := a.products[name]
			if !ok {
				p = a.products[filepath.FromSlash(name)]
			}
			digest := p.Digest[dv]
			writeMerkleEntry(h, name, digest)
		}
		root[dv] = encodeRoot(h, dv)
	}
	return root
}

// sortStrings is a tiny indirection so the test file does not need an
// extra "sort" import alongside the production code.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func TestIsSPDXJson(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "valid SPDX with large buffer",
			input:    []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com/test","creationInfo":{"created":"2024-01-01T00:00:00Z","creators":["Tool: test"]},"packages":[],"files":[],"relationships":[],"externalDocumentRefs":[],"snippets":[],"annotations":[],"reviewedBy":[],"comment":"","licenseListVersion":"3.21","creator":{"person":[],"organization":[],"tool":[]}}`),
			expected: true,
		},
		{
			name:     "valid SPDX with small buffer (< 500 bytes)",
			input:    []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test","documentNamespace":"https://example.com/test","creationInfo":{"created":"2024-01-01T00:00:00Z","creators":["Tool: test"]},"packages":[]}`),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSPDXJson(tt.input)
			assert.Equal(t, tt.expected, result, "IsSPDXJson() result mismatch")
		})
	}
}

func TestIsCycloneDXJson(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "valid CycloneDX with large buffer",
			input:    []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":1,"metadata":{"timestamp":"2024-01-01T00:00:00Z","tools":[{"vendor":"test","name":"test","version":"1.0.0"}],"component":{"type":"application","bom-ref":"pkg:generic/test","name":"test","version":"1.0.0"}},"components":[],"dependencies":[]}`),
			expected: true,
		},
		{
			name:     "valid CycloneDX with small buffer (< 500 bytes)",
			input:    []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":1,"metadata":{"timestamp":"2024-01-01T00:00:00Z"},"components":[]}`),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCycloneDXJson(tt.input)
			assert.Equal(t, tt.expected, result, "IsCycloneDXJson() result mismatch")
		})
	}
}
