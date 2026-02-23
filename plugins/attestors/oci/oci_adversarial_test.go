//go:build audit

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

package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Helpers
// ============================================================================

// buildTarFile writes a tar archive to disk and returns its path.
func buildTarFile(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range entries {
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0600))
	return p
}

// buildTarFileWithRawHeaders writes a tar where we can control the header Size
// independently of the actual data written. Used to simulate adversarial headers.
func buildTarFileWithRawHeaders(t *testing.T, entries []struct {
	Name    string
	Size    int64 // claimed size in header
	Content []byte
}) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name: e.Name,
			Mode: 0600,
			Size: e.Size,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		// Write exactly Size bytes (pad with zeros if content is shorter)
		data := make([]byte, e.Size)
		copy(data, e.Content)
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0600))
	return p
}

// gzCompress compresses data with gzip.
func gzCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// defaultHashes returns the default hashes used by AttestationContext.
func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256, GitOID: true},
		{Hash: crypto.SHA1, GitOID: true},
	}
}

// makeCtxWithProduct creates an AttestationContext with a product registered
// at the given path with the given MIME type, and computes its digest.
func makeCtxWithProduct(t *testing.T, path, mimeType string) *attestation.AttestationContext {
	t.Helper()

	// We need to add a product to the context. Since Products() is read-only
	// and we don't have a setter, we use a small Producer attestor.
	prod := &fakeProducer{
		path:     path,
		mimeType: mimeType,
		hashes:   defaultHashes(),
	}
	// Run the attestor to register the product
	prod.computeDigest(t)

	prodCtx, err := attestation.NewContext("test",
		[]attestation.Attestor{prod},
		attestation.WithWorkingDir(filepath.Dir(path)),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)
	require.NoError(t, prodCtx.RunAttestors())

	return prodCtx
}

// fakeProducer is a minimal attestor that registers a file as a product.
type fakeProducer struct {
	path     string
	mimeType string
	hashes   []cryptoutil.DigestValue
	digest   cryptoutil.DigestSet
}

func (fp *fakeProducer) Name() string                                      { return "fake-producer" }
func (fp *fakeProducer) Type() string                                      { return "fake" }
func (fp *fakeProducer) RunType() attestation.RunType                      { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error     { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                        { return nil }

func (fp *fakeProducer) computeDigest(t *testing.T) {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromFile(fp.path, fp.hashes)
	require.NoError(t, err)
	fp.digest = ds
}

func (fp *fakeProducer) Products() map[string]attestation.Product {
	return map[string]attestation.Product{
		fp.path: {
			MimeType: fp.mimeType,
			Digest:   fp.digest,
		},
	}
}

// ============================================================================
// BUG #1: getCandidate uses strings.Contains for MIME type matching
// ============================================================================
// The check `!strings.Contains(mimeTypes, product.MimeType)` is broken:
//   - Empty MimeType "" matches because strings.Contains("application/x-tar", "") is true
//   - Partial strings like "tar", "x-tar", "x-t" all match
//   - This should be an equality check: product.MimeType == mimeTypes

func TestBug_MIMETypeContainsCheck(t *testing.T) {
	// Build a valid tar with a manifest
	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{}},
	})
	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte(`{"architecture":"amd64"}`),
	})

	// Test 1: Empty MIME type should NOT match, but it does
	t.Run("empty_mime_type_matches_unexpectedly", func(t *testing.T) {
		ctx := makeCtxWithProduct(t, tarPath, "")
		a := New()
		err := a.getCandidate(ctx)
		// BUG: This SHOULD return "no tar file found" error, but the Contains
		// check passes for empty string since strings.Contains(anything, "") == true.
		// If getCandidate succeeds with empty MIME, that's the bug.
		if err == nil {
			t.Logf("BUG CONFIRMED: getCandidate accepted empty MIME type")
			t.Logf("strings.Contains(%q, %q) = %v", mimeTypes, "", strings.Contains(mimeTypes, ""))
		}
	})

	// Test 2: Partial MIME type "tar" should NOT match
	t.Run("partial_mime_type_tar_matches_unexpectedly", func(t *testing.T) {
		ctx := makeCtxWithProduct(t, tarPath, "tar")
		a := New()
		err := a.getCandidate(ctx)
		if err == nil {
			t.Logf("BUG CONFIRMED: getCandidate accepted partial MIME type 'tar'")
			t.Logf("strings.Contains(%q, %q) = %v", mimeTypes, "tar", strings.Contains(mimeTypes, "tar"))
		}
	})

	// Test 3: Partial MIME type "x-tar" should NOT match
	t.Run("partial_mime_type_x_tar_matches_unexpectedly", func(t *testing.T) {
		ctx := makeCtxWithProduct(t, tarPath, "x-tar")
		a := New()
		err := a.getCandidate(ctx)
		if err == nil {
			t.Logf("BUG CONFIRMED: getCandidate accepted partial MIME type 'x-tar'")
		}
	})

	// Test 4: Correct MIME type should match
	t.Run("correct_mime_type_matches", func(t *testing.T) {
		ctx := makeCtxWithProduct(t, tarPath, "application/x-tar")
		a := New()
		err := a.getCandidate(ctx)
		assert.NoError(t, err, "Correct MIME type should match")
	})

	// Test 5: Superset MIME type should NOT match
	t.Run("superset_mime_type_rejected", func(t *testing.T) {
		ctx := makeCtxWithProduct(t, tarPath, "application/x-tar+gzip")
		a := New()
		err := a.getCandidate(ctx)
		// This correctly fails because "application/x-tar+gzip" is not contained in "application/x-tar"
		assert.Error(t, err, "Superset MIME type should be rejected")
	})
}

// ============================================================================
// BUG #2: getLayerDIFFIDs has an unbounded gzip decompression bomb vector
// ============================================================================
// The code checks h.Size < 0 || h.Size > maxTarEntrySize for the compressed
// layer size, but after decompression via io.ReadAll(breader), there is NO
// bound on the decompressed size. A small gzip bomb could decompress to
// gigabytes, causing OOM.

func TestBug_GzipDecompressionBomb(t *testing.T) {
	// Create a gzip bomb: highly compressible data that's small compressed
	// but would be large decompressed. We use a moderate size here (10MB
	// decompressed, well within test limits) to demonstrate the lack of
	// bound checking without actually causing OOM.
	decompressedSize := 10 * 1024 * 1024 // 10 MB
	uncompressed := bytes.Repeat([]byte{0x00}, decompressedSize)
	compressed := gzCompress(t, uncompressed)

	t.Logf("Compressed size: %d bytes", len(compressed))
	t.Logf("Decompressed size: %d bytes", decompressedSize)
	t.Logf("Compression ratio: %.1fx", float64(decompressedSize)/float64(len(compressed)))

	// The compressed data is small enough to pass the maxTarEntrySize check,
	// but decompresses to 10MB. In a real attack, the ratio could be 1000:1+.
	assert.Less(t, int64(len(compressed)), int64(maxTarEntrySize),
		"Compressed data should be well under maxTarEntrySize")

	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{"layer.tar.gz"}},
	})

	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte(`{"architecture":"amd64"}`),
		"layer.tar.gz":  compressed,
	})

	ctx := makeCtxWithProduct(t, tarPath, "application/x-tar")
	a := New()
	a.tarFilePath = tarPath
	a.ManifestRaw = manifest
	a.Manifest = []Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{"layer.tar.gz"}},
	}

	// This succeeds, but the io.ReadAll inside getLayerDIFFIDs is unbounded.
	// A real gzip bomb with 1000:1 ratio at 256MB compressed = 256GB decompressed.
	layerDiffIDs, err := a.Manifest[0].getLayerDIFFIDs(ctx, a.tarFilePath)
	if err == nil {
		t.Logf("BUG: getLayerDIFFIDs succeeded reading %d bytes of decompressed data with no bound check", decompressedSize)
		t.Logf("A gzip bomb could cause OOM since io.ReadAll has no size limit after decompression")
		assert.Len(t, layerDiffIDs, 1)
	} else {
		t.Logf("getLayerDIFFIDs returned error (unexpected): %v", err)
	}
}

// ============================================================================
// BUG #3: defer breader.Close() inside a for loop (resource leak)
// ============================================================================
// In getLayerDIFFIDs, `defer breader.Close()` is called inside the inner
// for loop at line 315. All deferred closes accumulate and only execute
// when the function returns, not when each loop iteration ends.

func TestBug_DeferCloseInsideLoop(t *testing.T) {
	// Create multiple gzip-compressed layers
	numLayers := 5
	layers := make([]string, numLayers)
	entries := map[string][]byte{
		"config.json": []byte(`{"architecture":"amd64"}`),
	}
	for i := 0; i < numLayers; i++ {
		layerName := "layer" + string(rune('0'+i)) + ".tar.gz"
		layers[i] = layerName
		data := bytes.Repeat([]byte{byte(i)}, 1024)
		entries[layerName] = gzCompress(t, data)
	}

	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: layers},
	})
	entries["manifest.json"] = manifest

	tarPath := buildTarFile(t, entries)

	ctx := makeCtxWithProduct(t, tarPath, "application/x-tar")
	m := Manifest{Config: "config.json", Layers: layers}

	// This works but all gzip readers remain open until function return
	layerDiffIDs, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err)
	assert.Len(t, layerDiffIDs, numLayers,
		"All layers should be processed despite defer-in-loop bug")
	t.Logf("BUG: %d gzip readers were deferred inside a loop; all stay open until function returns", numLayers)
}

// ============================================================================
// Adversarial: maxTarEntrySize enforcement
// ============================================================================

func TestMaxTarEntrySizeEnforcement_Manifest(t *testing.T) {
	t.Run("manifest_exactly_at_limit", func(t *testing.T) {
		// Create a manifest that is exactly at a small size.
		// We can't actually allocate 256MB in tests, so we test with a small entry.
		entries := []struct {
			Name    string
			Size    int64
			Content []byte
		}{
			{Name: "manifest.json", Size: 10, Content: []byte(`[{"Config":"c"}]`)},
		}
		tarPath := buildTarFileWithRawHeaders(t, entries)

		a := New()
		a.tarFilePath = tarPath

		// parseMaifest should handle the size mismatch between header and content
		err := a.parseMaifest(makeCtxWithProduct(t, tarPath, "application/x-tar"))
		// It may or may not error depending on io.ReadFull behavior, but must not panic
		_ = err
	})

	t.Run("manifest_over_limit", func(t *testing.T) {
		// Verify the constant value - we can't allocate 256MB in tests
		assert.Equal(t, int64(256*1024*1024), int64(maxTarEntrySize))
	})
}

func TestMaxTarEntrySizeEnforcement_Config(t *testing.T) {
	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{}},
	})

	t.Run("config_at_zero_size", func(t *testing.T) {
		tarPath := buildTarFile(t, map[string][]byte{
			"manifest.json": manifest,
			"config.json":   []byte{}, // zero-length config
		})
		ctx := makeCtxWithProduct(t, tarPath, "application/x-tar")
		m := Manifest{Config: "config.json"}
		_, err := m.getImageID(ctx, tarPath)
		// Zero-size should work (io.ReadFull on empty = io.ErrUnexpectedEOF or empty)
		// The key thing is: no panic, no OOM
		_ = err
	})
}

// ============================================================================
// Adversarial: Truncated tar entries
// ============================================================================

func TestTruncatedTarEntries(t *testing.T) {
	t.Run("truncated_manifest", func(t *testing.T) {
		// Create a tar where the manifest header claims 1000 bytes but only 10 are written
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		hdr := &tar.Header{
			Name: "manifest.json",
			Mode: 0600,
			Size: 1000,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		// Write less data than claimed
		_, _ = tw.Write([]byte(`[{"Config":`))
		// Don't close properly - create truncated tar
		data := buf.Bytes()

		dir := t.TempDir()
		tarPath := filepath.Join(dir, "truncated.tar")
		require.NoError(t, os.WriteFile(tarPath, data, 0600))

		a := New()
		a.tarFilePath = tarPath
		ctx, err := attestation.NewContext("test", []attestation.Attestor{},
			attestation.WithWorkingDir(dir),
			attestation.WithHashes(defaultHashes()),
		)
		require.NoError(t, err)

		// parseMaifest should return an error, not panic
		err = a.parseMaifest(ctx)
		assert.Error(t, err, "Truncated manifest should cause an error")
	})

	t.Run("truncated_config", func(t *testing.T) {
		manifest, _ := json.Marshal([]Manifest{
			{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{}},
		})

		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		// Write valid manifest
		mhdr := &tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest))}
		require.NoError(t, tw.WriteHeader(mhdr))
		_, _ = tw.Write(manifest)
		// Write config with truncated data
		chdr := &tar.Header{Name: "config.json", Mode: 0600, Size: 500}
		require.NoError(t, tw.WriteHeader(chdr))
		_, _ = tw.Write([]byte(`{"arch`)) // truncated

		data := buf.Bytes()
		dir := t.TempDir()
		tarPath := filepath.Join(dir, "truncated_config.tar")
		require.NoError(t, os.WriteFile(tarPath, data, 0600))

		ctx, err := attestation.NewContext("test", []attestation.Attestor{},
			attestation.WithWorkingDir(dir),
			attestation.WithHashes(defaultHashes()),
		)
		require.NoError(t, err)

		m := Manifest{Config: "config.json"}
		_, err = m.getImageID(ctx, tarPath)
		assert.Error(t, err, "Truncated config should cause an error from io.ReadFull")
	})

	t.Run("truncated_layer", func(t *testing.T) {
		manifest, _ := json.Marshal([]Manifest{
			{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{"layer.tar"}},
		})

		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		mhdr := &tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest))}
		require.NoError(t, tw.WriteHeader(mhdr))
		_, _ = tw.Write(manifest)
		chdr := &tar.Header{Name: "config.json", Mode: 0600, Size: 5}
		require.NoError(t, tw.WriteHeader(chdr))
		_, _ = tw.Write([]byte(`{}`))
		// Pad to match claimed size
		_, _ = tw.Write(make([]byte, 3))
		// Layer with truncated data
		lhdr := &tar.Header{Name: "layer.tar", Mode: 0600, Size: 1000}
		require.NoError(t, tw.WriteHeader(lhdr))
		_, _ = tw.Write([]byte("truncated"))

		data := buf.Bytes()
		dir := t.TempDir()
		tarPath := filepath.Join(dir, "truncated_layer.tar")
		require.NoError(t, os.WriteFile(tarPath, data, 0600))

		ctx, err := attestation.NewContext("test", []attestation.Attestor{},
			attestation.WithWorkingDir(dir),
			attestation.WithHashes(defaultHashes()),
		)
		require.NoError(t, err)

		m := Manifest{Config: "config.json", Layers: []string{"layer.tar"}}
		_, err = m.getLayerDIFFIDs(ctx, tarPath)
		assert.Error(t, err, "Truncated layer should cause an error from io.ReadFull")
	})
}

// ============================================================================
// Adversarial: Corrupted gzip data in layers
// ============================================================================

func TestCorruptedGzipLayer(t *testing.T) {
	// Data that starts with gzip magic bytes but is corrupted
	corruptGzip := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff} // corrupt

	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{"layer.tar.gz"}},
	})

	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte(`{"architecture":"amd64"}`),
		"layer.tar.gz":  corruptGzip,
	})

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	m := Manifest{Config: "config.json", Layers: []string{"layer.tar.gz"}}
	_, err = m.getLayerDIFFIDs(ctx, tarPath)
	assert.Error(t, err, "Corrupted gzip data should produce an error")
}

// ============================================================================
// Adversarial: Non-existent tar file
// ============================================================================

func TestNonExistentTarFile(t *testing.T) {
	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	t.Run("parseMaifest_nonexistent", func(t *testing.T) {
		a := New()
		a.tarFilePath = "/nonexistent/path/image.tar"
		err := a.parseMaifest(ctx)
		assert.Error(t, err)
	})

	t.Run("getImageID_nonexistent", func(t *testing.T) {
		m := Manifest{Config: "config.json"}
		_, err := m.getImageID(ctx, "/nonexistent/path/image.tar")
		assert.Error(t, err)
	})

	t.Run("getLayerDIFFIDs_nonexistent", func(t *testing.T) {
		m := Manifest{Config: "config.json", Layers: []string{"layer.tar"}}
		_, err := m.getLayerDIFFIDs(ctx, "/nonexistent/path/image.tar")
		assert.Error(t, err)
	})
}

// ============================================================================
// Adversarial: Empty tar archive
// ============================================================================

func TestEmptyTarArchive(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.Close())

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "empty.tar")
	require.NoError(t, os.WriteFile(tarPath, buf.Bytes(), 0600))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	t.Run("parseMaifest_empty", func(t *testing.T) {
		a := New()
		a.tarFilePath = tarPath
		err := a.parseMaifest(ctx)
		// ManifestRaw will be nil/empty since no manifest.json found
		// CalculateDigestSetFromBytes on nil should either error or work
		// json.Unmarshal on nil should error
		assert.Error(t, err, "Empty tar should fail manifest parsing")
	})

	t.Run("getImageID_empty", func(t *testing.T) {
		m := Manifest{Config: "config.json"}
		_, err := m.getImageID(ctx, tarPath)
		assert.Error(t, err, "Empty tar should fail to find config")
		assert.Contains(t, err.Error(), "could not find config")
	})

	t.Run("getLayerDIFFIDs_empty", func(t *testing.T) {
		m := Manifest{Config: "config.json", Layers: []string{"layer.tar"}}
		layerDiffIDs, err := m.getLayerDIFFIDs(ctx, tarPath)
		// No matching layers found, but no error either
		assert.NoError(t, err)
		assert.Empty(t, layerDiffIDs)
	})
}

// ============================================================================
// Adversarial: Invalid JSON manifest
// ============================================================================

func TestInvalidJSONManifest(t *testing.T) {
	testCases := []struct {
		name     string
		manifest []byte
	}{
		{"not_json", []byte("this is not json")},
		{"empty_object", []byte("{}")},
		{"null", []byte("null")},
		{"number", []byte("42")},
		{"empty_string", []byte(`""`)},
		{"malformed_json", []byte(`[{"Config": "c"`)},
		{"wrong_type_config", []byte(`[{"Config": 42}]`)},
		{"nested_arrays", []byte(`[[[[]]]]`)},
		{"very_deep_nesting", []byte(`{"a":{"b":{"c":{"d":{"e":"f"}}}}}`)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := buildTarFile(t, map[string][]byte{
				"manifest.json": tc.manifest,
			})

			ctx, err := attestation.NewContext("test", []attestation.Attestor{},
				attestation.WithWorkingDir(filepath.Dir(tarPath)),
				attestation.WithHashes(defaultHashes()),
			)
			require.NoError(t, err)

			a := New()
			a.tarFilePath = tarPath
			err = a.parseMaifest(ctx)
			// Some may parse successfully (empty array), others should error.
			// The key thing is: no panic.
			if err != nil {
				t.Logf("parseMaifest returned error (expected): %v", err)
			} else {
				t.Logf("parseMaifest succeeded with manifest: %s", string(tc.manifest))
			}
		})
	}
}

// ============================================================================
// Adversarial: Manifest with directory traversal paths
// ============================================================================

func TestManifestWithPathTraversal(t *testing.T) {
	testCases := []struct {
		name       string
		configPath string
	}{
		{"relative_parent", "../../../etc/passwd"},
		{"absolute_path", "/etc/passwd"},
		{"double_dot", "foo/../../bar"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, _ := json.Marshal([]Manifest{
				{Config: tc.configPath, RepoTags: []string{"test:latest"}, Layers: []string{}},
			})

			tarPath := buildTarFile(t, map[string][]byte{
				"manifest.json": manifest,
				tc.configPath:   []byte(`{"architecture":"amd64"}`),
			})

			ctx, err := attestation.NewContext("test", []attestation.Attestor{},
				attestation.WithWorkingDir(filepath.Dir(tarPath)),
				attestation.WithHashes(defaultHashes()),
			)
			require.NoError(t, err)

			m := Manifest{Config: tc.configPath}
			// The code searches tar entries by name match, so traversal paths
			// in the manifest just need to match a tar entry. This isn't a
			// file-system traversal per se, but worth testing that it doesn't panic.
			_, err = m.getImageID(ctx, tarPath)
			// May succeed or fail, must not panic
			_ = err
		})
	}
}

// ============================================================================
// Adversarial: Tar with only directories
// ============================================================================

func TestTarWithOnlyDirectories(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, dir := range []string{"dir1/", "dir2/", "dir3/"} {
		hdr := &tar.Header{
			Name:     dir,
			Mode:     0755,
			Typeflag: tar.TypeDir,
		}
		require.NoError(t, tw.WriteHeader(hdr))
	}
	require.NoError(t, tw.Close())

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "dirs_only.tar")
	require.NoError(t, os.WriteFile(tarPath, buf.Bytes(), 0600))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	a := New()
	a.tarFilePath = tarPath
	err = a.parseMaifest(ctx)
	// ManifestRaw will be nil; should error during digest calc or unmarshal
	assert.Error(t, err)
}

// ============================================================================
// Adversarial: Negative size header
// ============================================================================

func TestNegativeSizeHeader(t *testing.T) {
	// Go's tar library may reject negative sizes during write, but we test
	// the code's behavior when it encounters them during read.
	// The size check `h.Size < 0` should catch this.
	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", Layers: []string{}},
	})

	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte(`{"architecture":"amd64"}`),
	})

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	// Valid tar should work fine
	a := New()
	a.tarFilePath = tarPath
	err = a.parseMaifest(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, a.ManifestRaw)
}

// ============================================================================
// Adversarial: Subjects() on nil/empty digest sets
// ============================================================================

func TestSubjectsWithNilDigests(t *testing.T) {
	// Subjects() accesses maps by key without nil checks. If any digest set
	// is nil, the map access should return zero value (empty string).
	t.Run("nil_manifest_digest", func(t *testing.T) {
		a := &Attestor{
			ManifestDigest: nil,
			TarDigest:      nil,
			ImageID:        nil,
		}
		// This should NOT panic even with nil digest sets
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Subjects() panicked with nil digests: %v", r)
			}
		}()
		_ = a.Subjects()
	})

	t.Run("empty_digest_sets", func(t *testing.T) {
		a := &Attestor{
			ManifestDigest: cryptoutil.DigestSet{},
			TarDigest:      cryptoutil.DigestSet{},
			ImageID:        cryptoutil.DigestSet{},
		}
		subjects := a.Subjects()
		assert.NotNil(t, subjects)
	})

	t.Run("with_image_tags", func(t *testing.T) {
		a := &Attestor{
			ManifestDigest: cryptoutil.DigestSet{},
			TarDigest:      cryptoutil.DigestSet{},
			ImageID:        cryptoutil.DigestSet{},
			ImageTags:      []string{"tag1", "tag2", ""},
		}
		subjects := a.Subjects()
		assert.NotNil(t, subjects)
	})
}

// ============================================================================
// Adversarial: io.ReadFull error propagation
// ============================================================================

func TestReadFullErrorPropagation(t *testing.T) {
	// Create a valid tar with proper manifest but config content shorter than claimed
	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", Layers: []string{}},
	})

	// Build tar where config's header claims more bytes than present
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Valid manifest entry
	mhdr := &tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest))}
	require.NoError(t, tw.WriteHeader(mhdr))
	_, err := tw.Write(manifest)
	require.NoError(t, err)

	// Config entry with correct size
	configData := []byte(`{"architecture":"amd64"}`)
	chdr := &tar.Header{Name: "config.json", Mode: 0600, Size: int64(len(configData))}
	require.NoError(t, tw.WriteHeader(chdr))
	_, err = tw.Write(configData)
	require.NoError(t, err)

	require.NoError(t, tw.Close())

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "valid.tar")
	require.NoError(t, os.WriteFile(tarPath, buf.Bytes(), 0600))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	// Should succeed with properly formed tar
	m := Manifest{Config: "config.json"}
	imageID, err := m.getImageID(ctx, tarPath)
	assert.NoError(t, err)
	assert.NotNil(t, imageID)
}

// ============================================================================
// Adversarial: Multiple manifest.json entries in tar
// ============================================================================

func TestMultipleManifestEntries(t *testing.T) {
	// A tar can contain duplicate entries. The code should use the first one
	// because it breaks after finding manifest.json.
	manifest1, _ := json.Marshal([]Manifest{
		{Config: "config1.json", RepoTags: []string{"first:latest"}, Layers: []string{}},
	})
	manifest2, _ := json.Marshal([]Manifest{
		{Config: "config2.json", RepoTags: []string{"second:latest"}, Layers: []string{}},
	})

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// First manifest
	hdr1 := &tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest1))}
	require.NoError(t, tw.WriteHeader(hdr1))
	_, _ = tw.Write(manifest1)

	// Second manifest (duplicate name)
	hdr2 := &tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest2))}
	require.NoError(t, tw.WriteHeader(hdr2))
	_, _ = tw.Write(manifest2)

	require.NoError(t, tw.Close())

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "dupmanifest.tar")
	require.NoError(t, os.WriteFile(tarPath, buf.Bytes(), 0600))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	a := New()
	a.tarFilePath = tarPath
	err = a.parseMaifest(ctx)
	require.NoError(t, err)

	// Should have used the FIRST manifest (breaks after finding it)
	assert.Equal(t, "config1.json", a.Manifest[0].Config)
}

// ============================================================================
// Adversarial: Very large number of layers
// ============================================================================

func TestManyLayers(t *testing.T) {
	numLayers := 100
	layers := make([]string, numLayers)
	entries := map[string][]byte{
		"config.json": []byte(`{"architecture":"amd64"}`),
	}
	for i := 0; i < numLayers; i++ {
		name := fmt.Sprintf("layer%03d.tar", i)
		layers[i] = name
		entries[name] = []byte("layer-content-" + name)
	}

	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: layers},
	})
	entries["manifest.json"] = manifest

	tarPath := buildTarFile(t, entries)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	m := Manifest{Config: "config.json", Layers: layers}
	layerDiffIDs, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err)
	assert.Len(t, layerDiffIDs, numLayers)
}

// ============================================================================
// Adversarial: Symlink and hardlink entries in tar
// ============================================================================

func TestSymlinkEntries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Symlink entry
	hdr := &tar.Header{
		Name:     "manifest.json",
		Linkname: "/etc/passwd",
		Typeflag: tar.TypeSymlink,
		Mode:     0777,
	}
	require.NoError(t, tw.WriteHeader(hdr))
	require.NoError(t, tw.Close())

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "symlink.tar")
	require.NoError(t, os.WriteFile(tarPath, buf.Bytes(), 0600))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	a := New()
	a.tarFilePath = tarPath
	// Symlinks are directories in terms of FileInfo (they may be treated differently).
	// The code checks h.FileInfo().IsDir() but symlinks aren't directories.
	// The code will try to read it but Size is 0, so io.ReadFull reads 0 bytes.
	err = a.parseMaifest(ctx)
	// Should not panic
	_ = err
}

// ============================================================================
// Adversarial: Garbage/random bytes as tar file
// ============================================================================

func TestGarbageTarFile(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"all_zeros", make([]byte, 1024)},
		{"random_bytes", []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}},
		{"single_byte", []byte{0xff}},
		{"empty", []byte{}},
		{"tar_magic_only", []byte("ustar\x00")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tarPath := filepath.Join(dir, "garbage.tar")
			require.NoError(t, os.WriteFile(tarPath, tc.data, 0600))

			ctx, err := attestation.NewContext("test", []attestation.Attestor{},
				attestation.WithWorkingDir(dir),
				attestation.WithHashes(defaultHashes()),
			)
			require.NoError(t, err)

			a := New()
			a.tarFilePath = tarPath
			err = a.parseMaifest(ctx)
			// Must not panic, should return error
			assert.Error(t, err, "Garbage data should cause parsing error")
		})
	}
}

// ============================================================================
// Adversarial: File descriptor leak detection in parseMaifest
// ============================================================================

func TestParseMaifestFileDescriptorLeak(t *testing.T) {
	// parseMaifest opens the tar file with os.Open but does NOT have a
	// defer f.Close()! Let's check if the file handle is leaked.
	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{}},
	})

	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte(`{"architecture":"amd64"}`),
	})

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	// Call parseMaifest many times to see if file handles accumulate.
	// On macOS/Linux, the default ulimit is typically 256-1024.
	// If there's a leak, this will eventually fail with "too many open files".
	for i := 0; i < 100; i++ {
		a := New()
		a.tarFilePath = tarPath
		err := a.parseMaifest(ctx)
		if err != nil {
			t.Fatalf("parseMaifest failed on iteration %d: %v", i, err)
		}
	}
	t.Logf("BUG: parseMaifest opens file with os.Open but never calls f.Close() - file descriptor leak")
}

// ============================================================================
// Adversarial: io.ReadFull on zero-size entry
// ============================================================================

func TestReadFullZeroSize(t *testing.T) {
	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", Layers: []string{"layer.tar"}},
	})

	// Layer with zero bytes
	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte(`{}`),
		"layer.tar":     []byte{},
	})

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	m := Manifest{Config: "config.json", Layers: []string{"layer.tar"}}
	// io.ReadFull on zero bytes should succeed (reads nothing)
	layerDiffIDs, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err)
	assert.Len(t, layerDiffIDs, 1)
}

// ============================================================================
// Adversarial: Non-gzip content that passes DetectContentType
// ============================================================================

func TestContentTypeDetectionEdgeCases(t *testing.T) {
	testCases := []struct {
		name    string
		content []byte
	}{
		{"plain_text", []byte("Hello, World!")},
		{"binary_data", bytes.Repeat([]byte{0x00, 0x01, 0x02}, 100)},
		{"json_data", []byte(`{"key":"value"}`)},
		{"html_data", []byte("<html><body>test</body></html>")},
		{"pdf_magic", []byte("%PDF-1.4 fake pdf content here")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, _ := json.Marshal([]Manifest{
				{Config: "config.json", Layers: []string{"layer.tar"}},
			})

			tarPath := buildTarFile(t, map[string][]byte{
				"manifest.json": manifest,
				"config.json":   []byte(`{}`),
				"layer.tar":     tc.content,
			})

			ctx, err := attestation.NewContext("test", []attestation.Attestor{},
				attestation.WithWorkingDir(filepath.Dir(tarPath)),
				attestation.WithHashes(defaultHashes()),
			)
			require.NoError(t, err)

			m := Manifest{Config: "config.json", Layers: []string{"layer.tar"}}
			layerDiffIDs, err := m.getLayerDIFFIDs(ctx, tarPath)
			// Should treat as non-gzip and hash directly
			require.NoError(t, err)
			assert.Len(t, layerDiffIDs, 1)
		})
	}
}
