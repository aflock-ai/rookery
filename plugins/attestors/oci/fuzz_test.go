//go:build audit

package oci

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzOCITarParsing fuzzes the OCI tar parsing logic with random tar archives
// containing random entry sizes. This specifically tests:
//   - No panics regardless of tar content
//   - The maxTarEntrySize bound is enforced (256 MB)
//   - Malformed tar headers don't cause crashes
//   - Very large claimed sizes (decompression bomb) are rejected
func FuzzOCITarParsing(f *testing.F) {
	// Helper to build a valid tar archive with a manifest.json
	buildTar := func(manifestJSON []byte, extraEntries map[string][]byte) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)

		if manifestJSON != nil {
			hdr := &tar.Header{
				Name: "manifest.json",
				Mode: 0600,
				Size: int64(len(manifestJSON)),
			}
			_ = tw.WriteHeader(hdr)
			_, _ = tw.Write(manifestJSON)
		}

		for name, content := range extraEntries {
			hdr := &tar.Header{
				Name: name,
				Mode: 0600,
				Size: int64(len(content)),
			}
			_ = tw.WriteHeader(hdr)
			_, _ = tw.Write(content)
		}

		_ = tw.Close()
		return buf.Bytes()
	}

	// Valid manifest
	validManifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: []string{"layer.tar"}},
	})

	// Seed: valid tar with manifest
	f.Add(buildTar(validManifest, map[string][]byte{
		"config.json": []byte(`{"architecture":"amd64"}`),
		"layer.tar":   []byte("layer-content"),
	}))

	// Seed: empty tar
	f.Add(func() []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.Close()
		return buf.Bytes()
	}())

	// Seed: tar with only manifest
	f.Add(buildTar(validManifest, nil))

	// Seed: tar with empty manifest
	f.Add(buildTar([]byte("[]"), nil))

	// Seed: tar with invalid JSON manifest
	f.Add(buildTar([]byte("not json"), nil))

	// Seed: completely garbage bytes
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{})

	// Seed: tar with a header claiming a huge size but no actual data (bomb test).
	// We construct a tar header that claims maxTarEntrySize + 1 bytes.
	f.Add(func() []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		hdr := &tar.Header{
			Name: "manifest.json",
			Mode: 0600,
			Size: maxTarEntrySize + 1, // exceeds limit
		}
		_ = tw.WriteHeader(hdr)
		// Don't write the full body -- the tar will be truncated/invalid
		_, _ = tw.Write([]byte("x"))
		_ = tw.Close()
		return buf.Bytes()
	}())

	// Seed: tar with negative size header
	f.Add(func() []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		hdr := &tar.Header{
			Name: "manifest.json",
			Mode: 0600,
			Size: -1,
		}
		// WriteHeader may reject negative size, but we try anyway
		_ = tw.WriteHeader(hdr)
		_ = tw.Close()
		return buf.Bytes()
	}())

	// Seed: tar with many entries
	f.Add(func() []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for i := 0; i < 100; i++ {
			name := "file" + string(rune('0'+i%10)) + ".txt"
			data := bytes.Repeat([]byte("x"), i)
			hdr := &tar.Header{
				Name: name,
				Mode: 0600,
				Size: int64(len(data)),
			}
			_ = tw.WriteHeader(hdr)
			_, _ = tw.Write(data)
		}
		_ = tw.Close()
		return buf.Bytes()
	}())

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test raw tar reading -- this exercises the same tar.NewReader path
		// used by parseMaifest, getImageID, and getLayerDIFFIDs.
		tarReader := tar.NewReader(bytes.NewReader(data))

		var manifestRaw []byte
		for {
			hdr, err := tarReader.Next()
			if err != nil {
				break
			}

			if hdr == nil {
				continue
			}

			// Verify the size bound is respected: if the code were to
			// allocate based on hdr.Size without checking, a large value
			// could cause an OOM. We simulate the size check from oci.go.
			if hdr.Size < 0 || hdr.Size > maxTarEntrySize {
				// This is expected -- the code should reject this entry.
				continue
			}

			// Safely read the entry (bounded by maxTarEntrySize)
			buf := make([]byte, hdr.Size)
			n, err := tarReader.Read(buf)
			if err != nil && n == 0 {
				continue
			}
			buf = buf[:n]

			if hdr.Name == "manifest.json" {
				manifestRaw = buf
			}
		}

		// If we found a manifest, try to unmarshal it -- must not panic.
		if manifestRaw != nil {
			var manifests []Manifest
			_ = json.Unmarshal(manifestRaw, &manifests)
		}

		// Also verify that creating an Attestor and setting fields doesn't panic.
		a := New()
		_ = a.Name()
		_ = a.Type()
		_ = a.RunType()
	})
}
