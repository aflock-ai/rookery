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

// Security audit tests for oci/oci.go -- R3-165 through R3-169.
//
// Each test targets a specific, provable flaw in the OCI attestor.
// Tests are designed to FAIL if the bug is present and PASS once fixed.
package oci

import (
	"archive/tar"
	"bytes"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// R3-165: Subjects() hardcodes SHA256 lookup key, producing empty/incorrect
// subject keys when the attestation context uses non-SHA256 hash algorithms
//
// SECURITY IMPACT:
//   Subjects() at oci.go:263-265 constructs subject map keys by looking up
//   the SHA256 hash value from each DigestSet:
//
//       a.ManifestDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
//
//   If the AttestationContext was configured with ONLY SHA512 (or any non-SHA256
//   hash), the DigestSet will not contain a SHA256 entry. The map lookup
//   returns "" (zero value for string), producing malformed subject keys like:
//
//       "manifestdigest:"  (empty hash)
//       "tardigest:"       (empty hash)
//       "imageid:"         (empty hash)
//
//   These empty-hash subjects:
//   1. Collide with each other (all three map to "prefix:"), overwriting
//      entries in the subject map so only the last write survives.
//   2. Fail policy verification since the subject identifier carries no
//      meaningful digest information.
//   3. Could cause false-positive policy matches if an attacker crafts
//      a policy expecting empty-hash subjects.
//
// AFFECTED CODE: oci.go lines 263-265, and 279
// =============================================================================

func TestSecurity_R3_165_SubjectsEmptyHashOnNonSHA256(t *testing.T) {
	// Simulate an attestation that was run with ONLY SHA512 hashes (no SHA256).
	// The DigestSets will contain SHA512 entries but NOT SHA256 entries.
	// Subjects() hardcodes a SHA256 lookup, so all keys will have empty hashes.

	sha512Only := cryptoutil.DigestValue{Hash: crypto.SHA512}
	fakeHash := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

	a := &Attestor{
		ManifestDigest: cryptoutil.DigestSet{sha512Only: fakeHash + "1"},
		TarDigest:      cryptoutil.DigestSet{sha512Only: fakeHash + "2"},
		ImageID:        cryptoutil.DigestSet{sha512Only: fakeHash + "3"},
		ImageTags:      []string{"test:latest"},
		LayerDiffIDs: []cryptoutil.DigestSet{
			{sha512Only: fakeHash + "4"},
		},
	}

	subjects := a.Subjects()
	require.NotNil(t, subjects)

	// With SHA512-only digest sets, the hardcoded SHA256 lookup returns "".
	// This means subject keys will be:
	//   "manifestdigest:"  (empty hash!)
	//   "tardigest:"       (empty hash!)
	//   "imageid:"         (empty hash!)
	//   "layerdiffid00:"   (empty hash!)
	//
	// These keys all have empty hash portions, and the first three will
	// NOT collide (different prefixes), but the hash is meaningless.

	for key := range subjects {
		// Skip imagetag entries -- those are computed from tag bytes, not looked up.
		if strings.HasPrefix(key, "imagetag:") {
			continue
		}

		parts := strings.SplitN(key, ":", 2)
		require.Len(t, parts, 2, "subject key should have prefix:value format, got: %q", key)

		assert.NotEmpty(t, parts[1],
			"Subject key %q has empty hash value. "+
				"Subjects() hardcodes crypto.SHA256 lookup at oci.go:263-265, "+
				"but DigestSet only contains SHA512. The map lookup returns '' "+
				"(zero value), producing a meaningless subject identifier. "+
				"Fix: iterate the DigestSet to find an available hash, or accept "+
				"the hash algorithm as a parameter.",
			key)
	}
}

// =============================================================================
// R3-166: RepoTags from untrusted manifest JSON are used directly in subject
// keys without any sanitization
//
// SECURITY IMPACT:
//   The Manifest.RepoTags field is populated from user-controlled JSON inside
//   the OCI tar archive. At oci.go:274, the raw tag value is interpolated
//   directly into the subject map key:
//
//       subj[fmt.Sprintf("imagetag:%s", tag)] = hash
//
//   An attacker can craft a tar archive with RepoTags containing:
//   - Empty strings: creates "imagetag:" key (ambiguous with no-tag state)
//   - Newlines/control chars: corrupts log output, potential log injection
//   - Very long strings: memory amplification in the subject map
//   - Special characters: depending on downstream consumers, could cause
//     parsing issues in policy engines or storage backends
//   - Colons: creates keys like "imagetag:prefix:rest" that could confuse
//     naive "split on first colon" parsers
//
//   While none of these produce immediate RCE, they enable:
//   1. Subject key ambiguity attacks against policy verification
//   2. Log injection/corruption in monitoring systems
//   3. DoS via extremely long tag strings
//
// AFFECTED CODE: oci.go lines 268-275 (image tag loop in Subjects())
// =============================================================================

func TestSecurity_R3_166_UnsanitizedRepoTagsInSubjectKeys(t *testing.T) {
	// Create a valid OCI tar with crafted RepoTags.
	maliciousTags := []string{
		"",                                   // empty string
		"normal:latest",                      // legitimate tag
		"tag\nwith\nnewlines",                // newline injection
		"tag\x00with\x00nulls",               // null byte injection
		strings.Repeat("A", 10000),           // oversized tag
		"imageid:" + strings.Repeat("f", 64), // mimics another subject key prefix
		"manifestdigest:spoofed",             // attempts to spoof manifest digest subject
	}

	manifest, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: maliciousTags, Layers: []string{}},
	})
	configData := []byte(`{"architecture":"amd64"}`)

	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   configData,
	})

	ctx := makeCtxWithProduct(t, tarPath, "application/x-tar")
	a := New()
	err := a.getCandidate(ctx)
	require.NoError(t, err)
	err = a.parseMaifest(ctx)
	require.NoError(t, err)
	a.ImageID, err = a.Manifest[0].getImageID(ctx, a.tarFilePath)
	require.NoError(t, err)
	a.ImageTags = a.Manifest[0].RepoTags

	subjects := a.Subjects()
	require.NotNil(t, subjects)

	// Validate that all subject keys are well-formed.
	for key := range subjects {
		// No control characters in subject keys.
		for _, ch := range key {
			assert.False(t, ch < 0x20 && ch != '\t',
				"Subject key contains control character (0x%02x): %q. "+
					"RepoTags from untrusted manifest JSON should be sanitized "+
					"before use in subject keys.",
				ch, key)
		}

		// No null bytes.
		assert.NotContains(t, key, "\x00",
			"Subject key contains null byte: RepoTags must be sanitized. Key: %q", key)

		// No newlines.
		assert.NotContains(t, key, "\n",
			"Subject key contains newline: potential log injection. Key starts with: %q",
			key[:min(50, len(key))])

		// Reasonable length (say, 1024 chars max).
		assert.LessOrEqual(t, len(key), 1024,
			"Subject key is %d chars long. RepoTags should be length-limited "+
				"to prevent memory amplification.", len(key))
	}

	// Empty tags should be rejected, not create "imagetag:" entries.
	_, hasEmptyTag := subjects["imagetag:"]
	assert.False(t, hasEmptyTag,
		"Empty RepoTag created an 'imagetag:' subject key. "+
			"Empty tags should be skipped or rejected.")
}

// =============================================================================
// R3-167: parseMaifest does not validate ManifestRaw is non-empty before
// computing its digest and unmarshaling
//
// SECURITY IMPACT:
//   In parseMaifest (oci.go:211-258), if the tar archive does not contain
//   a "manifest.json" entry, the loop terminates without setting ManifestRaw.
//   ManifestRaw remains nil (its zero value from New()).
//
//   The code then proceeds to:
//   1. CalculateDigestSetFromBytes(nil, ...) at line 245 -- this computes a
//      digest of an empty/nil byte slice. Whether it errors or returns a
//      "hash of nothing" depends on the implementation.
//   2. json.Unmarshal(nil, &a.Manifest) at line 252 -- this returns
//      "unexpected end of JSON input" error.
//
//   The problem: if CalculateDigestSetFromBytes(nil) SUCCEEDS (returns a
//   valid DigestSet for empty content), then ManifestDigest is set to the
//   hash of empty bytes. Only the json.Unmarshal step catches the error.
//   This means ManifestDigest can be non-nil while Manifest is nil, leaving
//   the Attestor in an inconsistent state if error handling is imprecise.
//
//   The fix should explicitly check that ManifestRaw is non-empty before
//   proceeding with digest computation.
//
// AFFECTED CODE: oci.go lines 244-257 (post-loop processing in parseMaifest)
// =============================================================================

func TestSecurity_R3_167_ParseManifestMissingEntry(t *testing.T) {
	// Create a tar with NO manifest.json entry.
	configData := []byte(`{"architecture":"amd64"}`)
	tarPath := buildTarFile(t, map[string][]byte{
		"config.json": configData,
		"other.json":  []byte(`{}`),
	})

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)

	a := New()
	a.tarFilePath = tarPath

	err = a.parseMaifest(ctx)

	// parseMaifest should return an error for missing manifest.json.
	require.Error(t, err, "parseMaifest should fail when manifest.json is missing from tar")

	// Critical: ManifestDigest should NOT be set when manifest.json is missing.
	// If the empty/nil ManifestRaw passes through CalculateDigestSetFromBytes
	// successfully, ManifestDigest will contain a "hash of nothing" -- which
	// is a valid but semantically wrong value.
	assert.Nil(t, a.ManifestDigest,
		"ManifestDigest should be nil when manifest.json is missing. "+
			"If CalculateDigestSetFromBytes(nil) succeeds before json.Unmarshal "+
			"fails, ManifestDigest gets set to hash-of-empty-bytes. "+
			"Fix: check ManifestRaw is non-empty before computing its digest.")
}

// =============================================================================
// R3-168: getLayerDIFFIDs allocates h.Size bytes for each layer in memory
// before decompression, enabling memory exhaustion via many large layers
//
// SECURITY IMPACT:
//   In getLayerDIFFIDs (oci.go:307-310), for each layer entry:
//       b := make([]byte, h.Size)
//       io.ReadFull(tarReader, b)
//
//   Each layer can be up to maxTarEntrySize (256 MB). If the manifest
//   declares N layers, the function allocates N * 256 MB sequentially.
//   While Go's garbage collector reclaims previous allocations, a tar with
//   many layers that are each close to the limit (e.g., 100 layers at 200MB)
//   can cause severe memory pressure.
//
//   Additionally, the compressed layer is held in memory while the
//   decompressed content is also read into memory (io.ReadAll). This means
//   at peak, we hold:
//     - b (compressed): up to 256 MB
//     - c (decompressed): up to 256 MB (maxDecompressedSize)
//   Total peak: ~512 MB per layer.
//
//   No limit exists on the total number of layers processed. The O(entries * layers)
//   loop in getLayerDIFFIDs iterates all tar entries for every layer.
//
//   Fix: stream layers through a hash function instead of loading into memory,
//   or impose a limit on total layer count.
//
// AFFECTED CODE: oci.go lines 284-349 (getLayerDIFFIDs)
// =============================================================================

func TestSecurity_R3_168_NoLayerCountLimit(t *testing.T) {
	// Demonstrate that there is no limit on layer count.
	// An attacker could craft an image with thousands of layers.
	numLayers := 1000
	layers := make([]string, numLayers)
	entries := map[string][]byte{
		"config.json": []byte(`{"architecture":"amd64"}`),
	}

	for i := 0; i < numLayers; i++ {
		name := "layers/" + strings.Repeat("x", 200) + "/" + string(rune('a'+(i%26))) + ".tar"
		if i < 100 {
			// Use shorter names for the first 100 to avoid path length limits.
			name = "l" + string(rune('0'+(i/100)%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10)) + ".tar"
		} else {
			name = "l" + string([]byte{byte('0' + (i/100)%10), byte('0' + (i/10)%10), byte('0' + i%10)}) + ".tar"
		}
		layers[i] = name
		entries[name] = []byte("layer-content")
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

	// The function processes all 1000 layers without any limit check.
	// This test proves no layer count validation exists.
	layerDiffIDs, err := m.getLayerDIFFIDs(ctx, tarPath)

	if err == nil {
		// BUG: All 1000 layers processed without any limit.
		assert.LessOrEqual(t, len(layerDiffIDs), 500,
			"getLayerDIFFIDs processed %d layers without any count limit. "+
				"An attacker can craft an image with thousands of layers to cause "+
				"O(entries * layers) iteration and memory pressure from per-layer "+
				"allocations. Fix: impose a maximum layer count (e.g., 128).",
			len(layerDiffIDs))
	}
}

// =============================================================================
// R3-169: Multiple sequential tar file opens create a TOCTOU window
//
// SECURITY IMPACT:
//   The Attest() method (oci.go:147-178) processes the OCI tar in three
//   sequential phases, each opening the tar file independently:
//     1. parseMaifest() -- opens tarFilePath, reads manifest.json
//     2. getImageID()   -- opens tarFilePath again, reads config
//     3. getLayerDIFFIDs() -- opens tarFilePath again, reads layers
//
//   Between each open, the file could be replaced by an attacker (TOCTOU).
//   For example:
//     - parseMaifest reads a legitimate manifest from file A
//     - Attacker replaces the file with file B (different content)
//     - getImageID reads config from file B
//     - The manifest says config is "config.json" but the actual config
//       content comes from a different (attacker-controlled) tar
//
//   This breaks the integrity assumption that all data comes from the same
//   tar archive. The TarDigest was computed from the ORIGINAL file in
//   getCandidate, but subsequent reads may operate on a DIFFERENT file.
//
//   Fix: open the tar file once in Attest() and pass the reader (or the
//   opened file handle) to all sub-functions.
//
// AFFECTED CODE: oci.go lines 86-91, 211-217, 284-292 (three os.Open calls)
// =============================================================================

func TestSecurity_R3_169_MultipleFileOpensAllowTOCTOU(t *testing.T) {
	// Build a legitimate OCI tar.
	manifest1, _ := json.Marshal([]Manifest{
		{Config: "config.json", RepoTags: []string{"legit:v1"}, Layers: []string{}},
	})
	config1 := []byte(`{"architecture":"amd64","os":"linux"}`)

	tarPath := buildTarFile(t, map[string][]byte{
		"manifest.json": manifest1,
		"config.json":   config1,
	})

	// Build a DIFFERENT tar with a different config.
	config2 := []byte(`{"architecture":"arm64","os":"evil"}`)
	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	// Write same manifest (so manifest parsing succeeds the same way)
	mhdr := &tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest1))}
	require.NoError(t, tw2.WriteHeader(mhdr))
	_, err := tw2.Write(manifest1)
	require.NoError(t, err)
	// Write different config
	chdr := &tar.Header{Name: "config.json", Mode: 0600, Size: int64(len(config2))}
	require.NoError(t, tw2.WriteHeader(chdr))
	_, err = tw2.Write(config2)
	require.NoError(t, err)
	require.NoError(t, tw2.Close())
	tar2Bytes := buf2.Bytes()

	// Prove that each phase opens the file independently by:
	// 1. Running parseMaifest on the original tar
	// 2. Replacing the file with the evil tar
	// 3. Running getImageID -- it reads from the replaced file

	ctx, err := attestation.NewContext("test", []attestation.Attestor{},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
	)
	require.NoError(t, err)

	a := New()
	a.tarFilePath = tarPath

	// Phase 1: Parse manifest from original tar.
	err = a.parseMaifest(ctx)
	require.NoError(t, err)
	require.Len(t, a.Manifest, 1)
	assert.Equal(t, "legit:v1", a.Manifest[0].RepoTags[0])

	// Compute the original image ID for comparison.
	origImageID, err := a.Manifest[0].getImageID(ctx, tarPath)
	require.NoError(t, err)

	// TOCTOU: Replace the tar file with the evil version between opens.
	require.NoError(t, os.WriteFile(tarPath, tar2Bytes, 0600))

	// Phase 2: getImageID opens the file AGAIN -- now it reads the evil tar.
	evilImageID, err := a.Manifest[0].getImageID(ctx, tarPath)
	require.NoError(t, err)

	// The image IDs should be the same if the code maintained a single file handle.
	// But because it opens the file independently each time, the evil tar's
	// config produces a DIFFERENT image ID.
	equal := origImageID.Equal(evilImageID)
	assert.True(t, equal,
		"TOCTOU: getImageID produced a different image ID after the tar file "+
			"was replaced between parseMaifest and getImageID calls. "+
			"Manifest was parsed from the original file, but config was read from "+
			"the replaced file. The three sequential os.Open calls create a race "+
			"window. Fix: open the tar file once and pass the reader to all phases.")
}
