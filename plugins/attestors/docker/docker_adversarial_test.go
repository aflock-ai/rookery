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

package docker

import (
	"crypto"
	"encoding/json"
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

func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256, GitOID: true},
		{Hash: crypto.SHA1, GitOID: true},
	}
}

// fakeProducer is a minimal attestor that registers a file as a product.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (fp *fakeProducer) Name() string                                      { return "fake-producer" }
func (fp *fakeProducer) Type() string                                      { return "fake" }
func (fp *fakeProducer) RunType() attestation.RunType                      { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error     { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                        { return nil }
func (fp *fakeProducer) Products() map[string]attestation.Product          { return fp.products }

// writeProductFile writes a JSON file and returns a context with it registered as a product.
func writeProductFile(t *testing.T, dir, filename string, data []byte, mimeType string) *attestation.AttestationContext {
	t.Helper()
	path := filepath.Join(dir, filename)
	require.NoError(t, os.WriteFile(path, data, 0600))

	digest, err := cryptoutil.CalculateDigestSetFromFile(path, defaultHashes())
	require.NoError(t, err)

	prod := &fakeProducer{
		products: map[string]attestation.Product{
			filename: {
				MimeType: mimeType,
				Digest:   digest,
			},
		},
	}

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{prod},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	return ctx
}

// ============================================================================
// BUG #1: Subjects() iterates ImageReferences TWICE
// ============================================================================
// Lines 217-223 iterate p.ImageReferences, then lines 237-243 iterate
// p.ImageReferences AGAIN. Both loops create the same subject key format
// "imagereference:<ref>". The second loop overwrites the first, which is
// wasteful but not harmful. However, it indicates copy-paste code smell.

func TestBug_SubjectsDoubleIteratesImageReferences(t *testing.T) {
	a := &Attestor{
		Products: map[string]DockerProduct{
			"abc123": {
				ImageDigest: cryptoutil.DigestSet{
					cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
				},
				ImageReferences: []string{"myimage:latest", "myimage:v1.0"},
				Materials:       map[string][]Material{},
			},
		},
	}

	subjects := a.Subjects()
	assert.NotNil(t, subjects)

	// Count how many imagereference subjects we get
	refCount := 0
	for key := range subjects {
		if strings.HasPrefix(key, "imagereference:") {
			refCount++
		}
	}

	// We have 2 image references, but they're iterated twice.
	// Since both loops use the same key format, the second loop overwrites
	// the first. We should get exactly 2 unique keys.
	assert.Equal(t, 2, refCount,
		"Should have 2 unique imagereference subjects (second loop overwrites first)")
	t.Logf("BUG: Subjects() iterates ImageReferences twice (lines 217-223 and 237-243), second loop overwrites first")
}

// ============================================================================
// Adversarial: MIME type equality check
// ============================================================================

func TestMIMETypeEqualityCheck(t *testing.T) {
	testCases := []struct {
		name       string
		mimeType   string
		shouldFind bool
	}{
		{"exact_json", "application/json", true},
		{"uppercase_json", "APPLICATION/JSON", false},
		{"json_with_charset", "application/json; charset=utf-8", false},
		{"partial_json", "json", false},
		{"text_plain", "text/plain", false},
		{"empty", "", false},
		{"sha256_text", "text/sha256+text", false},
		{"application_x_tar", "application/x-tar", false},
		{"json_prefix", "application/json-extra", false},
		{"json_suffix", "extra/application/json", false},
		{"whitespace", " application/json ", false},
		{"newline", "application/json\n", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			buildInfo := BuildInfo{
				ContainerImageDigest: "sha256:abcdef1234567890",
				ImageName:            "testimage:latest",
				Provenance:           make(map[string]Provenance),
			}
			data, err := json.Marshal(buildInfo)
			require.NoError(t, err)

			ctx := writeProductFile(t, dir, "metadata.json", data, tc.mimeType)

			a := New()
			mets, err := a.getDockerCandidates(ctx)

			if tc.shouldFind {
				require.NoError(t, err)
				assert.NotEmpty(t, mets, "Should find candidates with MIME type %q", tc.mimeType)
			} else {
				// Either error or empty results
				if err == nil {
					assert.Empty(t, mets, "Should NOT find candidates with MIME type %q", tc.mimeType)
				}
			}
		})
	}
}

// ============================================================================
// Adversarial: setDockerCandidate digest prefix handling
// ============================================================================

func TestSetDockerCandidate_DigestPrefixHandling(t *testing.T) {
	testCases := []struct {
		name         string
		digest       string
		wantProduct  bool
		wantKey      string
	}{
		{
			name:        "valid_sha256",
			digest:      "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			wantProduct: true,
			wantKey:     "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
		{
			name:        "sha256_short",
			digest:      "sha256:abc",
			wantProduct: true,
			wantKey:     "abc",
		},
		{
			name:        "sha256_empty_after_prefix",
			digest:      "sha256:",
			wantProduct: true,
			wantKey:     "",
		},
		{
			name:        "no_prefix",
			digest:      "abcdef1234567890",
			wantProduct: false,
		},
		{
			name:        "wrong_prefix",
			digest:      "sha512:abcdef",
			wantProduct: false,
		},
		{
			name:        "uppercase_SHA256",
			digest:      "SHA256:abcdef",
			wantProduct: false,
		},
		{
			name:        "leading_space",
			digest:      " sha256:abcdef",
			wantProduct: false,
		},
		{
			name:        "empty_digest",
			digest:      "",
			wantProduct: false,
		},
		{
			name:        "sha256_with_spaces_in_hash",
			digest:      "sha256:abc def",
			wantProduct: true,
			wantKey:     "abc def",
		},
		{
			name:        "sha256_with_newline",
			digest:      "sha256:abc\ndef",
			wantProduct: true,
			wantKey:     "abc\ndef",
		},
		{
			name:        "sha256_with_null_bytes",
			digest:      "sha256:abc\x00def",
			wantProduct: true,
			wantKey:     "abc\x00def",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := New()
			a.Products = map[string]DockerProduct{}

			met := &BuildInfo{
				ContainerImageDigest: tc.digest,
				ImageName:            "testimage:latest",
				Provenance:           make(map[string]Provenance),
			}

			// Must not panic
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("setDockerCandidate panicked: %v", r)
					}
				}()
				err := a.setDockerCandidate(met)
				assert.NoError(t, err)
			}()

			if tc.wantProduct {
				assert.Contains(t, a.Products, tc.wantKey,
					"Expected product with key %q", tc.wantKey)
			} else {
				assert.Empty(t, a.Products,
					"Should not have any products for digest %q", tc.digest)
			}
		})
	}
}

// ============================================================================
// Adversarial: setDockerCandidate with nil Products map
// ============================================================================
// The fuzz test comments mention this bug: calling setDockerCandidate
// without initializing Products first causes a nil map assignment panic.
// Attest() initializes it, but the method itself doesn't guard against it.

func TestSetDockerCandidate_NilProductsMap(t *testing.T) {
	a := New()
	// Products is nil by default from New()
	assert.Nil(t, a.Products)

	met := &BuildInfo{
		ContainerImageDigest: "sha256:abcdef",
		ImageName:            "testimage:latest",
		Provenance:           make(map[string]Provenance),
	}

	// This should panic with "assignment to entry in nil map"
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				t.Logf("BUG CONFIRMED: setDockerCandidate panicked with nil Products map: %v", r)
			}
		}()
		_ = a.setDockerCandidate(met)
	}()

	if panicked {
		t.Logf("BUG: setDockerCandidate does not initialize or check for nil Products map")
	}
}

// ============================================================================
// Adversarial: BuildInfo UnmarshalJSON with adversarial keys
// ============================================================================

func TestBuildInfoUnmarshal_AdversarialKeys(t *testing.T) {
	testCases := []struct {
		name string
		json string
	}{
		{
			name: "valid_provenance",
			json: `{
				"containerimage.digest": "sha256:abc",
				"image.name": "test:latest",
				"buildx.build.ref": "ref-123",
				"buildx.build.provenance/amd64": {"buildType": "test"}
			}`,
		},
		{
			name: "provenance_without_slash",
			json: `{
				"containerimage.digest": "sha256:abc",
				"image.name": "test:latest",
				"buildx.build.provenance": {"buildType": "test", "materials": []}
			}`,
		},
		{
			name: "provenance_with_deep_path",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance/linux/amd64": {"buildType": "test"}
			}`,
		},
		{
			name: "provenance_with_empty_arch",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance/": {"buildType": "test"}
			}`,
		},
		{
			name: "many_provenance_entries",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance/amd64": {"buildType": "test"},
				"buildx.build.provenance/arm64": {"buildType": "test"},
				"buildx.build.provenance/arm/v7": {"buildType": "test"},
				"buildx.build.provenance/s390x": {"buildType": "test"}
			}`,
		},
		{
			name: "provenance_value_is_not_object",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance/amd64": "not-an-object"
			}`,
		},
		{
			name: "provenance_value_is_null",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance/amd64": null
			}`,
		},
		{
			name: "provenance_value_is_number",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance/amd64": 42
			}`,
		},
		{
			name: "buildx_ref_is_number",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.ref": 42
			}`,
		},
		{
			name: "empty_json",
			json: `{}`,
		},
		{
			name: "all_fields_null",
			json: `{
				"containerimage.digest": null,
				"image.name": null,
				"buildx.build.ref": null
			}`,
		},
		{
			name: "special_characters_in_keys",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance\u0000": {"buildType": "test"}
			}`,
		},
		{
			name: "very_long_arch_name",
			json: `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance/` + strings.Repeat("a", 10000) + `": {"buildType": "test"}
			}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var bi BuildInfo
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("UnmarshalJSON panicked: %v", r)
					}
				}()
				err := json.Unmarshal([]byte(tc.json), &bi)
				// Error is OK; panic is not
				if err != nil {
					t.Logf("Unmarshal returned error (OK): %v", err)
				}
			}()
		})
	}
}

// ============================================================================
// Adversarial: BuildInfo UnmarshalJSON with materials containing URLs
// ============================================================================

func TestBuildInfoUnmarshal_MaterialURLParsing(t *testing.T) {
	testCases := []struct {
		name string
		uri  string
	}{
		{"normal_url", "https://example.com/repo?platform=linux%2Famd64"},
		{"url_with_unicode_escape", `https://example.com/repo?platform=linux\u0026amd64`},
		{"empty_url", ""},
		{"not_a_url", "not a url"},
		{"url_with_no_query", "https://example.com/repo"},
		{"url_with_empty_platform", "https://example.com/repo?platform="},
		{"url_with_encoded_platform", "https://example.com/repo?platform=linux%2Farm%2Fv7"},
		{"url_with_multiple_platforms", "https://example.com/repo?platform=amd64&platform=arm64"},
		{"url_with_special_chars", "https://example.com/repo?platform=%00%01%02"},
		{"url_with_path_traversal", "https://example.com/../../../etc/passwd?platform=amd64"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonData := `{
				"containerimage.digest": "sha256:abc",
				"buildx.build.provenance": {
					"buildType": "test",
					"materials": [
						{"uri": "` + tc.uri + `", "digest": {"sha256": "abc123"}}
					]
				}
			}`

			var bi BuildInfo
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("UnmarshalJSON panicked with URI %q: %v", tc.uri, r)
					}
				}()
				err := json.Unmarshal([]byte(jsonData), &bi)
				if err != nil {
					t.Logf("Unmarshal returned error (OK): %v", err)
				}
			}()
		})
	}
}

// ============================================================================
// Adversarial: Subjects() on empty/nil products
// ============================================================================

func TestSubjects_EmptyProducts(t *testing.T) {
	testCases := []struct {
		name     string
		attestor *Attestor
	}{
		{
			name:     "nil_products",
			attestor: &Attestor{Products: nil},
		},
		{
			name:     "empty_products",
			attestor: &Attestor{Products: map[string]DockerProduct{}},
		},
		{
			name: "product_with_nil_materials",
			attestor: &Attestor{
				Products: map[string]DockerProduct{
					"abc": {
						ImageDigest: cryptoutil.DigestSet{
							cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc",
						},
						Materials:       nil,
						ImageReferences: nil,
					},
				},
			},
		},
		{
			name: "product_with_empty_digest",
			attestor: &Attestor{
				Products: map[string]DockerProduct{
					"": {
						ImageDigest:     cryptoutil.DigestSet{},
						Materials:       map[string][]Material{},
						ImageReferences: []string{},
					},
				},
			},
		},
		{
			name: "product_with_nil_digest",
			attestor: &Attestor{
				Products: map[string]DockerProduct{
					"abc": {
						ImageDigest:     nil,
						Materials:       map[string][]Material{},
						ImageReferences: []string{"image:latest"},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Subjects() panicked: %v", r)
					}
				}()
				subjects := tc.attestor.Subjects()
				assert.NotNil(t, subjects)
			}()
		})
	}
}

// ============================================================================
// Adversarial: Subjects() with materials containing edge-case data
// ============================================================================

func TestSubjects_MaterialEdgeCases(t *testing.T) {
	testCases := []struct {
		name      string
		materials map[string][]Material
	}{
		{
			name: "material_with_empty_uri",
			materials: map[string][]Material{
				"amd64": {
					{URI: "", Architecture: "amd64", Digest: cryptoutil.DigestSet{
						cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc",
					}},
				},
			},
		},
		{
			name: "material_with_nil_digest",
			materials: map[string][]Material{
				"amd64": {
					{URI: "https://example.com", Architecture: "amd64", Digest: nil},
				},
			},
		},
		{
			name: "material_with_empty_digest",
			materials: map[string][]Material{
				"amd64": {
					{URI: "https://example.com", Architecture: "amd64", Digest: cryptoutil.DigestSet{}},
				},
			},
		},
		{
			name: "many_architectures",
			materials: map[string][]Material{
				"amd64": {{URI: "u1", Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "a"}}},
				"arm64": {{URI: "u2", Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "b"}}},
				"arm/v7": {{URI: "u3", Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "c"}}},
				"s390x": {{URI: "u4", Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "d"}}},
			},
		},
		{
			name: "material_with_very_long_uri",
			materials: map[string][]Material{
				"amd64": {
					{URI: strings.Repeat("https://example.com/", 1000), Digest: cryptoutil.DigestSet{
						cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc",
					}},
				},
			},
		},
		{
			name: "empty_material_slice",
			materials: map[string][]Material{
				"amd64": {},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Attestor{
				Products: map[string]DockerProduct{
					"abc123": {
						ImageDigest: cryptoutil.DigestSet{
							cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
						},
						Materials:       tc.materials,
						ImageReferences: []string{"test:latest"},
					},
				},
			}

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Subjects() panicked with materials %v: %v", tc.name, r)
					}
				}()
				subjects := a.Subjects()
				assert.NotNil(t, subjects)
			}()
		})
	}
}

// ============================================================================
// Adversarial: getDockerCandidates with non-JSON files
// ============================================================================

func TestGetDockerCandidates_NonJSONFiles(t *testing.T) {
	testCases := []struct {
		name     string
		content  []byte
		mimeType string
	}{
		{"text_file_json_mime", []byte("not json at all"), "application/json"},
		{"binary_file_json_mime", []byte{0x00, 0x01, 0x02, 0x03}, "application/json"},
		{"empty_file_json_mime", []byte{}, "application/json"},
		{"xml_file_json_mime", []byte("<root><child/></root>"), "application/json"},
		{"valid_json_wrong_mime", []byte(`{"containerimage.digest": "sha256:abc"}`), "text/plain"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ctx := writeProductFile(t, dir, "metadata.json", tc.content, tc.mimeType)

			a := New()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("getDockerCandidates panicked: %v", r)
					}
				}()
				mets, err := a.getDockerCandidates(ctx)
				// Should not panic. Errors or empty results are fine.
				_ = mets
				_ = err
			}()
		})
	}
}

// ============================================================================
// Adversarial: Full Attest flow with adversarial metadata files
// ============================================================================

func TestAttest_AdversarialMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		metadata interface{}
	}{
		{
			name: "valid_buildinfo",
			metadata: map[string]interface{}{
				"containerimage.digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
				"image.name":           "testimage:latest",
			},
		},
		{
			name: "digest_without_prefix",
			metadata: map[string]interface{}{
				"containerimage.digest": "abcdef1234567890",
				"image.name":           "testimage:latest",
			},
		},
		{
			name: "empty_digest",
			metadata: map[string]interface{}{
				"containerimage.digest": "",
				"image.name":           "testimage:latest",
			},
		},
		{
			name: "empty_image_name",
			metadata: map[string]interface{}{
				"containerimage.digest": "sha256:abc",
				"image.name":           "",
			},
		},
		{
			name: "nested_provenance",
			metadata: map[string]interface{}{
				"containerimage.digest":         "sha256:abc",
				"image.name":                    "test:latest",
				"buildx.build.ref":              "ref-123",
				"buildx.build.provenance/amd64": map[string]interface{}{
					"buildType": "docker",
					"materials": []interface{}{
						map[string]interface{}{
							"uri": "https://example.com",
							"digest": map[string]interface{}{
								"sha256": "def456",
							},
						},
					},
				},
			},
		},
		{
			name:     "null_value",
			metadata: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			var data []byte
			var err error
			if tc.metadata != nil {
				data, err = json.Marshal(tc.metadata)
				require.NoError(t, err)
			} else {
				data = []byte("null")
			}

			ctx := writeProductFile(t, dir, "metadata.json", data, "application/json")

			a := New()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Attest panicked: %v", r)
					}
				}()
				err := a.Attest(ctx)
				// Errors are OK, panics are not
				if err != nil {
					t.Logf("Attest returned error (OK): %v", err)
				} else {
					t.Logf("Attest succeeded")
					// Verify subjects don't panic
					subjects := a.Subjects()
					assert.NotNil(t, subjects)
				}
			}()
		})
	}
}

// ============================================================================
// Adversarial: Concurrent Subjects() calls
// ============================================================================

func TestSubjects_ConcurrentAccess(t *testing.T) {
	a := &Attestor{
		Products: map[string]DockerProduct{
			"abc123": {
				ImageDigest: cryptoutil.DigestSet{
					cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
				},
				ImageReferences: []string{"image:latest", "image:v1"},
				Materials: map[string][]Material{
					"amd64": {
						{URI: "https://example.com", Digest: cryptoutil.DigestSet{
							cryptoutil.DigestValue{Hash: crypto.SHA256}: "mat1",
						}},
					},
				},
			},
		},
	}

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				subjects := a.Subjects()
				assert.NotNil(t, subjects)
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// ============================================================================
// Adversarial: setDockerCandidate with provenance containing materials
// ============================================================================

func TestSetDockerCandidate_WithProvenance(t *testing.T) {
	a := New()
	a.Products = map[string]DockerProduct{}

	met := &BuildInfo{
		ContainerImageDigest: "sha256:abc123",
		ImageName:            "testimage:latest",
		Provenance: map[string]Provenance{
			"amd64": {
				BuildType: "docker",
				Materials: []ProvenanceMaterial{
					{
						URI:    "https://example.com/source",
						Digest: Digest{Sha256: "def456"},
					},
					{
						URI:    "https://example.com/base-image",
						Digest: Digest{Sha256: "ghi789"},
					},
				},
			},
			"arm64": {
				BuildType: "docker",
				Materials: []ProvenanceMaterial{
					{
						URI:    "https://example.com/source-arm",
						Digest: Digest{Sha256: "jkl012"},
					},
				},
			},
		},
	}

	err := a.setDockerCandidate(met)
	require.NoError(t, err)

	product, exists := a.Products["abc123"]
	require.True(t, exists)
	assert.Equal(t, "abc123", product.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])
	assert.Equal(t, []string{"testimage:latest"}, product.ImageReferences)
	assert.Len(t, product.Materials["amd64"], 2)
	assert.Len(t, product.Materials["arm64"], 1)
}

// ============================================================================
// Adversarial: setDockerCandidate with empty provenance materials
// ============================================================================

func TestSetDockerCandidate_EmptyMaterials(t *testing.T) {
	a := New()
	a.Products = map[string]DockerProduct{}

	met := &BuildInfo{
		ContainerImageDigest: "sha256:abc123",
		ImageName:            "testimage:latest",
		Provenance: map[string]Provenance{
			"amd64": {
				BuildType: "docker",
				Materials: []ProvenanceMaterial{}, // empty
			},
			"arm64": {
				BuildType: "docker",
				Materials: nil, // nil
			},
		},
	}

	err := a.setDockerCandidate(met)
	require.NoError(t, err)

	product, exists := a.Products["abc123"]
	require.True(t, exists)
	// Materials should be empty since both architectures have no materials
	assert.Empty(t, product.Materials)
}

// ============================================================================
// Adversarial: New() returns Attestor with nil Products
// ============================================================================

func TestNew_ProductsIsNil(t *testing.T) {
	a := New()
	assert.Nil(t, a.Products, "New() should return Attestor with nil Products (potential panic source)")
}

// ============================================================================
// Adversarial: Schema() should not panic
// ============================================================================

func TestSchema_NoPanic(t *testing.T) {
	a := New()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Schema() panicked: %v", r)
			}
		}()
		schema := a.Schema()
		assert.NotNil(t, schema)
	}()
}

// ============================================================================
// Adversarial: Constants are correct
// ============================================================================

func TestConstants(t *testing.T) {
	assert.Equal(t, "docker", Name)
	assert.Equal(t, "https://aflock.ai/attestations/docker/v0.1", Type)
	assert.Equal(t, attestation.PostProductRunType, RunType)
	assert.Equal(t, "text/sha256+text", sha256MimeType)
	assert.Equal(t, "application/json", jsonMimeType)
}
