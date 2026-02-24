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
	"encoding/json"
	"strings"
	"testing"
)

// FuzzDockerMIMETypeCheck exercises the MIME type comparison logic used in
// getDockerCandidates and setDockerCandidate.  The attestor checks
// product.MimeType == jsonMimeType and whether ContainerImageDigest starts
// with "sha256:".  We fuzz the BuildInfo JSON unmarshaling plus the digest
// prefix check to ensure nothing panics and the invariants hold.
func FuzzDockerMIMETypeCheck(f *testing.F) {
	// Seed corpus: (mimeType, digest, imageName)
	f.Add("application/json", "sha256:abc123def456", "myimage:latest")
	f.Add("application/json", "sha256:", "img")
	f.Add("application/json", "sha256:a", "i")
	f.Add("text/sha256+text", "sha256:abc123", "img:tag")
	f.Add("application/json", "notsha256:abc123", "img")
	f.Add("text/plain", "sha256:abc123", "img")
	f.Add("", "", "")
	f.Add("application/json", "", "")
	f.Add("", "sha256:abc", "img")
	// Edge cases
	f.Add("application/json", "SHA256:abc123", "img")                   // Wrong case
	f.Add("application/json", " sha256:abc123", "img")                  // Leading space
	f.Add("application/json", "sha256:abc123 ", "img")                  // Trailing space
	f.Add("application/json", "sha256:\x00\x01\x02", "img")             // Binary in digest
	f.Add("application/json", "sha256:"+strings.Repeat("a", 64), "img") // Full SHA256 length
	// Unicode
	f.Add("application/json", "sha256:\u00e9\u00e8", "img\u00e9")
	// Very long values
	f.Add("application/json", "sha256:"+strings.Repeat("f", 1000), strings.Repeat("image", 200))

	f.Fuzz(func(t *testing.T, mimeType, digest, imageName string) {
		// Test 1: MIME type equality check must be consistent
		isJSON := mimeType == jsonMimeType
		isSHA256Text := mimeType == sha256MimeType

		// These should never both be true
		if isJSON && isSHA256Text {
			t.Fatal("MIME type cannot be both JSON and SHA256 text")
		}

		// Test 2: Digest prefix check
		hasSHA256Prefix := strings.HasPrefix(digest, "sha256:")
		if hasSHA256Prefix {
			trimmed, found := strings.CutPrefix(digest, "sha256:")
			if !found {
				t.Fatal("CutPrefix failed but HasPrefix succeeded")
			}
			if len(trimmed)+len("sha256:") != len(digest) {
				t.Fatal("CutPrefix result length mismatch")
			}
		}

		// Test 3: BuildInfo JSON round-trip must not panic
		buildInfoJSON := map[string]interface{}{
			"containerimage.digest": digest,
			"image.name":            imageName,
		}
		data, err := json.Marshal(buildInfoJSON)
		if err != nil {
			return
		}

		var bi BuildInfo
		// UnmarshalJSON must not panic even with arbitrary input
		_ = json.Unmarshal(data, &bi)

		// Test 4: setDockerCandidate-style logic must not panic
		//
		// NOTE: setDockerCandidate assumes a.Products has been initialized
		// by Attest(). Calling it on a bare New() attestor panics with
		// "assignment to entry in nil map" at docker.go:170. This is a
		// real production bug -- setDockerCandidate should either check for
		// nil or initialize the map itself. We initialize it here to mirror
		// the Attest() flow and continue fuzzing the rest of the logic.
		a := New()
		a.Products = map[string]DockerProduct{}
		if hasSHA256Prefix {
			met := BuildInfo{
				ContainerImageDigest: digest,
				ImageName:            imageName,
				Provenance:           make(map[string]Provenance),
			}
			// Must not panic -- may return an error and that's fine
			_ = a.setDockerCandidate(&met)

			// If successful, verify the trimmed digest is stored correctly
			if len(a.Products) > 0 {
				trimmed, _ := strings.CutPrefix(digest, "sha256:")
				if _, exists := a.Products[trimmed]; !exists {
					t.Errorf("expected product with key %q to exist", trimmed)
				}
			}
		}

		// Test 5: Subjects() on an empty/populated attestor must not panic
		_ = a.Subjects()

		// Test 6: Fuzz the full JSON unmarshal with provenance keys
		fullJSON := map[string]interface{}{
			"containerimage.digest": digest,
			"image.name":            imageName,
			"buildx.build.ref":      "ref-123",
			"buildx.build.provenance/amd64": map[string]interface{}{
				"buildType": "test",
				"materials": []interface{}{},
			},
		}
		fullData, err := json.Marshal(fullJSON)
		if err != nil {
			return
		}
		var bi2 BuildInfo
		_ = json.Unmarshal(fullData, &bi2)
	})
}
