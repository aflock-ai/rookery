// Copyright 2026 The Witness Contributors
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

package trivy

import (
	"crypto"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The attestor must declare its scan target as back-references so the
// platform graph can anchor the verdict to the image's build/run
// attestations.
var _ attestation.BackReffer = &Attestor{}

const trivyTestManifestDigest = "1111111111111111111111111111111111111111111111111111111111111111"

// TestBackRefs_ImageScanTarget proves an image scan backrefs the scanned
// image's manifest digest and references — with digest values formatted
// exactly like the docker attestor's imagedigest subjects (bare hex, raw
// digest as the DigestSet value) so shared-(kind,value) graph edges connect.
func TestBackRefs_ImageScanTarget(t *testing.T) {
	a := New()
	a.Summary = Summary{
		ArtifactName: "nginx:1.27",
		ArtifactType: "container_image",
		Metadata: MetadataSummary{
			ImageID:     "sha256:deadbeef",
			RepoTags:    []string{"nginx:1.27"},
			RepoDigests: []string{"nginx@sha256:" + trivyTestManifestDigest},
		},
		FailedFindings: []FailedFinding{
			{Class: "vuln", ID: "CVE-2024-1234"},
		},
	}

	refs := a.BackRefs()

	digestKey := "imagedigest:" + trivyTestManifestDigest
	require.Contains(t, refs, digestKey)
	assert.Equal(t,
		cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: trivyTestManifestDigest},
		refs[digestKey],
		"backref digest must be the raw manifest digest, matching docker attestor semantics")

	assert.Contains(t, refs, "imagereference:nginx:1.27")

	// Findings are claims, not provenance anchors. A CVE backref would
	// cross-link every unrelated product sharing the vulnerability.
	for key := range refs {
		assert.NotContains(t, key, "cve", "findings must never be backrefs")
	}
}

// TestBackRefs_FilesystemScanFallsBackToArtifact covers fs/repo scans where
// trivy emits no image metadata — the artifact name is the only stable
// anchor for the verdict.
func TestBackRefs_FilesystemScanFallsBackToArtifact(t *testing.T) {
	a := New()
	a.Summary = Summary{
		ArtifactName: "/src/infra",
		ArtifactType: "filesystem",
	}

	refs := a.BackRefs()
	assert.Contains(t, refs, "trivy:artifact:/src/infra")
	assert.Len(t, refs, 1)
}

// TestBackRefs_MalformedRepoDigestSkipped: entries without @sha256: must be
// skipped rather than emitting a garbage edge.
func TestBackRefs_MalformedRepoDigestSkipped(t *testing.T) {
	a := New()
	a.Summary = Summary{
		ArtifactName: "weird:latest",
		ArtifactType: "container_image",
		Metadata: MetadataSummary{
			RepoDigests: []string{"weird@md5:abc", "noseparator"},
		},
	}

	refs := a.BackRefs()
	for key := range refs {
		assert.NotContains(t, key, "imagedigest:", "malformed repo digests must not produce digest backrefs")
	}
}
