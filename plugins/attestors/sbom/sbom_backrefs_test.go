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

package sbom

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ attestation.BackReffer = &SBOMAttestor{}

const sbomTestImageDigest = "6666666666666666666666666666666666666666666666666666666666666666"

// TestBackRefsFromExtraction_CycloneDxImagePurl proves a syft image SBOM
// backrefs the source image digest parsed from metadata.component.purl
// (pkg:oci form, with the URL-encoded sha256%3A separator syft emits).
// The key/value format matches the docker attestor's imagedigest subjects
// so shared graph edges connect.
func TestBackRefsFromExtraction_CycloneDxImagePurl(t *testing.T) {
	var extracted sbomSubjectExtractor
	extracted.Metadata.Component.Name = "nginx"
	extracted.Metadata.Component.Version = "1.27"
	extracted.Metadata.Component.PURL = "pkg:oci/nginx@sha256%3A" + sbomTestImageDigest + "?repository_url=index.docker.io%2Flibrary%2Fnginx"

	refs := backRefsFromExtraction(CycloneDxPredicateType, extracted)

	key := "imagedigest:" + sbomTestImageDigest
	require.Contains(t, refs, key)
	got := refs[key]
	assert.Len(t, got, 1)
	for _, v := range got {
		assert.Equal(t, sbomTestImageDigest, v, "backref must carry the raw image digest")
	}
}

// TestBackRefsFromExtraction_UnencodedPurlSeparator handles the plain
// sha256: separator some generators emit.
func TestBackRefsFromExtraction_UnencodedPurlSeparator(t *testing.T) {
	var extracted sbomSubjectExtractor
	extracted.Metadata.Component.PURL = "pkg:oci/app@sha256:" + sbomTestImageDigest

	refs := backRefsFromExtraction(CycloneDxPredicateType, extracted)
	assert.Contains(t, refs, "imagedigest:"+sbomTestImageDigest)
}

// TestBackRefsFromExtraction_NameFallback: without a digest-bearing purl,
// the component name is the only anchor for the inventory.
func TestBackRefsFromExtraction_NameFallback(t *testing.T) {
	var extracted sbomSubjectExtractor
	extracted.Metadata.Component.Name = "my-service"

	refs := backRefsFromExtraction(CycloneDxPredicateType, extracted)
	assert.Contains(t, refs, "name:my-service")
	assert.Len(t, refs, 1)
}

// TestBackRefsFromExtraction_SPDXDocumentName anchors SPDX documents by
// document name.
func TestBackRefsFromExtraction_SPDXDocumentName(t *testing.T) {
	extracted := sbomSubjectExtractor{SPDXDocumentName: "my-spdx-doc"}

	refs := backRefsFromExtraction(SPDXPredicateType, extracted)
	assert.Contains(t, refs, "name:my-spdx-doc")
}

// TestBackRefsFromExtraction_Empty: nothing extractable, no refs.
func TestBackRefsFromExtraction_Empty(t *testing.T) {
	var extracted sbomSubjectExtractor
	refs := backRefsFromExtraction(CycloneDxPredicateType, extracted)
	assert.Empty(t, refs)
}
