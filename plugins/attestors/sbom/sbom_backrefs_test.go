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
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
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

// TestBackRefsFromExtraction_SyftContainerVersion: syft (1.5.0 in
// boms/cyclonedx-json/alpine.cyclonedx.json, and 1.52.0 on an OCI archive)
// emits NO purl for an image source. It puts the manifest digest in
// metadata.component.version of a type "container" component. That is the
// image digest and must backref as imagedigest:, or a syft image SBOM never
// joins the docker attestor's imagedigest subject.
func TestBackRefsFromExtraction_SyftContainerVersion(t *testing.T) {
	var extracted sbomSubjectExtractor
	extracted.Metadata.Component.Type = "container"
	extracted.Metadata.Component.Name = "dist/hugo-image.tar"
	extracted.Metadata.Component.Version = "sha256:" + sbomTestImageDigest

	refs := backRefsFromExtraction(CycloneDxPredicateType, extracted)
	assert.Equal(t, map[string]string{"imagedigest:" + sbomTestImageDigest: sbomTestImageDigest}, flatten(refs))
}

// The real syft 1.5.0 fixture takes the same path end to end.
func TestBackRefsFromExtraction_SyftFixture(t *testing.T) {
	bytes, err := os.ReadFile("boms/cyclonedx-json/alpine.cyclonedx.json")
	require.NoError(t, err)
	var extracted sbomSubjectExtractor
	require.NoError(t, json.Unmarshal(bytes, &extracted))
	refs := backRefsFromExtraction(CycloneDxPredicateType, extracted)
	assert.Contains(t, refs, "imagedigest:1c3b93ed450e26eac89b471d6d140e2f99488f489739b8b8ea5e8202dd086f82")
}

// A digest-shaped version is an image digest only on a container component,
// and only when it is exactly sha256:<64 hex>. A library whose version looks
// like a digest, or a malformed one, falls back to the name.
func TestBackRefsFromExtraction_ContainerVersionIsExact(t *testing.T) {
	for name, component := range map[string][2]string{
		"library type":    {"library", "sha256:" + sbomTestImageDigest},
		"no type":         {"", "sha256:" + sbomTestImageDigest},
		"short digest":    {"container", "sha256:abc"},
		"uppercase":       {"container", "sha256:" + strings.Repeat("A", 64)},
		"non-hex":         {"container", "sha256:" + strings.Repeat("g", 64)},
		"other algorithm": {"container", "sha512:" + sbomTestImageDigest},
		"trailing text":   {"container", "sha256:" + sbomTestImageDigest + " x"},
		"tag":             {"container", "3.24"},
	} {
		var extracted sbomSubjectExtractor
		extracted.Metadata.Component.Type = component[0]
		extracted.Metadata.Component.Name = "img"
		extracted.Metadata.Component.Version = component[1]
		refs := backRefsFromExtraction(CycloneDxPredicateType, extracted)
		assert.Equal(t, map[string]string{"name:img": ""}, keysOnly(refs), name)
	}
	// A purl digest wins over the version when both are present.
	var extracted sbomSubjectExtractor
	extracted.Metadata.Component.Type = "container"
	extracted.Metadata.Component.Version = "sha256:" + strings.Repeat("7", 64)
	extracted.Metadata.Component.PURL = "pkg:oci/app@sha256:" + sbomTestImageDigest
	assert.Equal(t, map[string]string{"imagedigest:" + sbomTestImageDigest: sbomTestImageDigest},
		flatten(backRefsFromExtraction(CycloneDxPredicateType, extracted)))
}

func flatten(refs map[string]cryptoutil.DigestSet) map[string]string {
	out := map[string]string{}
	for key, set := range refs {
		for _, value := range set {
			out[key] = value
		}
	}
	return out
}

func keysOnly(refs map[string]cryptoutil.DigestSet) map[string]string {
	out := map[string]string{}
	for key := range refs {
		out[key] = ""
	}
	return out
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
