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

package oci

import (
	"crypto"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ attestation.BackReffer = &Attestor{}

const (
	ociTestManifestDigest = "2222222222222222222222222222222222222222222222222222222222222222"
	ociTestImageID        = "3333333333333333333333333333333333333333333333333333333333333333"
	ociTestLayerDiffID    = "4444444444444444444444444444444444444444444444444444444444444444"
	ociTestTarDigest      = "5555555555555555555555555555555555555555555555555555555555555555"
)

func ociSha256Set(value string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: value}
}

// TestBackRefs_ImageIdentity proves the attestor backrefs the identity of
// the image it examined — manifest digest, image id, and tags — while
// layer diff IDs and the local tarball digest stay subjects only. Layers
// are shared across every image built on a common base; backreffing them
// would create hub edges linking unrelated products.
func TestBackRefs_ImageIdentity(t *testing.T) {
	a := &Attestor{
		TarDigest:      ociSha256Set(ociTestTarDigest),
		ManifestDigest: ociSha256Set(ociTestManifestDigest),
		ImageID:        ociSha256Set(ociTestImageID),
		ImageTags:      []string{"registry.example.com/app:v1.2.3"},
		LayerDiffIDs:   []cryptoutil.DigestSet{ociSha256Set(ociTestLayerDiffID)},
	}

	refs := a.BackRefs()

	manifestKey := "manifestdigest:" + ociTestManifestDigest
	require.Contains(t, refs, manifestKey)
	assert.Equal(t, ociSha256Set(ociTestManifestDigest), refs[manifestKey],
		"manifest digest backref must carry the raw digest")

	assert.Contains(t, refs, "imageid:"+ociTestImageID)
	assert.Contains(t, refs, "imagetag:registry.example.com/app:v1.2.3")

	for key := range refs {
		assert.False(t, strings.HasPrefix(key, "layerdiffid"),
			"layer diff IDs are hub edges and must not be backrefs")
		assert.False(t, strings.HasPrefix(key, "tardigest"),
			"local tarball digest is not a cross-collection anchor")
	}
}

// TestBackRefs_EmptyDigestsSkipped: an attestor that never ran (zero-value
// digest sets) must not emit empty-valued backrefs.
func TestBackRefs_EmptyDigestsSkipped(t *testing.T) {
	a := &Attestor{}
	refs := a.BackRefs()
	assert.Empty(t, refs)
}
