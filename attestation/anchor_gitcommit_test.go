// jade:ring local
// Copyright 2026 The Aflock Authors
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

package attestation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// D15-2 (docs/design/attestation-anchors.md 3.7, row D15-a): git commit
// hashes are a typed anchor kind, and A3 becomes a per-kind algorithm
// allowlist. git-commit admits sha1 and sha256; every other kind stays
// sha256 only.

const testCommitSHA1 = "3b836de006c9f8ad64ec8f741d83aec36f680533"

// The allowlist is pinned (A13). Mutation M-D15a, admitting sha1 for every
// kind, turns this red.
func TestAnchorKindAlgorithmsGolden(t *testing.T) {
	got := map[AnchorKind][]string{}
	for _, k := range AnchorKinds() {
		got[k] = KindAlgorithms(k)
	}
	assert.Equal(t, map[AnchorKind][]string{
		KindImageRegistryManifest: {"sha256"},
		KindImageConfig:           {"sha256"},
		KindGitCommit:             {"sha1", "sha256"},
		KindFileContent:           nil,
	}, got)
	assert.Nil(t, KindAlgorithms(AnchorKind("image-tag")))

	algs := KindAlgorithms(KindGitCommit)
	algs[0] = "md5"
	assert.Equal(t, []string{"sha1", "sha256"}, KindAlgorithms(KindGitCommit), "callers get a copy")
}

func TestCanonical_GitCommitAccepts(t *testing.T) {
	id, err := Canonical(KindGitCommit, testCommitSHA1, NormalizationBareHex)
	require.NoError(t, err)
	assert.Equal(t, Identity{Kind: KindGitCommit, Algorithm: "sha1", Value: testCommitSHA1}, id)

	id, err = Canonical(KindGitCommit, testHex, NormalizationBareHex)
	require.NoError(t, err)
	assert.Equal(t, Identity{Kind: KindGitCommit, Algorithm: "sha256", Value: testHex}, id)
}

func TestCanonical_GitCommitNegativeSet(t *testing.T) {
	cases := []struct {
		name string
		kind AnchorKind
		raw  string
		rule Normalization
	}{
		{"39 hex", KindGitCommit, testCommitSHA1[:39], NormalizationBareHex},
		{"41 hex", KindGitCommit, testCommitSHA1 + "0", NormalizationBareHex},
		{"63 hex", KindGitCommit, testHex[:63], NormalizationBareHex},
		{"65 hex", KindGitCommit, testHex + "0", NormalizationBareHex},
		{"uppercase sha1", KindGitCommit, strings.ToUpper(testCommitSHA1), NormalizationBareHex},
		{"uppercase sha256", KindGitCommit, strings.ToUpper(testHex), NormalizationBareHex},
		{"null sha1 id", KindGitCommit, strings.Repeat("0", 40), NormalizationBareHex},
		{"null sha256 id", KindGitCommit, strings.Repeat("0", 64), NormalizationBareHex},
		{"sha1-prefixed", KindGitCommit, "sha1:" + testCommitSHA1, NormalizationBareHex},
		{"sha256-prefixed under bare-hex", KindGitCommit, "sha256:" + testHex, NormalizationBareHex},
		{"empty", KindGitCommit, "", NormalizationBareHex},
		{"trailing newline", KindGitCommit, testCommitSHA1 + "\n", NormalizationBareHex},

		// bare hex only: no other normalization reads a commit.
		{"prefixed rule", KindGitCommit, "sha256:" + testHex, NormalizationPrefixed},
		{"repo-at-digest rule", KindGitCommit, "ghcr.io/org/app@sha256:" + testHex, NormalizationRepoAtDigest},
		{"purl rule", KindGitCommit, "pkg:oci/app@sha256%3A" + testHex, NormalizationPURLVersion},

		// sha1 is honoured for git-commit only.
		{"40 hex image config", KindImageConfig, testCommitSHA1, NormalizationBareHex},
		{"40 hex image manifest", KindImageRegistryManifest, testCommitSHA1, NormalizationBareHex},
		{"40 hex reserved kind", KindFileContent, testCommitSHA1, NormalizationBareHex},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := Canonical(c.kind, c.raw, c.rule)
			require.ErrorIs(t, err, errNonCanonical)
			assert.Equal(t, Identity{}, id)
		})
	}
}

// A sha256 repository's commit and an image digest can share a value; the
// identities still differ by kind, so they never compare equal.
func TestCanonical_CommitAndImageWithOneValueAreDistinct(t *testing.T) {
	commit, err := Canonical(KindGitCommit, testHex, NormalizationBareHex)
	require.NoError(t, err)
	image, err := Canonical(KindImageRegistryManifest, testHex, NormalizationBareHex)
	require.NoError(t, err)
	assert.NotEqual(t, commit, image)
}
