// Copyright 2026 TestifySec, Inc.
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

package material

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sha256OfEmpty is sha256(""), which RFC 6962 also defines as the root of an
// EMPTY merkle tree.
const sha256OfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// This attestor already had a guard — `if a.MerkleRoot == ""` in Subjects().
// It never fires for an empty tree, because the empty-tree path explicitly
// computes and stores a real root. This test pins the mechanism so the wrong
// discriminator cannot be reintroduced.
func TestEmptyMaterialSetYieldsTheSharedEmptyRootNotAnEmptyString(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{})

	require.Equal(t, uint64(0), a.TreeSize, "an empty material set must have TreeSize 0")
	require.NotEmpty(t, a.MerkleRoot,
		"the empty-tree path computes a REAL root, so a `MerkleRoot == \"\"` guard is dead code")
	require.Equal(t, sha256OfEmpty, a.MerkleRoot,
		"and that root is sha256(\"\") — shared by every material-less step")
}

func TestBackRefsOmittedForEmptyTree(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{})

	assert.Empty(t, a.BackRefs(),
		"an empty material tree must contribute NO back-reference: every material-less step "+
			"shares this root, so emitting it joins them all into one clique")
}

func TestSubjectsStillCarriesRootForEmptyTree(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{})

	subjects := a.Subjects()
	require.Len(t, subjects, 1,
		"Subjects must still assert the empty root — 'provably consumed nothing' is a real "+
			"claim and must stay distinguishable from an absent attestation")
	digest, ok := subjects[TreeSubjectName]
	require.True(t, ok)
	for _, v := range digest {
		assert.Equal(t, sha256OfEmpty, v)
	}
}

// NEGATIVE CONTROL: a non-empty tree keeps mirroring Subjects exactly.
func TestBackRefsPresentForNonEmptyTree(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{"x.txt": "X"})

	require.Greater(t, a.TreeSize, uint64(0))
	require.NotEqual(t, sha256OfEmpty, a.MerkleRoot)

	backRefs := a.BackRefs()
	require.Len(t, backRefs, 1, "a non-empty material tree is a real artifact-flow edge")
	assert.Equal(t, a.Subjects(), backRefs,
		"for a non-empty tree BackRefs must still mirror Subjects exactly")
}
