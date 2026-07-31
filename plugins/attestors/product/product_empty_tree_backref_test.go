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

package product

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sha256OfEmpty is sha256(""), which RFC 6962 also defines as the root of an
// EMPTY merkle tree. A step that produced nothing computes exactly this root,
// so the value is shared by every product-less step rather than identifying
// any one of them.
const sha256OfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Documents the mechanism the guard exists for: an empty product set does NOT
// leave MerkleRoot unset — it produces a real, and universally shared, root.
// Any guard written against `MerkleRoot == ""` would never fire.
func TestEmptyProductSetYieldsTheSharedEmptyRoot(t *testing.T) {
	a := makeAttestor(t, map[string]string{})

	require.Equal(t, uint64(0), a.TreeSize, "an empty product set must have TreeSize 0")
	require.Equal(t, sha256OfEmpty, a.MerkleRoot,
		"the RFC 6962 empty-tree root is sha256(\"\") — note it is NOT the empty string, "+
			"so TreeSize is the only sound discriminator for 'this tree is empty'")
}

// The graph edge must be withheld for an empty tree.
func TestBackRefsOmittedForEmptyTree(t *testing.T) {
	a := makeAttestor(t, map[string]string{})

	assert.Empty(t, a.BackRefs(),
		"an empty product tree must contribute NO back-reference: every product-less step "+
			"shares this root, so emitting it joins them all into one clique and the verify "+
			"search set explodes")
}

// The statement's CLAIM is unchanged. Subjects() deliberately always carries a
// root so a verifier can distinguish "provably empty" from "absent" — only the
// graph EDGE is withheld.
func TestSubjectsStillCarriesRootForEmptyTree(t *testing.T) {
	a := makeAttestor(t, map[string]string{})

	subjects := a.Subjects()
	require.Len(t, subjects, 1,
		"Subjects must still assert the empty root; withholding it would make 'provably "+
			"empty' indistinguishable from 'no attestation', which is a weaker claim")
	digest, ok := subjects[TreeSubjectName]
	require.True(t, ok)
	for _, v := range digest {
		assert.Equal(t, sha256OfEmpty, v)
	}
}

// NEGATIVE CONTROL: a non-empty tree must still emit its edge unchanged.
func TestBackRefsPresentForNonEmptyTree(t *testing.T) {
	a := makeAttestor(t, map[string]string{"x.txt": "X"})

	require.Greater(t, a.TreeSize, uint64(0))
	require.NotEqual(t, sha256OfEmpty, a.MerkleRoot)

	backRefs := a.BackRefs()
	require.Len(t, backRefs, 1, "a non-empty product tree is a real artifact-flow edge")
	digest, ok := backRefs[TreeSubjectName]
	require.True(t, ok)
	assert.Equal(t, a.Subjects()[TreeSubjectName], digest,
		"for a non-empty tree BackRefs must still mirror Subjects exactly")
}
