// jade:ring local
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

package git

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// D15-3 (docs/design/attestation-anchors.md 3.7, row D15-b): the git attestor
// anchors its own measured commit, one git-commit anchor of role about, and
// only from the hardened path (commithashverified). Never a parent.

var _ attestation.Anchorer = (*Attestor)(nil)

func TestAnchorsNameTheVerifiedCommitOnly(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	a := New()
	require.NoError(t, attestAt(t, dir, a))
	require.True(t, a.CommitHashVerified)

	got := a.Anchors(nil)
	require.Equal(t, []attestation.Anchor{{
		Key:      "commithash:" + a.CommitHash,
		Identity: attestation.Identity{Kind: attestation.KindGitCommit, Algorithm: "sha1", Value: a.CommitHash},
		Role:     attestation.RoleAbout,
		Basis:    attestation.BasisMeasured,
	}}, got)

	// A9: every anchor is a subject the collection carries.
	_, isSubject := a.Subjects()[got[0].Key]
	require.True(t, isSubject)
}

func TestAnchorsWithoutTheHardenedMarkerAreNone(t *testing.T) {
	a := &Attestor{CommitHash: strings.Repeat("ab", 20)}
	require.Empty(t, a.Anchors(nil))
}

// A merge commit still anchors itself once; its parents are relationships.
func TestAnchorsNeverNameAParent(t *testing.T) {
	c := strings.Repeat("ab", 20)
	a := &Attestor{
		CommitHash:         c,
		CommitHashVerified: true,
		ParentHashes:       []string{strings.Repeat("cd", 20), strings.Repeat("ef", 20)},
	}
	got := a.Anchors(nil)
	require.Len(t, got, 1)
	require.Equal(t, "commithash:"+c, got[0].Key)
}

// The registry row is sha1; a sha256 repository's commit has no row yet, and a
// non-canonical value is never repaired into one.
func TestAnchorsRefuseWhatTheRowDoesNotAdmit(t *testing.T) {
	for name, c := range map[string]string{
		"sha256 repository": strings.Repeat("ab", 32),
		"uppercase":         strings.Repeat("AB", 20),
		"null id":           strings.Repeat("0", 40),
		"empty":             "",
	} {
		t.Run(name, func(t *testing.T) {
			a := &Attestor{CommitHash: c, CommitHashVerified: true}
			require.Empty(t, a.Anchors(nil))
		})
	}
}
