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
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/require"
)

// The git attestor reads HEAD before the wrapped command runs. If the command
// (or a second shell in the same worktree) moves HEAD, the collection would
// sign commit A for tests that ran against tree B (testifysec/judge#9359).
// CheckBeforeSigning re-reads HEAD and refuses on any move.

var _ attestation.SigningGuard = (*Attestor)(nil)

func TestCheckBeforeSigningPassesWhenHeadDidNotMove(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	a := New()
	require.NoError(t, attestAt(t, dir, a))
	require.NoError(t, a.CheckBeforeSigning())
}

func TestCheckBeforeSigningRefusesANewCommit(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	a := New()
	require.NoError(t, attestAt(t, dir, a))
	before := a.CommitHash

	createTestCommit(t, dir, "made during the wrapped command")
	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	after := head.Hash().String()
	require.NotEqual(t, before, after)

	err = a.CheckBeforeSigning()
	require.Error(t, err)
	require.Contains(t, err.Error(), before, "the refusal names the commit that was attested")
	require.Contains(t, err.Error(), after, "the refusal names the commit HEAD moved to")
	require.Contains(t, err.Error(), "moved during the run")
}

// The reported mechanism: a second invocation's `git checkout --detach <sha>`.
func TestCheckBeforeSigningRefusesADetachedCheckout(t *testing.T) {
	repo, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	first, err := repo.Head()
	require.NoError(t, err)
	createTestCommit(t, dir, "second")

	a := New()
	require.NoError(t, attestAt(t, dir, a))

	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Hash: first.Hash()}))

	err = a.CheckBeforeSigning()
	require.Error(t, err)
	require.Contains(t, err.Error(), first.Hash().String())
}

// A branch switch to another ref at the SAME commit leaves the tree the same;
// the attested commit still holds.
func TestCheckBeforeSigningAllowsSameCommitOnAnotherRef(t *testing.T) {
	repo, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	a := New()
	require.NoError(t, attestAt(t, dir, a))

	head, err := repo.Head()
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("other"), Hash: head.Hash(), Create: true}))
	require.NoError(t, a.CheckBeforeSigning())
}

func TestCheckBeforeSigningRefusesAFirstCommitInAnUnbornRepository(t *testing.T) {
	repo, dir, cleanup := createTestRepo(t, false)
	defer cleanup()
	a := New()
	require.NoError(t, attestAt(t, dir, a))
	require.Empty(t, a.CommitHash)

	addCommit(dir, t, repo)
	err := a.CheckBeforeSigning()
	require.Error(t, err)
	require.Contains(t, err.Error(), "moved during the run")
}

// An attestor that never ran here (decoded from a signed predicate) has no
// observation to re-check and must not invent one.
func TestCheckBeforeSigningIsInertOnADecodedPredicate(t *testing.T) {
	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()
	a := New()
	require.NoError(t, attestAt(t, dir, a))
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	var decoded Attestor
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.NoError(t, decoded.CheckBeforeSigning())
}
