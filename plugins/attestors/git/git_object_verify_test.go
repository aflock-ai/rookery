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
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/require"
)

// These tests enforce the terminal link of the SHA-1 commit-subject chain: the
// attestor must RE-HASH the canonical commit object bytes with the
// collision-detecting hasher and attest only the COMPUTED id — never the id
// the repository's storage merely claims. The pin test
// (TestGitObjectHashIsCollisionDetecting) proves the hasher is CAPABLE of
// collision detection; without re-hashing, that capability is never exercised
// on the subject-producing object, so a crafted repository whose storage
// carries a tampered or colliding object under a benign name would still be
// attested under the benign id.

// TestAttestRefusesTamperedCommitObject is the end-to-end refusal: a
// repository whose ref claims commit id H while the loose object stored under
// H contains DIFFERENT canonical bytes must fail attestation, not attest H.
//
// The tampered bytes are kept a syntactically valid commit of identical
// length, so the only thing wrong with them is that they do not hash to H —
// proving the refusal comes from the hash verification, not from a parse
// error or a size check.
func TestAttestRefusesTamperedCommitObject(t *testing.T) {
	repo, dir, cleanup := createTestRepo(t, true)
	defer cleanup()

	head, err := repo.Head()
	require.NoError(t, err)
	claimed := head.Hash()

	// Read the canonical content of the commit object (without the
	// "commit <len>\0" header) so the tampered replacement stays well-formed.
	encoded, err := repo.Storer.EncodedObject(plumbing.CommitObject, claimed)
	require.NoError(t, err)
	reader, err := encoded.Reader()
	require.NoError(t, err)
	content, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	// Same length, different bytes: the commit message "Initial commit"
	// becomes "Jnitial commit". A same-length substitution keeps the stored
	// size header truthful, so nothing but the object id is wrong.
	tampered := bytes.Replace(content, []byte("Initial commit"), []byte("Jnitial commit"), 1)
	require.NotEqual(t, content, tampered, "fixture rot: expected the commit message %q in the object bytes", "Initial commit")
	require.Len(t, tampered, len(content))

	// Overwrite the loose object stored under the CLAIMED id with the
	// tampered bytes. go-git writes loose objects read-only, so re-permit.
	objPath := filepath.Join(dir, ".git", "objects", claimed.String()[:2], claimed.String()[2:])
	require.FileExists(t, objPath, "fixture assumption broken: HEAD commit is not a loose object")
	require.NoError(t, os.Chmod(objPath, 0o644))
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err = fmt.Fprintf(zw, "commit %d\x00", len(tampered))
	require.NoError(t, err)
	_, err = zw.Write(tampered)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(objPath, buf.Bytes(), 0o644))

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)

	err = attestor.Attest(ctx)
	require.Error(t, err,
		"attestation must refuse a commit whose storage-claimed id does not match the hash of its canonical bytes — attesting the claimed id would bypass collision detection entirely")
	require.Contains(t, err.Error(), claimed.String(),
		"the refusal must name the claimed id so the mismatch is diagnosable")
	require.Empty(t, attestor.CommitHash,
		"a refused attestation must not have recorded ANY commit hash — the claimed value must never survive into the attested subject")
	require.False(t, attestor.CommitHashVerified,
		"a refused attestation must not carry the verified-commit-hash marker — the marker is the matcher's licence to anchor SHA-1, and it may only ever accompany a hash that survived verification")
}

// TestComputeVerifiedCommitHash unit-tests the seam that is the ONLY path to
// an attested CommitHash, with inputs the fixture above cannot easily reach.
func TestComputeVerifiedCommitHash(t *testing.T) {
	content := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author a <a@b.c> 0 +0000\ncommitter a <a@b.c> 0 +0000\n\nx\n")
	honest := plumbing.ComputeHash(plumbing.CommitObject, content)

	t.Run("computed equals claimed", func(t *testing.T) {
		got, err := computeVerifiedCommitHash(honest, content)
		require.NoError(t, err)
		require.Equal(t, honest.String(), got)
	})

	t.Run("claimed id that does not match the bytes is refused, naming both ids", func(t *testing.T) {
		liar := plumbing.NewHash("aaaa0000beef1111cafe2222f00d3333feed4444")
		_, err := computeVerifiedCommitHash(liar, content)
		require.Error(t, err)
		require.Contains(t, err.Error(), liar.String(), "the error must name the claimed id")
		require.Contains(t, err.Error(), honest.String(), "the error must name the computed id")
	})

	// The remaining refusal — CollisionResistantSum reporting a detected
	// collision — cannot be exercised with honest inputs: fabricating bytes
	// that trip sha1cd requires an actual SHA-1 near-collision. Its guard is
	// the type assertion (pinned by TestGitObjectHashIsCollisionDetecting)
	// plus the branch itself; a future public collision commit fixture could
	// close this gap.
}

// TestAttestRecordsComputedHashOnHonestRepository is the happy path: on a
// repository whose storage is honest, the computed hash equals the claimed
// hash and attestation is unchanged — the verification must not break normal
// repositories.
func TestAttestRecordsComputedHashOnHonestRepository(t *testing.T) {
	repo, dir, cleanup := createTestRepo(t, true)
	defer cleanup()

	head, err := repo.Head()
	require.NoError(t, err)

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)

	require.NoError(t, attestor.Attest(ctx))
	require.Equal(t, head.Hash().String(), attestor.CommitHash,
		"on an honest repository the computed id must equal the claimed id and be recorded unchanged")
	require.NotEmpty(t, attestor.TreeHash, "tree hash must still be recorded from the verified bytes")
	require.True(t, attestor.CommitHashVerified,
		"a successful attestation must emit the verified-commit-hash capability marker alongside the hash — without it the matcher (correctly) treats the evidence as legacy and refuses SHA-1 commit anchoring")
}

// TestVerifiedMarkerContractWithMatcher binds the PRODUCER side of the SHA-1
// exception to the CONSUMER side across packages, so the two cannot drift
// apart silently:
//
//   - the predicate type this attestor publishes must be the exact type the
//     matcher accepts as hardened (a version bump breaks this test on
//     purpose — carrying the exception forward is a conscious edit on BOTH
//     sides, or sha1 anchoring fails closed for the new version);
//   - the JSON this attestor signs must carry the marker under the exact key
//     the matcher's narrow decode reads (a struct-tag typo here would demote
//     every new attestation to legacy — loud in these assertions, silent in
//     production).
func TestVerifiedMarkerContractWithMatcher(t *testing.T) {
	require.True(t, cryptoutil.IsHardenedGitAttestationType(Type),
		"the git attestor's Type is no longer the matcher's hardened git attestation type — hardened evidence produced now would never anchor a SHA-1 commit match; update cryptoutil's hardenedGitAttestationType (and its contract) together with any version bump")

	_, dir, cleanup := createTestRepo(t, true)
	defer cleanup()

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	body, err := json.Marshal(attestor)
	require.NoError(t, err)
	require.True(t, cryptoutil.HasGitCommitVerifiedMarker(body),
		"the attestor's marshaled predicate does not satisfy the matcher's marker decode — the commithashverified key the producer writes and the key cryptoutil reads have drifted apart")
}
