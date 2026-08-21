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
	"crypto"
	"crypto/sha1" //nolint:gosec // this pin test asserts go-git does NOT use plain crypto/sha1
	"testing"

	gogithash "github.com/go-git/go-git/v5/plumbing/hash"
)

// The collisionDetectingHash discriminator interface now lives in git.go:
// production itself asserts it in computeVerifiedCommitHash, which re-hashes
// the canonical commit object at attestation time. This test remains the CI
// pin that go-git's hasher keeps satisfying it.

// TestGitObjectHashIsCollisionDetecting is the ENFORCED invariant behind the
// git-commit SHA-1 subject-match arm (attestation/cryptoutil isGitCommitSubject
// / IsMatchableSubjectDigest). That arm is the ONE place a SHA-1 digest may
// anchor a subject match, and it is sound ONLY because the SHA-1 that produced a
// commit id is collision-DETECTING: an object carrying a chosen-prefix
// collision is rejected rather than hashed, so an attacker cannot replay a
// benign commit's signed evidence against a colliding object.
//
// commithash subjects come from go-git's head.Hash() (git.go: a.CommitHash =
// head.Hash().String()), and go-git hashes SHA-1 objects through
// plumbing/hash.New(crypto.SHA1). Until now the cryptoutil arm only DOCUMENTED
// that this routes through sha1cd ("BORROWED, not enforced"); this test makes it
// a checked invariant. A go-git downgrade to a version that used crypto/sha1, or
// a plumbing/hash.RegisterHash swap back to crypto/sha1, now breaks this test
// instead of silently weakening the arm to plain, collision-purchasable SHA-1.
func TestGitObjectHashIsCollisionDetecting(t *testing.T) {
	// Control: plain crypto/sha1 must NOT satisfy the collision-detecting
	// interface — otherwise the invariant assertion below would be vacuous.
	if _, ok := any(sha1.New()).(collisionDetectingHash); ok {
		t.Fatal("control failed: crypto/sha1 unexpectedly satisfies the collision-detecting interface; " +
			"the discriminator is broken and the invariant below proves nothing")
	}

	// Invariant: go-git's SHA-1 object hasher — the source of every commithash
	// subject — is the collision-detecting implementation.
	h := gogithash.New(crypto.SHA1)
	if _, ok := any(h).(collisionDetectingHash); !ok {
		t.Fatalf("go-git's SHA-1 object hasher (%T) is NOT collision-detecting — the git-commit "+
			"subject-match arm would rest on plain SHA-1, which has practical chosen-prefix collisions, "+
			"so a colliding object could replay a benign commit's signed evidence", h)
	}
}
