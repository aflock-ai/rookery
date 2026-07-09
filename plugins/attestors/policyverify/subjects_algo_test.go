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

package policyverify

import (
	"crypto"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestSubjects_PreservesDeclaredAlgorithm pins the algorithm-threading fix: a
// seed subject declared sha1 (a git commit) must be re-emitted by the
// policyverify attestor under sha1 — the old code flattened every seed to a
// bare string and relabeled it sha256 in the emitted collection.
func TestSubjects_PreservesDeclaredAlgorithm(t *testing.T) {
	const commit = "cf12d38eb1e8513c00f13313ca95bd2c7769f72a"
	const fileDigest = "7b8c52c06dad0eb1cf800bb3343525b78e3dff07a076aac566d52beff2b7e38d"

	a := New()
	a.SetSubjectDigests([]cryptoutil.DigestSet{
		{cryptoutil.DigestValue{Hash: crypto.SHA1, GitOID: false}: commit},
		{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: fileDigest},
	})

	subjects := a.Subjects()

	sha1Set, ok := subjects["artifact:"+commit]
	if !ok {
		t.Fatalf("missing artifact subject for the sha1 seed; got %v", subjects)
	}
	if got := sha1Set[cryptoutil.DigestValue{Hash: crypto.SHA1, GitOID: false}]; got != commit {
		t.Fatalf("sha1 seed emitted as %v, want it under crypto.SHA1", sha1Set)
	}
	if _, mislabeled := sha1Set[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}]; mislabeled {
		t.Fatal("sha1 seed must NOT be relabeled sha256 in the emitted collection")
	}

	sha256Set, ok := subjects["artifact:"+fileDigest]
	if !ok {
		t.Fatalf("missing artifact subject for the sha256 seed; got %v", subjects)
	}
	if got := sha256Set[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}]; got != fileDigest {
		t.Fatalf("sha256 seed emitted as %v", sha256Set)
	}
}

// TestSeedDigestStrings_FlattensValuesForSearch: the policy engine's
// value-based subject search still receives the bare hex values regardless of
// declared algorithm.
func TestSeedDigestStrings_FlattensValuesForSearch(t *testing.T) {
	const commit = "cf12d38eb1e8513c00f13313ca95bd2c7769f72a"
	a := New()
	a.SetSubjectDigests([]cryptoutil.DigestSet{
		{cryptoutil.DigestValue{Hash: crypto.SHA1, GitOID: false}: commit},
	})
	got := a.seedDigestStrings()
	if len(got) != 1 || got[0] != commit {
		t.Fatalf("seedDigestStrings = %v, want [%s]", got, commit)
	}
}
