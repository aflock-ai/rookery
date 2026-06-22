// Copyright 2024 The Witness Contributors
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

package cryptoutil

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecurity_R3_128_DigestSetEqualHashDowngrade proves DigestSet.Equal does
// NOT downgrade to the weakest shared hash (GHSA-pgpm-j729-qcvh, finding R3-128).
//
// An attacker who controls one DigestSet could otherwise include only a weak
// algorithm (e.g. SHA-1) and omit the stronger one (SHA-256); the old Equal
// returned true on the single weak match even though the strong digests never
// agreed. The secure contract: the strongest algorithm present on either side
// must be carried by both sides and agree, and no shared algorithm of any
// strength may disagree.
func TestSecurity_R3_128_DigestSetEqualHashDowngrade(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}
	sha1Key := DigestValue{Hash: crypto.SHA1}
	gitoidSHA256 := DigestValue{Hash: crypto.SHA256, GitOID: true} // same 32-byte size as sha256
	gitoidSHA1 := DigestValue{Hash: crypto.SHA1, GitOID: true}

	tests := []struct {
		name  string
		ds1   DigestSet
		ds2   DigestSet
		equal bool
	}{
		{
			name:  "both have sha256+sha1, all match -> equal",
			ds1:   DigestSet{sha256Key: "abc123", sha1Key: "def456"},
			ds2:   DigestSet{sha256Key: "abc123", sha1Key: "def456"},
			equal: true,
		},
		{
			name:  "strongest shared digest differs -> not equal",
			ds1:   DigestSet{sha256Key: "abc123", sha1Key: "def456"},
			ds2:   DigestSet{sha256Key: "DIFFERENT", sha1Key: "def456"},
			equal: false,
		},
		{
			name:  "DOWNGRADE: attacker omits sha256, only weak sha1 agrees -> not equal",
			ds1:   DigestSet{sha256Key: "abc123", sha1Key: "def456"},
			ds2:   DigestSet{sha1Key: "def456"},
			equal: false,
		},
		{
			name:  "DOWNGRADE reverse: weak-only receiver vs strong-bearing other -> not equal",
			ds1:   DigestSet{sha1Key: "def456"},
			ds2:   DigestSet{sha256Key: "TOTALLY_DIFFERENT_FILE", sha1Key: "def456"},
			equal: false,
		},
		{
			name:  "weaker side is a superset, strong digest agrees -> equal",
			ds1:   DigestSet{sha256Key: "abc123"},
			ds2:   DigestSet{sha256Key: "abc123", sha1Key: "def456"},
			equal: true,
		},
		{
			name:  "no common hash algorithm -> not equal",
			ds1:   DigestSet{sha256Key: "abc123"},
			ds2:   DigestSet{sha1Key: "def456"},
			equal: false,
		},
		{
			name:  "empty ds1 -> not equal",
			ds1:   DigestSet{},
			ds2:   DigestSet{sha256Key: "abc123"},
			equal: false,
		},
		{
			name:  "both empty -> not equal",
			ds1:   DigestSet{},
			ds2:   DigestSet{},
			equal: false,
		},
		{
			name:  "DOWNGRADE: gitoid sha1-only omits sha256 -> not equal",
			ds1:   DigestSet{sha256Key: "abc123", gitoidSHA1: "gitoid:sha1:def456"},
			ds2:   DigestSet{gitoidSHA1: "gitoid:sha1:def456"},
			equal: false,
		},
		{
			name:  "tie at strongest size: shared sha256 agrees, gitoid:sha256 omitted -> equal",
			ds1:   DigestSet{sha256Key: "abc123", gitoidSHA256: "gitoid:sha256:g"},
			ds2:   DigestSet{sha256Key: "abc123"},
			equal: true,
		},
		{
			name:  "tie at strongest size: shared sha256 disagrees -> not equal",
			ds1:   DigestSet{sha256Key: "abc123", gitoidSHA256: "gitoid:sha256:g"},
			ds2:   DigestSet{sha256Key: "DIFFERENT"},
			equal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.equal, tt.ds1.Equal(tt.ds2))
			require.Equal(t, tt.equal, tt.ds2.Equal(tt.ds1), "Equal must be symmetric")
		})
	}
}

// TestDigestSetEqual_UnknownHashDoesNotPanic guards against a DoS: a caller that
// hand-builds a DigestSet with a zero-value or otherwise unregistered
// DigestValue must not make Equal panic via crypto.Hash.Size(). Such entries are
// treated as unrecognized and never establish equality.
func TestDigestSetEqual_UnknownHashDoesNotPanic(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}
	zero := DigestValue{} // Hash == crypto.Hash(0): Size() would panic if called

	unknownOnly := DigestSet{zero: "x"}
	unknownOnly2 := DigestSet{zero: "x"}
	strongOnly := DigestSet{sha256Key: "y"}
	strongPlusUnknown := DigestSet{sha256Key: "y", zero: "x"}

	require.NotPanics(t, func() {
		require.False(t, unknownOnly.Equal(unknownOnly2),
			"an unrecognized hash must not establish equality")
		require.False(t, unknownOnly.Equal(strongOnly))
		require.False(t, strongOnly.Equal(unknownOnly))
		// A recognized strong hash still governs when an unknown key rides along.
		require.True(t, strongPlusUnknown.Equal(strongOnly))

		// Equality ignores unrecognized keys entirely: two sets that agree on
		// every recognized algorithm must be equal even if they differ on an
		// unknown key (equivalence-relation consistency).
		strongPlusUnknownA := DigestSet{sha256Key: "y", zero: "a"}
		strongPlusUnknownB := DigestSet{sha256Key: "y", zero: "b"}
		require.True(t, strongPlusUnknownA.Equal(strongPlusUnknownB),
			"differing only on an unrecognized key must not make recognized-equal sets unequal")
	})
}
