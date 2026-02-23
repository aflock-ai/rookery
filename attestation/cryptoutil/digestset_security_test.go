//go:build audit

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
)

// TestSecurity_R3_128_DigestSetEqualHashDowngrade proves that DigestSet.Equal()
// is vulnerable to hash algorithm downgrade attacks. An attacker who controls
// one DigestSet can include only a weak hash algorithm (e.g., SHA1) and omit
// the stronger one (SHA256). The Equal check will pass if the single weak hash
// matches, even though the SHA256 digests are completely different.
//
// In the context of policy verification (compareArtifacts in policy.go), this
// means an attacker who can control a step's artifact output can forge a SHA1
// collision to pass artifact comparison between steps.
//
// Severity: MEDIUM — Requires SHA1 collision which is expensive but demonstrated
// (SHAttered, 2017). Impact escalates if weaker hashes are supported.
func TestSecurity_R3_128_DigestSetEqualHashDowngrade(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}
	sha1Key := DigestValue{Hash: crypto.SHA1}

	tests := []struct {
		name        string
		ds1         DigestSet
		ds2         DigestSet
		wantEqual   bool // what Equal() currently returns
		shouldEqual bool // what a secure implementation should return
		description string
	}{
		{
			name: "both have sha256 and sha1, all match → equal",
			ds1: DigestSet{
				sha256Key: "abc123",
				sha1Key:   "def456",
			},
			ds2: DigestSet{
				sha256Key: "abc123",
				sha1Key:   "def456",
			},
			wantEqual:   true,
			shouldEqual: true,
			description: "normal case — both have same hashes, all match",
		},
		{
			name: "both have sha256 and sha1, sha256 differs → not equal",
			ds1: DigestSet{
				sha256Key: "abc123",
				sha1Key:   "def456",
			},
			ds2: DigestSet{
				sha256Key: "DIFFERENT",
				sha1Key:   "def456",
			},
			wantEqual:   false,
			shouldEqual: false,
			description: "one hash differs → correctly reports not equal",
		},
		{
			name: "DOWNGRADE: attacker omits sha256, only provides sha1",
			ds1: DigestSet{
				sha256Key: "abc123",
				sha1Key:   "def456",
			},
			ds2: DigestSet{
				sha1Key: "def456", // only SHA1, omits SHA256
			},
			wantEqual:   true, // BUG: Equal says true because SHA1 matches
			shouldEqual: false,
			description: "attacker can forge SHA1 collision and omit SHA256 to pass verification",
		},
		{
			name: "DOWNGRADE reverse: legitimate set has sha1 only",
			ds1: DigestSet{
				sha1Key: "def456", // only SHA1
			},
			ds2: DigestSet{
				sha256Key: "TOTALLY_DIFFERENT_FILE",
				sha1Key:   "def456",
			},
			wantEqual:   true, // BUG: Equal only iterates ds1's keys
			shouldEqual: false,
			description: "iteration direction matters — ds1 with weak hash passes",
		},
		{
			name: "no common hashes → not equal (correct)",
			ds1: DigestSet{
				sha256Key: "abc123",
			},
			ds2: DigestSet{
				sha1Key: "def456",
			},
			wantEqual:   false,
			shouldEqual: false,
			description: "no common hash algorithms → correctly false",
		},
		{
			name: "empty ds1 → not equal (correct)",
			ds1: DigestSet{},
			ds2: DigestSet{
				sha256Key: "abc123",
			},
			wantEqual:   false,
			shouldEqual: false,
			description: "empty DigestSet → correctly false",
		},
		{
			name: "both empty → not equal (correct)",
			ds1: DigestSet{},
			ds2: DigestSet{},
			wantEqual:   false,
			shouldEqual: false,
			description: "both empty → no matching digests → false",
		},
		{
			name: "DOWNGRADE: gitoid sha1 collision",
			ds1: DigestSet{
				sha256Key: "abc123",
				{Hash: crypto.SHA1, GitOID: true}: "gitoid:sha1:def456",
			},
			ds2: DigestSet{
				// Attacker provides only gitoid sha1, omits sha256
				{Hash: crypto.SHA1, GitOID: true}: "gitoid:sha1:def456",
			},
			wantEqual:   true, // BUG: gitoid sha1 match is sufficient
			shouldEqual: false,
			description: "gitoid SHA1 collision bypasses SHA256 check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ds1.Equal(tt.ds2)

			if got != tt.wantEqual {
				t.Fatalf("DigestSet.Equal() = %v, expected %v based on current behavior", got, tt.wantEqual)
			}

			if tt.wantEqual != tt.shouldEqual {
				t.Errorf("SECURITY BUG R3-128: DigestSet.Equal() returns %v but secure behavior should be %v.\n"+
					"Description: %s\n"+
					"ds1: %v\n"+
					"ds2: %v\n"+
					"An attacker who can control one DigestSet can omit strong hashes and only "+
					"provide a collided weak hash to forge equality.",
					got, tt.shouldEqual, tt.description, tt.ds1, tt.ds2)
			}
		})
	}
}

// TestSecurity_R3_128_DigestSetEqualIterationAsymmetry proves that Equal()
// only iterates over the receiver's keys, not the argument's. This means
// the result depends on which side is the receiver vs the argument.
func TestSecurity_R3_128_DigestSetEqualIterationAsymmetry(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}
	sha1Key := DigestValue{Hash: crypto.SHA1}

	// ds1 has SHA256 + SHA1, ds2 has only SHA1 (but matching)
	ds1 := DigestSet{
		sha256Key: "strong_digest",
		sha1Key:   "weak_digest",
	}
	ds2 := DigestSet{
		sha1Key: "weak_digest",
	}

	// ds1.Equal(ds2): iterates over sha256 and sha1
	// - sha256: not in ds2 → skip
	// - sha1: matches → hasMatchingDigest = true
	// Returns true
	forward := ds1.Equal(ds2)

	// ds2.Equal(ds1): iterates over sha1 only
	// - sha1: matches → hasMatchingDigest = true
	// Returns true
	reverse := ds2.Equal(ds1)

	// Both directions return true, but neither should because
	// ds2 is missing the stronger SHA256 hash.
	if forward && reverse {
		t.Errorf("SECURITY BUG R3-128: Both ds1.Equal(ds2)=%v and ds2.Equal(ds1)=%v return true, "+
			"but ds2 is missing SHA256. A secure Equal() should require that ALL hashes "+
			"present in EITHER set match in the other, or that at least the strongest "+
			"common hash matches.", forward, reverse)
	}

	// Now test the case where the results DIFFER based on direction
	// ds3 has only SHA256, ds4 has SHA256 + SHA1 (sha256 matches, sha1 is extra)
	ds3 := DigestSet{
		sha256Key: "strong_digest",
	}
	ds4 := DigestSet{
		sha256Key: "strong_digest",
		sha1Key:   "extra_weak_digest",
	}

	// ds3.Equal(ds4): iterates sha256, finds match → true
	fwd2 := ds3.Equal(ds4)
	// ds4.Equal(ds3): iterates sha256 (match) and sha1 (not in ds3, skip) → true
	rev2 := ds4.Equal(ds3)

	// Both should be true here since sha256 matches and that's the strongest
	if fwd2 != rev2 {
		t.Errorf("Equal() is asymmetric: ds3.Equal(ds4)=%v, ds4.Equal(ds3)=%v", fwd2, rev2)
	}
}
