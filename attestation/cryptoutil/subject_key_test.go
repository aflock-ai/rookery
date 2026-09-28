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

package cryptoutil

import (
	"crypto"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	keyTestSHA256 = strings.Repeat("ab", 32) // 64 hex
	keyTestSHA1   = strings.Repeat("cd", 20) // 40 hex
)

func TestSubjectDigestKey_RoundTrip(t *testing.T) {
	for _, alg := range []string{"sha256", "sha1", "gitoid:sha256", "gitoid:sha1", "dirHash"} {
		for _, val := range []string{keyTestSHA256, "gitoid:blob:sha256:" + keyTestSHA256, "h1:abc=", "x:y:z"} {
			key := SubjectDigestKey(alg, val)
			gotAlg, gotVal, ok := ParseSubjectDigestKey(key)
			require.True(t, ok, key)
			assert.Equal(t, alg, gotAlg, key)
			assert.Equal(t, val, gotVal, key)
		}
	}
}

func TestParseSubjectDigestKey_RejectsUnknownAndBare(t *testing.T) {
	for _, s := range []string{
		"",
		keyTestSHA256,                         // bare value
		"md5:" + keyTestSHA256,                // unknown algorithm
		"gitoid:blob:sha256:" + keyTestSHA256, // bare gitoid URI, not a key
		"h1:abc=",                             // bare dirhash, not a key
		"sha256:",                             // empty value
		"SHA256:" + keyTestSHA256,             // algorithm names are case-exact
	} {
		_, _, ok := ParseSubjectDigestKey(s)
		assert.False(t, ok, "%q must not parse as a key", s)
	}
}

// TestNormalizeSubjectSeed pins the explicit legacy table for BARE seed values:
// a bare value is bound to exactly one algorithm, and only when its shape
// proves that algorithm. There is no value that normalizes to two algorithms,
// so no cross-algorithm match can come out of it (#9816).
func TestNormalizeSubjectSeed(t *testing.T) {
	gitoidURI := "gitoid:blob:sha256:" + keyTestSHA256
	cases := []struct {
		in, want string
	}{
		// Already a key: unchanged.
		{"sha256:" + keyTestSHA256, "sha256:" + keyTestSHA256},
		{"gitoid:sha256:" + gitoidURI, "gitoid:sha256:" + gitoidURI},
		{"dirHash:h1:abc=", "dirHash:h1:abc="},
		{"sha1:" + keyTestSHA1, "sha1:" + keyTestSHA1},
		// Bare values whose shape proves one algorithm.
		{keyTestSHA256, "sha256:" + keyTestSHA256},
		{strings.ToUpper(keyTestSHA256), "sha256:" + strings.ToUpper(keyTestSHA256)},
		{keyTestSHA1, "sha1:" + keyTestSHA1},
		{gitoidURI, "gitoid:sha256:" + gitoidURI},
		{"gitoid:blob:sha1:" + keyTestSHA1, "gitoid:sha1:gitoid:blob:sha1:" + keyTestSHA1},
		{"h1:abc=", "dirHash:h1:abc="},
		// Anything else stays opaque: it can only ever equal an identical
		// opaque string, never a real subject key.
		{"seed", "seed"},
		{"deadbeef", "deadbeef"},
		{"", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, NormalizeSubjectSeed(tc.in), "seed %q", tc.in)
	}
}

func TestNormalizeSubjectSeeds_Dedups(t *testing.T) {
	got := NormalizeSubjectSeeds([]string{keyTestSHA256, "sha256:" + keyTestSHA256, keyTestSHA1})
	assert.Equal(t, []string{"sha256:" + keyTestSHA256, "sha1:" + keyTestSHA1}, got)
	assert.Nil(t, NormalizeSubjectSeeds(nil))
}

func TestDigestSetSubjectKeys(t *testing.T) {
	ds := DigestSet{
		DigestValue{Hash: crypto.SHA256}:               keyTestSHA256,
		DigestValue{Hash: crypto.SHA256, GitOID: true}: "gitoid:blob:sha256:" + keyTestSHA256,
		DigestValue{Hash: crypto.SHA1}:                 keyTestSHA1,
	}
	got, err := DigestSetSubjectKeys(ds)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"sha256:" + keyTestSHA256,
		"gitoid:sha256:gitoid:blob:sha256:" + keyTestSHA256,
		"sha1:" + keyTestSHA1,
	}, got)
}
