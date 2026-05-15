// Copyright 2025 The Aflock Authors
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

package workflow

import (
	"crypto"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseSubjectFlags_DigestLength verifies that parseDigestSpec (via
// ParseSubjectFlags) rejects digests whose decoded byte length does not match
// the declared algorithm. Accepting a truncated digest would produce a
// malformed in-toto subject that downstream verifiers may reject or
// silently misinterpret.
func TestParseSubjectFlags_DigestLength(t *testing.T) {
	// 32-byte sha256 digest (zero-valued, valid hex and valid length).
	sha256Full := strings.Repeat("00", 32)
	// 20-byte sha1 digest.
	sha1Full := strings.Repeat("11", 20)

	// NOTE: cryptoutil.HashFromString currently only recognises sha256 and
	// sha1 (plus gitoid:/dirHash variants). sha512 etc. are unsupported, so
	// we can't exercise those lengths here — they fail at the algorithm
	// lookup before reaching the length check. The length check still fires
	// correctly for any algorithm whose crypto.Hash.Size() > 0, which
	// includes every sha variant if/when they're added to hashesByName.
	tests := []struct {
		name     string
		entry    string
		wantErr  string // substring of the expected error; empty means expect success
		wantHash crypto.Hash
	}{
		{
			name:     "sha256 correct length",
			entry:    "binary=sha256:" + sha256Full,
			wantHash: crypto.SHA256,
		},
		{
			name:    "sha256 truncated to 4 bytes",
			entry:   "binary=sha256:deadbeef",
			wantErr: "expected 32 bytes for sha256",
		},
		{
			name:    "sha256 oversized to 64 bytes",
			entry:   "binary=sha256:" + strings.Repeat("00", 64),
			wantErr: "expected 32 bytes for sha256",
		},
		{
			name:     "sha1 correct length",
			entry:    "file=sha1:" + sha1Full,
			wantHash: crypto.SHA1,
		},
		{
			name:    "sha1 truncated",
			entry:   "file=sha1:abcdef",
			wantErr: "expected 20 bytes for sha1",
		},
		{
			name:    "sha1 oversized (sha256-length)",
			entry:   "file=sha1:" + sha256Full,
			wantErr: "expected 20 bytes for sha1",
		},
		{
			name:    "odd-length hex fails at hex decode, not length check",
			entry:   "x=sha256:abc",
			wantErr: "not valid hex",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ParseSubjectFlags([]string{tc.entry})
			if tc.wantErr != "" {
				require.Error(t, err, "expected error for entry %q", tc.entry)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			// Extract name before '='.
			name := tc.entry
			if eq := strings.Index(tc.entry, "="); eq >= 0 {
				name = tc.entry[:eq]
			}
			ds, ok := out[name]
			// require: the rest of the test body dereferences ds, so bail out fast
			// on a missing subject rather than panic with a zero-value DigestSet.
			require.True(t, ok, "subject %q not present in output", name)
			assert.Len(t, ds, 1)
			for dv := range ds {
				assert.Equal(t, tc.wantHash, dv.Hash)
			}
		})
	}
}

// TestParseSubjectFlags_Happy covers the non-digest-length paths to ensure the
// new validation didn't regress the happy path and synthetic-digest branches.
func TestParseSubjectFlags_Happy(t *testing.T) {
	sha256Full := strings.Repeat("ab", 32)

	out, err := ParseSubjectFlags([]string{
		"product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd",
		"binary=sha256:" + sha256Full,
	})
	require.NoError(t, err)
	assert.Len(t, out, 2)
	assert.Contains(t, out, "product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd")
	assert.Contains(t, out, "binary")
}

// TestParseSubjectFlags_DuplicateName ensures duplicate-name detection still
// works after the length-validation refactor.
func TestParseSubjectFlags_DuplicateName(t *testing.T) {
	sha256Full := strings.Repeat("cd", 32)
	_, err := ParseSubjectFlags([]string{
		"binary=sha256:" + sha256Full,
		"binary=sha256:" + sha256Full,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate name")
}

// TestParseSubjectFlags_Empty confirms nil input and all-empty input both
// return an empty/nil map with no error.
func TestParseSubjectFlags_Empty(t *testing.T) {
	out, err := ParseSubjectFlags(nil)
	require.NoError(t, err)
	assert.Empty(t, out)

	out, err = ParseSubjectFlags([]string{"", "   "})
	require.NoError(t, err)
	assert.Empty(t, out)
}
