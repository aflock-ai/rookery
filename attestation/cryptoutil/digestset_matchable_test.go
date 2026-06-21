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

package cryptoutil

import (
	"strings"
	"testing"
)

// TestIsMatchableSubjectDigest pins finding S1: a subject digest may only be
// used as a subject-match key when its algorithm is collision-resistant AND its
// value is well-formed for that algorithm. SHA-1 (chosen-prefix collidable),
// unknown algorithms, and malformed/wrong-length values must all be rejected.
func TestIsMatchableSubjectDigest(t *testing.T) {
	validSHA256 := strings.Repeat("a", 64)

	tests := []struct {
		name      string
		algorithm string
		value     string
		want      bool
	}{
		{
			name:      "valid sha256 is matchable",
			algorithm: "sha256",
			value:     validSHA256,
			want:      true,
		},
		{
			name:      "sha1 is NOT matchable (collision-vulnerable)",
			algorithm: "sha1",
			value:     strings.Repeat("a", 40), // a well-formed sha1 hex value
			want:      false,
		},
		{
			name:      "gitoid:sha1 is NOT matchable",
			algorithm: "gitoid:sha1",
			value:     "gitoid:blob:sha1:" + strings.Repeat("a", 40),
			want:      false,
		},
		{
			name:      "unknown algorithm is NOT matchable",
			algorithm: "md5",
			value:     strings.Repeat("a", 32),
			want:      false,
		},
		{
			name:      "sha256 value too short is rejected",
			algorithm: "sha256",
			value:     strings.Repeat("a", 63),
			want:      false,
		},
		{
			name:      "sha256 value too long is rejected",
			algorithm: "sha256",
			value:     strings.Repeat("a", 65),
			want:      false,
		},
		{
			name:      "empty sha256 value is rejected",
			algorithm: "sha256",
			value:     "",
			want:      false,
		},
		{
			// Finding S1 follow-up: correct length is NOT sufficient — a
			// 64-char string of non-hex characters is not a real sha256 and
			// must not anchor a subject match.
			name:      "sha256 correct length but non-hex is rejected",
			algorithm: "sha256",
			value:     strings.Repeat("z", 64),
			want:      false,
		},
		{
			name:      "sha256 with a single non-hex character is rejected",
			algorithm: "sha256",
			value:     strings.Repeat("a", 63) + "g",
			want:      false,
		},
		{
			name:      "sha256 uppercase hex is still valid hex",
			algorithm: "sha256",
			value:     strings.Repeat("A", 64),
			want:      true,
		},
		{
			name:      "gitoid:sha256 (non-hex value) is matchable when non-empty",
			algorithm: "gitoid:sha256",
			value:     "gitoid:blob:sha256:" + validSHA256,
			want:      true,
		},
		{
			name:      "gitoid:sha256 empty value is rejected",
			algorithm: "gitoid:sha256",
			value:     "",
			want:      false,
		},
		{
			name:      "dirHash value is matchable when non-empty",
			algorithm: "dirHash",
			value:     "h1:abcdef==",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsMatchableSubjectDigest(tt.algorithm, tt.value); got != tt.want {
				t.Fatalf("IsMatchableSubjectDigest(%q, %q) = %v, want %v",
					tt.algorithm, tt.value, got, tt.want)
			}
		})
	}
}
