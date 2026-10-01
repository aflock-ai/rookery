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

package slsa

import (
	"strings"
	"testing"
)

func TestTrustedBuildersCatalog(t *testing.T) {
	builders := TrustedBuilders()
	if len(builders) == 0 {
		t.Fatal("empty trusted-builder catalog")
	}
	seen := map[string]bool{}
	for _, b := range builders {
		if b.ID == "" || strings.Contains(b.ID, "@") || seen[b.ID] {
			t.Errorf("entry %+v: id must be unique, non-empty and carry no @<ref>", b)
		}
		seen[b.ID] = true
		if b.MaxLevel < 1 || b.MaxLevel > 3 {
			t.Errorf("entry %s: max level %d outside 1..3", b.ID, b.MaxLevel)
		}
		if b.Requires == "" || b.Proof == "" {
			t.Errorf("entry %s: every level grant names what a verifier must check and the proof behind it", b.ID)
		}
		// Only a builder with a verifier that checks its signer identity may
		// be trusted to L3; today that is the isolated provenance workflow.
		if b.MaxLevel == 3 && b.ID != "https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml" {
			t.Errorf("entry %s: L3 without a level-3 verifier", b.ID)
		}
	}
}

// The level comes from the catalog keyed by builder.id, never from anything
// else in the provenance; unknown builders get nothing.
func TestBuilderMaxLevel(t *testing.T) {
	for id, want := range map[string]int{
		"https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml@0123456789abcdef0123456789abcdef01234567": 3,
		"https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml@refs/tags/v1":                             3,
		"https://aflock.ai/cilock/inline/github-actions@v1":                                                                    2,
		"https://aflock.ai/cilock/inline/unknown-platform@v1":                                                                  1,
		"https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml":                                          0,
		"https://github.com/mallory/cilock-action/.github/workflows/provenance.yml@x":                                          0,
		"https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml.evil@x":                                   0,
		"HTTPS://GITHUB.COM/aflock-ai/cilock-action/.github/workflows/provenance.yml@x":                                        0,
		"https://aflock.ai/attestation-github-action-builder@v0.1":                                                             0,
		"": 0,
	} {
		if got := BuilderMaxLevel(id); got != want {
			t.Errorf("BuilderMaxLevel(%q) = %d, want %d", id, got, want)
		}
	}
}
