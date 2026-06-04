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

package cli

import (
	"strings"
	"testing"
)

// TestEnrichSkippedDetail_AppendsGeneratorHint proves a skipped format
// attestor (sbom) gets an actionable hint naming the external tools that would
// feed it, sourced from the detection registry. cilock never invokes those
// tools, so the hint must say so.
func TestEnrichSkippedDetail_AppendsGeneratorHint(t *testing.T) {
	got := enrichSkippedDetail("sbom", "no products to attest")
	if !strings.HasPrefix(got, "no products to attest;") {
		t.Errorf("original detail should be preserved, got %q", got)
	}
	if !strings.Contains(got, "syft") {
		t.Errorf("expected an SBOM generator (syft) in the hint, got %q", got)
	}
	if !strings.Contains(got, "cilock does NOT run it") {
		t.Errorf("hint must make clear cilock does not invoke the tool, got %q", got)
	}
}

// TestEnrichSkippedDetail_NoDoubleUp ensures the hint isn't appended when the
// attestor's own soft-error message already named a generator (sbom's richer
// message references syft).
func TestEnrichSkippedDetail_NoDoubleUp(t *testing.T) {
	original := "no SBOM file found in product set — run `syft <dir> -o spdx-json=sbom.spdx.json`"
	got := enrichSkippedDetail("sbom", original)
	if got != original {
		t.Errorf("detail already naming a generator must be left unchanged,\nwant %q\ngot  %q", original, got)
	}
}

// TestEnrichSkippedDetail_SelfContainedAttestor proves a self-contained
// attestor (git reads .git/, no external generator) gets no spurious hint.
func TestEnrichSkippedDetail_SelfContainedAttestor(t *testing.T) {
	original := "no .git directory"
	got := enrichSkippedDetail("git", original)
	if got != original {
		t.Errorf("self-contained attestor should get no generator hint,\nwant %q\ngot  %q", original, got)
	}
}
