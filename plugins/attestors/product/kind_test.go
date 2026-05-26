// Copyright 2026 The Rookery Contributors
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

// V2 plan Phase 10: sandbox-boundary linkage via product `kind` hints.
// Pins the detection table for well-known attestation/SBOM/scan-result
// file types so verifiers can pick up inner attestations from the
// outer trace's product set without re-parsing every file.

package product

import "testing"

func TestDetectProductKind(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		// in-toto envelopes (bare Statement or DSSE-wrapped)
		{"/build/out/manifest.intoto.json", "intoto"},
		{"/build/out/manifest.intoto.jsonl", "intoto"},
		{"/build/out/signed.intoto.dsse", "intoto-dsse"},
		{"/build/out/signed.dsse", "intoto-dsse"},
		// SLSA
		{"/dist/release-v1.2.3.slsa-provenance.json", "slsa-provenance"},
		// SBOMs
		{"/build/sbom.spdx.json", "spdx"},
		{"/build/sbom.spdx.yaml", "spdx"},
		{"/build/sbom.cdx.json", "cyclonedx"},
		{"/build/sbom.cdx.xml", "cyclonedx"},
		{"/build/bom.json", "cyclonedx"},
		{"bom.json", "cyclonedx"},
		// scan results
		{"/findings/results.sarif", "sarif"},
		{"/findings/results.sarif.json", "sarif"},
		{"/vex/notice.vex.json", "vex"},
		{"/vex/csaf.csaf.json", "vex"},
		// case-insensitive
		{"/Dist/Manifest.INTOTO.JSON", "intoto"},
		// unknown — empty string
		{"/build/output.tar.gz", ""},
		{"/build/binary", ""},
		{"/build/main.go", ""},
		{"/build/random.json", ""},
		// not a partial-match — bom.json must be at end or basename
		{"/something/bomb.json", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := detectProductKind(tc.path)
			if got != tc.want {
				t.Errorf("detectProductKind(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}
