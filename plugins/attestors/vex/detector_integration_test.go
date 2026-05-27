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

//go:build integration
// +build integration

package vex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// realOpenVEX is a minimum-well-formed OpenVEX document. Verifies the
// vex detector's product_glob matches the canonical filename.
const realOpenVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/example-2024",
  "author": "Cole Kennedy <cole@testifysec.com>",
  "timestamp": "2024-01-01T00:00:00Z",
  "statements": []
}`

func TestVEXDetectorAgainstCanonicalFilenames(t *testing.T) {
	cases := []string{
		"vex.json",
		"report.openvex.json",
		"my.vex.json",
	}
	for _, fn := range cases {
		t.Run(fn, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fn)
			if err := os.WriteFile(path, []byte(realOpenVEX), 0o600); err != nil {
				t.Fatal(err)
			}
			reg := detection.NewRegistry()
			reg.Register(Name, detectorYAML)
			pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
			res := detection.RunPostPlanWith(reg, detection.PostPlan{
				Pre:       pre,
				Products:  map[string]detection.ProductRef{fn: {Path: fn}},
				TraceMode: detection.TraceLight,
				Cwd:       dir,
			})
			for _, f := range res.Fire {
				if f.Attestor == Name {
					return
				}
			}
			t.Fatalf("vex did not fire on %s: %+v", fn, res)
		})
	}
}
