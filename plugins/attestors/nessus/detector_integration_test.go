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

package nessus

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

func TestNessusDetectorAgainstCanonicalFilename(t *testing.T) {
	cases := []string{"scan.nessus", "host-report.nessus", "subdir/inner.nessus"}
	for _, fn := range cases {
		t.Run(fn, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, filepath.FromSlash(fn))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`<?xml version="1.0"?><NessusClientData_v2/>`), 0o600); err != nil {
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
			t.Fatalf("nessus did not fire on %q: %+v", fn, res)
		})
	}
}
