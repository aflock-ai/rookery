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

package testresults

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// realJUnit is a real JUnit XML report (minimum well-formed shape). We
// don't need an actual test runner to validate the detector's
// product_glob — the matcher only cares about the filename. Writing a
// real-shape document confirms we can match the canonical filename
// conventions every test runner uses.
const realJUnit = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="example" tests="1" failures="0" errors="0">
  <testsuite name="pkg/example" tests="1" failures="0" errors="0">
    <testcase classname="pkg/example" name="TestExample" time="0.001"/>
  </testsuite>
</testsuites>`

// TestDetectorAgainstRealJUnitFile writes a junit.xml at canonical
// filenames and asserts the test-results detector's product_glob
// matches each of them.
func TestDetectorAgainstRealJUnitFile(t *testing.T) {
	cases := []string{
		"junit.xml",
		"junit-report.xml",
		"JUnit.xml",
		"TEST-pkg.example.xml",
		"ctrf-report.json",
	}
	for _, fn := range cases {
		t.Run(fn, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fn)
			if err := os.WriteFile(path, []byte(realJUnit), 0o600); err != nil {
				t.Fatal(err)
			}

			reg := detection.NewRegistry()
			reg.Register(Name, detectorYAML)

			pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
			res := detection.RunPostPlanWith(reg, detection.PostPlan{
				Pre: pre,
				Products: map[string]detection.ProductRef{
					fn: {Path: fn},
				},
				TraceMode: detection.TraceLight,
				Cwd:       dir,
			})

			for _, f := range res.Fire {
				if f.Attestor == Name {
					return
				}
			}
			t.Errorf("test-results detector did not fire on %q: fire=%+v skip=%+v", fn, res.Fire, res.Skip)
		})
	}
}
