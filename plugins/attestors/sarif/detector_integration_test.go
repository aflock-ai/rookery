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

package sarif

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestSARIFDetectorAgainstRealTrivySARIF uses real trivy to emit a SARIF
// document (trivy supports --format sarif) and asserts the sarif
// detector's product_glob matches it. This is the canonical pattern
// for SARIF-producing scanners.
func TestSARIFDetectorAgainstRealTrivySARIF(t *testing.T) {
	tv, err := exec.LookPath("trivy")
	if err != nil {
		t.Skip("trivy not installed; skipping integration test")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")
	cmd := exec.Command(tv, "fs", "--quiet", "--format", "sarif", "--output", out, dir)
	if err := cmd.Run(); err != nil {
		t.Skipf("trivy sarif emit failed: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Size() == 0 {
		t.Skipf("trivy did not produce sarif (size=%d err=%v)", info.Size(), err)
	}

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
	res := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre: pre,
		Products: map[string]detection.ProductRef{
			"report.sarif": {Path: "report.sarif"},
		},
		TraceMode: detection.TraceLight,
		Cwd:       dir,
	})

	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("sarif detector did not fire on real trivy SARIF: fire=%+v skip=%+v", res.Fire, res.Skip)
}
